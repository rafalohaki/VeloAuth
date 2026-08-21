package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry;
import net.rafalohaki.veloauth.util.DatabaseErrorHandler;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import net.rafalohaki.veloauth.util.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;

import java.net.InetAddress;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * Shared context for all command implementations.
 * Provides access to common services and template methods used by extracted commands.
 */
class CommandContext {

    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");
    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");

    private final VeloAuth plugin;
    private final DatabaseManager databaseManager;
    private final AuthCache authCache;
    private final Settings settings;
    private final Messages messages;
    private final Logger logger;
    private final IPRateLimiter ipRateLimiter;
    private final net.rafalohaki.veloauth.auth.ConflictModeService conflictModeService;
    private final ConcurrentHashMap<UUID, ConnectionLifecycleRegistry.Operation> activeCommands =
            new ConcurrentHashMap<>();

    /**
     * Per-IP mutex for the {@code /register} flow. Closes the TOCTOU window between the
     * "count registrations by IP" check and the "save player" write: two concurrent /register
     * commands from the same IP can no longer both pass the {@code ip-limit-registrations}
     * gate. Caffeine-bounded (≤10k IPs) with a short TTL — far longer than any register call
     * but bounded enough to recover from leaked locks if a register handler throws past its
     * release point. */
    private final Cache<InetAddress, Object> registrationLocks = Caffeine.newBuilder()
            .maximumSize(10_000)
            .expireAfterWrite(Duration.ofMinutes(1))
            .build();

    CommandContext(VeloAuth plugin, DatabaseManager databaseManager,
                   AuthCache authCache, Settings settings, Messages messages) {
        this.plugin = plugin;
        this.databaseManager = databaseManager;
        this.authCache = authCache;
        this.settings = settings;
        this.messages = messages;
        this.logger = plugin.getLogger();
        Settings.BruteForceSettings bruteForceSettings =
                settings.captureOperationSettings().bruteForce();
        this.ipRateLimiter = new IPRateLimiter(
                bruteForceSettings.maxAttempts(),
                bruteForceSettings.timeoutMinutes());
        authCache.setIpRateLimiter(this.ipRateLimiter);
        this.conflictModeService = new net.rafalohaki.veloauth.auth.ConflictModeService(
                databaseManager, bruteForceSettings.conflictModeTtlHours());
    }

    VeloAuth plugin() { return plugin; }
    DatabaseManager databaseManager() { return databaseManager; }
    AuthCache authCache() { return authCache; }
    Settings settings() { return settings; }
    Messages messages() { return messages; }
    Logger logger() { return logger; }
    IPRateLimiter ipRateLimiter() { return ipRateLimiter; }
    net.rafalohaki.veloauth.auth.ConflictModeService conflictModeService() { return conflictModeService; }

    /**
     * Releases resources held by the command layer. Currently a passthrough to
     * {@link IPRateLimiter#shutdown()} for lifecycle symmetry with other components.
     */
    void shutdown() {
        ipRateLimiter.shutdown();
    }
    net.rafalohaki.veloauth.auth.totp.TotpService totpService() { return plugin.getTotpService(); }
    net.rafalohaki.veloauth.auth.totp.PendingTotpStore pendingTotpStore() { return plugin.getPendingTotpStore(); }
    net.rafalohaki.veloauth.auth.totp.TotpReplayGuard totpReplayGuard() { return plugin.getTotpReplayGuard(); }
    net.rafalohaki.veloauth.audit.AuditLogService auditLogService() { return plugin.getAuditLogService(); }
    net.rafalohaki.veloauth.report.ReportService reportService() { return plugin.getReportService(); }
    ConnectionLifecycleRegistry.Operation captureConnectionOperation(Player player) {
        return plugin.getConnectionLifecycleRegistry().capture(player);
    }
    boolean isConnectionCurrent(ConnectionLifecycleRegistry.Operation operation) {
        return plugin.getConnectionLifecycleRegistry().isCurrent(operation);
    }
    boolean runIfConnectionCurrent(ConnectionLifecycleRegistry.Operation operation, Runnable effect) {
        return plugin.getConnectionLifecycleRegistry().runIfCurrent(operation, effect);
    }
    void retireConnectionOperation(Player player) {
        plugin.getConnectionLifecycleRegistry().markRetired(
                player, () -> plugin.clearConnectionBoundState(
                        player, authCache, plugin.getConnectionManager()));
    }

    /**
     * Template method for common authentication pre-checks:
     * 1. Validate player source
     * 2. Check brute force protection
     * 3. Fetch player from database with error handling
     *
     * @param source      command source
     * @param commandName name of the command for logging
     * @return AuthenticationContext if all checks pass, null otherwise
     */
    AuthenticationContext validateAndAuthenticatePlayer(CommandSource source, String commandName) {
        Player player = CommandHelper.validatePlayerSource(source, messages);
        if (player == null) {
            return null;
        }

        ConnectionLifecycleRegistry.Operation operation = captureConnectionOperation(player);
        if (operation == null) {
            return null;
        }
        return validateAndAuthenticatePlayer(player, commandName, operation);
    }

    AuthenticationContext validateAndAuthenticatePlayer(
            Player player, String commandName,
            ConnectionLifecycleRegistry.Operation operation) {
        return validateAndAuthenticatePlayer(
                player, commandName, operation,
                message -> runIfConnectionCurrent(
                        operation, () -> player.sendMessage(message)));
    }

    AuthenticationContext validateAndAuthenticatePlayer(
            Player player, String commandName,
            ConnectionLifecycleRegistry.Operation operation,
            DatabaseManager.RegistrationCommitPermit permit) {
        return validateAndAuthenticatePlayer(
                player, commandName, operation,
                message -> completeRegistrationWithoutCommit(
                        operation, permit, () -> player.sendMessage(message)));
    }

    private AuthenticationContext validateAndAuthenticatePlayer(
            Player player, String commandName,
            ConnectionLifecycleRegistry.Operation operation,
            Consumer<Component> messageSender) {
        if (!isConnectionCurrent(operation)) {
            return null;
        }

        InetAddress playerAddress = PlayerAddressUtils.getPlayerAddress(player);

        if (playerAddress != null && authCache.isBlocked(playerAddress, player.getUsername())) {
            messageSender.accept(messages.component(
                    "security.brute_force.blocked", NamedTextColor.RED));
            if (logger.isWarnEnabled()) {
                logger.warn(SECURITY_MARKER, "[BRUTE FORCE BLOCK] IP {} attempted {}", playerAddress.getHostAddress(), commandName);
            }
            return null;
        }

        String username = player.getUsername();
        DatabaseManager.DbResult<net.rafalohaki.veloauth.model.RegisteredPlayer> dbResult;
        try {
            dbResult = databaseManager.findPlayerByNickname(username).join();
        } catch (CompletionException e) {
            logger.error(DB_MARKER, "Database error during {} for player {}", commandName, username, e);
            messageSender.accept(messages.component("error.database.query", NamedTextColor.RED));
            return null;
        }

        if (DatabaseErrorHandler.handleError(
                dbResult, username, commandName + " lookup for", logger, messages,
                messageSender)) {
            return null;
        }

        if (!isConnectionCurrent(operation)) {
            return null;
        }
        return new AuthenticationContext(player, username, playerAddress, dbResult.getValue(), operation);
    }

    /**
     * Checks premium status with error handling and logging.
     */
    DatabaseManager.DbResult<Boolean> checkPremiumStatus(Player player, String operation) {
        DatabaseManager.DbResult<Boolean> result;
        try {
            result = databaseManager.isPremium(player.getUsername()).join();
        } catch (CompletionException e) {
            logger.error(DB_MARKER, "[DATABASE ERROR] {} failed for {}", operation, player.getUsername(), e);
            player.sendMessage(messages.component("error.database.query", NamedTextColor.RED));
            return DatabaseManager.DbResult.databaseError("CompletionException: " + e.getMessage());
        }
        if (result.isDatabaseError()) {
            if (logger.isErrorEnabled()) {
                logger.error(SECURITY_MARKER, "[DATABASE ERROR] {} failed for {}: {}", operation, player.getUsername(), result.getErrorMessage());
            }
            player.sendMessage(messages.component("error.database.query", NamedTextColor.RED));
        }
        return result;
    }

    DatabaseManager.DbResult<Boolean> checkPremiumStatus(
            String username, Player player, String operation,
            ConnectionLifecycleRegistry.Operation connectionOperation) {
        DatabaseManager.DbResult<Boolean> result;
        try {
            result = databaseManager.isPremium(username).join();
        } catch (RuntimeException e) {
            logger.error(DB_MARKER, "[DATABASE ERROR] {} failed for {}", operation, username, e);
            runIfConnectionCurrent(connectionOperation,
                    () -> player.sendMessage(messages.component(
                            "error.database.query", NamedTextColor.RED)));
            return DatabaseManager.DbResult.databaseError(
                    e.getClass().getSimpleName() + ": " + e.getMessage());
        }
        if (result.isDatabaseError()) {
            if (logger.isErrorEnabled()) {
                logger.error(SECURITY_MARKER, "[DATABASE ERROR] {} failed for {}: {}",
                        operation, username, result.getErrorMessage());
            }
            runIfConnectionCurrent(connectionOperation,
                    () -> player.sendMessage(messages.component(
                            "error.database.query", NamedTextColor.RED)));
        }
        return result;
    }

    /**
     * Handles database errors consistently across all commands.
     */
    boolean handleDatabaseError(DatabaseManager.DbResult<?> result, Player player, String operation) {
        return DatabaseErrorHandler.handleError(result, player, operation, logger, messages);
    }

    boolean handleDatabaseError(
            DatabaseManager.DbResult<?> result, String identifier, Player player, String operation,
            ConnectionLifecycleRegistry.Operation connectionOperation) {
        return DatabaseErrorHandler.handleError(
                result, identifier, operation, logger, messages,
                message -> runIfConnectionCurrent(
                        connectionOperation, () -> player.sendMessage(message)));
    }

    /**
     * Handles database errors consistently across admin commands.
     */
    boolean handleDatabaseError(DatabaseManager.DbResult<?> result, CommandSource source,
                                String identifier, String operation) {
        return DatabaseErrorHandler.handleError(result, source, identifier, operation, logger, messages);
    }

    /**
     * Resets brute-force and rate-limit counters for the given IP address and username.
     */
    void resetSecurityCounters(InetAddress playerAddress, String username) {
        SecurityUtils.resetSecurityCounters(playerAddress, username, authCache, ipRateLimiter);
    }

    /**
     * Sends a database error message to the player.
     */
    void sendDatabaseErrorMessage(Player player) {
        player.sendMessage(messages.component("error.database.query", NamedTextColor.RED));
    }

    /**
     * Sends a database error message to any command source.
     */
    void sendDatabaseErrorMessage(CommandSource source) {
        source.sendMessage(messages.component("error.database.query", NamedTextColor.RED));
    }

    /**
     * Executes a command asynchronously using the shared command helper.
     */
    void runAsyncCommand(CommandSource source, Runnable task, String errorKey) {
        CommandHelper.runAsyncCommand(task, messages, source, errorKey);
    }

    void runAsyncCommand(
            Player player, ConnectionLifecycleRegistry.Operation operation,
            Runnable task, String errorKey) {
        CommandHelper.runAsyncCommand(task, messages, errorKey,
                message -> runIfConnectionCurrent(
                        operation, () -> player.sendMessage(message)));
    }

    /**
     * Executes a command asynchronously with timeout using the shared command helper.
     */
    void runAsyncCommandWithTimeout(CommandSource source, Runnable task,
                                    String errorKey, String timeoutKey) {
        CommandHelper.runAsyncCommandWithTimeout(task, messages, source, errorKey, timeoutKey);
    }

    void runAsyncCommandWithTimeout(
            Player player, ConnectionLifecycleRegistry.Operation operation, Runnable task,
            String errorKey, String timeoutKey) {
        CommandHelper.runAsyncCommandWithTimeout(task, messages, errorKey, timeoutKey,
                message -> runIfConnectionCurrent(
                        operation, () -> player.sendMessage(message)));
    }

    void runRegistrationCommandWithTimeout(
            Player player, ConnectionLifecycleRegistry.Operation operation,
            DatabaseManager.RegistrationCommitPermit permit, Runnable task,
            String errorKey) {
        CommandHelper.runAsyncCommandWithTimeout(
                task, messages, errorKey,
                message -> runIfConnectionCurrent(
                        operation, () -> player.sendMessage(message)),
                () -> handleRegistrationTimeout(player, operation, permit));
    }

    @SuppressWarnings("java:S6916") // See the COMMIT_UNKNOWN comment: the suggested guard cannot compile here.
    DatabaseManager.RegistrationTimeoutDisposition handleRegistrationTimeout(
            Player player, ConnectionLifecycleRegistry.Operation operation,
            DatabaseManager.RegistrationCommitPermit permit) {
        DatabaseManager.RegistrationTimeoutDisposition disposition = permit.onTimeout();
        switch (disposition) {
            case CANCELLED_BEFORE_COMMIT -> sendRegistrationDeadlineMessage(
                    player, operation, "auth.registration.timeout", NamedTextColor.RED);
            case COMMIT_IN_PROGRESS, COMMIT_COMPLETED -> sendRegistrationDeadlineMessage(
                    player, operation, "auth.registration.commit_pending", NamedTextColor.YELLOW);
            // S6916 suggests a `when` guard here, but guards are only legal on pattern case
            // labels (JLS 14.11.1) and this switch selects over enum constants — the rule's
            // suggested rewrite does not compile.
            case COMMIT_UNKNOWN -> {
                if (permit.claimCommitUnknownMessage()) {
                    sendRegistrationDeadlineMessage(
                            player, operation, "auth.registration.commit_unknown",
                            NamedTextColor.RED);
                }
            }
            case NO_ACTION -> {
                // The command already reached a terminal result and owns its player message.
            }
        }
        return disposition;
    }

    boolean completeRegistrationWithoutCommit(
            ConnectionLifecycleRegistry.Operation operation,
            DatabaseManager.RegistrationCommitPermit permit, Runnable effect) {
        if (!permit.tryCompleteWithoutCommit()) {
            return false;
        }
        return runIfConnectionCurrent(operation, effect);
    }

    private void sendRegistrationDeadlineMessage(
            Player player, ConnectionLifecycleRegistry.Operation operation,
            String messageKey, NamedTextColor color) {
        runIfConnectionCurrent(operation,
                () -> player.sendMessage(messages.component(messageKey, color)));
    }

    /**
     * Ensures the database is currently connected before continuing an admin command.
     */
    boolean ensureDatabaseConnected(CommandSource source, String operation) {
        if (databaseManager.isConnected()) {
            return true;
        }

        if (logger.isWarnEnabled()) {
            logger.warn(SECURITY_MARKER, "[DATABASE ERROR] {} failed: database not connected", operation);
        }
        sendDatabaseErrorMessage(source);
        return false;
    }

    /**
     * Sends the standard per-player in-progress message.
     */
    void sendCommandInProgress(Player player) {
        player.sendMessage(messages.component("auth.command.in_progress", NamedTextColor.YELLOW));
    }

    boolean beginConnectionCommand(
            Player player, ConnectionLifecycleRegistry.Operation operation) {
        if (!isConnectionCurrent(operation)) {
            return false;
        }
        if (tryAcquireCommandLock(operation.playerId(), operation)) {
            return true;
        }
        runIfConnectionCurrent(operation, () -> sendCommandInProgress(player));
        return false;
    }

    boolean beginConnectionCommand(
            Player player, ConnectionLifecycleRegistry.Operation operation,
            DatabaseManager.RegistrationCommitPermit permit) {
        if (!isConnectionCurrent(operation)) {
            return false;
        }
        if (tryAcquireCommandLock(operation.playerId(), operation)) {
            return true;
        }
        completeRegistrationWithoutCommit(
                operation, permit, () -> sendCommandInProgress(player));
        return false;
    }

    boolean rejectRateLimited(
            Player player, InetAddress address,
            ConnectionLifecycleRegistry.Operation operation) {
        if (address == null || !ipRateLimiter.isRateLimited(address)) {
            return false;
        }
        runIfConnectionCurrent(operation, () -> player.sendMessage(messages.component(
                "security.brute_force.blocked", NamedTextColor.RED)));
        return true;
    }

    boolean rejectRateLimited(
            Player player, InetAddress address,
            ConnectionLifecycleRegistry.Operation operation,
            DatabaseManager.RegistrationCommitPermit permit) {
        if (address == null || !ipRateLimiter.isRateLimited(address)) {
            return false;
        }
        completeRegistrationWithoutCommit(
                operation, permit,
                () -> player.sendMessage(messages.component(
                        "security.brute_force.blocked", NamedTextColor.RED)));
        return true;
    }

    /**
     * Tries to acquire a per-player command lock to prevent concurrent command execution.
     *
     * @param playerId UUID of the player
     * @return true if lock acquired, false if already processing
     */
    boolean tryAcquireCommandLock(
            UUID playerId, ConnectionLifecycleRegistry.Operation operation) {
        AtomicBoolean acquired = new AtomicBoolean();
        activeCommands.compute(playerId, (ignored, current) -> {
            if (current == null || !isConnectionCurrent(current)) {
                acquired.set(true);
                return operation;
            }
            return current;
        });
        return acquired.get();
    }

    /**
     * Releases the per-player command lock.
     *
     * @param playerId UUID of the player
     */
    void releaseCommandLock(
            UUID playerId, ConnectionLifecycleRegistry.Operation operation) {
        activeCommands.remove(playerId, operation);
    }

    /**
     * Tries to acquire the per-IP register lock — closes the TOCTOU window on
     * {@code ip-limit-registrations}. {@code null} address never acquires (treated as
     * not-allowed; caller surface defends with its own null-checks).
     */
    RegistrationLockLease tryAcquireRegistrationLock(InetAddress address) {
        if (address == null) {
            return null;
        }
        Object owner = new Object();
        return registrationLocks.asMap().putIfAbsent(address, owner) == null
                ? new RegistrationLockLease(address, owner)
                : null;
    }

    /** Releases the exact per-IP register lease. No-op for {@code null} or a replaced lease. */
    void releaseRegistrationLock(RegistrationLockLease lease) {
        if (lease != null) {
            registrationLocks.asMap().remove(lease.address(), lease.owner());
        }
    }

    record RegistrationLockLease(InetAddress address, Object owner) { }
}
