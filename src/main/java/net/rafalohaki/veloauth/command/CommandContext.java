package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.i18n.SimpleMessages;
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
    private final SimpleMessages sm;
    private final IPRateLimiter ipRateLimiter;
    private final ConcurrentHashMap<UUID, Boolean> activeCommands = new ConcurrentHashMap<>();

    /**
     * Per-IP mutex for the {@code /register} flow. Closes the TOCTOU window between the
     * "count registrations by IP" check and the "save player" write: two concurrent /register
     * commands from the same IP can no longer both pass the {@code ip-limit-registrations}
     * gate. Caffeine-bounded (≤10k IPs) with a short TTL — far longer than any register call
     * but bounded enough to recover from leaked locks if a register handler throws past its
     * release point. */
    private final Cache<InetAddress, Boolean> registrationLocks = Caffeine.newBuilder()
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
        this.ipRateLimiter = new IPRateLimiter(
                settings.getBruteForceMaxAttempts(),
                settings.getBruteForceTimeoutMinutes());
        authCache.setIpRateLimiter(this.ipRateLimiter);
        this.sm = new SimpleMessages(messages);
    }

    VeloAuth plugin() { return plugin; }
    DatabaseManager databaseManager() { return databaseManager; }
    AuthCache authCache() { return authCache; }
    Settings settings() { return settings; }
    Messages messages() { return messages; }
    Logger logger() { return logger; }
    SimpleMessages sm() { return sm; }
    IPRateLimiter ipRateLimiter() { return ipRateLimiter; }
    net.rafalohaki.veloauth.auth.totp.TotpService totpService() { return plugin.getTotpService(); }
    net.rafalohaki.veloauth.auth.totp.PendingTotpStore pendingTotpStore() { return plugin.getPendingTotpStore(); }
    net.rafalohaki.veloauth.auth.totp.TotpReplayGuard totpReplayGuard() { return plugin.getTotpReplayGuard(); }
    net.rafalohaki.veloauth.audit.AuditLogService auditLogService() { return plugin.getAuditLogService(); }
    net.rafalohaki.veloauth.report.ReportService reportService() { return plugin.getReportService(); }

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

        InetAddress playerAddress = PlayerAddressUtils.getPlayerAddress(player);

        if (playerAddress != null && authCache.isBlocked(playerAddress, player.getUsername())) {
            player.sendMessage(sm.bruteForceBlocked());
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
            player.sendMessage(sm.errorDatabase());
            return null;
        }

        if (handleDatabaseError(dbResult, player, commandName + " lookup for")) {
            return null;
        }

        return new AuthenticationContext(player, username, playerAddress, dbResult.getValue());
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
            player.sendMessage(sm.errorDatabase());
            return DatabaseManager.DbResult.databaseError("CompletionException: " + e.getMessage());
        }
        if (result.isDatabaseError()) {
            if (logger.isErrorEnabled()) {
                logger.error(SECURITY_MARKER, "[DATABASE ERROR] {} failed for {}: {}", operation, player.getUsername(), result.getErrorMessage());
            }
            player.sendMessage(sm.errorDatabase());
        }
        return result;
    }

    /**
     * Handles database errors consistently across all commands.
     */
    boolean handleDatabaseError(DatabaseManager.DbResult<?> result, Player player, String operation) {
        return DatabaseErrorHandler.handleError(result, player, operation, logger, messages);
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
        player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
    }

    /**
     * Sends a database error message to any command source.
     */
    void sendDatabaseErrorMessage(CommandSource source) {
        source.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
    }

    /**
     * Executes a command asynchronously using the shared command helper.
     */
    void runAsyncCommand(CommandSource source, Runnable task, String errorKey) {
        CommandHelper.runAsyncCommand(task, messages, source, errorKey);
    }

    /**
     * Executes a command asynchronously with timeout using the shared command helper.
     */
    void runAsyncCommandWithTimeout(CommandSource source, Runnable task,
                                    String errorKey, String timeoutKey) {
        CommandHelper.runAsyncCommandWithTimeout(task, messages, source, errorKey, timeoutKey);
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
        player.sendMessage(ValidationUtils.createWarningComponent(messages.get("auth.command.in_progress")));
    }

    /**
     * Tries to acquire a per-player command lock to prevent concurrent command execution.
     *
     * @param playerId UUID of the player
     * @return true if lock acquired, false if already processing
     */
    boolean tryAcquireCommandLock(UUID playerId) {
        return activeCommands.putIfAbsent(playerId, Boolean.TRUE) == null;
    }

    /**
     * Releases the per-player command lock.
     *
     * @param playerId UUID of the player
     */
    void releaseCommandLock(UUID playerId) {
        activeCommands.remove(playerId);
    }

    /**
     * Tries to acquire the per-IP register lock — closes the TOCTOU window on
     * {@code ip-limit-registrations}. {@code null} address never acquires (treated as
     * not-allowed; caller surface defends with its own null-checks).
     */
    boolean tryAcquireRegistrationLock(InetAddress address) {
        if (address == null) {
            return false;
        }
        return registrationLocks.asMap().putIfAbsent(address, Boolean.TRUE) == null;
    }

    /** Releases the per-IP register lock. No-op for {@code null}. */
    void releaseRegistrationLock(InetAddress address) {
        if (address != null) {
            registrationLocks.invalidate(address);
        }
    }
}
