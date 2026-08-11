package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.authserver.AuthServerProvider;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
import org.slf4j.Logger;

import com.velocitypowered.api.scheduler.ScheduledTask;

import java.net.InetSocketAddress;
import java.util.concurrent.CompletableFuture;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Manager połączeń i transferów graczy między serwerami.
 * Zarządza przepuszczaniem graczy między Velocity, serwerem auth (limbo) i serwerami backend.
 * <p>
 * Flow autoryzacji:
 * 1. Gracz dołącza -> domyślnie przez auth server; jawny opt-in może przepuścić premium
 * 2. Gracz na auth server -> jeśli zweryfikowany w cache: auto-transfer na backend
 * 3. Gracz na auth server -> /login lub /register -> transfer na backend
 * 4. Gracz na backend -> już autoryzowany, brak dodatkowych sprawdzeń
 */
public class ConnectionManager {

    /** Timeout for server connection attempts - configurable via Settings */
    private static final String CONNECTION_ERROR_GAME_SERVER = "connection.error.game_server";
    private static final String MSG_ERROR_UNKNOWN = "error.unknown";
    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final int MAX_AUTH_SERVER_WAIT_ATTEMPTS = 3;
    private static final int BACKEND_WAIT_REMINDER_INTERVAL = 6;
    private static final long BACKEND_FALLBACK_WARN_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(30);

    /** Current concrete player owner and generation for each UUID. */
    private final ConcurrentMap<UUID, PlayerTransferState> transferStates = new ConcurrentHashMap<>();
    private final AtomicLong transferGeneration = new AtomicLong();
    
    /** Retry attempt counter per player to prevent infinite fallback loops */
    private final Map<UUID, AtomicInteger> retryAttempts = new ConcurrentHashMap<>();
    
    /** One-shot timeout retry flag per player to avoid repeated scheduling */
    private final Map<UUID, Boolean> timeoutRetryScheduled = new ConcurrentHashMap<>();

    /** Timeout retry tasks per player - allows cancellation on disconnect and manual transfers */
    private final ConcurrentMap<UUID, ScheduledTask> timeoutRetryTasks = new ConcurrentHashMap<>();
    
    /** Pending transfer tasks per player - allows cancellation on disconnect to prevent race conditions */
    private final ConcurrentMap<UUID, ScheduledTask> pendingTransfers = new ConcurrentHashMap<>();
    
    /** Backend wait retry tasks per player - allows cancellation on disconnect */
    private final ConcurrentMap<UUID, ScheduledTask> backendWaitTasks = new ConcurrentHashMap<>();

    /** Owns the concrete backend connection attempt, not merely its scheduling task. */
    private final ConcurrentMap<UUID, Player> backendConnectionOwners = new ConcurrentHashMap<>();

    /** Serializes task publication with shutdown so late async completions cannot resurrect work. */
    private final ReentrantLock taskLifecycleLock = new ReentrantLock();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicLong backendFallbackWarnAfterNanos = new AtomicLong(System.nanoTime());
    private final AtomicInteger suppressedBackendFallbackWarnings = new AtomicInteger();
    
    /** Max number of backend wait retries before giving up (5s interval × 60 = 5 minutes) */
    private static final int MAX_BACKEND_WAIT_RETRIES = 60;
    private static final long BACKEND_WAIT_INTERVAL_SECONDS = 5;
    
    /** Forced host targets per player - preserves original intended server through auth flow */
    private final Map<UUID, String> forcedHostTargets = new ConcurrentHashMap<>();

    private final VeloAuth plugin;
    private final AuthCache authCache;
    private final Settings settings;
    private final Logger logger;
    private final Messages messages;
    private final AuthServerProvider authServerProvider;

    /**
     * Tworzy nowy ConnectionManager.
     *
     * @param plugin          VeloAuth plugin instance
     * @param authCache       Cache autoryzacji
     * @param settings        Ustawienia pluginu
     * @param messages        System wiadomości i18n
     */
    public ConnectionManager(VeloAuth plugin,
                             AuthCache authCache, Settings settings, Messages messages) {
        this(plugin, authCache, settings, messages,
                initializedExternalProvider(plugin, settings));
    }

    /**
     * Creates a connection manager against the restart-scoped auth-server topology.
     *
     * @param plugin plugin instance
     * @param authCache authorization cache
     * @param settings validated settings
     * @param messages i18n messages
     * @param authServerProvider external or embedded auth-server owner
     */
    public ConnectionManager(VeloAuth plugin,
                             AuthCache authCache, Settings settings, Messages messages,
                             AuthServerProvider authServerProvider) {
        this.plugin = plugin;
        this.authCache = authCache;
        this.settings = settings;
        this.logger = plugin.getLogger();
        this.messages = messages;
        this.authServerProvider = authServerProvider;

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.manager.initialized", authServerProvider.serverName()));
        }
    }

    private static AuthServerProvider initializedExternalProvider(VeloAuth plugin, Settings settings) {
        AuthServerProvider provider = AuthServerProvider.forExternal(
                plugin.getServer(), settings.getAuthServerName(), plugin.getLogger());
        provider.start();
        return provider;
    }

    /**
     * Starts a new concrete-player transfer generation, replacing any prior owner for the UUID.
     * This is the only boundary allowed to replace a state owned by another {@link Player} object.
     */
    public void beginTransferSession(Player player) {
        UUID playerId = player.getUniqueId();
        PlayerTransferState replacement = new PlayerTransferState(
                playerId, player, transferGeneration.incrementAndGet());
        PlayerTransferState displaced;
        while (true) {
            displaced = transferStates.putIfAbsent(playerId, replacement);
            if (displaced == null || transferStates.replace(playerId, displaced, replacement)) {
                break;
            }
        }
        initializeForcedHostTarget(replacement);
        if (displaced != null) {
            cancelStateTasks(displaced);
        }
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Concrete Velocity Player identity owns the generation.
    private PlayerTransferState currentState(Player player) {
        UUID playerId = player.getUniqueId();
        PlayerTransferState current = transferStates.get(playerId);
        if (current != null) {
            return current.owner() == player ? current : null;
        }

        PlayerTransferState candidate = new PlayerTransferState(
                playerId, player, transferGeneration.incrementAndGet());
        PlayerTransferState raced = transferStates.putIfAbsent(playerId, candidate);
        if (raced == null) {
            initializeForcedHostTarget(candidate);
            return candidate;
        }
        return raced.owner() == player ? raced : null;
    }

    private void initializeForcedHostTarget(PlayerTransferState state) {
        String target = forcedHostTargets.remove(state.playerId());
        if (target != null && isCurrent(state)) {
            state.forcedHostTarget().compareAndSet(null, target);
        }
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // State identity is the generation token.
    private boolean isCurrent(PlayerTransferState state) {
        return transferStates.get(state.playerId()) == state;
    }

    private boolean isStale(PlayerTransferState state) {
        return closed.get() || !isCurrent(state);
    }

    private boolean resetTasksIfCurrent(PlayerTransferState state, boolean clearForcedHostTarget) {
        if (!isCurrent(state)) {
            return false;
        }
        cancelStateTasks(state);
        if (clearForcedHostTarget) {
            state.forcedHostTarget().set(null);
        }
        return true;
    }

    private boolean finishIfCurrent(PlayerTransferState state, boolean clearForcedHostTarget) {
        if (!transferStates.remove(state.playerId(), state)) {
            return false;
        }
        cancelStateTasks(state);
        if (clearForcedHostTarget) {
            state.forcedHostTarget().set(null);
        }
        return true;
    }

    private void cancelStateTasks(PlayerTransferState state) {
        state.timeoutRetryActive().set(false);
        ScheduledTaskRegistry.cancel(state.pendingTransfer());
        ScheduledTaskRegistry.cancel(state.backendWait());
        ScheduledTaskRegistry.cancel(state.timeoutRetry());
    }

    public CompletableFuture<Boolean> transferToAuthServerAsync(Player player) {
        try {
            resetTransferState(player.getUniqueId(), false);
            RegisteredServer targetServer = validateAndGetAuthServer(player);
            if (targetServer == null) {
                return CompletableFuture.completedFuture(false);
            }

            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("player.transfer.attempt", player.getUsername()));
            }

            return executeAuthServerTransferAsync(player, targetServer);
        } catch (RuntimeException e) {
            return CompletableFuture.completedFuture(handleTransferError(player, e));
        }
    }
    
    private RegisteredServer validateAndGetAuthServer(Player player) {
        return validateAndGetAuthServer(player, null);
    }

    private RegisteredServer validateAndGetAuthServer(
            Player player, @javax.annotation.Nullable PlayerTransferState state) {
        Optional<RegisteredServer> authServer = authServerProvider.resolve();

        if (authServer.isEmpty()) {
            if (state != null && isStale(state)) {
                return null;
            }
            logger.error("Auth server '{}' is not registered!",
                    authServerProvider.serverName());

            if (state == null || !isStale(state)) {
                player.disconnect(messages.component("connection.error.auth_server", NamedTextColor.RED));
            }
            return null;
        }
        
        return authServer.get();
    }
    
    private boolean handleTransferError(Player player, Exception e) {
        if (logger.isErrorEnabled()) {
            logger.error("Critical error transferring player to auth server: {}", player.getUsername(), e);
        }

        player.disconnect(messages.component("connection.error.auth_connect", NamedTextColor.RED));
        return false;
    }

    /**
     * Wykonuje transfer gracza na serwer auth (limbo).
     * @param player       Gracz do transferu
     * @param targetServer Serwer docelowy auth
     * @return true jeśli transfer się udał
     */
    private CompletableFuture<Boolean> executeAuthServerTransferAsync(Player player, RegisteredServer targetServer) {
        return waitForAuthServerReadyAsync(targetServer, 0)
                .thenCompose(ready -> {
                    if (!ready && logger.isWarnEnabled()) {
                        logger.warn("Auth server not responding to ping after retries - attempting connection anyway...");
                    }

                    return player.createConnectionRequest(targetServer)
                            .connect()
                            .orTimeout(settings.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                            .handle((result, throwable) -> handleAuthServerTransferResult(player, result, throwable));
                });
    }

    private boolean handleAuthServerTransferResult(Player player,
                                                   com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result result,
                                                   Throwable throwable) {
        if (throwable != null) {
            if (logger.isErrorEnabled()) {
                logger.error("Error transferring player {} to auth server: {}",
                        player.getUsername(), throwable.getMessage(), throwable);
            }

            player.sendMessage(messages.component("connection.error.auth_server", NamedTextColor.RED));
            return false;
        }

        if (result != null && result.isSuccessful()) {
            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("player.transfer.success", player.getUsername()));
            }
            return true;
        }

        if (logger.isWarnEnabled()) {
            logger.warn("❌ Transfer {} to auth server FAILED: {}",
                    player.getUsername(),
                    KickReasonRenderer.renderPlain(result));
        }

        player.sendMessage(messages.component("connection.error.auth_connect", NamedTextColor.RED));
        return false;
    }

    private CompletableFuture<Boolean> waitForAuthServerReadyAsync(RegisteredServer targetServer, int attempt) {
        if (attempt >= MAX_AUTH_SERVER_WAIT_ATTEMPTS) {
            return CompletableFuture.completedFuture(false);
        }

        return targetServer.ping()
                .orTimeout(settings.getPingTimeoutMillis(), TimeUnit.MILLISECONDS)
                .handle((ping, throwable) -> ping != null)
                .thenCompose(ready -> {
                    if (ready) {
                        return CompletableFuture.completedFuture(true);
                    }
                    if (attempt >= 2) {
                        return CompletableFuture.completedFuture(false);
                    }
                    return scheduleAuthServerReadyRetry(targetServer, attempt + 1);
                });
    }

    private CompletableFuture<Boolean> scheduleAuthServerReadyRetry(RegisteredServer targetServer, int nextAttempt) {
        CompletableFuture<Boolean> retryFuture = new CompletableFuture<>();
        plugin.getServer().getScheduler().buildTask(plugin, () ->
                waitForAuthServerReadyAsync(targetServer, nextAttempt)
                        .whenComplete((ready, throwable) -> completeAsyncResult(retryFuture, ready, throwable))
        ).delay(50, TimeUnit.MILLISECONDS).schedule();
        return retryFuture;
    }

    private <T> void completeAsyncResult(CompletableFuture<T> future, T value, Throwable throwable) {
        if (throwable != null) {
            future.completeExceptionally(throwable);
            return;
        }
        future.complete(value);
    }

    /**
     * Transferuje gracza na serwer backend.
     * Używa synchronicznego połączenia z timeoutem.
     *
     * @param player Gracz do transferu
     * @return true jeśli transfer się udał
     */
    public boolean transferToBackend(Player player) {
        PlayerTransferState state = currentState(player);
        if (closed.get() || state == null || !resetTasksIfCurrent(state, false)) {
            return false;
        }
        try {
            // 1. Sprawdź forced host target (zapamiętany z pierwszego połączenia)
            Optional<RegisteredServer> backendServer = resolveForcedHostTarget(player, state);

            // 2. Fallback: znajdź dostępny serwer z try list
            if (backendServer.isEmpty()) {
                backendServer = findAvailableBackendServer();
            }

            if (backendServer.isEmpty()) {
                if (isStale(state)) {
                    return false;
                }
                logger.warn("No available backend servers for {} - starting background retry",
                        player.getUsername());
                scheduleBackendWaitRetry(player, 0);
                // Player stays on auth server; background retry is the success path.
                // Caller should NOT treat this as a hard failure requiring auth rollback.
                return true;
            }

            RegisteredServer targetServer = backendServer.get();
            String serverName = targetServer.getServerInfo().getName();

            if (isStale(state)) {
                return false;
            }

            // Send connecting message
            player.sendMessage(messages.component("connection.connecting", NamedTextColor.YELLOW));

            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("player.transfer.backend.attempt", player.getUsername(), serverName));
            }

            // Wykonaj transfer synchroniczny z timeoutem
            return executeBackendTransfer(player, state, targetServer, serverName);

        } catch (RuntimeException e) {
            if (isStale(state)) {
                return false;
            }
            logger.error("Error transferring player to backend: {}", player.getUsername(), e);

            sendErrorMessageIfCurrent(player, state);
            return false;
        }
    }
    
    private boolean executeBackendTransfer(Player player, PlayerTransferState state,
                                           RegisteredServer targetServer, String serverName) {
        if (isStale(state) || !validatePlayerActive(player, serverName)) {
            return false;
        }

        int attempts = state.retryAttempts().get();
        if (!validateRetryLimit(player, state, attempts)) {
            return false;
        }

        if (!claimBackendConnection(state)) {
            logger.debug("Backend transfer already active for {} - coalescing duplicate request",
                    player.getUsername());
            return true;
        }
        try {
            return performTransfer(player, state, targetServer, serverName, attempts);
        } finally {
            releaseBackendConnection(state);
        }
    }

    private boolean executeBackendTransfer(Player player, RegisteredServer targetServer, String serverName) {
        PlayerTransferState state = currentState(player);
        return state != null && executeBackendTransfer(player, state, targetServer, serverName);
    }

    private boolean claimBackendConnection(PlayerTransferState state) {
        if (isStale(state)
                || !state.backendConnectionActive().compareAndSet(false, true)) {
            return false;
        }
        if (isStale(state)) {
            state.backendConnectionActive().set(false);
            return false;
        }
        return true;
    }

    private void releaseBackendConnection(PlayerTransferState state) {
        state.backendConnectionActive().set(false);
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Velocity Player identity owns the attempt.
    private boolean claimBackendConnection(Player player) {
        UUID playerUuid = player.getUniqueId();
        while (true) {
            Player currentOwner = backendConnectionOwners.putIfAbsent(playerUuid, player);
            if (currentOwner == null) {
                return true;
            }
            if (currentOwner == player || currentOwner.isActive()) {
                return false;
            }
            if (backendConnectionOwners.replace(playerUuid, currentOwner, player)) {
                return true;
            }
        }
    }

    private void releaseBackendConnection(Player player) {
        backendConnectionOwners.remove(player.getUniqueId(), player);
    }

    private boolean validatePlayerActive(Player player, String serverName) {
        if (!player.isActive()) {
            if (logger.isDebugEnabled()) {
                logger.debug("Player {} is no longer active - skipping transfer to {}",
                        player.getUsername(), serverName);
            }
            return false;
        }
        return true;
    }

    private boolean validateRetryLimit(Player player, PlayerTransferState state, int attempts) {
        if (attempts >= MAX_RETRY_ATTEMPTS) {
            logger.warn("Player {} exceeded transfer retry limit ({}) - aborting",
                    player.getUsername(), MAX_RETRY_ATTEMPTS);
            state.retryAttempts().set(0);
            if (finishIfCurrent(state, false)) {
                sendErrorMessage(player);
            }
            return false;
        }
        return true;
    }

    private boolean performTransfer(Player player, PlayerTransferState state,
                                    RegisteredServer targetServer, String serverName, int attempts) {
        try {
            if (isStale(state)) {
                return false;
            }
            if (!player.isActive()) {
                logger.debug("Player {} disconnected before transfer started", player.getUsername());
                return false;
            }

            var result = player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(settings.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                    .join();

            return handleTransferResult(player, state, targetServer, serverName, attempts, result);
        } catch (CompletionException e) {
            if (isStale(state)) {
                return false;
            }
            return handleCompletionException(player, state, targetServer, serverName, attempts, e);
        } catch (RuntimeException e) {
            if (isStale(state)) {
                return false;
            }
            logTransferError(player, serverName, e);
            sendErrorMessageIfCurrent(player, state);
            return false;
        }
    }

    private boolean handleTransferResult(Player player, PlayerTransferState state,
                                         RegisteredServer targetServer, String serverName, int attempts,
                                         com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result result) {
        if (isStale(state)) {
            return false;
        }
        if (!player.isActive()) {
            finishIfCurrent(state, false);
            logger.debug("Player {} disconnected while connecting to {} - skipping result handling",
                    player.getUsername(), serverName);
            return false;
        }
        if (result.isSuccessful()) {
            return handleSuccessfulTransfer(player, state, serverName);
        }
        return handleFailedTransfer(player, state, targetServer, serverName, attempts, result);
    }

    private boolean handleSuccessfulTransfer(Player player, PlayerTransferState state, String serverName) {
        // Player is now successfully on a backend server — drop any pending forced-host preference
        // so a future reconnect uses the regular flow instead of replaying a stale target.
        if (!finishIfCurrent(state, true)) {
            return false;
        }
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("player.transfer.backend.success", player.getUsername(), serverName));
        }
        return true;
    }

    private boolean handleFailedTransfer(Player player, PlayerTransferState state,
                                         RegisteredServer targetServer, String serverName, int attempts,
                                         com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result result) {
        if (isStale(state)) {
            return false;
        }
        if (logger.isWarnEnabled()) {
            logger.warn("Failed to transfer player {} to server {} (Status: {}): {}",
                    player.getUsername(), serverName, result.getStatus(),
                    KickReasonRenderer.renderPlain(result));
        }

        if (attemptAuthServerFallback(player, state, targetServer, serverName, attempts)) {
            return true;
        }

        String reason = KickReasonRenderer.renderPlain(result);
        sendErrorMessageIfCurrent(player, state, reason);
        return false;
    }

    private boolean attemptAuthServerFallback(Player player, PlayerTransferState state,
                                              RegisteredServer targetServer, String serverName, int attempts) {
        if (isStale(state)) {
            return false;
        }
        RegisteredServer authServer = validateAndGetAuthServer(player, state);
        if (authServer == null || isPlayerOnAuthServer(player)) {
            return false;
        }

        if (!resetTasksIfCurrent(state, false)) {
            return false;
        }
        state.retryAttempts().incrementAndGet();
        if (logger.isInfoEnabled()) {
            logger.info("Attempting fallback for player {} (attempt {}/{}): send to auth server then retry backend {}",
                    player.getUsername(), attempts + 1, MAX_RETRY_ATTEMPTS, serverName);
        }

        scheduleAuthServerFallback(player, authServer, targetServer, serverName);
        return true;
    }

    private void scheduleAuthServerFallback(Player player, RegisteredServer authServer,
                                           RegisteredServer targetServer, String serverName) {
        player.createConnectionRequest(authServer)
                .connect()
                .orTimeout(settings.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                .whenComplete((limboResult, ex) ->
                        handleAuthServerFallbackResult(player, targetServer, serverName, limboResult, ex));
    }

    private void handleAuthServerFallbackResult(Player player, RegisteredServer targetServer, String serverName,
                                               com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result limboResult, Throwable ex) {
        if (ex != null || limboResult == null || !limboResult.isSuccessful()) {
            logFallbackFailure(player, limboResult, ex);
            sendErrorMessage(player);
            return;
        }
        scheduleBackendRetryAfterLimbo(player, targetServer, serverName);
    }

    private void logFallbackFailure(Player player,
                                   com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result limboResult, Throwable ex) {
        String reason;
        if (ex != null) {
            reason = ex.getMessage();
        } else if (limboResult == null) {
            reason = "null result";
        } else {
            reason = KickReasonRenderer.renderPlain(limboResult);
        }
        logger.warn("Fallback to auth server for {} failed: {}", player.getUsername(), reason);
    }

    private void scheduleBackendRetryAfterLimbo(Player player, RegisteredServer targetServer, String serverName) {
        UUID playerUuid = player.getUniqueId();

        scheduleOwnedTask(pendingTransfers, playerUuid,
                settings.getAutoTransferDelayMillis(), TimeUnit.MILLISECONDS, () -> {
            if (!player.isActive() || !isPlayerOnAuthServer(player)) {
                return;
            }
            // Retry blokuje na join() — wykonaj na virtual thread, nie na wątku schedulera
            VirtualThreadExecutorProvider.submitTask(() ->
                    executeBackendRetryAfterLimbo(player, targetServer, serverName));
        });
    }

    /**
     * Schedules periodic retries when no backend server is available after authentication.
     * Player stays on auth/limbo server and gets notified. Retries every 5 seconds up to 5 minutes.
     */
    private void scheduleBackendWaitRetry(Player player, int attempt) {
        UUID playerUuid = player.getUniqueId();

        if (attempt == 0) {
            sendIfNotEmpty(player, "connection.waiting_for_server", NamedTextColor.YELLOW);
        }

        if (attempt >= MAX_BACKEND_WAIT_RETRIES) {
            ScheduledTaskRegistry.cancel(backendWaitTasks, playerUuid);
            logger.warn("Backend wait timeout for {} after {} attempts", player.getUsername(), attempt);
            sendIfNotEmpty(player, "connection.error.no_servers", NamedTextColor.RED);
            return;
        }

        scheduleOwnedTask(backendWaitTasks, playerUuid,
                BACKEND_WAIT_INTERVAL_SECONDS, TimeUnit.SECONDS, () -> {
            if (!player.isActive() || !isPlayerOnAuthServer(player)) {
                return;
            }

            findAvailableBackendServerForRetryAsync(player)
                    .whenComplete((server, throwable) ->
                            handleBackendWaitSelection(player, attempt, server, throwable));
        });
    }

    private void handleBackendWaitSelection(Player player, int attempt,
                                            Optional<RegisteredServer> server, Throwable throwable) {
        if (!player.isActive() || !isPlayerOnAuthServer(player)) {
            return;
        }
        if (throwable != null) {
            logger.warn("Backend selection failed while {} was waiting; retrying",
                    player.getUsername(), throwable);
        }
        if (throwable == null && server != null && server.isPresent()) {
            RegisteredServer target = server.get();
            String targetName = target.getServerInfo().getName();
            logger.info("Backend server available for {} after waiting - transferring to {}",
                    player.getUsername(), targetName);
            sendIfNotEmpty(player, "connection.connecting", NamedTextColor.GREEN);
            VirtualThreadExecutorProvider.submitTask(() ->
                    executeBackendTransfer(player, target, targetName));
            return;
        }
        if (attempt % BACKEND_WAIT_REMINDER_INTERVAL == BACKEND_WAIT_REMINDER_INTERVAL - 1) {
            sendIfNotEmpty(player, "connection.waiting_for_server", NamedTextColor.YELLOW);
        }
        scheduleBackendWaitRetry(player, attempt + 1);
    }

    /**
     * Sends a localized message to a player only if the resolved message body is non-empty.
     * <p>
     * Operators can suppress noisy backend-wait notifications (e.g. "No available servers…")
     * by setting the corresponding key to an empty value in {@code messages_*.properties}
     * without forking the plugin. This is the deliberate opt-out mechanism — empty value
     * means "do not send", any non-empty value sends as before.
     */
    private void sendIfNotEmpty(Player player, String messageKey, NamedTextColor color) {
        String resolved = messages.get(messageKey);
        if (resolved == null || resolved.isEmpty()) {
            return;
        }
        player.sendMessage(messages.componentFromResolvedText(resolved, color));
    }

    private void executeBackendRetryAfterLimbo(Player player, RegisteredServer targetServer, String serverName) {
        if (!claimBackendConnection(player)) {
            logger.debug("Backend transfer already active for {} - skipping limbo retry",
                    player.getUsername());
            return;
        }
        try {
            var retry = player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(settings.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                    .join();
            if (!retry.isSuccessful()) {
                logger.warn("Retry to connect {} to {} after auth server failed: {}",
                        player.getUsername(), serverName, KickReasonRenderer.renderPlain(retry));
                sendErrorMessage(player);
            }
        } catch (java.util.concurrent.CompletionException retryEx) {
            logger.error("Error while retrying backend transfer for {}: {}",
                    player.getUsername(), retryEx.getMessage(), retryEx);
            sendErrorMessage(player);
        } finally {
            releaseBackendConnection(player);
        }
    }

    private boolean handleCompletionException(Player player, PlayerTransferState state,
                                              RegisteredServer targetServer, String serverName,
                                              int attempts, CompletionException e) {
        if (isStale(state)) {
            return false;
        }
        if (e.getCause() instanceof TimeoutException && handleTimeoutRetry(player, targetServer, serverName, attempts)) {
            return true;
        }
        logger.error("Error transferring player {} to server {}", player.getUsername(), serverName, e);
        sendErrorMessageIfCurrent(player, state);
        return false;
    }

    private void logTransferError(Player player, String serverName, RuntimeException e) {
        if (logger.isErrorEnabled()) {
            logger.error("Error transferring player {} to server {}: {}",
                    player.getUsername(), serverName, e.getMessage(), e);
        }
    }

    private void sendErrorMessage(Player player) {
        sendErrorMessage(player, messages.get(MSG_ERROR_UNKNOWN));
    }

    private void sendErrorMessage(Player player, String reason) {
        player.sendMessage(messages.component(CONNECTION_ERROR_GAME_SERVER, NamedTextColor.RED, reason));
    }

    private void sendErrorMessageIfCurrent(Player player, PlayerTransferState state) {
        if (!isStale(state)) {
            sendErrorMessage(player);
        }
    }

    private void sendErrorMessageIfCurrent(Player player, PlayerTransferState state, String reason) {
        if (!isStale(state)) {
            sendErrorMessage(player, reason);
        }
    }

    /**
     * Handles connection timeout by scheduling a single async retry with a short delay.
     * Shows friendly message to player instead of error stack trace.
     */
    private boolean handleTimeoutRetry(Player player, RegisteredServer targetServer, String serverName, int attempts) {
        if (!validateTimeoutRetryConditions(player, attempts)) {
            return false;
        }

        retryAttempts.computeIfAbsent(player.getUniqueId(), k -> new AtomicInteger(0)).incrementAndGet();
        player.sendMessage(messages.component("connection.retry", NamedTextColor.YELLOW));

        scheduleTimeoutRetry(player, targetServer, serverName);
        return true;
    }

    private boolean validateTimeoutRetryConditions(Player player, int attempts) {
        if (!player.isActive()) {
            return false;
        }
        if (timeoutRetryScheduled.putIfAbsent(player.getUniqueId(), Boolean.TRUE) != null) {
            return false;
        }
        if (attempts >= MAX_RETRY_ATTEMPTS) {
            timeoutRetryScheduled.remove(player.getUniqueId());
            return false;
        }
        return true;
    }

    private void scheduleTimeoutRetry(Player player, RegisteredServer targetServer, String serverName) {
        UUID playerUuid = player.getUniqueId();

        scheduleOwnedTask(timeoutRetryTasks, playerUuid, 400, TimeUnit.MILLISECONDS,
                () -> executeTimeoutRetry(player, targetServer, serverName));
    }

    private void executeTimeoutRetry(Player player, RegisteredServer targetServer, String serverName) {
        try {
            if (!player.isActive() || !isPlayerOnAuthServer(player)) {
                timeoutRetryScheduled.remove(player.getUniqueId());
                return;
            }
            if (!claimBackendConnection(player)) {
                timeoutRetryScheduled.remove(player.getUniqueId());
                logger.debug("Backend transfer already active for {} - skipping timeout retry",
                        player.getUsername());
                return;
            }
            player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(settings.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                    .whenComplete((result, ex) -> {
                        try {
                            handleTimeoutRetryResult(player, serverName, result, ex);
                        } finally {
                            releaseBackendConnection(player);
                        }
                    });
        } catch (RuntimeException retryEx) {
            releaseBackendConnection(player);
            timeoutRetryScheduled.remove(player.getUniqueId());
            logger.error("Error scheduling retry after timeout for {}: {}", player.getUsername(), retryEx.getMessage());
        }
    }

    private void handleTimeoutRetryResult(Player player, String serverName,
                                          com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result result, Throwable ex) {
        timeoutRetryScheduled.remove(player.getUniqueId());

        if (ex != null) {
            logger.warn("Retry after timeout failed for {} -> {}: {}", player.getUsername(), serverName, ex.getMessage());
            sendErrorMessage(player);
            return;
        }

        if (result != null && result.isSuccessful()) {
            resetTransferState(player.getUniqueId(), false);
            retryAttempts.remove(player.getUniqueId());
            if (logger.isDebugEnabled()) {
                logger.debug("Retry after timeout succeeded for {} -> {}", player.getUsername(), serverName);
            }
        } else {
            String reason = KickReasonRenderer.renderPlain(result);
            logger.warn("Retry after timeout not successful for {} -> {}: {}", player.getUsername(), serverName, reason);
            sendErrorMessage(player);
        }
    }

    /**
     * Znajduje dostępny serwer backend używając Velocity try servers configuration.
     * Sync wrapper used by callers that already run on a virtual thread; prefer
     * {@link #findAvailableBackendServerAsync()} when composing async chains.
     */
    private Optional<RegisteredServer> findAvailableBackendServer() {
        return findAvailableBackendServerAsync().join();
    }

    /**
     * Selects an available non-auth backend for an initial connection whose Velocity target
     * is the auth server. The returned future preserves the configured {@code try} order and
     * never blocks the caller's event thread.
     *
     * @return future containing the first available backend, or empty when none is reachable
     */
    public CompletableFuture<Optional<RegisteredServer>> findAvailableBackendServerForInitialConnectionAsync() {
        return findAvailableBackendServerAsync();
    }

    /**
     * Fully-async variant: probes each candidate phase concurrently without blocking the caller.
     * <p>
     * Previous behavior: the try-list phase pinged in parallel but the fallback (line 690 in
     * the old code) used a sequential stream of {@code isServerAvailable(...).join()} — worst
     * case <em>N × ping-timeout-ms</em> blocked on the calling thread. The new fallback fans out
     * pings like the try-list, while each phase can finish as soon as its highest-priority reachable
     * result is known. Worst-case wall time per phase stays at one
     * {@code connection.ping-timeout-ms} timeout regardless of the number of registered servers.
     */
    private CompletableFuture<Optional<RegisteredServer>> findAvailableBackendServerAsync() {
        String authServerName = authServerProvider.serverName();
        var tryServers = plugin.getServer().getConfiguration().getAttemptConnectionOrder();
        if (logger.isDebugEnabled()) {
            logger.debug("Velocity try servers: {}", tryServers);
        }

        java.util.List<RegisteredServer> tryCandidates = tryServers.stream()
                .filter(name -> !name.equals(authServerName))
                .flatMap(name -> plugin.getServer().getServer(name).stream())
                .toList();

        return pickFirstAvailable(tryCandidates).thenCompose(found -> {
            if (found.isPresent()) {
                return CompletableFuture.completedFuture(found);
            }
            // Fallback: parallel ping of every registered server (minus auth).
            logBackendFallbackWarning();
            Set<String> alreadyChecked = tryCandidates.stream()
                    .map(server -> server.getServerInfo().getName())
                    .collect(java.util.stream.Collectors.toUnmodifiableSet());
            java.util.List<RegisteredServer> fallbackCandidates = plugin.getServer().getAllServers().stream()
                    .filter(server -> !authServerProvider.isAuthServer(server))
                    .filter(server -> !alreadyChecked.contains(server.getServerInfo().getName()))
                    .toList();
            return pickFirstAvailable(fallbackCandidates);
        });
    }

    private void logBackendFallbackWarning() {
        long now = System.nanoTime();
        long warnAfter = backendFallbackWarnAfterNanos.get();
        if (now >= warnAfter && backendFallbackWarnAfterNanos.compareAndSet(
                warnAfter, now + BACKEND_FALLBACK_WARN_INTERVAL_NANOS)) {
            int suppressed = suppressedBackendFallbackWarnings.getAndSet(0);
            if (suppressed == 0) {
                logger.warn("No reachable server from the Velocity try list; attempting fallback");
            } else {
                logger.warn(
                        "No reachable server from the Velocity try list; attempting fallback"
                                + " ({} repeated checks suppressed)",
                        suppressed);
            }
            return;
        }
        suppressedBackendFallbackWarnings.incrementAndGet();
        if (logger.isDebugEnabled()) {
            logger.debug("No reachable server from the Velocity try list; fallback check suppressed");
        }
    }

    private CompletableFuture<Optional<RegisteredServer>> findAvailableBackendServerForRetryAsync(Player player) {
        return resolveForcedHostTargetAsync(player).thenCompose(forcedTarget -> {
            if (forcedTarget.isPresent()) {
                return CompletableFuture.completedFuture(forcedTarget);
            }
            return findAvailableBackendServerAsync();
        });
    }

    /**
     * Pings candidates concurrently while preserving input order. Selection completes as soon as
     * the first reachable candidate and every higher-priority result are known; an unrelated slow
     * lower-priority ping cannot delay the transfer.
     */
    private CompletableFuture<Optional<RegisteredServer>> pickFirstAvailable(
            java.util.List<RegisteredServer> candidates) {
        if (candidates.isEmpty()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        OrderedPingSelection selection = new OrderedPingSelection(candidates);
        for (int index = 0; index < candidates.size() && !selection.future().isDone(); index++) {
            final int candidateIndex = index;
            try {
                candidates.get(index).ping()
                        .orTimeout(settings.getPingTimeoutMillis(), TimeUnit.MILLISECONDS)
                        .whenComplete((ignored, failure) ->
                                selection.record(candidateIndex, failure == null));
            } catch (RuntimeException failure) {
                selection.record(candidateIndex, false);
            }
        }
        return selection.future();
    }

    private final class OrderedPingSelection {
        private final java.util.List<RegisteredServer> candidates;
        private final AtomicReferenceArray<Boolean> results;
        private final CompletableFuture<Optional<RegisteredServer>> future = new CompletableFuture<>();
        private final ReentrantLock lock = new ReentrantLock();
        private int nextResult;

        private OrderedPingSelection(java.util.List<RegisteredServer> candidates) {
            this.candidates = candidates;
            results = new AtomicReferenceArray<>(candidates.size());
        }

        private void record(int index, boolean available) {
            RegisteredServer selected = null;
            boolean shouldComplete = false;
            lock.lock();
            try {
                if (future.isDone() || results.get(index) != null) {
                    return;
                }
                results.set(index, available);
                while (nextResult < candidates.size()) {
                    Boolean result = results.get(nextResult);
                    if (result == null) {
                        break;
                    }
                    if (result) {
                        selected = candidates.get(nextResult);
                        shouldComplete = true;
                        break;
                    }
                    nextResult++;
                }
                if (nextResult == candidates.size()) {
                    shouldComplete = true;
                }
            } finally {
                lock.unlock();
            }
            if (shouldComplete && future.complete(Optional.ofNullable(selected)) && selected != null) {
                logger.debug("Found available server: {}", selected.getServerInfo().getName());
            }
        }

        private CompletableFuture<Optional<RegisteredServer>> future() {
            return future;
        }
    }

    /**
     * Resolves a forced host target for the given player.
     * If the player was redirected from a forced-host connection, this method
     * retrieves and validates the originally intended server.
     * <p>
     * The target is <b>NOT</b> consumed on retrieval — it stays in the owner state until either
     * a direct transfer succeeds or {@link #clearRetryAttempts(UUID)} (player disconnected) fires.
     * This way a temporarily
     * offline forced-host target is retried on subsequent attempts instead of being silently
     * downgraded to a try-list fallback after the first failure.
     *
     * @param player the player to resolve for
     * @return Optional with the target server if available and online
     */
    private Optional<RegisteredServer> resolveForcedHostTarget(Player player, PlayerTransferState state) {
        Optional<ForcedHostTarget> resolvedTarget = findStoredForcedHostTarget(player, state);
        if (resolvedTarget.isEmpty()) {
            return Optional.empty();
        }
        ForcedHostTarget target = resolvedTarget.get();
        if (isServerAvailable(target.server(), target.name())) {
            logger.debug("Forced host target '{}' for {} is available - using it",
                    target.name(), player.getUsername());
            return Optional.of(target.server());
        }

        // Server is registered but currently offline — keep the entry so the next retry
        // (scheduleBackendWaitRetry or transferToBackend) can try it again once it comes back up.
        logger.warn("Forced host target '{}' for {} is offline - falling back to try list (will retry forced host on next attempt)",
                target.name(), player.getUsername());
        return Optional.empty();
    }

    private CompletableFuture<Optional<RegisteredServer>> resolveForcedHostTargetAsync(Player player) {
        PlayerTransferState state = currentState(player);
        if (state == null) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        Optional<ForcedHostTarget> resolvedTarget = findStoredForcedHostTarget(player, state);
        if (resolvedTarget.isEmpty()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        ForcedHostTarget target = resolvedTarget.get();
        return target.server().ping()
                .orTimeout(settings.getPingTimeoutMillis(), TimeUnit.MILLISECONDS)
                .handle((ignored, throwable) -> handleForcedHostPingResult(player, target, throwable));
    }

    private Optional<ForcedHostTarget> findStoredForcedHostTarget(Player player, PlayerTransferState state) {
        String targetName = state.forcedHostTarget().get();
        if (targetName == null) {
            return Optional.empty();
        }

        String authServerName = authServerProvider.serverName();
        if (targetName.equals(authServerName)) {
            logger.debug("Forced host target for {} is auth server '{}' - ignoring",
                    player.getUsername(), targetName);
            // The auth-server target would loop. Drop it so retries use the try-list directly.
            state.forcedHostTarget().compareAndSet(targetName, null);
            return Optional.empty();
        }

        Optional<RegisteredServer> server = plugin.getServer().getServer(targetName);
        if (server.isEmpty()) {
            logger.warn("Forced host target '{}' for {} is not registered - falling back to try list",
                    targetName, player.getUsername());
            // An unknown server cannot recover without a new captured target; avoid repeat log spam.
            state.forcedHostTarget().compareAndSet(targetName, null);
            return Optional.empty();
        }
        return Optional.of(new ForcedHostTarget(targetName, server.get()));
    }

    private Optional<RegisteredServer> handleForcedHostPingResult(Player player, ForcedHostTarget target,
                                                                  Throwable throwable) {
        if (throwable == null) {
            logger.debug("Forced host target '{}' for {} is available - using it",
                    target.name(), player.getUsername());
            return Optional.of(target.server());
        }
        logger.warn("Forced host target '{}' for {} is offline - falling back to try list "
                        + "(will retry forced host on next attempt)",
                target.name(), player.getUsername());
        return Optional.empty();
    }

    private record ForcedHostTarget(String name, RegisteredServer server) {
    }

    /**
     * Saves the intended server for a player before redirecting to auth server.
     * Called from AuthListener when intercepting a first connection to preserve
     * the Velocity forced-host or try-list target through the auth flow.
     *
     * @param playerUuid target player UUID
     * @param serverName the name of the originally intended server
     */
    public void setForcedHostTarget(UUID playerUuid, String serverName) {
        PlayerTransferState state = transferStates.get(playerUuid);
        if (state == null) {
            forcedHostTargets.put(playerUuid, serverName);
        } else {
            state.forcedHostTarget().set(serverName);
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Saved forced host target '{}' for player UUID: {}", serverName, playerUuid);
        }
    }

    /**
     * Sync availability check — only used by {@link #resolveForcedHostTarget(Player, PlayerTransferState)}
     * which already
     * runs on a virtual thread (called from transfer paths that are themselves submitted to
     * the VT executor). For new code prefer pinging in parallel via
     * {@link #pickFirstAvailable(java.util.List)}.
     */
    private boolean isServerAvailable(RegisteredServer server, String serverName) {
        try {
            Boolean ok = server.ping()
                    .orTimeout(settings.getPingTimeoutMillis(), TimeUnit.MILLISECONDS)
                    .handle((ignored, ex) -> ex == null)
                    .join();
            if (Boolean.TRUE.equals(ok)) {
                logger.debug("Found available server: {}", serverName);
                return true;
            }
        } catch (Exception e) {
            logger.debug("Server {} unavailable: {}", serverName, e.getMessage());
        }
        return false;
    }

    /**
     * Sprawdza czy gracz jest na serwerze auth (limbo).
     *
     * @param player Gracz do sprawdzenia
     * @return true jeśli na auth server
     */
    public boolean isPlayerOnAuthServer(Player player) {
        return player.getCurrentServer()
                .map(com.velocitypowered.api.proxy.ServerConnection::getServer)
                .map(authServerProvider::isAuthServer)
                .orElse(false);
    }

    /** Returns the restart-scoped auth-server name used by routing and forced-host exclusion. */
    public String getAuthServerName() {
        return authServerProvider.serverName();
    }

    /** Returns the usable auth-server registration, never a partially started embedded listener. */
    public Optional<RegisteredServer> resolveAuthServer() {
        return authServerProvider.resolve();
    }

    /** Checks the exact auth-server identity for the current topology. */
    public boolean isAuthServer(RegisteredServer server) {
        return authServerProvider.isAuthServer(server);
    }

    /**
     * Creates the one-time UUID/name correlation for the loopback-only embedded redirect.
     * External mode remains a no-op. Failures disconnect with a localized reason and fail closed.
     */
    public boolean prepareAuthServerConnection(Player player) {
        AuthServerProvider.Preparation preparation = authServerProvider.prepare(player);
        if (preparation == AuthServerProvider.Preparation.READY) {
            return true;
        }

        String messageKey = switch (preparation) {
            case CAPACITY_REACHED -> "embedded.disconnect.overloaded";
            case UNSUPPORTED_PROTOCOL -> "embedded.disconnect.unsupported_protocol";
            case UNAVAILABLE -> "embedded.disconnect.unavailable";
            case READY -> throw new IllegalStateException("READY preparation handled above");
        };
        logger.warn("Auth-server preparation rejected player {} (reason={})",
                player.getUsername(), preparation);
        if (preparation == AuthServerProvider.Preparation.UNSUPPORTED_PROTOCOL) {
            player.disconnect(messages.component(
                    messageKey, NamedTextColor.RED, authServerProvider.compatibilityDescription()));
        } else {
            player.disconnect(messages.component(messageKey, NamedTextColor.RED));
        }
        return false;
    }

    /**
     * Wymusza ponowną autoryzację gracza.
     * Can be used for /logout command implementation.
     *
     * @param player Gracz do wylogowania
     */
    public void forceReauth(Player player) {
        try {
            resetTransferState(player.getUniqueId(), false);
            retryAttempts.remove(player.getUniqueId());

            // Usuń z cache
            authCache.removeAuthorizedPlayer(player.getUniqueId());
            authCache.endSession(player.getUniqueId());
            
            // Transfer na auth server bez blokowania wątku wywołującego.
            transferToAuthServerAsync(player);

            player.sendMessage(messages.component("auth.logged_out", NamedTextColor.YELLOW));

            if (logger.isDebugEnabled()) {
                logger.debug("Forced re-authentication for player: {}", player.getUsername());
            }

        } catch (Exception e) {
            if (logger.isErrorEnabled()) {
                logger.error("Error forcing re-authentication for {}", player.getUsername(), e);
            }
        }
    }

    /**
     * Automatycznie transferuje zweryfikowanego gracza z auth server na backend.
     * Wywoływane przez AuthListener.onServerConnected gdy gracz jest już w cache autoryzacji.
     * Używa opóźnienia dla poprawnej synchronizacji ViaVersion/ViaFabric.
     * <p>
     * Task jest zapisywany w {@link #pendingTransfers} i może być anulowany przez
     * {@link #cancelPendingTransfer(UUID)} przy rozłączeniu gracza, zapobiegając race conditions.
     *
     * @param player Gracz do transferu
     */
    public void autoTransferFromAuthServerToBackend(Player player) {
        UUID playerUuid = player.getUniqueId();
        String playerIp = getPlayerIp(player);
        CachedAuthUser cachedUser = authCache.getAuthorizedPlayer(playerUuid);
        
        if (cachedUser == null || !cachedUser.matchesIp(playerIp)) {
            // Gracz nie jest zweryfikowany w cache - nic nie rób
            if (logger.isDebugEnabled()) {
                logger.debug("Auto-transfer: gracz {} nie jest zweryfikowany w cache", player.getUsername());
            }
            return;
        }
        
        if (logger.isDebugEnabled()) {
            logger.debug("Auto-transfer: gracz {} jest zweryfikowany - planowanie transferu na backend", 
                    player.getUsername());
        }
        
        // Configured compatibility buffer plus concrete connection-attempt ownership.
        scheduleOwnedTask(pendingTransfers, playerUuid,
                settings.getAutoTransferDelayMillis(), TimeUnit.MILLISECONDS, () -> {
                    // Sprawdź czy gracz nadal jest aktywny i na auth server
                    if (!player.isActive()) {
                        logger.debug("Auto-transfer: player {} is no longer active", player.getUsername());
                        return;
                    }
                    
                    if (!isPlayerOnAuthServer(player)) {
                        logger.debug("Auto-transfer: player {} is no longer on auth server", player.getUsername());
                        return;
                    }
                    
                    // Wykonaj transfer na virtual thread aby nie blokować scheduler
                    VirtualThreadExecutorProvider.submitTask(() -> {
                        boolean success = transferToBackend(player);
                        if (success) {
                            logger.debug("Auto-transfer: gracz {} przeniesiony na backend", player.getUsername());
                        } else {
                            logger.warn("Auto-transfer: failed to transfer player {} to backend",
                                    player.getUsername());
                        }
                    });
                });
    }

    private void scheduleOwnedTask(
            ConcurrentMap<UUID, ScheduledTask> registry,
            UUID playerUuid,
            long delay,
            TimeUnit unit,
            Runnable action) {
        taskLifecycleLock.lock();
        try {
            if (closed.get()) {
                return;
            }
            ScheduledTaskRegistry.replace(registry, playerUuid, callback ->
                    plugin.getServer().getScheduler().buildTask(plugin, callback)
                            .delay(delay, unit)
                            .schedule(), () -> {
                if (!closed.get()) {
                    action.run();
                }
            });
        } finally {
            taskLifecycleLock.unlock();
        }
    }

    /**
     * Anuluje oczekujący transfer dla gracza.
     * Wywoływane przy rozłączeniu aby zapobiec race conditions.
     *
     * @param playerUuid UUID gracza
     */
    public void cancelPendingTransfer(UUID playerUuid) {
        if (ScheduledTaskRegistry.cancel(pendingTransfers, playerUuid) && logger.isDebugEnabled()) {
            logger.debug("Anulowano pending transfer dla gracza UUID: {}", playerUuid);
        }
    }

    private void cancelBackendWaitTask(UUID playerUuid) {
        if (ScheduledTaskRegistry.cancel(backendWaitTasks, playerUuid) && logger.isDebugEnabled()) {
            logger.debug("Anulowano backend wait task dla gracza UUID: {}", playerUuid);
        }
    }

    private void cancelTimeoutRetryTask(UUID playerUuid) {
        if (ScheduledTaskRegistry.cancel(timeoutRetryTasks, playerUuid) && logger.isDebugEnabled()) {
            logger.debug("Anulowano timeout retry task dla gracza UUID: {}", playerUuid);
        }
    }

    private void resetTransferState(UUID playerUuid, boolean clearForcedHostTarget) {
        timeoutRetryScheduled.remove(playerUuid);
        cancelPendingTransfer(playerUuid);
        cancelBackendWaitTask(playerUuid);
        cancelTimeoutRetryTask(playerUuid);

        if (clearForcedHostTarget) {
            forcedHostTargets.remove(playerUuid);
        }
    }
    
    /**
     * Czyści licznik prób i anuluje pending transfers dla gracza (np. przy rozłączeniu).
     * Zapobiega race conditions gdy gracz szybko się rozłącza i łączy ponownie.
     * 
     * @param playerUuid UUID gracza
     */
    public void clearRetryAttempts(UUID playerUuid) {
        PlayerTransferState state = transferStates.get(playerUuid);
        if (state != null && transferStates.remove(playerUuid, state)) {
            state.forcedHostTarget().set(null);
            cancelStateTasks(state);
        }
        retryAttempts.remove(playerUuid);
        backendConnectionOwners.remove(playerUuid);
        resetTransferState(playerUuid, true);
    }
    
    /**
     * Zamyka ConnectionManager.
     * Anuluje wszystkie pending transfers i czyści wszystkie mapy stanu.
     */
    public void shutdown() {
        taskLifecycleLock.lock();
        try {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            ScheduledTaskRegistry.cancelAll(pendingTransfers);
            ScheduledTaskRegistry.cancelAll(backendWaitTasks);
            ScheduledTaskRegistry.cancelAll(timeoutRetryTasks);
            transferStates.forEach((playerId, state) -> {
                if (transferStates.remove(playerId, state)) {
                    cancelStateTasks(state);
                }
            });
        } finally {
            taskLifecycleLock.unlock();
        }
        
        // Wyczyść wszystkie mapy stanu
        retryAttempts.clear();
        timeoutRetryScheduled.clear();
        backendConnectionOwners.clear();
        forcedHostTargets.clear();
        
        logger.info("ConnectionManager shut down");
    }

    /**
     * Debuguje dostępne serwery.
     * Wyświetla wszystkie zarejestrowane serwery i sprawdza konfigurację auth server.
     */
    public void debugServers() {
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.servers.available"));
            
            plugin.getServer().getAllServers().forEach(server -> {
                String name = server.getServerInfo().getName();
                String address = server.getServerInfo().getAddress().toString();
                logger.debug("  - {} ({})", name, address);
            });
            
            logger.debug(messages.get("connection.picolimbo.server", authServerProvider.serverName()));
        }

        // Sprawdź czy auth server istnieje
        Optional<RegisteredServer> authServer = authServerProvider.resolve();

        if (authServer.isEmpty()) {
            if (logger.isErrorEnabled()) {
                logger.error(messages.get("connection.picolimbo.error"),
                    authServerProvider.serverName());
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("connection.picolimbo.found",
                        authServerProvider.serverName(),
                        authServer.get().getServerInfo().getAddress()));
            }
        }
    }

    // Utility methods

    /**
     * Pobiera IP gracza jako string.
     */
    private String getPlayerIp(Player player) {
        var address = player.getRemoteAddress();
        if (address instanceof InetSocketAddress inetAddress) {
            return inetAddress.getAddress().getHostAddress();
        }
        return "unknown";
    }

}
