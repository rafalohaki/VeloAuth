package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.authserver.AuthServerProvider;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;

import com.velocitypowered.api.scheduler.ScheduledTask;

import java.util.concurrent.CompletableFuture;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

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
    private static final int MAX_AUTH_SERVER_WAIT_ATTEMPTS = 3;

    /** Current concrete player owner and generation for each UUID. */
    private final ConcurrentMap<UUID, PlayerTransferState> transferStates = new ConcurrentHashMap<>();
    private final AtomicLong transferGeneration = new AtomicLong();

    /** Serializes task publication with shutdown so late async completions cannot resurrect work. */
    private final ReentrantLock taskLifecycleLock = new ReentrantLock();
    private final AtomicBoolean closed = new AtomicBoolean();
    
    private final VeloAuth plugin;
    private final Settings settings;
    private final Logger logger;
    private final Messages messages;
    private final AuthServerProvider authServerProvider;
    private final BackendSelector backendSelector;
    private final BackendTransferCoordinator backendTransferCoordinator;

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
        this.settings = settings;
        this.logger = plugin.getLogger();
        this.messages = messages;
        this.authServerProvider = authServerProvider;
        this.backendSelector = new BackendSelector(
                plugin.getServer(), authServerProvider, logger, this);
        this.backendTransferCoordinator = new BackendTransferCoordinator(
                this, backendSelector, authCache, settings, logger, messages);

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
        taskLifecycleLock.lock();
        try {
            if (closed.get()) {
                return;
            }
            displaced = transferStates.put(playerId, replacement);
        } finally {
            taskLifecycleLock.unlock();
        }
        if (displaced != null) {
            cancelStateTasks(displaced);
        }
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Concrete Velocity Player identity owns the generation.
    PlayerTransferState currentState(Player player) {
        UUID playerId = player.getUniqueId();
        taskLifecycleLock.lock();
        try {
            if (closed.get()) {
                return null;
            }
            PlayerTransferState current = transferStates.get(playerId);
            // PostLogin is the sole generation-creation boundary. Never lazily recreate state for
            // a concrete Player retired by /logout or DisconnectEvent.
            return current != null && current.owner() == player ? current : null;
        } finally {
            taskLifecycleLock.unlock();
        }
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // State identity is the generation token.
    private boolean isCurrent(PlayerTransferState state) {
        return transferStates.get(state.playerId()) == state;
    }

    boolean isStale(PlayerTransferState state) {
        return closed.get() || !isCurrent(state);
    }

    boolean resetTasksIfCurrent(PlayerTransferState state, boolean clearForcedHostTarget) {
        if (!isCurrent(state)) {
            return false;
        }
        cancelStateTasks(state);
        if (clearForcedHostTarget) {
            state.forcedHostTarget().set(null);
        }
        return true;
    }

    boolean finishIfCurrent(PlayerTransferState state, boolean clearForcedHostTarget) {
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
        state.cancelTasks();
    }

    public CompletableFuture<Boolean> transferToAuthServerAsync(Player player) {
        PlayerTransferState state = currentState(player);
        if (state == null || !resetTasksIfCurrent(state, false)) {
            return CompletableFuture.completedFuture(false);
        }
        try {
            RegisteredServer targetServer = validateAndGetAuthServer(player, state);
            if (targetServer == null) {
                return CompletableFuture.completedFuture(false);
            }

            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("player.transfer.attempt", player.getUsername()));
            }

            return executeAuthServerTransferAsync(player, state, targetServer);
        } catch (RuntimeException e) {
            return CompletableFuture.completedFuture(handleTransferError(player, state, e));
        }
    }

    RegisteredServer validateAndGetAuthServer(
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
    
    private boolean handleTransferError(Player player, PlayerTransferState state, Exception e) {
        if (isStale(state)) {
            return false;
        }
        if (logger.isErrorEnabled()) {
            logger.error("Critical error transferring player to auth server: {}", player.getUsername(), e);
        }

        if (!isStale(state)) {
            player.disconnect(messages.component("connection.error.auth_connect", NamedTextColor.RED));
        }
        return false;
    }

    /**
     * Wykonuje transfer gracza na serwer auth (limbo).
     * @param player       Gracz do transferu
     * @param targetServer Serwer docelowy auth
     * @return {@code true} when the request was accepted, including coalesced or deferred retries;
     *         {@code false} when it was rejected
     */
    private CompletableFuture<Boolean> executeAuthServerTransferAsync(
            Player player, PlayerTransferState state, RegisteredServer targetServer) {
        return waitForAuthServerReadyAsync(state, targetServer, 0)
                .thenCompose(ready -> {
                    if (isStale(state)) {
                        return CompletableFuture.completedFuture(false);
                    }
                    if (!ready && logger.isWarnEnabled()) {
                        logger.warn("Auth server not responding to ping after retries - attempting connection anyway...");
                    }

                    CompletableFuture<com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result> connection =
                            startAuthServerConnection(player, state, targetServer);
                    if (connection == null) {
                        return CompletableFuture.completedFuture(false);
                    }
                    return connection.handle((result, throwable) ->
                            handleAuthServerTransferResult(player, state, result, throwable));
                });
    }

    private CompletableFuture<com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result> startAuthServerConnection(
            Player player, PlayerTransferState state, RegisteredServer targetServer) {
        return startConnectionIfCurrent(player, state, targetServer);
    }

    CompletableFuture<com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result> startConnectionIfCurrent(
            Player player, PlayerTransferState state, RegisteredServer targetServer) {
        return startIoIfAllowed(state, () -> player.createConnectionRequest(targetServer)
                .connect()
                .orTimeout(settings.getConnectionTimeoutSeconds(), TimeUnit.SECONDS));
    }

    CompletableFuture<com.velocitypowered.api.proxy.server.ServerPing> startPingIfAllowed(
            @javax.annotation.Nullable PlayerTransferState state, RegisteredServer targetServer) {
        return startIoIfAllowed(state, () -> targetServer.ping()
                .orTimeout(settings.getPingTimeoutMillis(), TimeUnit.MILLISECONDS));
    }

    private <T> CompletableFuture<T> startIoIfAllowed(
            @javax.annotation.Nullable PlayerTransferState state,
            Supplier<CompletableFuture<T>> initiation) {
        taskLifecycleLock.lock();
        try {
            if (isIoOwnerUnavailable(state)) {
                return null;
            }
            return initiation.get();
        } finally {
            taskLifecycleLock.unlock();
        }
    }

    boolean isIoOwnerUnavailable(@javax.annotation.Nullable PlayerTransferState state) {
        return closed.get() || (state != null && !isCurrent(state));
    }

    private boolean handleAuthServerTransferResult(Player player, PlayerTransferState state,
                                                   com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result result,
                                                   Throwable throwable) {
        if (isStale(state)) {
            return false;
        }
        if (throwable != null) {
            if (logger.isErrorEnabled()) {
                logger.error("Error transferring player {} to auth server: {}",
                        player.getUsername(), throwable.getMessage(), throwable);
            }

            if (!isStale(state)) {
                player.sendMessage(messages.component("connection.error.auth_server", NamedTextColor.RED));
            }
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

        if (!isStale(state)) {
            player.sendMessage(messages.component("connection.error.auth_connect", NamedTextColor.RED));
        }
        return false;
    }

    private CompletableFuture<Boolean> waitForAuthServerReadyAsync(
            PlayerTransferState state, RegisteredServer targetServer, int attempt) {
        if (isStale(state) || attempt >= MAX_AUTH_SERVER_WAIT_ATTEMPTS) {
            return CompletableFuture.completedFuture(false);
        }

        CompletableFuture<com.velocitypowered.api.proxy.server.ServerPing> ping =
                startAuthServerPing(state, targetServer);
        if (ping == null) {
            return CompletableFuture.completedFuture(false);
        }
        return ping.handle((result, throwable) -> !isStale(state) && result != null)
                .thenCompose(ready -> {
                    if (isStale(state)) {
                        return CompletableFuture.completedFuture(false);
                    }
                    if (Boolean.TRUE.equals(ready)) {
                        return CompletableFuture.completedFuture(true);
                    }
                    if (attempt >= 2) {
                        return CompletableFuture.completedFuture(false);
                    }
                    return scheduleAuthServerReadyRetry(state, targetServer, attempt + 1);
                });
    }

    private CompletableFuture<com.velocitypowered.api.proxy.server.ServerPing> startAuthServerPing(
            PlayerTransferState state, RegisteredServer targetServer) {
        return startPingIfAllowed(state, targetServer);
    }

    private CompletableFuture<Boolean> scheduleAuthServerReadyRetry(
            PlayerTransferState state, RegisteredServer targetServer, int nextAttempt) {
        CompletableFuture<Boolean> retryFuture = new CompletableFuture<>();
        state.authReadyRetryCompletion().set(retryFuture);
        boolean scheduled = scheduleOwnedTask(state, state.authReadyRetry(), 50, TimeUnit.MILLISECONDS, () ->
                waitForAuthServerReadyAsync(state, targetServer, nextAttempt)
                        .whenComplete((ready, throwable) -> {
                            state.authReadyRetryCompletion().compareAndSet(retryFuture, null);
                            completeAsyncResult(retryFuture, ready, throwable);
                        }));
        if (!scheduled) {
            state.authReadyRetryCompletion().compareAndSet(retryFuture, null);
            retryFuture.complete(false);
        }
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
        return backendTransferCoordinator.transfer(player).accepted();
    }

    /**
     * Selects an available non-auth backend for an initial connection whose Velocity target
     * is the auth server. The returned future preserves the configured {@code try} order and
     * never blocks the caller's event thread.
     *
     * @return future containing the first available backend, or empty when none is reachable
     */
    public CompletableFuture<Optional<RegisteredServer>> findAvailableBackendServerForInitialConnectionAsync() {
        return backendSelector.findAvailableBackendServerForInitialConnectionAsync();
    }

    /**
     * Saves the intended server for a player before redirecting to auth server.
     * Called from AuthListener when intercepting a first connection to preserve
     * the Velocity forced-host or try-list target through the auth flow.
     *
     * @param player target player connection
     * @param serverName the name of the originally intended server
     */
    public void setForcedHostTarget(Player player, String serverName) {
        PlayerTransferState state = currentState(player);
        if (state == null || isStale(state)) {
            return;
        }
        state.forcedHostTarget().set(serverName);
        if (logger.isDebugEnabled()) {
            logger.debug("Saved forced host target '{}' for player UUID: {}",
                    serverName, player.getUniqueId());
        }
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
     * Automatycznie transferuje zweryfikowanego gracza z auth server na backend.
     * Wywoływane przez AuthListener.onServerConnected gdy gracz jest już w cache autoryzacji.
     * Używa opóźnienia dla poprawnej synchronizacji ViaVersion/ViaFabric.
     * <p>
     * Task jest zapisywany w stanie konkretnego połączenia i może być anulowany przez
     * state-local cancellation at disconnect prevents reconnect race conditions.
     *
     * @param player Gracz do transferu
     */
    public void autoTransferFromAuthServerToBackend(Player player) {
        backendTransferCoordinator.autoTransferFromAuthServerToBackend(player);
    }

    boolean scheduleOwnedTask(
            PlayerTransferState state,
            AtomicReference<ScheduledTask> taskSlot,
            long delay,
            TimeUnit unit,
            Runnable action) {
        ScheduledTaskRegistry.PreparedTask prepared;
        taskLifecycleLock.lock();
        try {
            if (isStale(state)) {
                return false;
            }
            prepared = ScheduledTaskRegistry.prepare(taskSlot, () -> {
                if (!isStale(state)) {
                    action.run();
                }
            });
        } finally {
            taskLifecycleLock.unlock();
        }
        prepared.cancelPrevious();
        prepared.schedule(callback ->
                plugin.getServer().getScheduler().buildTask(plugin, callback)
                        .delay(delay, unit)
                        .schedule());
        return true;
    }

    /**
     * Clears transfer state only when it is still owned by the concrete disconnecting connection.
     *
     * @param player disconnecting player connection
     */
    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Concrete Velocity Player identity owns the state.
    public void clearTransferState(Player player) {
        PlayerTransferState state = transferStates.get(player.getUniqueId());
        if (state == null || state.owner() != player
                || !transferStates.remove(state.playerId(), state)) {
            return;
        }
        state.forcedHostTarget().set(null);
        cancelStateTasks(state);
    }
    
    /**
     * Zamyka ConnectionManager.
     * Anuluje wszystkie pending transfers i czyści wszystkie mapy stanu.
     */
    public void shutdown() {
        java.util.List<PlayerTransferState> statesToCancel;
        taskLifecycleLock.lock();
        try {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            statesToCancel = new java.util.ArrayList<>(transferStates.values());
            transferStates.clear();
        } finally {
            taskLifecycleLock.unlock();
        }

        statesToCancel.forEach(this::cancelStateTasks);
        
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

}
