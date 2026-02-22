package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.util.StringConstants;
import org.slf4j.Logger;

import com.velocitypowered.api.scheduler.ScheduledTask;

import java.net.InetSocketAddress;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

/**
 * Manager połączeń i transferów graczy między serwerami.
 * Zarządza przepuszczaniem graczy między Velocity, serwerem auth (limbo) i serwerami backend.
 * <p>
 * Flow autoryzacji:
 * 1. Gracz dołącza -> sprawdź cache -> zawsze przez auth server dla spójności ViaVersion
 * 2. Gracz na auth server -> jeśli zweryfikowany w cache: auto-transfer na backend
 * 3. Gracz na auth server -> /login lub /register -> transfer na backend
 * 4. Gracz na backend -> już autoryzowany, brak dodatkowych sprawdzeń
 */
public class ConnectionManager {

    /** Timeout for server connection attempts - configurable via Settings */
    private static final String CONNECTION_ERROR_GAME_SERVER = "connection.error.game_server";
    private static final int MAX_RETRY_ATTEMPTS = 3;
    
    /** Retry attempt counter per player to prevent infinite fallback loops */
    private final Map<UUID, Integer> retryAttempts = new ConcurrentHashMap<>();
    
    /** One-shot timeout retry flag per player to avoid repeated scheduling */
    private final Map<UUID, Boolean> timeoutRetryScheduled = new ConcurrentHashMap<>();
    
    /** Pending transfer tasks per player - allows cancellation on disconnect to prevent race conditions */
    private final Map<UUID, ScheduledTask> pendingTransfers = new ConcurrentHashMap<>();

    private final VeloAuth plugin;
    private final AuthCache authCache;
    private final Settings settings;
    private final Logger logger;
    private final Messages messages;

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
        this.plugin = plugin;
        this.authCache = authCache;
        this.settings = settings;
        this.logger = plugin.getLogger();
        this.messages = messages;

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.manager.initialized", settings.getAuthServerName()));
        }
    }

    /**
     * Transferuje gracza na serwer auth (limbo) z asynchronicznym sprawdzeniem konta.
     * Używa synchronicznego połączenia z prawidłową obsługą błędów.
     *
     * @param player Gracz do transferu
     * @return true jeśli transfer się udał
     */
    public boolean transferToAuthServer(Player player) {
        try {
            RegisteredServer targetServer = validateAndGetAuthServer(player);
            if (targetServer == null) {
                return false;
            }

            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("player.transfer.attempt", player.getUsername()));
            }

            return executeAuthServerTransfer(player, targetServer);

        } catch (Exception e) {
            return handleTransferError(player, e);
        }
    }

    /** @deprecated Use {@link #transferToAuthServer(Player)} instead. */
    @Deprecated(since = "1.1.0", forRemoval = true)
    public boolean transferToPicoLimbo(Player player) {
        return transferToAuthServer(player);
    }
    
    private RegisteredServer validateAndGetAuthServer(Player player) {
        Optional<RegisteredServer> authServer = plugin.getServer()
                .getServer(settings.getAuthServerName());

        if (authServer.isEmpty()) {
            logger.error("Auth server '{}' is not registered!",
                    settings.getAuthServerName());

            player.disconnect(Component.text(
                    messages.get("connection.error.auth_server"),
                    NamedTextColor.RED
            ));
            return null;
        }
        
        return authServer.get();
    }
    
    private boolean handleTransferError(Player player, Exception e) {
        if (logger.isErrorEnabled()) {
            logger.error("Critical error transferring player to auth server: {}", player.getUsername(), e);
        }

        disconnectWithError(player, messages.get("connection.error.auth_connect"));
        return false;
    }

    /**
     * Wykonuje transfer gracza na serwer auth (limbo).
     * @param player       Gracz do transferu
     * @param targetServer Serwer docelowy auth
     * @return true jeśli transfer się udał
     */
    private boolean executeAuthServerTransfer(Player player, RegisteredServer targetServer) {
        try {
            // Ensure auth server is ready before connecting using Ping check
            // This prevents race conditions better than a blind sleep
            if (!waitForAuthServerReady(targetServer) && logger.isWarnEnabled()) {
                logger.warn("Auth server not responding to ping after retries - attempting connection anyway...");
            }

            var result = player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(settings.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                    .join();  // Czekaj na zakończenie transferu

            if (result.isSuccessful()) {
                if (logger.isDebugEnabled()) {
                    logger.debug(messages.get("player.transfer.success", player.getUsername()));
                }
                return true;
            } else {
                if (logger.isWarnEnabled()) {
                    logger.warn("❌ Transfer {} to auth server FAILED: {}",
                            player.getUsername(),
                            result.getReasonComponent().orElse(createUnknownErrorComponent()));
                }

                player.sendMessage(Component.text(
                        messages.get("connection.error.auth_connect"),
                        NamedTextColor.RED
                ));
                return false;
            }
        } catch (Exception e) {
            if (logger.isErrorEnabled()) {
                logger.error("Error transferring player {} to auth server: {}",
                        player.getUsername(), e.getMessage(), e);
            }

            player.sendMessage(Component.text(
                    messages.get("connection.error.auth_server"),
                    NamedTextColor.RED
            ));
            return false;
        }
    }

    private boolean waitForAuthServerReady(RegisteredServer targetServer) {
        // Attempt to ping server 3 times with small delays
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                // Short timeout for ping check
                var ping = targetServer.ping()
                        .orTimeout(1, TimeUnit.SECONDS)
                        .join();
                if (ping != null) {
                    return true;
                }
            } catch (Exception ignored) {
                // Ping failed, retry
            }
            
            // Small delay between attempts using LockSupport (thread-safe sleep)
            LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(50));
        }
        return false;
    }

    /**
     * Transferuje gracza na serwer backend.
     * Używa synchronicznego połączenia z timeoutem.
     *
     * @param player Gracz do transferu
     * @return true jeśli transfer się udał
     */
    public boolean transferToBackend(Player player) {
        try {
            // Znajdź dostępny serwer backend (nie auth server)
            Optional<RegisteredServer> backendServer = findAvailableBackendServer();

            if (backendServer.isEmpty()) {
                logger.error("No available backend servers!");

                player.sendMessage(Component.text(
                        messages.get("connection.error.no_servers"),
                        NamedTextColor.RED
                ));
                return false;
            }

            RegisteredServer targetServer = backendServer.get();
            String serverName = targetServer.getServerInfo().getName();

            // Send connecting message
            player.sendMessage(Component.text(
                    messages.get("connection.connecting"),
                    NamedTextColor.YELLOW
            ));

            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("player.transfer.backend.attempt", player.getUsername(), serverName));
            }

            // Wykonaj transfer synchroniczny z timeoutem
            return executeBackendTransfer(player, targetServer, serverName);

        } catch (Exception e) {
            logger.error("Error transferring player to backend: {}", player.getUsername(), e);

            player.sendMessage(Component.text(
                    messages.get(CONNECTION_ERROR_GAME_SERVER),
                    NamedTextColor.RED
            ));
            return false;
        }
    }
    
    private boolean executeBackendTransfer(Player player, RegisteredServer targetServer, String serverName) {
        if (!validatePlayerActive(player, serverName)) {
            return false;
        }

        int attempts = retryAttempts.getOrDefault(player.getUniqueId(), 0);
        if (!validateRetryLimit(player, attempts)) {
            return false;
        }

        return performTransfer(player, targetServer, serverName, attempts);
    }

    private boolean validatePlayerActive(Player player, String serverName) {
        if (!player.isActive()) {
            if (logger.isDebugEnabled()) {
                logger.debug("Gracz {} nie jest już aktywny - pomijam transfer do {}",
                        player.getUsername(), serverName);
            }
            return false;
        }
        return true;
    }

    private boolean validateRetryLimit(Player player, int attempts) {
        if (attempts >= MAX_RETRY_ATTEMPTS) {
            logger.warn("Gracz {} przekroczył limit prób transferu ({}) - przerywam",
                    player.getUsername(), MAX_RETRY_ATTEMPTS);
            retryAttempts.remove(player.getUniqueId());
            sendErrorMessage(player);
            return false;
        }
        return true;
    }

    private boolean performTransfer(Player player, RegisteredServer targetServer, String serverName, int attempts) {
        try {
            if (!player.isActive()) {
                logger.debug("Gracz {} rozłączył się przed rozpoczęciem transferu", player.getUsername());
                return false;
            }

            var result = player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(settings.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                    .join();

            return handleTransferResult(player, targetServer, serverName, attempts, result);
        } catch (CompletionException e) {
            return handleCompletionException(player, targetServer, serverName, attempts, e);
        } catch (Exception e) {
            logTransferError(player, serverName, e);
            sendErrorMessage(player);
            return false;
        }
    }

    private boolean handleTransferResult(Player player, RegisteredServer targetServer, String serverName,
                                        int attempts, com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result result) {
        if (result.isSuccessful()) {
            return handleSuccessfulTransfer(player, serverName);
        }
        return handleFailedTransfer(player, targetServer, serverName, attempts, result);
    }

    private boolean handleSuccessfulTransfer(Player player, String serverName) {
        retryAttempts.remove(player.getUniqueId());
        timeoutRetryScheduled.remove(player.getUniqueId());
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("player.transfer.backend.success", player.getUsername(), serverName));
        }
        return true;
    }

    private boolean handleFailedTransfer(Player player, RegisteredServer targetServer, String serverName,
                                        int attempts, com.velocitypowered.api.proxy.ConnectionRequestBuilder.Result result) {
        if (logger.isWarnEnabled()) {
            logger.warn("Failed to transfer player {} to server {}: {}",
                    player.getUsername(), serverName,
                    result.getReasonComponent().orElse(createUnknownErrorComponent()));
        }

        if (attemptAuthServerFallback(player, targetServer, serverName, attempts)) {
            return true;
        }

        sendErrorMessage(player);
        return false;
    }

    private boolean attemptAuthServerFallback(Player player, RegisteredServer targetServer, String serverName, int attempts) {
        RegisteredServer authServer = validateAndGetAuthServer(player);
        if (authServer == null || isPlayerOnAuthServer(player)) {
            return false;
        }

        retryAttempts.put(player.getUniqueId(), attempts + 1);
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
            reason = limboResult.getReasonComponent().map(Component::toString).orElse("unknown");
        }
        logger.warn("Fallback to auth server for {} failed: {}", player.getUsername(), reason);
    }

    private void scheduleBackendRetryAfterLimbo(Player player, RegisteredServer targetServer, String serverName) {
        plugin.getServer().getScheduler().buildTask(plugin, () ->
                executeBackendRetryAfterLimbo(player, targetServer, serverName)
        ).delay(300, TimeUnit.MILLISECONDS).schedule();
    }

    private void executeBackendRetryAfterLimbo(Player player, RegisteredServer targetServer, String serverName) {
        try {
            var retry = player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(settings.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                    .join();
            if (!retry.isSuccessful()) {
                logger.warn("Retry to connect {} to {} after auth server failed: {}",
                        player.getUsername(), serverName, retry.getReasonComponent().orElse(createUnknownErrorComponent()));
                sendErrorMessage(player);
            }
        } catch (Exception retryEx) {
            logger.error("Error while retrying backend transfer for {}: {}",
                    player.getUsername(), retryEx.getMessage(), retryEx);
            sendErrorMessage(player);
        }
    }

    private boolean handleCompletionException(Player player, RegisteredServer targetServer,
                                             String serverName, int attempts, CompletionException e) {
        if (e.getCause() instanceof TimeoutException && handleTimeoutRetry(player, targetServer, serverName, attempts)) {
            return true;
        }
        logger.error("Error transferring player {} to server {}: {}", player.getUsername(), serverName, e.getMessage());
        sendErrorMessage(player);
        return false;
    }

    private void logTransferError(Player player, String serverName, Exception e) {
        if (logger.isErrorEnabled()) {
            logger.error("Error transferring player {} to server {}: {}",
                    player.getUsername(), serverName, e.getMessage(), e);
        }
    }

    private void sendErrorMessage(Player player) {
        player.sendMessage(Component.text(messages.get(CONNECTION_ERROR_GAME_SERVER), NamedTextColor.RED));
    }

    /**
     * Handles connection timeout by scheduling a single async retry with a short delay.
     * Shows friendly message to player instead of error stack trace.
     */
    private boolean handleTimeoutRetry(Player player, RegisteredServer targetServer, String serverName, int attempts) {
        if (!validateTimeoutRetryConditions(player, attempts)) {
            return false;
        }

        retryAttempts.put(player.getUniqueId(), attempts + 1);
        player.sendMessage(Component.text(messages.get("connection.retry"), NamedTextColor.YELLOW));

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
        plugin.getServer().getScheduler().buildTask(plugin, () ->
            executeTimeoutRetry(player, targetServer, serverName)
        ).delay(400, TimeUnit.MILLISECONDS).schedule();
    }

    private void executeTimeoutRetry(Player player, RegisteredServer targetServer, String serverName) {
        try {
            player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(settings.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                    .whenComplete((result, ex) -> handleTimeoutRetryResult(player, serverName, result, ex));
        } catch (Exception retryEx) {
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
            retryAttempts.remove(player.getUniqueId());
            if (logger.isDebugEnabled()) {
                logger.debug("Retry after timeout succeeded for {} -> {}", player.getUsername(), serverName);
            }
        } else {
            Component reason;
            if (result != null) {
                reason = result.getReasonComponent().orElse(createUnknownErrorComponent());
            } else {
                reason = createUnknownErrorComponent();
            }
            logger.warn("Retry after timeout not successful for {} -> {}: {}", player.getUsername(), serverName, reason);
            sendErrorMessage(player);
        }
    }

    /**
     * Znajduje dostępny serwer backend używając Velocity try servers configuration.
     * Iteruje przez listę serwerów z velocity.toml [servers.try] w kolejności.
     *
     * @return Optional z dostępny serwer backend
     */
    private Optional<RegisteredServer> findAvailableBackendServer() {
        String authServerName = settings.getAuthServerName();
        
        // Użyj Velocity try servers configuration
        var tryServers = plugin.getServer().getConfiguration().getAttemptConnectionOrder();
        
        if (logger.isDebugEnabled()) {
            logger.debug("Velocity try servers: {}", tryServers);
        }
        
        // Iteruj przez try servers w kolejności z konfiguracji Velocity
        for (String serverName : tryServers) {
            // Skip auth server - it's an auth server, not a backend
            if (serverName.equals(authServerName)) {
                logger.debug("Skipping auth server: {}", serverName);
            } else {
                Optional<RegisteredServer> server = plugin.getServer().getServer(serverName);
                if (server.isEmpty()) {
                    logger.debug("Serwer {} z try nie jest zarejestrowany", serverName);
                } else {
                    RegisteredServer registeredServer = server.get();
                    if (isServerAvailable(registeredServer, serverName)) {
                        return Optional.of(registeredServer);
                    }
                }
            }
        }
        
        // Fallback: jeśli żaden try server nie jest dostępny, spróbuj dowolny inny
        logger.warn("Żaden serwer z try nie jest dostępny, próbuję fallback...");
        return plugin.getServer().getAllServers().stream()
                .filter(server -> !server.getServerInfo().getName().equals(authServerName))
                .filter(server -> isServerAvailable(server, server.getServerInfo().getName()))
                .findFirst();
    }

    private boolean isServerAvailable(RegisteredServer server, String serverName) {
        try {
            if (server.ping().orTimeout(2, TimeUnit.SECONDS).join() != null) {
                logger.debug("Znaleziono dostępny serwer: {}", serverName);
                return true;
            }
        } catch (Exception e) {
            logger.debug("Serwer {} niedostępny: {}", serverName, e.getMessage());
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
                .map(serverConnection -> serverConnection.getServerInfo().getName())
                .map(serverName -> serverName.equals(settings.getAuthServerName()))
                .orElse(false);
    }

    /** @deprecated Use {@link #isPlayerOnAuthServer(Player)} instead. */
    @Deprecated(since = "1.1.0", forRemoval = true)
    public boolean isPlayerOnPicoLimbo(Player player) {
        return isPlayerOnAuthServer(player);
    }

    /**
     * Wymusza ponowną autoryzację gracza.
     * Can be used for /logout command implementation.
     *
     * @param player Gracz do wylogowania
     */
    public void forceReauth(Player player) {
        try {
            // Usuń z cache
            authCache.removeAuthorizedPlayer(player.getUniqueId());
            
            // Clear timeout retry flag
            timeoutRetryScheduled.remove(player.getUniqueId());

            // Transfer na auth server
            transferToAuthServer(player);

            player.sendMessage(Component.text(
                    messages.get("auth.logged_out"),
                    NamedTextColor.YELLOW
            ));

            if (logger.isDebugEnabled()) {
                logger.debug("Wymuszono ponowną autoryzację gracza: {}", player.getUsername());
            }

        } catch (Exception e) {
            if (logger.isErrorEnabled()) {
                logger.error("Błąd podczas wymuszania ponownej autoryzacji: {}", player.getUsername(), e);
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
        
        // Anuluj poprzedni pending transfer jeśli istnieje (rapid reconnect protection)
        cancelPendingTransfer(playerUuid);
        
        if (logger.isDebugEnabled()) {
            logger.debug("Auto-transfer: gracz {} jest zweryfikowany - planowanie transferu na backend", 
                    player.getUsername());
        }
        
        // Delay dla ViaVersion synchronizacji (300ms)
        // Zapisz task aby móc go anulować przy rozłączeniu
        ScheduledTask task = plugin.getServer().getScheduler()
                .buildTask(plugin, () -> {
                    // Usuń z pending przed wykonaniem
                    pendingTransfers.remove(playerUuid);
                    
                    // Sprawdź czy gracz nadal jest aktywny i na auth server
                    if (!player.isActive()) {
                        logger.debug("Auto-transfer: gracz {} już nie jest aktywny", player.getUsername());
                        return;
                    }
                    
                    if (!isPlayerOnAuthServer(player)) {
                        logger.debug("Auto-transfer: gracz {} już nie jest na auth server", player.getUsername());
                        return;
                    }
                    
                    // Wykonaj transfer
                    boolean success = transferToBackend(player);
                    if (success) {
                        logger.debug("Auto-transfer: gracz {} przeniesiony na backend", player.getUsername());
                    } else {
                        logger.warn("Auto-transfer: nie udało się przenieść gracza {} na backend", 
                                player.getUsername());
                    }
                })
                .delay(300, TimeUnit.MILLISECONDS)
                .schedule();
        
        pendingTransfers.put(playerUuid, task);
    }

    /** @deprecated Use {@link #autoTransferFromAuthServerToBackend(Player)} instead. */
    @Deprecated(since = "1.1.0", forRemoval = true)
    public void autoTransferFromPicoLimboToBackend(Player player) {
        autoTransferFromAuthServerToBackend(player);
    }
    
    /**
     * Anuluje oczekujący transfer dla gracza.
     * Wywoływane przy rozłączeniu aby zapobiec race conditions.
     *
     * @param playerUuid UUID gracza
     */
    public void cancelPendingTransfer(UUID playerUuid) {
        ScheduledTask pending = pendingTransfers.remove(playerUuid);
        if (pending != null) {
            pending.cancel();
            if (logger.isDebugEnabled()) {
                logger.debug("Anulowano pending transfer dla gracza UUID: {}", playerUuid);
            }
        }
    }
    
    /**
     * Czyści licznik prób i anuluje pending transfers dla gracza (np. przy rozłączeniu).
     * Zapobiega race conditions gdy gracz szybko się rozłącza i łączy ponownie.
     * 
     * @param playerUuid UUID gracza
     */
    public void clearRetryAttempts(UUID playerUuid) {
        retryAttempts.remove(playerUuid);
        timeoutRetryScheduled.remove(playerUuid);
        cancelPendingTransfer(playerUuid);
    }
    
    /**
     * Zamyka ConnectionManager.
     * Anuluje wszystkie pending transfers i czyści wszystkie mapy stanu.
     */
    public void shutdown() {
        // Anuluj wszystkie pending transfers
        pendingTransfers.values().forEach(ScheduledTask::cancel);
        pendingTransfers.clear();
        
        // Wyczyść wszystkie mapy stanu
        retryAttempts.clear();
        timeoutRetryScheduled.clear();
        
        logger.info("ConnectionManager zamknięty");
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
            
            logger.debug(messages.get("connection.picolimbo.server", settings.getAuthServerName()));
        }

        // Sprawdź czy auth server istnieje
        Optional<RegisteredServer> authServer = plugin.getServer()
                .getServer(settings.getAuthServerName());

        if (authServer.isEmpty()) {
            if (logger.isErrorEnabled()) {
                logger.error(messages.get("connection.picolimbo.error"),
                    settings.getAuthServerName());
            }
        } else {
            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("connection.picolimbo.found",
                        settings.getAuthServerName(),
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
        return StringConstants.UNKNOWN;
    }

    // Helper methods for consistent messaging
    private void disconnectWithError(Player player, String message) {
        player.disconnect(Component.text(message, NamedTextColor.RED));
    }

    private Component createUnknownErrorComponent() {
        return Component.text(messages.get("error.unknown"), NamedTextColor.RED);
    }
}
