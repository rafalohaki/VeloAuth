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
import java.util.List;
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
 * Zarządza przepuszczaniem graczy między Velocity, PicoLimbo i serwerami backend.
 * <p>
 * Flow autoryzacji:
 * 1. Gracz dołącza -> sprawdź cache -> zawsze przez PicoLimbo dla spójności ViaVersion
 * 2. Gracz na PicoLimbo -> jeśli zweryfikowany w cache: auto-transfer na backend
 * 3. Gracz na PicoLimbo -> /login lub /register -> transfer na backend
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
            logger.debug(messages.get("connection.manager.initialized", settings.getPicoLimboServerName()));
        }
    }

    /**
     * Transferuje gracza na serwer PicoLimbo z asynchronicznym sprawdzeniem konta.
     * Używa synchronicznego połączenia z prawidłową obsługą błędów.
     *
     * @param player Gracz do transferu
     * @return true jeśli transfer się udał
     */
    public boolean transferToPicoLimbo(Player player) {
        try {
            RegisteredServer targetServer = validateAndGetPicoLimboServer(player);
            if (targetServer == null) {
                return false;
            }

            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("player.transfer.attempt", player.getUsername()));
            }

            return executePicoLimboTransfer(player, targetServer);

        } catch (Exception e) {
            return handleTransferError(player, e);
        }
    }
    
    private RegisteredServer validateAndGetPicoLimboServer(Player player) {
        Optional<RegisteredServer> picoLimboServer = plugin.getServer()
                .getServer(settings.getPicoLimboServerName());

        if (picoLimboServer.isEmpty()) {
            logger.error("Serwer PicoLimbo '{}' nie jest zarejestrowany!",
                    settings.getPicoLimboServerName());

            player.disconnect(Component.text(
                    messages.get("connection.error.auth_server"),
                    NamedTextColor.RED
            ));
            return null;
        }
        
        return picoLimboServer.get();
    }
    
    private boolean handleTransferError(Player player, Exception e) {
        if (logger.isErrorEnabled()) {
            logger.error("Krytyczny błąd podczas próby transferu gracza na PicoLimbo: {}", player.getUsername(), e);
        }

        disconnectWithError(player, messages.get("connection.error.auth_connect"));
        return false;
    }

    /**
     * Wykonuje transfer gracza na serwer PicoLimbo.
     * @param player       Gracz do transferu
     * @param targetServer Serwer docelowy PicoLimbo
     * @return true jeśli transfer się udał
     */
    private boolean executePicoLimboTransfer(Player player, RegisteredServer targetServer) {
        try {
            // FIX: Ensure PicoLimbo is ready before connecting using Ping check
            // This prevents race conditions better than a blind sleep
            if (!waitForPicoLimboReady(targetServer) && logger.isWarnEnabled()) {
                logger.warn("PicoLimbo not responding to ping after retries - attempting connection anyway...");
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
                    logger.warn("❌ Transfer {} na PicoLimbo FAILED: {}",
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
                logger.error("Error transferring player {} to PicoLimbo: {}",
                        player.getUsername(), e.getMessage(), e);
            }

            player.sendMessage(Component.text(
                    messages.get("connection.error.auth_server"),
                    NamedTextColor.RED
            ));
            return false;
        }
    }

    private boolean waitForPicoLimboReady(RegisteredServer targetServer) {
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
            // Znajdź dostępny serwer backend (nie PicoLimbo)
            Optional<RegisteredServer> backendServer = findAvailableBackendServer(player);

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

        if (attemptPicoLimboFallback(player, targetServer, serverName, attempts)) {
            return true;
        }

        sendErrorMessage(player);
        return false;
    }

    private boolean attemptPicoLimboFallback(Player player, RegisteredServer targetServer, String serverName, int attempts) {
        RegisteredServer picoLimbo = validateAndGetPicoLimboServer(player);
        if (picoLimbo == null || isPlayerOnPicoLimbo(player)) {
            return false;
        }

        retryAttempts.put(player.getUniqueId(), attempts + 1);
        if (logger.isInfoEnabled()) {
            logger.info("Attempting fallback for player {} (attempt {}/{}): send to PicoLimbo then retry backend {}",
                    player.getUsername(), attempts + 1, MAX_RETRY_ATTEMPTS, serverName);
        }

        schedulePicoLimboFallback(player, picoLimbo, targetServer, serverName);
        return true;
    }

    private void schedulePicoLimboFallback(Player player, RegisteredServer picoLimbo,
                                           RegisteredServer targetServer, String serverName) {
        player.createConnectionRequest(picoLimbo)
                .connect()
                .orTimeout(settings.getConnectionTimeoutSeconds(), TimeUnit.SECONDS)
                .whenComplete((limboResult, ex) ->
                        handlePicoLimboFallbackResult(player, targetServer, serverName, limboResult, ex));
    }

    private void handlePicoLimboFallbackResult(Player player, RegisteredServer targetServer, String serverName,
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
        logger.warn("Fallback to PicoLimbo for {} failed: {}", player.getUsername(), reason);
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
                logger.warn("Retry to connect {} to {} after PicoLimbo failed: {}",
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
     * Finds available backend server using Velocity configuration.
     * Always checks forced hosts first if player's virtual host matches, then falls back to try servers.
     * 
     * @param player Player to find backend server for
     * @return Optional with available backend server
     */
    private Optional<RegisteredServer> findAvailableBackendServer(Player player) {
        String picoLimboName = settings.getPicoLimboServerName();
        
        // Always check forced hosts first if player has a virtual host
        Optional<RegisteredServer> forcedHostServer = findForcedHostServer(player, picoLimboName);
        if (forcedHostServer.isPresent()) {
            return forcedHostServer;
        }
        
        // Use Velocity try servers configuration
        var tryServers = plugin.getServer().getConfiguration().getAttemptConnectionOrder();
        
        if (logger.isDebugEnabled()) {
            logger.debug("Velocity try servers: {}", tryServers);
        }
        
        // Iteruj przez try servers w kolejności z konfiguracji Velocity
        for (String serverName : tryServers) {
            // Skip PicoLimbo - it's an auth server, not a backend
            if (serverName.equals(picoLimboName)) {
                logger.debug("Pomijam PicoLimbo server: {}", serverName);
            } else {
                Optional<RegisteredServer> server = plugin.getServer().getServer(serverName);
                if (server.isEmpty()) {
                    logger.debug("Serwer {} z try nie jest zarejestrowany", serverName);
                } else {
                    RegisteredServer registeredServer = server.get();
                    // Check availability only if not skipping availability check
                    if (settings.isSkipAvailabilityCheck() || isServerAvailable(registeredServer, serverName)) {
                        return Optional.of(registeredServer);
                    }
                }
            }
        }
        
        // No available server found from forced hosts or try servers
        return Optional.empty();
    }
    
    /**
     * Finds backend server based on Velocity forced hosts configuration.
     * 
     * @param player Player to find server for
     * @param picoLimboName PicoLimbo server name to exclude
     * @return Optional with available backend server from forced hosts, or empty if none found
     */
    private Optional<RegisteredServer> findForcedHostServer(Player player, String picoLimboName) {
        try {
            // Get player's virtual host (the hostname they connected with)
            Optional<InetSocketAddress> virtualHost = player.getVirtualHost();
            if (virtualHost.isEmpty()) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Player {} has no virtual host, skipping forced hosts check", 
                            player.getUsername());
                }
                return Optional.empty();
            }
            
            String hostname = virtualHost.get().getHostString();
            if (logger.isDebugEnabled()) {
                logger.debug("Checking forced hosts for player {} with hostname: {}", 
                        player.getUsername(), hostname);
            }
            
            // Get forced hosts configuration from Velocity
            var forcedHosts = plugin.getServer().getConfiguration().getForcedHosts();
            if (forcedHosts == null || forcedHosts.isEmpty()) {
                if (logger.isDebugEnabled()) {
                    logger.debug("No forced hosts configuration found");
                }
                return Optional.empty();
            }
            
            // Check each forced host entry
            for (Map.Entry<String, List<String>> entry : forcedHosts.entrySet()) {
                String forcedHostname = entry.getKey();
                List<String> serverNames = entry.getValue();
                
                // Check if player's hostname matches this forced host entry
                if (hostname.equalsIgnoreCase(forcedHostname)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Found forced host match: {} -> {}", forcedHostname, serverNames);
                    }
                    
                    // Try servers in order from forced host configuration
                    for (String serverName : serverNames) {
                        // Skip PicoLimbo
                        if (serverName.equals(picoLimboName)) {
                            if (logger.isDebugEnabled()) {
                                logger.debug("Skipping PicoLimbo server in forced hosts: {}", serverName);
                            }
                            continue;
                        }
                        
                        Optional<RegisteredServer> server = plugin.getServer().getServer(serverName);
                        if (server.isEmpty()) {
                            if (logger.isDebugEnabled()) {
                                logger.debug("Server {} from forced hosts is not registered", serverName);
                            }
                            continue;
                        }
                        
                        RegisteredServer registeredServer = server.get();
                        // Check availability only if not skipping availability check
                        if (settings.isSkipAvailabilityCheck() || isServerAvailable(registeredServer, serverName)) {
                            if (logger.isDebugEnabled()) {
                                logger.debug("Found available server from forced hosts: {}", serverName);
                            }
                            return Optional.of(registeredServer);
                        }
                    }
                }
            }
            
            if (logger.isDebugEnabled()) {
                logger.debug("No matching forced host found for hostname: {}", hostname);
            }
            return Optional.empty();
            
        } catch (Exception e) {
            logger.warn("Error checking forced hosts for player {}: {}", 
                    player.getUsername(), e.getMessage());
            if (logger.isDebugEnabled()) {
                logger.debug("Forced hosts check exception", e);
            }
            return Optional.empty();
        }
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
     * Sprawdza czy gracz jest na serwerze PicoLimbo.
     *
     * @param player Gracz do sprawdzenia
     * @return true jeśli na PicoLimbo
     */
    public boolean isPlayerOnPicoLimbo(Player player) {
        return player.getCurrentServer()
                .map(serverConnection -> serverConnection.getServerInfo().getName())
                .map(serverName -> serverName.equals(settings.getPicoLimboServerName()))
                .orElse(false);
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

            // Transfer na PicoLimbo
            transferToPicoLimbo(player);

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
     * Automatycznie transferuje zweryfikowanego gracza z PicoLimbo na backend.
     * Wywoływane przez AuthListener.onServerConnected gdy gracz jest już w cache autoryzacji.
     * Używa opóźnienia dla poprawnej synchronizacji ViaVersion/ViaFabric.
     * <p>
     * Task jest zapisywany w {@link #pendingTransfers} i może być anulowany przez
     * {@link #cancelPendingTransfer(UUID)} przy rozłączeniu gracza, zapobiegając race conditions.
     *
     * @param player Gracz do transferu
     */
    public void autoTransferFromPicoLimboToBackend(Player player) {
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
                    
                    // Sprawdź czy gracz nadal jest aktywny i na PicoLimbo
                    if (!player.isActive()) {
                        logger.debug("Auto-transfer: gracz {} już nie jest aktywny", player.getUsername());
                        return;
                    }
                    
                    if (!isPlayerOnPicoLimbo(player)) {
                        logger.debug("Auto-transfer: gracz {} już nie jest na PicoLimbo", player.getUsername());
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
     * Wyświetla wszystkie zarejestrowane serwery i sprawdza konfigurację PicoLimbo.
     */
    public void debugServers() {
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.servers.available"));
            
            plugin.getServer().getAllServers().forEach(server -> {
                String name = server.getServerInfo().getName();
                String address = server.getServerInfo().getAddress().toString();
                logger.debug("  - {} ({})", name, address);
            });
            
            logger.debug(messages.get("connection.picolimbo.server", settings.getPicoLimboServerName()));
        }

        // Sprawdź czy PicoLimbo serwer istnieje
        Optional<RegisteredServer> picoLimbo = plugin.getServer()
                .getServer(settings.getPicoLimboServerName());

        if (picoLimbo.isEmpty()) {
            if (logger.isErrorEnabled()) {
                logger.error(messages.get("connection.picolimbo.error"),
                    settings.getPicoLimboServerName());
            }
        } else {
            // Zmieniono na DEBUG, aby uniknąć duplikowania informacji o PicoLimbo przy starcie
            // Informacja o PicoLimbo jest już logowana w logStartupInfo w VeloAuth
            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("connection.picolimbo.found",
                        settings.getPicoLimboServerName(),
                        picoLimbo.get().getServerInfo().getAddress()));
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
