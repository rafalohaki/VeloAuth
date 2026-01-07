package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.StringConstants;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import com.velocitypowered.api.scheduler.ScheduledTask;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
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

    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");
    /** Timeout for server connection attempts - increased from 10s to 15s for slow/remote servers */
    private static final long CONNECT_TIMEOUT_SECONDS = 15;
    private static final String CONNECTION_ERROR_GAME_SERVER = "connection.error.game_server";
    private static final int MAX_RETRY_ATTEMPTS = 3;
    
    /** Retry attempt counter per player to prevent infinite fallback loops */
    private final Map<UUID, Integer> retryAttempts = new ConcurrentHashMap<>();
    
    /** Pending transfer tasks per player - allows cancellation on disconnect to prevent race conditions */
    private final Map<UUID, ScheduledTask> pendingTransfers = new ConcurrentHashMap<>();

    private final VeloAuth plugin;
    private final DatabaseManager databaseManager;
    private final AuthCache authCache;
    private final Settings settings;
    private final Logger logger;
    private final Messages messages;

    /**
     * Tworzy nowy ConnectionManager.
     *
     * @param plugin          VeloAuth plugin instance
     * @param databaseManager Manager bazy danych
     * @param authCache       Cache autoryzacji
     * @param settings        Ustawienia pluginu
     * @param messages        System wiadomości i18n
     */
    public ConnectionManager(VeloAuth plugin, DatabaseManager databaseManager,
                             AuthCache authCache, Settings settings, Messages messages) {
        this.plugin = plugin;
        this.databaseManager = databaseManager;
        this.authCache = authCache;
        this.settings = settings;
        this.logger = plugin.getLogger();
        this.messages = messages;

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.manager.initialized"),
                    settings.getPicoLimboServerName());
        }
    }

    /**
     * Obsługuje połączenie gracza z proxy.
     * Sprawdza cache autoryzacji i kieruje na odpowiedni serwer.
     *
     * @param player Gracz który się łączy
     * @return CompletableFuture<Boolean> - true jeśli transfer się udał
     */
    public CompletableFuture<Boolean> handlePlayerConnection(Player player) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (!isPluginReady(player)) {
                    return false;
                }

                String playerIp = getPlayerIp(player);
                InetAddress playerAddress = getPlayerAddress(player);

                logger.debug("Obsługa połączenia gracza {} z IP {}",
                        player.getUsername(), playerIp);

                if (isPlayerBlocked(player, playerAddress, playerIp)) {
                    return false;
                }

                return handleAuthCache(player, playerIp);

            } catch (Exception e) {
                return handleConnectionError(player, e);
            }
        });
    }
    
    private boolean isPluginReady(Player player) {
        if (!plugin.isInitialized()) {
            logger.warn("🔒 BLOKADA STARTU: Gracz {} próbował połączyć się przed pełną inicjalizacją VeloAuth - rozłączanie",
                    player.getUsername());

            player.disconnect(Component.text(
                    messages.get("system.starting"),
                    NamedTextColor.RED
            ));
            return false;
        }
        return true;
    }
    
    private boolean isPlayerBlocked(Player player, InetAddress playerAddress, String playerIp) {
        if (playerAddress != null && authCache.isBlocked(playerAddress)) {
            logger.warn("Gracz {} zablokowany za brute force z IP {}",
                    player.getUsername(), playerIp);

            player.disconnect(Component.text(
                    messages.get("security.brute_force.blocked"),
                    NamedTextColor.RED
            ));
            return true;
        }
        return false;
    }
    
    private boolean handleAuthCache(Player player, String playerIp) {
        CachedAuthUser cachedUser = authCache.getAuthorizedPlayer(player.getUniqueId());

        if (cachedUser != null && cachedUser.matchesIp(playerIp)) {
            // Cache HIT - gracz jest autoryzowany
            if (logger.isDebugEnabled()) {
                logger.debug("Cache HIT dla gracza {} - weryfikacja i transfer przez PicoLimbo", player.getUsername());
            }

            // ZAWSZE idź przez PicoLimbo - to rozwiązuje timing issues z ViaVersion/ViaFabric
            return verifyAndTransferToPicoLimbo(player, cachedUser);

        } else {
            // Cache MISS - gracz musi się zalogować
            if (logger.isDebugEnabled()) {
                logger.debug("Cache MISS dla gracza {} - transfer na PicoLimbo", player.getUsername());
            }

            return transferToPicoLimbo(player);
        }
    }
    
    private boolean handleConnectionError(Player player, Exception e) {
        if (logger.isErrorEnabled()) {
            logger.error("Błąd podczas obsługi połączenia gracza: {}", player.getUsername(), e);
        }

        player.disconnect(Component.text(
                messages.get("connection.error.generic"),
                NamedTextColor.RED
        ));
        return false;
    }

    /**
     * Weryfikuje gracza i kieruje go przez PicoLimbo zamiast bezpośredniego transferu na backend.
     * To zapewnia spójny flow dla klientów z ViaVersion/ViaFabric i daje czas na poprawne zainicjowanie sesji.
     */
    private boolean verifyAndTransferToPicoLimbo(Player player, CachedAuthUser cachedUser) {
        try {
            // Weryfikacja z bazą danych
            var dbResult = databaseManager.findPlayerByNickname(player.getUsername()).join();

            if (dbResult.isDatabaseError()) {
                logger.error("Database error during player verification for {}: {}",
                        player.getUsername(), dbResult.getErrorMessage());
                // Remove from cache and deny access for security
                authCache.removeAuthorizedPlayer(player.getUniqueId());
                authCache.endSession(player.getUniqueId());
                player.disconnect(Component.text(
                        messages.get("connection.error.database"),
                        NamedTextColor.RED
                ));
                return false;
            }

            RegisteredPlayer dbPlayer = dbResult.getValue();
            if (dbPlayer == null) {
                // Gracz nie istnieje w bazie - usuń z cache i prześlij na PicoLimbo
                logger.warn("Gracz {} w cache ale nie w bazie danych - usuwam z cache",
                        player.getUsername());

                authCache.removeAuthorizedPlayer(player.getUniqueId());
                authCache.endSession(player.getUniqueId()); // Zakończ sesję
                return transferToPicoLimbo(player);
            }

            // UUID verification
            UUID playerUuid = player.getUniqueId();
            UUID storedUuid = dbPlayer.getUuidAsUUID();

            if (storedUuid != null && !playerUuid.equals(storedUuid)) {
                if (logger.isErrorEnabled()) {
                    logger.error(SECURITY_MARKER,
                            "[UUID MISMATCH DETECTED] Gracz {} ma UUID {} ale baza zawiera {} (IP: {})",
                            player.getUsername(), playerUuid, storedUuid, getPlayerIp(player));
                }

                authCache.removeAuthorizedPlayer(player.getUniqueId());
                authCache.endSession(player.getUniqueId());

                player.disconnect(Component.text(
                        messages.get("connection.error.uuid_mismatch"),
                        NamedTextColor.RED
                ));
                return false;
            }

            // Aktualizuj IP logowania synchronicznie
            updatePlayerIpIfChanged(player, dbPlayer, cachedUser);

            // Informacja i transfer przez PicoLimbo
            player.sendMessage(Component.text(
                    messages.get("connection.connecting"),
                    NamedTextColor.YELLOW
            ));

            return transferToPicoLimbo(player);

        } catch (Exception e) {
            if (logger.isErrorEnabled()) {
                logger.error("Błąd podczas weryfikacji gracza: {}", player.getUsername(), e);
            }
            disconnectWithError(player, messages.get("connection.error.database"));
            return false;
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
                logger.debug(messages.get("player.transfer.attempt"), player.getUsername());
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
                    .orTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .join();  // Czekaj na zakończenie transferu

            if (result.isSuccessful()) {
                if (logger.isDebugEnabled()) {
                    logger.debug(messages.get("player.transfer.success"), player.getUsername());
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
                logger.debug(messages.get("player.transfer.backend.attempt"),
                        player.getUsername(), serverName);
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
        // Early exit if player disconnected (prevents TimeoutException on stale connections)
        if (!player.isActive()) {
            if (logger.isDebugEnabled()) {
                logger.debug("Gracz {} nie jest już aktywny - pomijam transfer do {}", 
                        player.getUsername(), serverName);
            }
            return false;
        }
        
        // Check retry limit before attempting
        int attempts = retryAttempts.getOrDefault(player.getUniqueId(), 0);
        if (attempts >= MAX_RETRY_ATTEMPTS) {
            logger.warn("Gracz {} przekroczył limit prób transferu ({}) - przerywam",
                    player.getUsername(), MAX_RETRY_ATTEMPTS);
            retryAttempts.remove(player.getUniqueId());
            player.sendMessage(Component.text(
                    messages.get(CONNECTION_ERROR_GAME_SERVER),
                    NamedTextColor.RED
            ));
            return false;
        }
        
        try {
            // Final check before blocking operation
            if (!player.isActive()) {
                logger.debug("Gracz {} rozłączył się przed rozpoczęciem transferu", player.getUsername());
                return false;
            }
            
            // Wykonaj transfer i zbierz wynik, aby logować przyczynę niepowodzenia
            var result = player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .join(); // Czekaj na zakończenie transferu

            if (result.isSuccessful()) {
                // Reset retry counter on success
                retryAttempts.remove(player.getUniqueId());
                if (logger.isDebugEnabled()) {
                    logger.debug(messages.get("player.transfer.backend.success"),
                            player.getUsername(), serverName);
                }
                return true;
            } else {
                // Szczegółowe logowanie powodu niepowodzenia
                if (logger.isWarnEnabled()) {
                    logger.warn("Failed to transfer player {} to server {}: {}",
                            player.getUsername(), serverName,
                            result.getReasonComponent().orElse(createUnknownErrorComponent()));
                }

                // Fallback: jeśli nie jesteśmy już na PicoLimbo, spróbuj przenieść gracza na PicoLimbo a następnie ponowić próbę
                RegisteredServer picoLimbo = validateAndGetPicoLimboServer(player);
                if (picoLimbo != null && !isPlayerOnPicoLimbo(player)) {
                    // Increment retry counter
                    retryAttempts.put(player.getUniqueId(), attempts + 1);
                    
                    if (logger.isInfoEnabled()) {
                        logger.info("Attempting fallback for player {} (attempt {}/{}): send to PicoLimbo then retry backend {}",
                                player.getUsername(), attempts + 1, MAX_RETRY_ATTEMPTS, serverName);
                    }

                    // Asynchroniczny transfer na PicoLimbo; po udanym połączeniu zaplanuj retry do backend
                    player.createConnectionRequest(picoLimbo)
                            .connect()
                            .orTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                            .whenComplete((limboResult, ex) -> {
                                if (ex != null || limboResult == null || !limboResult.isSuccessful()) {
                                    logger.warn("Fallback to PicoLimbo for {} failed: {}",
                                            player.getUsername(), ex != null ? ex.getMessage() : (limboResult == null ? "null result" : limboResult.getReasonComponent().map(Component::toString).orElse("unknown")));
                                    player.sendMessage(Component.text(messages.get(CONNECTION_ERROR_GAME_SERVER), NamedTextColor.RED));
                                    return;
                                }

                                // Poczekaj krótko, aby limbo miał czas na zainicjowanie sesji, następnie spróbuj ponownie połączenia do docelowego backendu
                                plugin.getServer().getScheduler().buildTask(plugin, () -> {
                                    try {
                                        var retry = player.createConnectionRequest(targetServer)
                                                .connect()
                                                .orTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                                                .join();
                                        if (!retry.isSuccessful()) {
                                            logger.warn("Retry to connect {} to {} after PicoLimbo failed: {}",
                                                    player.getUsername(), serverName, retry.getReasonComponent().orElse(createUnknownErrorComponent()));
                                            player.sendMessage(Component.text(messages.get(CONNECTION_ERROR_GAME_SERVER), NamedTextColor.RED));
                                        }
                                    } catch (Exception retryEx) {
                                        logger.error("Error while retrying backend transfer for {}: {}",
                                                player.getUsername(), retryEx.getMessage(), retryEx);
                                        player.sendMessage(Component.text(messages.get(CONNECTION_ERROR_GAME_SERVER), NamedTextColor.RED));
                                    }
                                }).delay(300, TimeUnit.MILLISECONDS).schedule();
                            });

                    // Informujemy wywołującego, że podjęto działania zapasowe (transfer do PicoLimbo)
                    return true;
                }

                // Jeśli fallback niedostępny lub jesteśmy już na PicoLimbo, przekazujemy błąd graczowi
                player.sendMessage(Component.text(
                        messages.get(CONNECTION_ERROR_GAME_SERVER),
                        NamedTextColor.RED
                ));
                return false;
            }
        } catch (Exception e) {
            if (logger.isErrorEnabled()) {
                logger.error("Error transferring player {} to server {}: {}",
                        player.getUsername(), serverName, e.getMessage(), e);
            }

            player.sendMessage(Component.text(
                    messages.get(CONNECTION_ERROR_GAME_SERVER),
                    NamedTextColor.RED
            ));
            return false;
        }
    }

    /**
     * Znajduje dostępny serwer backend używając Velocity try servers configuration.
     * Iteruje przez listę serwerów z velocity.toml [servers.try] w kolejności.
     *
     * @return Optional z dostępny serwer backend
     */
    private Optional<RegisteredServer> findAvailableBackendServer() {
        String picoLimboName = settings.getPicoLimboServerName();
        
        // Użyj Velocity try servers configuration
        var tryServers = plugin.getServer().getConfiguration().getAttemptConnectionOrder();
        
        if (logger.isDebugEnabled()) {
            logger.debug("Velocity try servers: {}", tryServers);
        }
        
    // Iteruj przez try servers w kolejności z konfiguracji Velocity
    for (String serverName : tryServers) {
        // Pomiń PicoLimbo - to jest serwer auth, nie docelowy
        if (!serverName.equals(picoLimboName)) {
            Optional<RegisteredServer> server = plugin.getServer().getServer(serverName);
            if (server.isPresent()) {
                RegisteredServer registeredServer = server.get();
                // Sprawdź czy serwer jest dostępny (ping)
                if (isServerAvailable(registeredServer, serverName)) {
                    return Optional.of(registeredServer);
                }
            } else {
                logger.debug("Serwer {} z try nie jest zarejestrowany", serverName);
            }
        } else {
            logger.debug("Pomijam PicoLimbo server: {}", serverName);
        }
    }
        
        // Fallback: jeśli żaden try server nie jest dostępny, spróbuj dowolny inny
        logger.warn("Żaden serwer z try nie jest dostępny, próbuję fallback...");
        return plugin.getServer().getAllServers().stream()
                .filter(server -> !server.getServerInfo().getName().equals(picoLimboName))
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
     * Sprawdza czy gracz jest na serwerze backend.
     *
     * @param player Gracz do sprawdzenia
     * @return true jeśli na backend
     */
    public boolean isPlayerOnBackend(Player player) {
        return player.getCurrentServer()
                .map(serverConnection -> serverConnection.getServerInfo().getName())
                .map(serverName -> !serverName.equals(settings.getPicoLimboServerName()))
                .orElse(false);
    }

    /**
     * Wymusza ponowną autoryzację gracza.
     *
     * @param player Gracz do wylogowania
     */
    public void forceReauth(Player player) {
        try {
            // Usuń z cache
            authCache.removeAuthorizedPlayer(player.getUniqueId());

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
        cancelPendingTransfer(playerUuid);
    }
    
    /**
     * Aktualizuje IP gracza w bazie danych i cache jeśli się zmienił.
     * Wykonywane synchronicznie dla spójności przed transferem.
     */
    private void updatePlayerIpIfChanged(Player player, RegisteredPlayer dbPlayer, CachedAuthUser cachedUser) {
        String currentIp = getPlayerIp(player);
        if (currentIp.equals(dbPlayer.getLoginIp())) {
            return; // IP się nie zmieniło
        }
        
        dbPlayer.updateLoginData(currentIp);
        try {
            databaseManager.savePlayer(dbPlayer).join(); // synchronicznie
            CachedAuthUser updatedUser = cachedUser.withUpdatedIp(currentIp);
            authCache.addAuthorizedPlayer(player.getUniqueId(), updatedUser);
            if (logger.isDebugEnabled()) {
                logger.debug("Zaktualizowano IP gracza {} w bazie danych i cache: {}",
                        player.getUsername(), currentIp);
            }
        } catch (Exception ex) {
            logger.error("Błąd podczas zapisu danych gracza {} do bazy danych - cache nie zaktualizowany",
                    player.getUsername(), ex);
        }
    }

    /**
     * Zamyka ConnectionManager.
     * Anuluje wszystkie pending transfers i czyści retry attempts.
     */
    public void shutdown() {
        // Anuluj wszystkie pending transfers
        pendingTransfers.values().forEach(ScheduledTask::cancel);
        pendingTransfers.clear();
        retryAttempts.clear();
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
            
            logger.debug(messages.get("connection.picolimbo.server"), settings.getPicoLimboServerName());
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
                logger.debug(messages.get("connection.picolimbo.found"),
                        settings.getPicoLimboServerName(),
                        picoLimbo.get().getServerInfo().getAddress());
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

    /**
     * Pobiera InetAddress gracza.
     */
    private InetAddress getPlayerAddress(Player player) {
        var address = player.getRemoteAddress();
        if (address instanceof InetSocketAddress inetAddress) {
            return inetAddress.getAddress();
        }
        return null;
    }

    // Helper methods for consistent messaging
    private void disconnectWithError(Player player, String message) {
        player.disconnect(Component.text(message, NamedTextColor.RED));
    }

    private Component createUnknownErrorComponent() {
        return Component.text(messages.get("error.unknown"), NamedTextColor.RED);
    }
}
