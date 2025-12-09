package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.StringConstants;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Manager połączeń i transferów graczy między serwerami.
 * Zarządza przepuszczaniem graczy między Velocity, PicoLimbo i serwerami backend.
 * <p>
 * Flow autoryzacji:
 * 1. Gracz dołącza -> sprawdź cache -> jeśli autoryzowany: backend, jeśli nie: PicoLimbo
 * 2. Gracz na PicoLimbo -> /login lub /register -> transfer na backend
 * 3. Gracz na backend -> już autoryzowany, brak dodatkowych sprawdzeń
 */
public class ConnectionManager {

    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");
    private static final long CONNECT_TIMEOUT_SECONDS = 5;

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
                    "VeloAuth się uruchamia. Spróbuj połączyć się ponownie za chwilę.",
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
                    "Zbyt wiele nieudanych prób logowania. Spróbuj ponownie później.",
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
                logger.debug("Cache HIT dla gracza {} - transfer na backend", player.getUsername());
            }

            // Weryfikuj z bazą danych dla bezpieczeństwa
            return verifyAndTransferToBackend(player, cachedUser);

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
                "Wystąpił błąd podczas łączenia. Spróbuj ponownie.",
                NamedTextColor.RED
        ));
        return false;
    }

    /**
     * Weryfikuje gracza z bazą danych i transferuje na backend.
     */
    @SuppressWarnings({"java:S3776", "java:S138"}) // Auth verification flow - 63 lines, complexity 9
    private boolean verifyAndTransferToBackend(Player player, CachedAuthUser cachedUser) {
        try {
            // Sprawdź w bazie danych dla bezpieczeństwa
            var dbResult = databaseManager.findPlayerByNickname(player.getUsername()).join();

            // CRITICAL: Fail-secure on database errors
            if (dbResult.isDatabaseError()) {
                logger.error("Database error during player verification for {}: {}",
                        player.getUsername(), dbResult.getErrorMessage());
                // Remove from cache and deny access for security
                authCache.removeAuthorizedPlayer(player.getUniqueId());
                authCache.endSession(player.getUniqueId());
                player.disconnect(Component.text(
                        "Wystąpił błąd weryfikacji bazy danych. Spróbuj ponownie później.",
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

            // NOWOŚĆ: Weryfikacja UUID - zapobiega UUID spoofing
            UUID playerUuid = player.getUniqueId();
            UUID storedUuid = dbPlayer.getUuidAsUUID();

            if (storedUuid != null && !playerUuid.equals(storedUuid)) {
                // UUID MISMATCH - POTENCJALNY ATAK!
                if (logger.isErrorEnabled()) {
                    logger.error(SECURITY_MARKER,
                            "[UUID MISMATCH DETECTED] Gracz {} ma UUID {} ale baza zawiera {} (IP: {})",
                            player.getUsername(), playerUuid, storedUuid, getPlayerIp(player));
                }

                // Usuń z cache i zakończ sesję
                authCache.removeAuthorizedPlayer(player.getUniqueId());
                authCache.endSession(player.getUniqueId());

                // Rozłącz gracza
                player.disconnect(Component.text(
                        "UUID nie zgadza się z kontem! Potencjalny atak spoofing.",
                        NamedTextColor.RED
                ));
                return false;
            }

            // Aktualizuj IP logowania jeśli się zmienił
            String currentIp = getPlayerIp(player);
            if (!currentIp.equals(dbPlayer.getLoginIp())) {
                dbPlayer.updateLoginData(currentIp);

                // Aktualizuj cache tylko po pomyślnym zapisie do bazy danych
                // skipcq: JAVA-W1087 - Future is properly handled with thenAccept/exceptionally
                databaseManager.savePlayer(dbPlayer)
                        .thenAccept(result -> {
                            // Sukces - zaktualizuj cache z nowym IP
                            CachedAuthUser updatedUser = cachedUser.withUpdatedIp(currentIp);
                            authCache.addAuthorizedPlayer(player.getUniqueId(), updatedUser);
                            logger.debug("Zaktualizowano IP gracza {} w bazie danych i cache: {}",
                                    player.getUsername(), currentIp);
                        })
                        .exceptionally(throwable -> {
                            // Błąd - loguj problem ale nie aktualizuj cache
                            logger.error("Błąd podczas zapisu danych gracza {} do bazy danych - cache nie zaktualizowany",
                                    player.getUsername(), throwable);
                            return null;
                        });
            }

            // Transfer na backend
            return transferToBackend(player);

        } catch (Exception e) {
            if (logger.isErrorEnabled()) {
                logger.error("Błąd podczas weryfikacji gracza: {}", player.getUsername(), e);
            }
            disconnectWithError(player, "Wystąpił błąd weryfikacji bazy danych.");
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
                    "Serwer autoryzacji jest niedostępny. Spróbuj ponownie później.",
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

        disconnectWithError(player, "Wystąpił krytyczny błąd podczas łączenia z serwerem autoryzacji.");
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
            // FIX: Add small delay to prevent race conditions during initial connection
            // PicoLimbo might not be ready to accept connections immediately
            try {
                Thread.sleep(50);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
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
                    messages.get("connection.error.game_server"),
                    NamedTextColor.RED
            ));
            return false;
        }
    }
    
    private boolean executeBackendTransfer(Player player, RegisteredServer targetServer, String serverName) {
        try {
            // Użyj .join() aby zablokować do czasu zakończenia transferu
            boolean transferSuccess = player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .join() // Czekaj na zakończenie transferu
                    .isSuccessful();

            if (transferSuccess) {
                if (logger.isDebugEnabled()) {
                    logger.debug(messages.get("player.transfer.backend.success"),
                            player.getUsername(), serverName);
                }
                return true;
            } else {
                if (logger.isWarnEnabled()) {
                    logger.warn("Failed to transfer player {} to server {}",
                            player.getUsername(), serverName);
                }

                player.sendMessage(Component.text(
                        messages.get("connection.error.game_server"),
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
                    messages.get("connection.error.game_server"),
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
            if (serverName.equals(picoLimboName)) {
                logger.debug("Pomijam PicoLimbo server: {}", serverName);
                continue;
            }
            
            Optional<RegisteredServer> server = plugin.getServer().getServer(serverName);
            if (server.isEmpty()) {
                logger.debug("Serwer {} z try nie jest zarejestrowany", serverName);
                continue;
            }
            
            RegisteredServer registeredServer = server.get();
            
            // Sprawdź czy serwer jest dostępny (ping)
            try {
                if (registeredServer.ping().orTimeout(2, TimeUnit.SECONDS).join() != null) {
                    logger.debug("Znaleziono dostępny serwer z try: {}", serverName);
                    return Optional.of(registeredServer);
                }
            } catch (Exception e) {
                logger.debug("Serwer {} z try niedostępny: {}", serverName, e.getMessage());
            }
        }
        
        // Fallback: jeśli żaden try server nie jest dostępny, spróbuj dowolny inny
        logger.warn("Żaden serwer z try nie jest dostępny, próbuję fallback...");
        return plugin.getServer().getAllServers().stream()
                .filter(server -> !server.getServerInfo().getName().equals(picoLimboName))
                .filter(server -> {
                    try {
                        return server.ping().join() != null;
                    } catch (Exception e) {
                        logger.debug("Serwer {} niedostępny: {}",
                                server.getServerInfo().getName(), e.getMessage());
                        return false;
                    }
                })
                .findFirst();
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
     * Zamyka ConnectionManager.
     */
    public void shutdown() {
        logger.info("ConnectionManager zamknięty");
    }

    /**
     * Debuguje dostępne serwery.
     * Wyświetla wszystkie zarejestrowane serwery i sprawdza konfigurację PicoLimbo.
     */
    public void debugServers() {
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.servers.available"));
        }
        plugin.getServer().getAllServers().forEach(server -> {
            String name = server.getServerInfo().getName();
            String address = server.getServerInfo().getAddress().toString();
            logger.debug("  - {} ({})", name, address);
        });
        if (logger.isDebugEnabled()) {
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
            if (logger.isInfoEnabled()) {
                logger.info(messages.get("connection.picolimbo.found"),
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
    private void sendLoginMessage(Player player) {
        player.sendMessage(Component.text(
                messages.get("auth.account_exists"),
                NamedTextColor.GREEN
        ));
    }

    private void sendRegisterMessage(Player player) {
        player.sendMessage(Component.text(
                messages.get("auth.first_time"),
                NamedTextColor.AQUA
        ));
    }

    private void sendGenericAuthMessage(Player player) {
        player.sendMessage(Component.text(
                messages.get("auth.prompt.generic"),
                NamedTextColor.YELLOW
        ));
    }

    private void disconnectWithError(Player player, String message) {
        player.disconnect(Component.text(message, NamedTextColor.RED));
    }

    private Component createUnknownErrorComponent() {
        return Component.text(messages.get("error.unknown"), NamedTextColor.RED);
    }
}
