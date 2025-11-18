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

        logger.info(messages.get("connection.manager.initialized"),
                settings.getPicoLimboServerName());
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
                // CRITICAL SECURITY: Block connections until plugin is fully initialized
                if (!plugin.isInitialized()) {
                    logger.warn("🔒 BLOKADA STARTU: Gracz {} próbował połączyć się przed pełną inicjalizacją VeloAuth - rozłączanie", 
                            player.getUsername());
                    
                    player.disconnect(Component.text(
                            "VeloAuth się uruchamia. Spróbuj połączyć się ponownie za chwilę.",
                            NamedTextColor.RED
                    ));
                    return false;
                }

                String playerIp = getPlayerIp(player);
                InetAddress playerAddress = getPlayerAddress(player);

                logger.debug("Obsługa połączenia gracza {} z IP {}",
                        player.getUsername(), playerIp);

                // Sprawdź brute force block
                if (playerAddress != null && authCache.isBlocked(playerAddress)) {
                    logger.warn("Gracz {} zablokowany za brute force z IP {}",
                            player.getUsername(), playerIp);

                    player.disconnect(Component.text(
                            "Zbyt wiele nieudanych prób logowania. Spróbuj ponownie później.",
                            NamedTextColor.RED
                    ));
                    return false;
                }

                // Sprawdź cache autoryzacji
                CachedAuthUser cachedUser = authCache.getAuthorizedPlayer(player.getUniqueId());

                if (cachedUser != null && cachedUser.matchesIp(playerIp)) {
                    // Cache HIT - gracz jest autoryzowany
                    logger.debug("Cache HIT dla gracza {} - transfer na backend", player.getUsername());

                    // Weryfikuj z bazą danych dla bezpieczeństwa
                    return verifyAndTransferToBackend(player, cachedUser);

                } else {
                    // Cache MISS - gracz musi się zalogować
                    logger.debug("Cache MISS dla gracza {} - transfer na PicoLimbo", player.getUsername());

                    return transferToPicoLimbo(player);
                }

            } catch (Exception e) {
                logger.error("Błąd podczas obsługi połączenia gracza: {}", player.getUsername(), e);

                player.disconnect(Component.text(
                        "Wystąpił błąd podczas łączenia. Spróbuj ponownie.",
                        NamedTextColor.RED
                ));
                return false;
            }
        });
    }

    /**
     * Weryfikuje gracza z bazą danych i transferuje na backend.
     */
    private boolean verifyAndTransferToBackend(Player player, CachedAuthUser cachedUser) {
        try {
            // Sprawdź w bazie danych dla bezpieczeństwa
            String lowercaseNick = player.getUsername().toLowerCase();
            var dbResult = databaseManager.findPlayerByNickname(lowercaseNick).join();
            
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
                logger.error(SECURITY_MARKER,
                        "[UUID MISMATCH DETECTED] Gracz {} ma UUID {} ale baza zawiera {} (IP: {})",
                        player.getUsername(), playerUuid, storedUuid, getPlayerIp(player));

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
            logger.error("Błąd podczas weryfikacji gracza: {}", player.getUsername(), e);
            return transferToPicoLimbo(player);
        }
    }

    /**
     * Transferuje gracza na serwer PicoLimbo.
     * Używa synchronicznego połączenia z prawidłową obsługą błędów.
     *
     * @param player Gracz do transferu
     * @return true jeśli transfer się udał
     */
    public boolean transferToPicoLimbo(Player player) {
        try {
            Optional<RegisteredServer> picoLimboServer = plugin.getServer()
                    .getServer(settings.getPicoLimboServerName());

            if (picoLimboServer.isEmpty()) {
                logger.error("Serwer PicoLimbo '{}' nie jest zarejestrowany!",
                        settings.getPicoLimboServerName());

                player.disconnect(Component.text(
                        "Serwer autoryzacji jest niedostępny. Spróbuj ponownie później.",
                        NamedTextColor.RED
                ));
                return false;
            }

            RegisteredServer targetServer = picoLimboServer.get();
            logger.info(messages.get("player.transfer.attempt"), player.getUsername());

            // Asynchroniczne sprawdzenie czy konto istnieje i wyświetlenie odpowiedniego komunikatu
            String lowercaseNick = player.getUsername().toLowerCase();
            CompletableFuture<Void> messageFuture = databaseManager.findPlayerByNickname(lowercaseNick)
                    .thenAccept(existingPlayer -> {
                        if (existingPlayer != null) {
                            // Konto istnieje - pokazuj komunikat logowania
                            sendLoginMessage(player);
                            logger.debug("Wykryto istniejące konto dla {} - pokazano komunikat logowania", player.getUsername());
                        } else {
                            // Konto nie istnieje - pokazuj komunikat rejestracji
                            sendRegisterMessage(player);
                            logger.debug("Wykryto nowe konto dla {} - pokazano komunikat rejestracji", player.getUsername());
                        }
                    })
                    .exceptionally(throwable -> {
                        logger.warn("Błąd podczas sprawdzania konta dla {}: {}", player.getUsername(), throwable.getMessage());
                        // Fallback do generycznego komunikatu w przypadku błędu
                        sendGenericAuthMessage(player);
                        return null;
                    });

            // Monitor completion of the async message operation with timeout
            messageFuture
                    .orTimeout(10, TimeUnit.SECONDS)
                    .whenComplete((result, throwable) -> {
                        if (throwable != null) {
                            logger.error("Krytyczny błąd w operacji wiadomości dla {}: {}",
                                    player.getUsername(), throwable.getMessage(), throwable);
                        }
                    }).join();  // Wait for message to complete before transfer

            return executePicoLimboTransfer(player, targetServer);

        } catch (Exception e) {
            logger.error("Krytyczny błąd podczas próby transferu gracza na PicoLimbo: {}", player.getUsername(), e);

            disconnectWithError(player, "Wystąpił krytyczny błąd podczas łączenia z serwerem autoryzacji.");
            return false;
        }
    }

    /**
     * Wykonuje transfer gracza na serwer PicoLimbo.
     *
     * @param player       Gracz do transferu
     * @param targetServer Serwer docelowy PicoLimbo
     * @return true jeśli transfer się udał
     */
    private boolean executePicoLimboTransfer(Player player, RegisteredServer targetServer) {
        try {
            var result = player.createConnectionRequest(targetServer)
                    .connect()
                    .join();  // Czekaj na zakończenie transferu

            if (result.isSuccessful()) {
                logger.info(messages.get("player.transfer.success"), player.getUsername());
                return true;
            } else {
                logger.warn("❌ Transfer {} na PicoLimbo FAILED: {}",
                        player.getUsername(),
                        result.getReasonComponent().orElse(createUnknownErrorComponent()));

                player.sendMessage(Component.text(
                        "Nie udało się połączyć z serwerem autoryzacji. Spróbuj ponownie.",
                        NamedTextColor.RED
                ));
                return false;
            }
        } catch (Exception e) {
            logger.error("Błąd podczas transferu gracza {} na PicoLimbo: {}",
                    player.getUsername(), e.getMessage(), e);

            player.sendMessage(Component.text(
                    "Wystąpił błąd podczas łączenia z serwerem autoryzacji.",
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
                logger.error("Brak dostępnych serwerów backend!");

                player.sendMessage(Component.text(
                        "Brak dostępnych serwerów gry. Spróbuj ponownie później.",
                        NamedTextColor.RED
                ));
                return false;
            }

            RegisteredServer targetServer = backendServer.get();
            String serverName = targetServer.getServerInfo().getName();

            // Wyślij wiadomość o próbie połączenia
            player.sendMessage(Component.text(
                    "Łączenie z serwerem gry...",
                    NamedTextColor.YELLOW
            ));

            logger.info(messages.get("player.transfer.backend.attempt"),
                    player.getUsername(), serverName);

            // Wykonaj transfer synchronicznie z timeoutem
            try {
                // Użyj .join() aby zablokować do czasu zakończenia transferu
                boolean transferSuccess = player.createConnectionRequest(targetServer)
                        .connect()
                        .join() // Czekaj na zakończenie transferu
                        .isSuccessful();

                if (transferSuccess) {
                    logger.info(messages.get("player.transfer.backend.success"),
                            player.getUsername(), serverName);
                    return true;
                } else {
                    logger.warn("Nie udało się przenieść gracza {} na serwer {}",
                            player.getUsername(), serverName);

                    player.sendMessage(Component.text(
                            "Nie udało się połączyć z serwerem gry. Spróbuj ponownie.",
                            NamedTextColor.RED
                    ));
                    return false;
                }
            } catch (Exception e) {
                logger.error("Błąd podczas transferu gracza {} na serwer {}: {}",
                        player.getUsername(), serverName, e.getMessage(), e);

                player.sendMessage(Component.text(
                        "Wystąpił błąd podczas łączenia z serwerem gry.",
                        NamedTextColor.RED
                ));
                return false;
            }
        } catch (Exception e) {
            logger.error("Krytyczny błąd podczas transferu gracza {}: {}",
                    player.getUsername(), e.getMessage(), e);

            player.sendMessage(Component.text(
                    "Wystąpił krytyczny błąd podczas transferu.",
                    NamedTextColor.RED
            ));
            return false;
        }
    }

    /**
     * Znajduje dostępny serwer backend (nie PicoLimbo).
     *
     * @return Optional z dostępny serwer backend
     */
    private Optional<RegisteredServer> findAvailableBackendServer() {
        String picoLimboName = settings.getPicoLimboServerName();

        return plugin.getServer().getAllServers().stream()
                .filter(server -> !server.getServerInfo().getName().equals(picoLimboName))
                .filter(server -> {
                    // Sprawdź czy serwer jest dostępny (ping)
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
                    "Zostałeś wylogowany. Zaloguj się ponownie.",
                    NamedTextColor.YELLOW
            ));

            logger.info("Wymuszono ponowną autoryzację gracza: {}", player.getUsername());

        } catch (Exception e) {
            logger.error("Błąd podczas wymuszania ponownej autoryzacji: {}", player.getUsername(), e);
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
        logger.info(messages.get("connection.servers.available"));
        plugin.getServer().getAllServers().forEach(server -> {
            String name = server.getServerInfo().getName();
            String address = server.getServerInfo().getAddress().toString();
            logger.info("  - {} ({})", name, address);
        });
        logger.info(messages.get("connection.picolimbo.server"), settings.getPicoLimboServerName());

        // Sprawdź czy PicoLimbo serwer istnieje
        Optional<RegisteredServer> picoLimbo = plugin.getServer()
                .getServer(settings.getPicoLimboServerName());

        if (picoLimbo.isEmpty()) {
            logger.error(messages.get("connection.picolimbo.error"),
                    settings.getPicoLimboServerName());
        } else {
            logger.info(messages.get("connection.picolimbo.found"),
                    settings.getPicoLimboServerName(),
                    picoLimbo.get().getServerInfo().getAddress());
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
                "Twoje konto już istnieje! Użyj /login <hasło>",
                NamedTextColor.GREEN
        ));
    }

    private void sendRegisterMessage(Player player) {
        player.sendMessage(Component.text(
                "Witaj po raz pierwszy! Użyj /register <hasło> <powtórz>",
                NamedTextColor.AQUA
        ));
    }

    private void sendGenericAuthMessage(Player player) {
        player.sendMessage(Component.text(
                "Musisz się zalogować! Użyj /login <hasło> lub /register <hasło> <powtórz>",
                NamedTextColor.YELLOW
        ));
    }

    private void disconnectWithError(Player player, String message) {
        player.disconnect(Component.text(message, NamedTextColor.RED));
    }

    private Component createUnknownErrorComponent() {
        return Component.text("Nieznany błąd", NamedTextColor.RED);
    }
}
