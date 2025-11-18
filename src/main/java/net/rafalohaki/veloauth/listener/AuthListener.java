package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.cache.AuthCache.PremiumCacheEntry;
import net.rafalohaki.veloauth.command.ValidationUtils;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.premium.PremiumResolution;
import net.rafalohaki.veloauth.premium.PremiumResolverService;
import net.rafalohaki.veloauth.util.StringConstants;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import javax.inject.Inject;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Listener eventów autoryzacji VeloAuth.
 * Obsługuje połączenia graczy i kieruje ich na odpowiednie serwery.
 * <p>
 * Flow eventów:
 * 1. PreLoginEvent -> sprawdź premium i force online mode
 * 2. LoginEvent -> sprawdź brute force
 * 3. PostLoginEvent -> kieruj na PicoLimbo lub backend
 * 4. ServerPreConnectEvent -> blokuj nieautoryzowane połączenia z backend
 * 5. ServerConnectedEvent -> loguj transfery
 */
public class AuthListener {

    // Markery SLF4J dla kategoryzowanego logowania
    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final VeloAuth plugin;
    private ConnectionManager connectionManager;
    private final AuthCache authCache;
    private final Settings settings;
    private final Logger logger;
    private PremiumResolverService premiumResolverService;
    private DatabaseManager databaseManager;
    private final Messages messages;

    /**
     * Tworzy nowy AuthListener.
     *
     * @param plugin                 VeloAuth plugin instance
     * @param connectionManager      Manager połączeń
     * @param authCache              Cache autoryzacji
     * @param settings               Ustawienia pluginu
     * @param premiumResolverService Premium resolver service
     * @param databaseManager        Manager bazy danych
     * @param messages               System wiadomości i18n
     */
    @Inject
    public AuthListener(VeloAuth plugin,
                        ConnectionManager connectionManager,
                        AuthCache authCache,
                        Settings settings,
                        PremiumResolverService premiumResolverService,
                        DatabaseManager databaseManager,
                        Messages messages) {
        this.plugin = plugin;
        this.connectionManager = connectionManager;
        this.authCache = authCache;
        this.settings = settings;
        this.logger = plugin.getLogger();
        this.premiumResolverService = premiumResolverService;
        this.databaseManager = databaseManager;
        this.messages = messages;

        logger.info(messages.get("connection.listener.registered"));
    }

    /**
     * Updates dependencies after full initialization.
     * This allows the AuthListener to be registered early for PreLogin protection,
     * then receive full dependencies when initialization completes.
     *
     * @param connectionManager      Manager połączeń (może być null przy wczesnej rejestracji)
     * @param premiumResolverService Premium resolver service (może być null przy wczesnej rejestracji)
     * @param databaseManager        Manager bazy danych (może być null przy wczesnej rejestracji)
     */
    public void updateDependencies(ConnectionManager connectionManager,
                                  PremiumResolverService premiumResolverService,
                                  DatabaseManager databaseManager) {
        this.connectionManager = connectionManager;
        this.premiumResolverService = premiumResolverService;
        this.databaseManager = databaseManager;
        logger.info("AuthListener dependencies updated successfully");
    }

    /**
     * Resolves the block reason for unauthorized connections.
     * Replaces nested ternary with clear if/else logic.
     *
     * @param isAuthorized     Whether player is authorized
     * @param hasActiveSession Whether player has active session
     * @return Human-readable reason string
     */
    private static String resolveBlockReason(boolean isAuthorized, boolean hasActiveSession) {
        if (!isAuthorized) {
            return "nieautoryzowany";
        }
        if (!hasActiveSession) {
            return "brak aktywnej sesji";
        }
        return "UUID mismatch";
    }

    /**
     * ✅ KLUCZOWY EVENT - PreLoginEvent
     * Tutaj sprawdzamy premium PRZED weryfikacją UUID!
     * Jeśli premium → forceOnlineMode() = Velocity zweryfikuje
     * <p>
     * KRYTYCZNE: Używamy async = false + maksymalny priorytet dla bezpieczeństwa
     * Zapobiega race conditions gdzie async handlers mogą wykonać się przed sync handlers
     * <p>
     * UWAGA: PreLoginEvent WYMAGA synchronicznej odpowiedzi.
     * Premium resolution na cache miss blokuje, ale to ograniczenie API Velocity.
     * Dwa warstwy cache (AuthCache + PremiumResolverService) minimalizują impact.
     */
    @Subscribe(priority = Short.MAX_VALUE, async = false)
    public void onPreLogin(PreLoginEvent event) {
        String username = event.getUsername();
        logger.info("\uD83D\uDD0D PreLogin: {}", username);

        // CRITICAL: Block connections until plugin is fully initialized
        if (!plugin.isInitialized()) {
            logger.warn("🔒 BLOKADA STARTU: Gracz {} próbował połączyć się przed pełną inicjalizacją VeloAuth - blokada PreLogin",
                    username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text("VeloAuth się uruchamia. Spróbuj połączyć się ponownie za chwilę.",
                            NamedTextColor.RED)
            ));
            return;
        }

        // WALIDACJA USERNAME - sprawdź format przed cokolwiek innego
        if (!isValidUsername(username)) {
            String message = "Nieprawidłowy format nazwy użytkownika! Użyj tylko liter, cyfr i podkreślenia (max 16 znaków).";
            logger.warn(SECURITY_MARKER, "[USERNAME VALIDATION FAILED] {} - invalid format", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(message, NamedTextColor.RED)
            ));
            return;
        }

        // Sprawdź brute force na poziomie IP PRZED jakimkolwiek przetwarzaniem
        InetAddress playerAddress = getPlayerAddressFromPreLogin(event);
        if (playerAddress != null && authCache.isBlocked(playerAddress)) {
            String message = "Zbyt wiele nieudanych prób logowania. Spróbuj ponownie później.";
            logger.warn(SECURITY_MARKER, "[BRUTE FORCE BLOCK] IP {} zablokowany", playerAddress.getHostAddress());
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(message, NamedTextColor.RED)
            ));
            return;
        }

        if (!settings.isPremiumCheckEnabled()) {
            logger.debug("Premium check wyłączony w konfiguracji - wymuszam offline mode dla {}", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
            return;
        }

        boolean premium = false;

        PremiumResolutionResult result = resolvePremiumStatus(username);
        premium = result.premium();

        if (premium) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
        } else {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
        }
    }

    /**
     * Resolves premium status for username with caching.
     *
     * @param username Username to check
     * @return PremiumResolutionResult with status and UUID
     */
    private PremiumResolutionResult resolvePremiumStatus(String username) {
        PremiumCacheEntry cachedStatus = authCache.getPremiumStatus(username);
        if (cachedStatus != null) {
            logger.debug("Premium cache hit dla {} -> {}", username, cachedStatus.isPremium());
            return new PremiumResolutionResult(cachedStatus.isPremium(), cachedStatus.getPremiumUuid());
        }

        // Cache miss - resolve via service with timeout to prevent blocking
        PremiumResolution resolution;
        try {
            // Use CompletableFuture with timeout to prevent blocking PreLoginEvent
            resolution = CompletableFuture.supplyAsync(() -> premiumResolverService.resolve(username))
                    .orTimeout(3, TimeUnit.SECONDS) // 3 second timeout for premium resolution
                    .exceptionally(throwable -> {
                        logger.warn("Premium resolution timeout for {}, treating as offline: {}", username, throwable.getMessage());
                        return PremiumResolution.offline(username, "VeloAuth-Timeout", "Timeout - fallback to offline");
                    })
                    .join();
        } catch (Exception e) {
            logger.warn("Premium resolution failed for {}, treating as offline: {}", username, e.getMessage());
            resolution = PremiumResolution.offline(username, "VeloAuth-Error", "Error - fallback to offline");
        }
        boolean premium = false;
        UUID premiumUuid = null;

        if (resolution.isPremium()) {
            premium = true;
            premiumUuid = resolution.uuid();
            String canonical = resolution.canonicalUsername() != null ? resolution.canonicalUsername() : username;
            authCache.addPremiumPlayer(canonical, premiumUuid);
            logger.info(messages.get("player.premium.confirmed"), username, resolution.source(), premiumUuid);
        } else if (resolution.isOffline()) {
            authCache.addPremiumPlayer(username, null);
            logger.debug("{} nie jest premium (resolver: {}, info: {})", username, resolution.source(), resolution.message());
        } else {
            logger.warn("⚠️ Nie udało się jednoznacznie potwierdzić statusu premium dla {} (resolver: {}, info: {})",
                    username, resolution.source(), resolution.message());
        }

        return new PremiumResolutionResult(premium, premiumUuid);
    }

    /**
     * Obsługuje event logowania gracza.
     * Sprawdza brute force i premium status SYNCHRONICZNIE.
     * <p>
     * KRYTYCZNE: Używamy async = false + maksymalny priorytet dla bezpieczeństwa
     * Zapobiega race conditions w procesie autoryzacji
     */
    @Subscribe(priority = Short.MAX_VALUE, async = false)
    public void onLogin(LoginEvent event) {
        Player player = event.getPlayer();
        String playerName = player.getUsername();
        UUID playerUuid = player.getUniqueId();
        String playerIp = getPlayerIp(player);

        boolean allowed = true;
        try {
            // CRITICAL SECURITY: Block login attempts until plugin is fully initialized
            if (!plugin.isInitialized()) {
                logger.warn("🔒 BLOKADA STARTU: Gracz {} próbował zalogować się przed pełną inicjalizacją VeloAuth - blokada logowania",
                        playerName);

                event.setResult(LoginEvent.ComponentResult.denied(
                        Component.text("VeloAuth się uruchamia. Spróbuj zalogować się ponownie za chwilę.",
                                NamedTextColor.RED)
                ));
                return;
            }

            logger.debug("LoginEvent dla gracza {} (UUID: {}) z IP {}",
                    playerName, playerUuid, playerIp);

            // 1. Sprawdź blokadę brute force
            InetAddress playerAddress = getPlayerAddress(player);
            if (playerAddress != null && authCache.isBlocked(playerAddress)) {
                String message = String.format("Zablokowano połączenie gracza %s za zbyt wiele nieudanych prób logowania",
                        playerName);
                logger.warn(SECURITY_MARKER, message);

                event.setResult(LoginEvent.ComponentResult.denied(
                        Component.text("Zbyt wiele nieudanych prób logowania. Spróbuj ponownie później.",
                                NamedTextColor.RED)
                ));
                allowed = false;
                return;
            }

            // Premium check został przeniesiony do PreLoginEvent

        } catch (Exception e) {
            logger.error("Błąd podczas obsługi LoginEvent dla gracza: "
                    + event.getPlayer().getUsername(), e);

            event.setResult(LoginEvent.ComponentResult.denied(
                    Component.text("Wystąpił błąd podczas łączenia. Spróbuj ponownie.",
                            NamedTextColor.RED)
            ));
            allowed = false;
        }

        if (allowed) {
            event.setResult(LoginEvent.ComponentResult.allowed());
        }
    }

    /**
     * Obsługuje disconnect gracza - kończy sesję premium.
     * Zapobiega session hijacking przez natychmiastowe kończenie sesji.
     */
    @Subscribe(priority = 0) // NORMAL priority
    public void onDisconnect(DisconnectEvent event) {
        try {
            Player player = event.getPlayer();

            // ✅ SESJE TRWAŁE: Nie kończ sesji przy rozłączeniu
            // Sesje powinny być trwałe dla autoryzowanych graczy offline
            // Kończymy tylko przy /logout, timeout lub banie

            logger.debug("Gracz {} rozłączył się - sesja pozostaje aktywna", player.getUsername());

        } catch (Exception e) {
            logger.error("Błąd podczas obsługi DisconnectEvent dla gracza: {}", event.getPlayer().getUsername(), e);
        }
    }

    /**
     * Obsługuje event po zalogowaniu gracza.
     * Kieruje gracza na odpowiedni serwer (PicoLimbo lub backend).
     */
    @Subscribe(priority = 0) // NORMAL priority
    public void onPostLogin(PostLoginEvent event) {
        Player player = event.getPlayer();
        String playerIp = getPlayerIp(player);

        logger.debug("PostLoginEvent dla gracza {} z IP {}",
                player.getUsername(), playerIp);

        try {
            if (player.isOnlineMode()) {
                logger.info(AUTH_MARKER, messages.get("player.premium.verified"), player.getUsername());

                UUID playerUuid = player.getUniqueId();
                UUID premiumUuid = Optional.ofNullable(authCache.getPremiumStatus(player.getUsername()))
                        .map(PremiumCacheEntry::getPremiumUuid)
                        .orElse(playerUuid);

                CachedAuthUser cachedUser = new CachedAuthUser(
                        playerUuid,
                        player.getUsername(),
                        playerIp,
                        System.currentTimeMillis(),
                        true,
                        premiumUuid
                );

                authCache.addAuthorizedPlayer(playerUuid, cachedUser);
                authCache.startSession(playerUuid, player.getUsername(), playerIp);
                return;
            }

            if (authCache.isPlayerAuthorized(player.getUniqueId(), playerIp)) {
                logger.info(AUTH_MARKER, "\u2705 Gracz {} jest już autoryzowany - pozostaje na backendzie",
                        player.getUsername());
                return;
            }

            logger.info(messages.get("player.unauthorized.redirect"),
                    player.getUsername());

            // Uruchom w osobnym wątku, aby nie blokować głównego
            plugin.getServer().getScheduler().buildTask(plugin, () -> {
                try {
                    boolean success = connectionManager.transferToPicoLimbo(player);
                    if (success) {
                        // Success logged by ConnectionManager to avoid duplication
                    } else {
                        logger.error("\u274C Błąd podczas przenoszenia gracza {} na PicoLimbo",
                                player.getUsername());

                        player.disconnect(Component.text(
                                "Nie udało się połączyć z serwerem autoryzacji. Spróbuj ponownie.",
                                NamedTextColor.RED
                        ));
                    }
                } catch (Exception e) {
                    logger.error("❌ Błąd podczas przenoszenia gracza {} na PicoLimbo: {}",
                            player.getUsername(), e.getMessage(), e);

                    player.disconnect(Component.text(
                            "Wystąpił błąd podczas łączenia z serwerem autoryzacji. Spróbuj ponownie.",
                            NamedTextColor.RED
                    ));
                }
            }).schedule();

        } catch (Exception e) {
            logger.error("Błąd podczas obsługi PostLoginEvent dla gracza: {}", event.getPlayer().getUsername(), e);

            event.getPlayer().disconnect(Component.text(
                    "Wystąpił błąd podczas łączenia. Spróbuj ponownie.",
                    NamedTextColor.RED
            ));
        }
    }

    /**
     * Obsługuje event przed połączeniem z serwerem.
     * Blokuje nieautoryzowane połączenia z serwerami backend.
     * <p>
     * KRYTYCZNE: Używamy async = false + maksymalny priorytet dla bezpieczeństwa
     * Zapobiega obejściu autoryzacji przez race conditions
     */
    @Subscribe(priority = Short.MAX_VALUE, async = false)
    public void onServerPreConnect(ServerPreConnectEvent event) {
        try {
            Player player = event.getPlayer();
            // NAPRAWIONE: Używamy getOriginalServer() zamiast getTarget()
            // getOriginalServer() to INPUT field (dokąd gracz chce iść)
            String targetServerName = event.getOriginalServer().getServerInfo().getName();
            String playerIp = getPlayerIp(player);

            logger.debug("ServerPreConnectEvent dla gracza {} -> serwer {}",
                    player.getUsername(), targetServerName);

            // ✅ JEŚLI TO PICOLIMBO - SPRAWDŹ DODATKOWO AUTORYZACJĘ
            if (targetServerName.equals(settings.getPicoLimboServerName())) {
                // DODATKOWA WERYFIKACJA - sprawdź czy gracz nie jest już autoryzowany
                // Jeśli jest autoryzowany, nie powinien iść na PicoLimbo
                boolean isAuthorized = authCache.isPlayerAuthorized(player.getUniqueId(), playerIp);
                if (isAuthorized) {
                    // AUTORYZOWANY GRACZ NA PICOLIMBO - przekieruj na backend
                    logger.debug("Autoryzowany gracz {} próbuje iść na PicoLimbo - przekierowuję na backend",
                            player.getUsername());
                    event.setResult(ServerPreConnectEvent.ServerResult.denied());
                    // Velocity automatycznie przekieruje na inny serwer
                    return;
                }
                logger.debug("PicoLimbo - pozwól (gracz nie jest autoryzowany)");
                return;
            }

            // ✅ JEŚLI TO BACKEND - SPRAWDŹ AUTORYZACJĘ + SESJĘ + CACHE
            boolean isAuthorized = authCache.isPlayerAuthorized(player.getUniqueId(), playerIp);

            // DODATKOWA WERYFIKACJA - sprawdź aktywną sesję z walidacją IP
            boolean hasActiveSession = authCache.hasActiveSession(player.getUniqueId(), player.getUsername(), ValidationUtils.getPlayerIp(player));

            // WERYFIKUJ UUID z bazą danych dla maksymalnego bezpieczeństwa
            boolean uuidMatches = verifyPlayerUuid(player);

            if (!isAuthorized || !hasActiveSession || !uuidMatches) {
                // ❌ NIE AUTORYZOWANY LUB BRAK SESJI LUB UUID MISMATCH
                String reason = resolveBlockReason(isAuthorized, hasActiveSession);

                logger.warn(SECURITY_MARKER, messages.get("player.blocked.unauthorized"),
                        player.getUsername(), targetServerName, reason, playerIp);

                event.setResult(ServerPreConnectEvent.ServerResult.denied());

                player.sendMessage(Component.text()
                        .content("❌ ")
                        .color(NamedTextColor.RED)
                        .append(Component.text("Musisz się zalogować na auth!")
                                .color(NamedTextColor.RED))
                        .build());

                // Jeśli UUID mismatch - usuń z cache dla bezpieczeństwa
                if (!uuidMatches) {
                    authCache.removeAuthorizedPlayer(player.getUniqueId());
                    authCache.endSession(player.getUniqueId());
                }

                return;
            }

            // ✅ WSZYSTKIE WERYFIKACJE PRZESZŁY - POZWÓL
            logger.debug("\u2705 Autoryzowany gracz {} idzie na {} (sesja: OK, UUID: OK)",
                    player.getUsername(), targetServerName);

        } catch (Exception e) {
            logger.error("Błąd w ServerPreConnect", e);
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
        }
    }

    /**
     * Obsługuje event połączenia z serwerem.
     * Loguje transfery graczy między serwerami.
     */
    @Subscribe(priority = -200) // LAST priority
    public void onServerConnected(ServerConnectedEvent event) {
        try {
            Player player = event.getPlayer();
            String serverName = event.getServer().getServerInfo().getName();

            logger.debug("ServerConnectedEvent dla gracza {} -> serwer {}",
                    player.getUsername(), serverName);

            // Loguj transfer na backend (debug level to reduce spam)
            if (!serverName.equals(settings.getPicoLimboServerName())) {
                if (logger.isDebugEnabled()) {
                    logger.debug(AUTH_MARKER, messages.get("player.connected.backend"),
                            player.getUsername(), serverName);
                }

                // Wyślij wiadomość powitalną
                player.sendMessage(Component.text(
                        "Witaj na serwerze! Miłej gry!",
                        NamedTextColor.GREEN
                ));
            } else {
                logger.debug(AUTH_MARKER, "Gracz {} połączył się z PicoLimbo", player.getUsername());

                // Wyślij instrukcje logowania
                player.sendMessage(Component.text(
                        "=== Autoryzacja VeloAuth ===",
                        NamedTextColor.GOLD
                ));
                player.sendMessage(Component.text(
                        "Jeśli masz konto: /login <hasło>",
                        NamedTextColor.YELLOW
                ));
                player.sendMessage(Component.text(
                        "Jeśli nie masz konta: /register <hasło> <powtórz>",
                        NamedTextColor.YELLOW
                ));
            }

        } catch (Exception e) {
            logger.error("Błąd podczas obsługi ServerConnectedEvent", e);
        }
    }

    /**
     * Pobiera IP gracza jako string.
     */
    private String getPlayerIp(Player player) {
        if (player.getRemoteAddress() != null && player.getRemoteAddress().getAddress() != null) {
            return player.getRemoteAddress().getAddress().getHostAddress();
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

    /**
     * Pobiera InetAddress z PreLoginEvent.
     * PreLoginEvent nie ma jeszcze Player object, więc musimy użyć connection data.
     */
    private InetAddress getPlayerAddressFromPreLogin(PreLoginEvent event) {
        try {
            // PreLoginEvent może zawierać connection information
            // Używamy refleksji lub innych metod do pobrania adresu
            // W Velocity, PreLoginEvent ma pole connection
            var connection = event.getConnection();
            if (connection != null) {
                var address = connection.getRemoteAddress();
                if (address instanceof InetSocketAddress inetAddress) {
                    return inetAddress.getAddress();
                }
            }
        } catch (Exception e) {
            logger.debug("Nie można pobrać adresu z PreLoginEvent: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Waliduje format nazwy użytkownika.
     * Sprawdza czy nickname zawiera tylko dozwolone znaki i ma prawidłową długość.
     */
    private boolean isValidUsername(String username) {
        if (username == null || username.isEmpty()) {
            return false;
        }

        // Minecraft username limit: 3-16 characters
        if (username.length() < 3 || username.length() > 16) {
            return false;
        }

        // Minecraft usernames: letters, numbers, underscore
        // Nie może zaczynać się od underscore (opcjonalnie)
        for (int i = 0; i < username.length(); i++) {
            char c = username.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '_') {
                return false;
            }
        }

        return true;
    }

    /**
     * Weryfikuje czy UUID gracza zgadza się z UUID w bazie danych.
     * Zapobiega UUID spoofing atakom.
     * <p>
     * UWAGA: Dla premium players (online mode) pomijamy weryfikację z bazą,
     * ponieważ nie muszą być zarejestrowani w bazie danych.
     */
    private boolean verifyPlayerUuid(Player player) {
        try {
            // Jeśli gracz jest online mode (premium), pomijamy weryfikację UUID z bazą
            // Ponieważ premium players nie muszą być w bazie danych
            if (player.isOnlineMode()) {
                logger.debug("Premium gracz {} - pomijam weryfikację UUID z bazą", player.getUsername());
                return true;
            }

            // Dla cracked players, zweryfikuj UUID z bazą danych
            return CompletableFuture.supplyAsync(() -> {
                try {
                    var dbResult = databaseManager.findPlayerByNickname(player.getUsername()).join();

                    // CRITICAL: Fail-secure on database errors
                    if (dbResult.isDatabaseError()) {
                        logger.error(SECURITY_MARKER, "[DATABASE ERROR] UUID verification failed for {}: {}",
                                player.getUsername(), dbResult.getErrorMessage());
                        // Remove from cache to prevent unauthorized access
                        authCache.removeAuthorizedPlayer(player.getUniqueId());
                        authCache.endSession(player.getUniqueId());
                        return false;
                    }

                    var dbPlayer = dbResult.getValue();
                    if (dbPlayer == null) {
                        logger.debug("Brak UUID w bazie dla gracza {}", player.getUsername());
                        return false;
                    }

                    UUID storedUuid = UUID.fromString(dbPlayer.getUuid());
                    UUID playerUuid = player.getUniqueId();

                    boolean matches = playerUuid.equals(storedUuid);
                    if (!matches) {
                        logger.warn(SECURITY_MARKER,
                                "[UUID VERIFICATION FAILED] Player: {} (UUID: {}), DB: {} (UUID: {})",
                                player.getUsername(), playerUuid, dbPlayer.getNickname(), storedUuid);
                        // Remove from cache for security
                        authCache.removeAuthorizedPlayer(player.getUniqueId());
                        authCache.endSession(player.getUniqueId());
                    }

                    return matches;
                } catch (Exception e) {
                    logger.error("Błąd podczas weryfikacji UUID dla gracza: {}", player.getUsername(), e);
                    // Remove from cache for security on any error
                    authCache.removeAuthorizedPlayer(player.getUniqueId());
                    authCache.endSession(player.getUniqueId());
                    return false; // Fail secure
                }
            }).join(); // Blokuj do czasu uzyskania wyniku
        } catch (Exception e) {
            logger.error("Błąd podczas weryfikacji UUID dla gracza: {}", player.getUsername(), e);
            // Remove from cache for security on any error
            authCache.removeAuthorizedPlayer(player.getUniqueId());
            authCache.endSession(player.getUniqueId());
            return false;
        }
    }

    /**
     * Simple data holder for premium resolution results using Java 21 record.
     */
    private record PremiumResolutionResult(boolean premium, UUID premiumUuid) {
    }
}
