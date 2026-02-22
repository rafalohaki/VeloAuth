package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import static com.velocitypowered.api.event.ResultedEvent.ComponentResult;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import javax.inject.Inject;
import java.net.InetAddress;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Listener eventów autoryzacji VeloAuth.
 * Obsługuje połączenia graczy i kieruje ich na odpowiednie serwery.
 * 
 * <p><b>Flow eventów:</b>
 * <ol>
 *   <li>PreLoginEvent → sprawdź premium i force online mode</li>
 *   <li>LoginEvent → sprawdź brute force</li>
 *   <li>PostLoginEvent → kieruj na auth server lub backend</li>
 *   <li>ServerPreConnectEvent → blokuj nieautoryzowane połączenia z backend</li>
 *   <li>ServerConnectedEvent → loguj transfery</li>
 * </ol>
 * 
 * <p><b>Initialization Safety (v2.0.0):</b>
 * Handlers (PreLoginHandler, PostLoginHandler) are now initialized before AuthListener
 * construction and passed via constructor, preventing NullPointerException during event
 * processing. Defense-in-depth null checks are included in event handlers as additional safety.
 * 
 * <p><b>Thread Safety:</b> All event handlers are thread-safe and can process concurrent events.
 * 
 * @since 1.0.0
 * @see PreLoginHandler
 * @see PostLoginHandler
 */
public class AuthListener {

    // Markery SLF4J dla kategoryzowanego logowania
    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final VeloAuth plugin;
    private final AuthCache authCache;
    private final Settings settings;
    private final Logger logger;
    private final Messages messages;
    private final DatabaseManager databaseManager;
    
    // Handler instances for delegating complex logic
    private final PreLoginHandler preLoginHandler;
    private final PostLoginHandler postLoginHandler;
    private final ConnectionManager connectionManager;
    private final UuidVerificationHandler uuidVerificationHandler;

    /**
     * Tworzy nowy AuthListener.
     *
     * @param plugin            VeloAuth plugin instance
     * @param authCache         Cache autoryzacji
     * @param settings          Ustawienia pluginu
     * @param preLoginHandler   Handler for pre-login logic
     * @param postLoginHandler  Handler for post-login logic
     * @param connectionManager Manager połączeń i transferów
     * @param databaseManager   Manager bazy danych
     * @param messages          System wiadomości i18n
     */
    @Inject
    public AuthListener(VeloAuth plugin,
            AuthCache authCache,
            Settings settings,
            PreLoginHandler preLoginHandler,
            PostLoginHandler postLoginHandler,
            ConnectionManager connectionManager,
            DatabaseManager databaseManager,
            Messages messages) {
        this.plugin = plugin;
        this.authCache = authCache;
        this.settings = settings;
        this.logger = plugin.getLogger();
        this.databaseManager = databaseManager;
        this.messages = messages;
        this.connectionManager = java.util.Objects.requireNonNull(connectionManager, 
            "ConnectionManager cannot be null - initialization failed");
        this.preLoginHandler = java.util.Objects.requireNonNull(preLoginHandler, 
            "PreLoginHandler cannot be null - initialization failed");
        this.postLoginHandler = java.util.Objects.requireNonNull(postLoginHandler, 
            "PostLoginHandler cannot be null - initialization failed");
        this.uuidVerificationHandler = new UuidVerificationHandler(databaseManager, authCache, logger);

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.listener.registered"));
        }
    }

    /**
     * Resolves the block reason for unauthorized connections.
     *
     * @param isAuthorized     Whether player is authorized
     * @param hasActiveSession Whether player has active session
     * @return Human-readable reason string (English for logs)
     */
    private static String resolveBlockReason(boolean isAuthorized, boolean hasActiveSession) {
        if (!isAuthorized) {
            return "unauthorized";
        }
        if (!hasActiveSession) {
            return "no active session";
        }
        return "UUID mismatch";
    }



    /**
     * ✅ KLUCZOWY EVENT - PreLoginEvent
     * Tutaj sprawdzamy premium PRZED weryfikacją UUID!
     * Jeśli premium → forceOnlineMode() = Velocity zweryfikuje
     * <p>
     * KRYTYCZNE: Używamy maksymalny priorytet dla bezpieczeństwa.
     * <p>
     * ASYNC: Zwraca EventTask aby NIE blokować wątku Netty IO.
     * Validation checks (fast, sync) wykonują się natychmiast.
     * Premium resolution + DB lookup wykonują się asynchronicznie.
     * Velocity wstrzymuje event processing do zakończenia EventTask.
     */
    @Subscribe(priority = Short.MAX_VALUE)
    public EventTask onPreLogin(PreLoginEvent event) {
        String username = event.getUsername();
        if (logger.isDebugEnabled()) {
            logger.debug("\uD83D\uDD0D PreLogin: {}", username);
        }

        if (!validatePreLoginConditions(event, username)) {
            return null;
        }

        if (!settings.isPremiumCheckEnabled()) {
            logger.debug("Premium check wyłączony w konfiguracji - wymuszam offline mode dla {}", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
            return null;
        }

        return EventTask.resumeWhenComplete(handlePremiumDetectionAsync(event, username));
    }

    private boolean validatePreLoginConditions(PreLoginEvent event, String username) {
        if (!validatePluginInitialized(event, username)) {
            return false;
        }
        if (!validateHandlerInitialized(event, username)) {
            return false;
        }
        if (!validateUsername(event, username)) {
            return false;
        }
        return !checkBruteForceBlocked(event);
    }

    private boolean validatePluginInitialized(PreLoginEvent event, String username) {
        if (!plugin.isInitialized()) {
            logger.warn("🔒 STARTUP BLOCK: Player {} tried to connect before VeloAuth fully initialized - PreLogin block", username);
            String msg = messages != null ? messages.get("system.starting") : "VeloAuth is starting. Please wait.";
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text(msg, NamedTextColor.RED)));
            return false;
        }
        return true;
    }

    private boolean validateHandlerInitialized(PreLoginEvent event, String username) {
        if (preLoginHandler == null) {
            logger.error("CRITICAL: PreLoginHandler is null during event processing for player {}", username);
            String msg = messages != null ? messages.get("system.init_error") : "System initialization error.";
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(Component.text(msg, NamedTextColor.RED)));
            return false;
        }
        return true;
    }

    private boolean validateUsername(PreLoginEvent event, String username) {
        if (!preLoginHandler.isValidUsername(username)) {
            logger.warn(SECURITY_MARKER, "[USERNAME VALIDATION FAILED] {} - invalid format", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(messages.get("validation.username.invalid"), NamedTextColor.RED)));
            return false;
        }
        return true;
    }

    private boolean checkBruteForceBlocked(PreLoginEvent event) {
        InetAddress playerAddress = PlayerAddressUtils.getAddressFromPreLogin(event);
        if (playerAddress != null && preLoginHandler.isBruteForceBlocked(playerAddress)) {
            if (logger.isWarnEnabled()) {
                logger.warn(SECURITY_MARKER, "[BRUTE FORCE BLOCK] IP {} blocked", playerAddress.getHostAddress());
            }
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(messages.get("security.brute_force.blocked"), NamedTextColor.RED)));
            return true;
        }
        return false;
    }

    /**
     * Async premium detection — chains premium resolution and DB lookup without blocking Netty IO.
     * Uses CompletableFuture composition: resolve premium → DB lookup → set event result.
     *
     * @param event    PreLoginEvent to set result on
     * @param username Player username
     * @return CompletableFuture that completes when event result is set
     */
    private CompletableFuture<Void> handlePremiumDetectionAsync(PreLoginEvent event, String username) {
        return preLoginHandler.resolvePremiumStatusAsync(username)
                .thenCompose(result -> {
                    // Hybrid API failure handling: null means all resolvers failed AND no DB cache
                    if (result == null) {
                        logger.error("[SECURITY] Login DENIED for {} — cannot verify premium status (all API resolvers failed)",
                                username);
                        event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                                Component.text(messages.get("security.api_failure.denied"), NamedTextColor.RED)));
                        return CompletableFuture.completedFuture(null);
                    }

                    boolean premium = result.premium();
                    UUID currentPremiumUuid = result.premiumUuid();

                    // Async DB lookup — no .join(), chains via thenAccept
                    return databaseManager.findPlayerByUuidOrNickname(username, currentPremiumUuid)
                            .thenAccept(dbResult -> {
                                RegisteredPlayer existingPlayer = dbResult.getValue();

                                if (existingPlayer != null) {
                                    boolean existingIsPremium = databaseManager.isPlayerPremiumRuntime(existingPlayer);

                                    if (preLoginHandler.isNicknameConflict(existingPlayer, premium,
                                            existingIsPremium, currentPremiumUuid)) {
                                        preLoginHandler.handleNicknameConflict(event, existingPlayer,
                                                premium, currentPremiumUuid);
                                        return;
                                    }
                                }

                                if (premium) {
                                    event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
                                } else {
                                    event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
                                }
                            });
                })
                .exceptionally(throwable -> {
                    logger.error("[ASYNC] Error during premium detection for {}: {}",
                            username, throwable.getMessage());
                    event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
                    return null;
                });
    }



    /**
     * Obsługuje event logowania gracza.
     * Sprawdza brute force i premium status SYNCHRONICZNIE.
     * <p>
     * KRYTYCZNE: Używamy async = false + maksymalny priorytet dla bezpieczeństwa
     * Zapobiega race conditions w procesie autoryzacji
     */
    @Subscribe(priority = Short.MAX_VALUE)
    public void onLogin(LoginEvent event) {
        Player player = event.getPlayer();
        String playerName = player.getUsername();
        UUID playerUuid = player.getUniqueId();
        String playerIp = PlayerAddressUtils.getPlayerIp(player);

        boolean allowed = true;
        try {
            // CRITICAL SECURITY: Block login attempts until plugin is fully initialized
            if (!plugin.isInitialized()) {
                logger.warn(
                        "🔒 STARTUP BLOCK: Player {} tried to login before VeloAuth fully initialized - login block",
                        playerName);
                // Use English fallback - Messages not available yet
                event.setResult(ComponentResult.denied(
                        Component.text(messages.get("system.starting"),
                                NamedTextColor.RED)));
                return;
            }

            logger.debug("LoginEvent dla gracza {} (UUID: {}) z IP {}",
                    playerName, playerUuid, playerIp);

            // 1. Check brute force block
            InetAddress playerAddress = PlayerAddressUtils.getPlayerAddress(player);
            if (playerAddress != null && authCache.isBlocked(playerAddress)) {
                logger.warn(SECURITY_MARKER, "Blocked connection for player {} - too many failed login attempts",
                        playerName);

                event.setResult(ComponentResult.denied(
                        Component.text(messages.get("security.brute_force.blocked"), NamedTextColor.RED)));
                return;
            }

            // Premium check został przeniesiony do PreLoginEvent

        } catch (Exception e) {
            logger.error("Error handling LoginEvent for player: {}", event.getPlayer().getUsername(), e);

            event.setResult(ComponentResult.denied(
                    Component.text(messages.get("connection.error.generic"), NamedTextColor.RED)));
            allowed = false;
        }

        if (allowed) {
            event.setResult(ComponentResult.allowed());
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
            
            // Cleanup retry attempts counter to prevent memory leak
            connectionManager.clearRetryAttempts(player.getUniqueId());

            if (logger.isDebugEnabled()) {
                logger.debug("Gracz {} rozłączył się - sesja pozostaje aktywna", player.getUsername());
            }

        } catch (Exception e) {
            logger.error("Błąd podczas obsługi DisconnectEvent dla gracza: {}", event.getPlayer().getUsername(), e);
        }
    }

    /**
     * Obsługuje event po zalogowaniu gracza.
     * Kieruje gracza na odpowiedni serwer (auth server lub backend).
     */
    @Subscribe(priority = 0) // NORMAL priority
    public void onPostLogin(PostLoginEvent event) {
        Player player = event.getPlayer();
        String playerIp = PlayerAddressUtils.getPlayerIp(player);

        logger.debug("PostLoginEvent dla gracza {} z IP {}",
                player.getUsername(), playerIp);

        // DEFENSE-IN-DEPTH: Verify handlers are initialized
        if (postLoginHandler == null) {
            logger.error("CRITICAL: PostLoginHandler is null during event processing for player {}", 
                player.getUsername());
            String msg = messages != null ? messages.get("system.init_error") : "System initialization error.";
            player.disconnect(Component.text(msg, NamedTextColor.RED));
            return;
        }

        try {
            // 🔥 USE_OFFLINE: Check for conflict resolution messages - delegate to PostLoginHandler
            // ASYNC: Run in separate task to avoid blocking event loop with DB operations
            plugin.getServer().getScheduler().buildTask(plugin, () -> {
                try {
                    if (postLoginHandler.shouldShowConflictMessage(player)) {
                        postLoginHandler.showConflictResolutionMessage(player);
                    }
                } catch (Exception e) {
                    logger.error("Error checking conflict message for {}", player.getUsername(), e);
                }
            }).schedule();

            // Delegate to PostLoginHandler based on player mode
            if (player.isOnlineMode()) {
                postLoginHandler.handlePremiumPlayer(player, playerIp);
                return;
            }

            // Handle offline player - delegate to PostLoginHandler
            postLoginHandler.handleOfflinePlayer(player, playerIp);

        } catch (Exception e) {
            logger.error("Error handling PostLoginEvent for player: {}", event.getPlayer().getUsername(), e);

            event.getPlayer().disconnect(Component.text(
                    messages.get("connection.error.generic"),
                    NamedTextColor.RED));
        }
    }

    /**
     * Obsługuje event przed połączeniem z serwerem.
     * Blokuje nieautoryzowane połączenia z serwerami backend.
     * <p>
     * KRYTYCZNE: Używamy async = false + maksymalny priorytet dla bezpieczeństwa
     * Zapobiega obejściu autoryzacji przez race conditions
     * <p>
     * FLOW dla nowych graczy (pierwszego połączenia):
     * - Velocity próbuje połączyć z pierwszym serwerem z listy try (np. 2b2t)
     * - My przechwytujemy i przekierowujemy na auth server
     * - Po połączeniu z auth server, onServerConnected uruchomi auto-transfer
     */
    @Subscribe(priority = Short.MAX_VALUE)
    public void onServerPreConnect(ServerPreConnectEvent event) {
        try {
            Player player = event.getPlayer();
            // NAPRAWIONE: Używamy getOriginalServer() zamiast getTarget()
            // getOriginalServer() to INPUT field (dokąd gracz chce iść)
            String targetServerName = event.getOriginalServer().getServerInfo().getName();

            logger.debug("ServerPreConnectEvent dla gracza {} -> serwer {}",
                    player.getUsername(), targetServerName);

            if (handleFirstConnection(event, player, targetServerName)) {
                return;
            }

            // ✅ JEŚLI TO AUTH SERVER - SPRAWDŹ DODATKOWO AUTORYZACJĘ
            if (handleAuthServerConnection(event, player, targetServerName)) {
                return;
            }

            // ✅ JEŚLI TO BACKEND - SPRAWDŹ AUTORYZACJĘ + SESJĘ + CACHE
            verifyBackendConnection(event, player, targetServerName);

        } catch (Exception e) {
            logger.error("Błąd w ServerPreConnect", e);
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
        }
    }

    private boolean handleFirstConnection(ServerPreConnectEvent event, Player player, String targetServerName) {
        // ✅ PIERWSZE POŁĄCZENIE: Gracz nie ma jeszcze currentServer
        // Velocity próbuje go wysłać na pierwszy serwer z try (np. 2b2t)
        // My MUSIMY przekierować na auth server dla ViaVersion compatibility
        if (player.getCurrentServer().isEmpty()) {
            String authServerName = settings.getAuthServerName();
            
            // Jeśli cel to już auth server - pozwól
            if (targetServerName.equals(authServerName)) {
                logger.debug("Pierwsze połączenie {} -> auth server - pozwalam", player.getUsername());
                return true;
            }
            
            // Przekieruj na auth server zamiast backend
            Optional<RegisteredServer> authServer = plugin.getServer().getServer(authServerName);
            if (authServer.isPresent()) {
                logger.debug("Pierwsze połączenie {} -> {} - przekierowuję na auth server", 
                        player.getUsername(), targetServerName);
                event.setResult(ServerPreConnectEvent.ServerResult.allowed(authServer.get()));
            } else {
                logger.error("Auth server '{}' not found! Player {} cannot connect.", 
                        authServerName, player.getUsername());
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
            }
            return true;
        }
        return false;
    }

    private boolean handleAuthServerConnection(ServerPreConnectEvent event, Player player, String targetServerName) {
        if (targetServerName.equals(settings.getAuthServerName())) {
            // DODATKOWA WERYFIKACJA - sprawdź czy gracz nie jest już autoryzowany
            // Jeśli jest autoryzowany, nie powinien iść na auth server
            String playerIp = PlayerAddressUtils.getPlayerIp(player);
            boolean isAuthorized = authCache.isPlayerAuthorized(player.getUniqueId(), playerIp);
            if (isAuthorized) {
                // AUTORYZOWANY GRACZ NA AUTH SERVER - przekieruj na backend
                logger.debug("Autoryzowany gracz {} próbuje iść na auth server - przekierowuję na backend",
                        player.getUsername());
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
                // Velocity automatycznie przekieruje na inny serwer
            } else {
                logger.debug("Auth server - pozwól (gracz nie jest autoryzowany)");
            }
            return true;
        }
        return false;
    }

    private void verifyBackendConnection(ServerPreConnectEvent event, Player player, String targetServerName) {
        String playerIp = PlayerAddressUtils.getPlayerIp(player);
        boolean isAuthorized = authCache.isPlayerAuthorized(player.getUniqueId(), playerIp);

        // DODATKOWA WERYFIKACJA - sprawdź aktywną sesję z walidacją IP
        boolean hasActiveSession = authCache.hasActiveSession(player.getUniqueId(), player.getUsername(),
                playerIp);

        // WERYFIKUJ UUID z bazą danych dla maksymalnego bezpieczeństwa - delegate to handler
        boolean uuidMatches = uuidVerificationHandler.verifyPlayerUuid(player);

        if (!isAuthorized || !hasActiveSession || !uuidMatches) {
            handleUnauthorizedConnection(event, player, targetServerName, isAuthorized, hasActiveSession, uuidMatches, playerIp);
        } else {
            // ✅ WSZYSTKIE WERYFIKACJE PRZESZŁY - POZWÓL
            logger.debug("\u2705 Autoryzowany gracz {} idzie na {} (sesja: OK, UUID: OK)",
                    player.getUsername(), targetServerName);
        }
    }

    private void handleUnauthorizedConnection(ServerPreConnectEvent event, Player player, String targetServerName,
                                            boolean isAuthorized, boolean hasActiveSession, boolean uuidMatches, String playerIp) {
        // ❌ NIE AUTORYZOWANY LUB BRAK SESJI LUB UUID MISMATCH
        String reason = resolveBlockReason(isAuthorized, hasActiveSession);

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("player.blocked.unauthorized", player.getUsername(), targetServerName, reason, playerIp));
        }

        event.setResult(ServerPreConnectEvent.ServerResult.denied());

        player.sendMessage(Component.text()
                .content("❌ ")
                .color(NamedTextColor.RED)
                .append(Component.text(messages.get("auth.must_login"))
                        .color(NamedTextColor.RED))
                .build());

        // Jeśli UUID mismatch - usuń z cache dla bezpieczeństwa
        if (!uuidMatches) {
            authCache.removeAuthorizedPlayer(player.getUniqueId());
            authCache.endSession(player.getUniqueId());
        }
    }

    /**
     * Handles server connected event.
     * Logs player transfers between servers and sends appropriate messages.
     * For verified players connecting to auth server, triggers auto-transfer to backend.
     */
    @Subscribe(priority = -200) // LAST priority
    public void onServerConnected(ServerConnectedEvent event) {
        try {
            Player player = event.getPlayer();
            String serverName = event.getServer().getServerInfo().getName();

            logger.debug("ServerConnectedEvent for player {} -> server {}",
                    player.getUsername(), serverName);

            if (!serverName.equals(settings.getAuthServerName())) {
                handleBackendConnection(player, serverName);
            } else {
                handleAuthServerConnection(player);
            }
        } catch (Exception e) {
            logger.error("Error in ServerConnected", e);
        }
    }

    private void handleBackendConnection(Player player, String serverName) {
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, messages.get("player.connected.backend"),
                    player.getUsername(), serverName);
        }
        player.sendMessage(Component.text(messages.get("general.welcome.full"), NamedTextColor.GREEN));
    }

    private void handleAuthServerConnection(Player player) {
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "ServerConnected to auth server: {}", player.getUsername());
        }

        String playerIp = PlayerAddressUtils.getPlayerIp(player);
        if (authCache.isPlayerAuthorized(player.getUniqueId(), playerIp)) {
            triggerAutoTransfer(player);
            return;
        }

        sendAuthInstructions(player);
    }

    private void triggerAutoTransfer(Player player) {
        if (logger.isDebugEnabled()) {
            logger.debug("Gracz {} jest zweryfikowany w cache - uruchamiam auto-transfer na backend",
                    player.getUsername());
        }
        connectionManager.autoTransferFromAuthServerToBackend(player);
    }

    private void sendAuthInstructions(Player player) {
        player.sendMessage(Component.text(messages.get("auth.header"), NamedTextColor.GOLD));

        databaseManager.findPlayerByNickname(player.getUsername())
                .thenAccept(dbResult -> sendAuthPrompt(player, dbResult))
                .exceptionally(e -> {
                    logger.error("Error sending auth prompt for {}", player.getUsername(), e);
                    return null;
                });
    }

    private void sendAuthPrompt(Player player, DbResult<RegisteredPlayer> dbResult) {
        if (dbResult.isDatabaseError()) {
            player.sendMessage(Component.text(messages.get("auth.prompt.generic"), NamedTextColor.YELLOW));
            return;
        }

        RegisteredPlayer registeredPlayer = dbResult.getValue();
        if (registeredPlayer != null) {
            player.sendMessage(Component.text(messages.get("auth.account_exists"), NamedTextColor.GREEN));
        } else {
            player.sendMessage(Component.text(messages.get("auth.first_time"), NamedTextColor.AQUA));
        }
    }


}
