package net.rafalohaki.veloauth.listener;

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
import net.rafalohaki.veloauth.util.AuthenticationErrorHandler;
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
 *   <li>PostLoginEvent → kieruj na PicoLimbo lub backend</li>
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

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.listener.registered"));
        }
    }

    /**
     * Resolves the block reason for unauthorized connections.
     * Replaces nested ternary with clear if/else logic.
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
     * KRYTYCZNE: Używamy async = false + maksymalny priorytet dla bezpieczeństwa
     * Zapobiega race conditions gdzie async handlers mogą wykonać się przed sync
     * handlers
     * <p>
     * UWAGA: PreLoginEvent WYMAGA synchronicznej odpowiedzi.
     * Premium resolution na cache miss blokuje, ale to ograniczenie API Velocity.
     * Dwa warstwy cache (AuthCache + PremiumResolverService) minimalizują impact.
     */
    @Subscribe(priority = Short.MAX_VALUE)
    public void onPreLogin(PreLoginEvent event) {
        String username = event.getUsername();
        if (logger.isDebugEnabled()) {
            logger.debug("\uD83D\uDD0D PreLogin: {}", username);
        }

        // CRITICAL: Block connections until plugin is fully initialized
        if (!plugin.isInitialized()) {
            logger.warn(
                    "🔒 STARTUP BLOCK: Player {} tried to connect before VeloAuth fully initialized - PreLogin block",
                    username);
            // Use fallback if messages not available
            String msg = messages != null ? messages.get("system.starting") : "VeloAuth is starting. Please wait.";
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(msg, NamedTextColor.RED)));
            return;
        }
        
        // DEFENSE-IN-DEPTH: Verify handlers are initialized
        if (preLoginHandler == null) {
            logger.error("CRITICAL: PreLoginHandler is null during event processing for player {}", username);
            String msg = messages != null ? messages.get("system.init_error") : "System initialization error.";
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(msg, NamedTextColor.RED)));
            return;
        }

        // WALIDACJA USERNAME - delegate to PreLoginHandler
        if (!preLoginHandler.isValidUsername(username)) {
            logger.warn(SECURITY_MARKER, "[USERNAME VALIDATION FAILED] {} - invalid format", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(messages.get("validation.username.invalid"), NamedTextColor.RED)));
            return;
        }

        // Check brute force at IP level BEFORE any processing
        InetAddress playerAddress = PlayerAddressUtils.getAddressFromPreLogin(event);
        if (playerAddress != null && preLoginHandler.isBruteForceBlocked(playerAddress)) {
            if (logger.isWarnEnabled()) {
                logger.warn(SECURITY_MARKER, "[BRUTE FORCE BLOCK] IP {} blocked", playerAddress.getHostAddress());
            }
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(messages.get("security.brute_force.blocked"), NamedTextColor.RED)));
            return;
        }

        if (!settings.isPremiumCheckEnabled()) {
            logger.debug("Premium check wyłączony w konfiguracji - wymuszam offline mode dla {}", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
            return;
        }

        // Delegate premium resolution to PreLoginHandler
        PreLoginHandler.PremiumResolutionResult result = preLoginHandler.resolvePremiumStatus(username);
        boolean premium = result.premium();

        // 🔥 USE_OFFLINE: Check for nickname conflicts with runtime detection
        RegisteredPlayer existingPlayer = databaseManager.findPlayerWithRuntimeDetection(username).join().getValue();

        if (existingPlayer != null) {
            boolean existingIsPremium = databaseManager.isPlayerPremiumRuntime(existingPlayer);

            if (preLoginHandler.isNicknameConflict(existingPlayer, premium, existingIsPremium)) {
                preLoginHandler.handleNicknameConflict(event, existingPlayer, premium);
                return;
            }
        }

        if (premium) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
        } else {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
        }
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
     * Kieruje gracza na odpowiedni serwer (PicoLimbo lub backend).
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
     * - My przechwytujemy i przekierowujemy na PicoLimbo
     * - Po połączeniu z PicoLimbo, onServerConnected uruchomi auto-transfer
     */
    @Subscribe(priority = Short.MAX_VALUE)
    @SuppressWarnings("java:S3776") // Complex security checks - cyclomatic complexity 9
    public void onServerPreConnect(ServerPreConnectEvent event) {
        try {
            Player player = event.getPlayer();
            // NAPRAWIONE: Używamy getOriginalServer() zamiast getTarget()
            // getOriginalServer() to INPUT field (dokąd gracz chce iść)
            String targetServerName = event.getOriginalServer().getServerInfo().getName();
            String playerIp = PlayerAddressUtils.getPlayerIp(player);

            logger.debug("ServerPreConnectEvent dla gracza {} -> serwer {}",
                    player.getUsername(), targetServerName);

            // ✅ PIERWSZE POŁĄCZENIE: Gracz nie ma jeszcze currentServer
            // Velocity próbuje go wysłać na pierwszy serwer z try (np. 2b2t)
            // My MUSIMY przekierować na PicoLimbo dla ViaVersion compatibility
            if (player.getCurrentServer().isEmpty()) {
                String picoLimboName = settings.getPicoLimboServerName();
                
                // Jeśli cel to już PicoLimbo - pozwól
                if (targetServerName.equals(picoLimboName)) {
                    logger.debug("Pierwsze połączenie {} -> PicoLimbo - pozwalam", player.getUsername());
                    return;
                }
                
                // Przekieruj na PicoLimbo zamiast backend
                Optional<RegisteredServer> picoLimbo = plugin.getServer().getServer(picoLimboName);
                if (picoLimbo.isPresent()) {
                    logger.debug("Pierwsze połączenie {} -> {} - przekierowuję na PicoLimbo", 
                            player.getUsername(), targetServerName);
                    event.setResult(ServerPreConnectEvent.ServerResult.allowed(picoLimbo.get()));
                    return;
                } else {
                    logger.error("PicoLimbo server '{}' nie znaleziony! Gracz {} nie może się połączyć.", 
                            picoLimboName, player.getUsername());
                    event.setResult(ServerPreConnectEvent.ServerResult.denied());
                    return;
                }
            }

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
            boolean hasActiveSession = authCache.hasActiveSession(player.getUniqueId(), player.getUsername(),
                    PlayerAddressUtils.getPlayerIp(player));

            // WERYFIKUJ UUID z bazą danych dla maksymalnego bezpieczeństwa
            boolean uuidMatches = verifyPlayerUuid(player);

            if (!isAuthorized || !hasActiveSession || !uuidMatches) {
                // ❌ NIE AUTORYZOWANY LUB BRAK SESJI LUB UUID MISMATCH
                String reason = resolveBlockReason(isAuthorized, hasActiveSession);

                if (logger.isDebugEnabled()) {
                    logger.debug(messages.get("player.blocked.unauthorized"),
                            player.getUsername(), targetServerName, reason, playerIp);
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
     * Handles server connected event.
     * Logs player transfers between servers and sends appropriate messages.
     * For verified players connecting to PicoLimbo, triggers auto-transfer to backend.
     */
    @Subscribe(priority = -200) // LAST priority
    public void onServerConnected(ServerConnectedEvent event) {
        try {
            Player player = event.getPlayer();
            String serverName = event.getServer().getServerInfo().getName();

            logger.debug("ServerConnectedEvent for player {} -> server {}",
                    player.getUsername(), serverName);

            // Log transfer to backend (debug level to reduce spam)
            if (!serverName.equals(settings.getPicoLimboServerName())) {
                if (logger.isDebugEnabled()) {
                    logger.debug(AUTH_MARKER, messages.get("player.connected.backend"),
                            player.getUsername(), serverName);
                }

                // Send welcome message
                player.sendMessage(Component.text(
                        messages.get("general.welcome.full"),
                        NamedTextColor.GREEN));
            } else {
                // Player connected to PicoLimbo
                if (logger.isDebugEnabled()) {
                    logger.debug(AUTH_MARKER, "ServerConnected to PicoLimbo: {}", player.getUsername());
                }
                
                // ✅ AUTO-TRANSFER: Jeśli gracz jest zweryfikowany w cache, automatycznie przenieś na backend
                String playerIp = PlayerAddressUtils.getPlayerIp(player);
                if (authCache.isPlayerAuthorized(player.getUniqueId(), playerIp)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Gracz {} jest zweryfikowany w cache - uruchamiam auto-transfer na backend", 
                                player.getUsername());
                    }
                    connectionManager.autoTransferFromPicoLimboToBackend(player);
                    return; // Nie pokazuj instrukcji logowania - gracz jest już zweryfikowany
                }

                // Gracz nie jest zweryfikowany - pokaż instrukcje logowania
                player.sendMessage(Component.text(
                        messages.get("auth.header"),
                        NamedTextColor.GOLD));

                // Check registration status async to send appropriate prompt
                databaseManager.findPlayerByNickname(player.getUsername())
                    .thenAccept(dbResult -> {
                        if (dbResult.isDatabaseError()) {
                             player.sendMessage(Component.text(
                                messages.get("auth.prompt.generic"),
                                NamedTextColor.YELLOW));
                             return;
                        }
                        
                        RegisteredPlayer registeredPlayer = dbResult.getValue();
                        if (registeredPlayer != null) {
                            // Account exists -> Login
                            player.sendMessage(Component.text(
                                messages.get("auth.account_exists"),
                                NamedTextColor.GREEN));
                        } else {
                            // No account -> Register
                            player.sendMessage(Component.text(
                                messages.get("auth.first_time"),
                                NamedTextColor.AQUA));
                        }
                    })
                    .exceptionally(e -> {
                        logger.error("Error sending auth prompt for {}", player.getUsername(), e);
                        return null;
                    });
            }
        } catch (Exception e) {
            logger.error("Error in ServerConnected", e);
        }
    }


    /**
     * Weryfikuje UUID gracza z bazą danych.
     * Dla graczy online mode (premium) pomija weryfikację,
     * ponieważ nie muszą być zarejestrowani w bazie danych.
     * <p>
     * <b>UUID Verification Process:</b>
     * <ol>
     *   <li>Premium players (online mode) - verification skipped</li>
     *   <li>Offline players - verify against database UUID and PREMIUMUUID</li>
     *   <li>CONFLICT_MODE players - allow UUID mismatch for conflict resolution</li>
     * </ol>
     * <p>
     * <b>Conflict Resolution Strategy:</b>
     * When a player has CONFLICT_MODE enabled, UUID mismatches are allowed.
     * This enables the USE_OFFLINE strategy where premium players who lose
     * their account can continue playing with offline authentication.
     * <p>
     * Sprawdza zarówno UUID jak i PREMIUMUUID fields zgodnie z wymaganiem 8.4.
     * Obsługuje CONFLICT_MODE zgodnie z wymaganiem 8.5.
     * 
     * @param player Player to verify
     * @return true if UUID verification passes, false otherwise
     */
    private boolean verifyPlayerUuid(Player player) {
        try {
            if (player.isOnlineMode()) {
                return handlePremiumPlayer(player);
            }

            return verifyCrackedPlayerUuid(player);
        } catch (Exception e) {
            return handleVerificationError(player, e);
        }
    }

    private boolean handlePremiumPlayer(Player player) {
        if (logger.isDebugEnabled()) {
            logger.debug("Premium gracz {} - pomijam weryfikację UUID z bazą", player.getUsername());
        }
        return true;
    }

    private boolean verifyCrackedPlayerUuid(Player player) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                var dbResult = databaseManager.findPlayerByNickname(player.getUsername()).join();

                if (dbResult.isDatabaseError()) {
                    return handleDatabaseVerificationError(player, dbResult);
                }

                return performUuidVerification(player, dbResult.getValue());
            } catch (Exception e) {
                return handleAsyncVerificationError(player, e);
            }
        }).join();
    }

    private boolean handleDatabaseVerificationError(Player player, DbResult<RegisteredPlayer> dbResult) {
        logger.error(SECURITY_MARKER, "[DATABASE ERROR] UUID verification failed for {}: {}",
                player.getUsername(), dbResult.getErrorMessage());
        AuthenticationErrorHandler.handleVerificationFailure(player, player.getUniqueId(), authCache, logger);
        return false;
    }

    /**
     * Performs UUID verification checking both UUID and PREMIUMUUID fields.
     * Handles CONFLICT_MODE for nickname conflict resolution.
     * <p>
     * <b>Verification Logic:</b>
     * <ol>
     *   <li>If CONFLICT_MODE is enabled - allow access (conflict resolution in progress)</li>
     *   <li>Check if player UUID matches database UUID field</li>
     *   <li>Check if player UUID matches database PREMIUMUUID field</li>
     *   <li>If no match - log mismatch and invalidate cache</li>
     * </ol>
     * 
     * Requirements: 8.1, 8.4, 8.5
     */
    private boolean performUuidVerification(Player player, RegisteredPlayer dbPlayer) {
        if (dbPlayer == null) {
            if (logger.isDebugEnabled()) {
                logger.debug("Brak UUID w bazie dla gracza {}", player.getUsername());
            }
            return false;
        }

        UUID playerUuid = player.getUniqueId();
        
        // Check if player is in CONFLICT_MODE (Requirement 8.5)
        if (dbPlayer.getConflictMode()) {
            logger.info(SECURITY_MARKER, 
                "[CONFLICT_MODE ACTIVE] Player {} (UUID: {}) is in conflict resolution mode - " +
                "allowing access despite potential UUID mismatch. Conflict timestamp: {}",
                player.getUsername(), 
                playerUuid,
                dbPlayer.getConflictTimestamp() > 0 ? 
                    java.time.Instant.ofEpochMilli(dbPlayer.getConflictTimestamp()) : "not set");
            return true;
        }

        // Check both UUID and PREMIUMUUID fields (Requirement 8.4)
        UUID storedUuid = parseUuid(dbPlayer.getUuid());
        UUID storedPremiumUuid = parseUuid(dbPlayer.getPremiumUuid());

        // Match against primary UUID
        if (storedUuid != null && playerUuid.equals(storedUuid)) {
            return true;
        }

        // Match against PREMIUMUUID (for premium players who switched to offline)
        if (storedPremiumUuid != null && playerUuid.equals(storedPremiumUuid)) {
            if (logger.isDebugEnabled()) {
                logger.debug("UUID matched against PREMIUMUUID for player {}", player.getUsername());
            }
            return true;
        }

        // UUID mismatch detected
        handleUuidMismatch(player, playerUuid, storedUuid, storedPremiumUuid, dbPlayer);
        return false;
    }

    /**
     * Safely parses UUID string, returning null if invalid.
     */
    private UUID parseUuid(String uuidString) {
        if (uuidString == null || uuidString.isEmpty()) {
            return null;
        }
        try {
            return UUID.fromString(uuidString);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Handles UUID mismatch with enhanced logging and cache invalidation.
     * 
     * Requirements: 8.2, 8.3
     */
    private void handleUuidMismatch(Player player, UUID playerUuid, UUID storedUuid, 
                                   UUID storedPremiumUuid, RegisteredPlayer dbPlayer) {
        AuthenticationErrorHandler.handleUuidMismatch(
            player, playerUuid, storedUuid, storedPremiumUuid, dbPlayer, authCache, logger);
    }

    private boolean handleAsyncVerificationError(Player player, Exception e) {
        return AuthenticationErrorHandler.handleVerificationError(player, e, authCache, logger);
    }

    private boolean handleVerificationError(Player player, Exception e) {
        return AuthenticationErrorHandler.handleVerificationError(player, e, authCache, logger);
    }


}
