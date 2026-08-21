package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.GameProfileRequestEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.InboundConnection;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import static com.velocitypowered.api.event.ResultedEvent.ComponentResult;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.auth.ConflictModeService;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry.Operation;
import net.rafalohaki.veloauth.util.FloodgateDetector;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.inject.Inject;
import java.net.InetAddress;
import java.net.SocketAddress;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;

/**
 * Listener eventów autoryzacji VeloAuth.
 * Obsługuje połączenia graczy i kieruje ich na odpowiednie serwery.
 * 
 * <p><b>Flow eventów:</b>
 * <ol>
 *   <li>PreLoginEvent → sprawdź premium i force online mode</li>
 *   <li>LoginEvent → sprawdź brute force</li>
 *   <li>PostLoginEvent → ustanów autoryzację premium lub stan offline</li>
 *   <li>ServerPreConnectEvent → zastosuj routing auth/backend i blokuj nieautoryzowany backend</li>
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
    private static final Marker PREMIUM_MARKER = MarkerFactory.getMarker("PREMIUM");
    private static final String MSG_CONNECTION_ERROR_DATABASE = "connection.error.database";

    // Guard against duplicate concurrent PreLogin events from the same (username|ip) pair.
    // Each entry retains the owning connection so a reconnect can replace an abandoned attempt.
    // The TTL remains a bounded fallback for connections that never finish cleanly.
    private final Cache<String, PendingLoginAttempt> pendingLogins = Caffeine.newBuilder()
            .maximumSize(10_000)
            .expireAfterWrite(Duration.ofSeconds(30))
            .build();

    /** Fail-secure hand-off from GameProfileRequestEvent to LoginEvent. */
    private final Cache<String, Boolean> rejectedProfileBindings = Caffeine.newBuilder()
            .maximumSize(10_000)
            .expireAfterWrite(Duration.ofSeconds(30))
            .build();

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
    private final ConnectionLifecycleRegistry connectionLifecycleRegistry;
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
        this.connectionLifecycleRegistry = plugin.getConnectionLifecycleRegistry();
        this.preLoginHandler = java.util.Objects.requireNonNull(preLoginHandler, 
            "PreLoginHandler cannot be null - initialization failed");
        this.postLoginHandler = java.util.Objects.requireNonNull(postLoginHandler, 
            "PostLoginHandler cannot be null - initialization failed");
        this.uuidVerificationHandler = new UuidVerificationHandler(databaseManager, authCache, logger,
                plugin::getAuditLogService,
                new ConflictModeService(databaseManager, settings.getConflictModeTtlHours()));

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

    private static boolean isFloodgatePlayer(
            Player player,
            Settings.FloodgateSettings floodgateSettings) {
        return floodgateSettings.isEnabled()
                && FloodgateDetector.isBedrockPlayer(player.getUniqueId());
    }

    private static boolean shouldBypassAuthServer(
            Player player,
            Settings.FloodgateSettings floodgateSettings) {
        return floodgateSettings.isBypassAuthServer()
                && isFloodgatePlayer(player, floodgateSettings);
    }

    private static boolean isFloodgatePreLogin(
            String username,
            Settings.FloodgateSettings floodgateSettings) {
        return floodgateSettings.isEnabled()
                && FloodgateDetector.isBedrockUsername(username);
    }

    /**
     * Re-authorizes a premium player whose cache entry expired.
     * Premium players are cryptographically verified by Velocity (Mojang handshake),
     * so {@code player.isOnlineMode()} is trustworthy and we can safely re-create the cache entry.
     */
    private void refreshPremiumAuthorization(Player player, String playerIp) {
        net.rafalohaki.veloauth.listener.PremiumAuthorizer.authorize(player, playerIp, authCache);
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "Refreshed premium authorization for {} (expired cache re-created)",
                    player.getUsername());
        }
    }

    private boolean refreshPremiumAuthorizationIfCurrent(
            Player player, String playerIp, Operation operation) {
        return connectionLifecycleRegistry.runIfCurrent(operation,
                () -> refreshPremiumAuthorization(player, playerIp));
    }

    private boolean prepareAuthServerConnectionIfCurrent(
            ServerPreConnectEvent event, Player player, RegisteredServer targetServer,
            Operation operation) {
        AtomicBoolean prepared = new AtomicBoolean();
        boolean executed = connectionLifecycleRegistry.runIfCurrent(operation, () -> {
            if (connectionManager.prepareAuthServerConnection(player)) {
                prepared.set(true);
                event.setResult(ServerPreConnectEvent.ServerResult.allowed(targetServer));
            }
        });
        if (!executed || !prepared.get()) {
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
        }
        return executed && prepared.get();
    }

    private boolean allowServerIfCurrent(
            ServerPreConnectEvent event, RegisteredServer targetServer, Operation operation) {
        boolean allowed = connectionLifecycleRegistry.runIfCurrent(operation,
                () -> event.setResult(ServerPreConnectEvent.ServerResult.allowed(targetServer)));
        if (!allowed) {
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
        }
        return allowed;
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
        Settings.OperationSettings operationSettings = settings.captureOperationSettings();
        Settings.PremiumSettings premiumSettings = operationSettings.premium();
        Settings.FloodgateSettings floodgateSettings = operationSettings.floodgate();
        String pendingLoginKey = createPendingLoginKey(event, username);
        PendingLoginAttempt pendingLoginAttempt = acquirePendingLogin(pendingLoginKey, event.getConnection());
        if (logger.isDebugEnabled()) {
            logger.debug("PreLogin: {}", username);
        }

        if (pendingLoginAttempt == null) {
            logger.warn(SECURITY_MARKER, "[DUPLICATE PRELOGIN] {} from {} - already connecting, denying",
                    username, pendingLoginKey);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    messages.component("connection.already_connecting", NamedTextColor.RED)));
            return null;
        }

        if (!validatePreLoginConditions(event, username)) {
            releasePendingLogin(pendingLoginKey, pendingLoginAttempt);
            return null;
        }

        if (floodgateSettings.isEnabled()) {
            return EventTask.resumeWhenComplete(handleFloodgateAwarePreLoginAsync(
                    event, username, premiumSettings, floodgateSettings)
                    .whenComplete((result, throwable) ->
                            releasePendingLogin(pendingLoginKey, pendingLoginAttempt)));
        }

        if (!premiumSettings.isCheckEnabled()) {
            logger.debug("Premium check disabled in config - forcing offline mode for {}", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
            releasePendingLogin(pendingLoginKey, pendingLoginAttempt);
            return null;
        }

        return EventTask.resumeWhenComplete(handlePremiumDetectionAsync(event, username, premiumSettings)
                .whenComplete((result, throwable) -> releasePendingLogin(pendingLoginKey, pendingLoginAttempt)));
    }

    private CompletableFuture<Void> handleFloodgateAwarePreLoginAsync(
            PreLoginEvent event,
            String username,
            Settings.PremiumSettings premiumSettings,
            Settings.FloodgateSettings floodgateSettings) {
        return isFloodgatePreLoginAsync(username, floodgateSettings)
                .thenCompose(floodgatePlayer -> {
                    // Floodgate has already authenticated the Bedrock connection and registered
                    // it during the encrypted handshake. This scan can be O(n), so it stays off
                    // the Velocity event thread. Backend bypass still requires UUID confirmation.
                    if (Boolean.TRUE.equals(floodgatePlayer)) {
                        logger.info(AUTH_MARKER,
                                "Floodgate player {} detected during pre-login - skipping Mojang resolution",
                                username);
                        event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
                        return CompletableFuture.completedFuture(null);
                    }
                    if (!premiumSettings.isCheckEnabled()) {
                        logger.debug("Premium check disabled in config - forcing offline mode for {}", username);
                        event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
                        return CompletableFuture.completedFuture(null);
                    }
                    return handlePremiumDetectionAsync(event, username, premiumSettings);
                });
    }

    private CompletableFuture<Boolean> isFloodgatePreLoginAsync(
            String username,
            Settings.FloodgateSettings floodgateSettings) {
        if (!floodgateSettings.isEnabled()) {
            return CompletableFuture.completedFuture(false);
        }
        return CompletableFuture.supplyAsync(
                () -> isFloodgatePreLogin(username, floodgateSettings),
                VirtualThreadExecutorProvider.getVirtualExecutor());
    }

    private PendingLoginAttempt acquirePendingLogin(String key, InboundConnection connection) {
        PendingLoginAttempt candidate = new PendingLoginAttempt(connection);
        AtomicBoolean acquired = new AtomicBoolean();
        pendingLogins.asMap().compute(key, (ignored, existing) -> {
            if (existing == null || !existing.connection().isActive()) {
                acquired.set(true);
                return candidate;
            }
            return existing;
        });
        return acquired.get() ? candidate : null;
    }

    private void releasePendingLogin(String key, PendingLoginAttempt attempt) {
        pendingLogins.asMap().remove(key, attempt);
    }

    private String createPendingLoginKey(PreLoginEvent event, String username) {
        String normalizedUsername = username.toLowerCase(Locale.ROOT);
        InetAddress address = PlayerAddressUtils.getAddressFromPreLogin(event);
        if (address != null) {
            return normalizedUsername + '|' + address.getHostAddress();
        }

        SocketAddress remoteAddress = event.getConnection() != null ? event.getConnection().getRemoteAddress() : null;
        if (remoteAddress != null) {
            return normalizedUsername + '|' + remoteAddress;
        }

        return normalizedUsername + "|connection:" + System.identityHashCode(event.getConnection());
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
            logger.warn("STARTUP BLOCK: Player {} tried to connect before VeloAuth fully initialized - PreLogin block", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(localizedOrFallback(
                    "system.starting", "VeloAuth is starting. Please wait.", NamedTextColor.RED)));
            return false;
        }
        return true;
    }

    private boolean validateHandlerInitialized(PreLoginEvent event, String username) {
        if (preLoginHandler == null) {
            logger.error("CRITICAL: PreLoginHandler is null during event processing for player {}", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(localizedOrFallback(
                    "system.init_error", "System initialization error.", NamedTextColor.RED)));
            return false;
        }
        return true;
    }

    private boolean validateUsername(PreLoginEvent event, String username) {
        if (!preLoginHandler.isValidUsername(username)) {
            logger.warn(SECURITY_MARKER, "[USERNAME VALIDATION FAILED] {} - invalid format", username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    messages.component("validation.username.invalid", NamedTextColor.RED)));
            return false;
        }
        return true;
    }

    private boolean checkBruteForceBlocked(PreLoginEvent event) {
        InetAddress playerAddress = PlayerAddressUtils.getAddressFromPreLogin(event);
        if (preLoginHandler.isBruteForceBlocked(playerAddress, event.getUsername())) {
            if (logger.isWarnEnabled()) {
                String playerIp = playerAddress != null ? playerAddress.getHostAddress() : "unknown";
                logger.warn(SECURITY_MARKER, "[BRUTE FORCE BLOCK] IP {} blocked", playerIp);
            }
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    messages.component("security.brute_force.blocked", NamedTextColor.RED)));
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
    private CompletableFuture<Void> handlePremiumDetectionAsync(
            PreLoginEvent event,
            String username,
            Settings.PremiumSettings premiumSettings) {
        InetAddress sourceAddress = PlayerAddressUtils.getAddressFromPreLogin(event);
        return preLoginHandler.resolvePremiumStatusAsync(username, sourceAddress)
                .thenCompose(result -> handlePremiumResolutionResult(
                        event, username, result, premiumSettings))
                .exceptionally(throwable -> {
                    logger.error(SECURITY_MARKER,
                            "[ASYNC] Error during premium detection for {} - denying login for safety",
                            username, throwable);
                    event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                            messages.component(MSG_CONNECTION_ERROR_DATABASE, NamedTextColor.RED)));
                    return null;
                });
    }

    private CompletableFuture<Void> handlePremiumResolutionResult(
            PreLoginEvent event,
            String username,
            PreLoginHandler.PremiumResolutionResult result,
            Settings.PremiumSettings premiumSettings) {
        if (result == null) {
            denyLoginOnApiFailure(event, username);
            return CompletableFuture.completedFuture(null);
        }

        return databaseManager.findPlayerByNicknameOrPremiumUuidReadOnly(username, result.premiumUuid())
                .thenAccept(dbResult -> applyPremiumDetectionResult(
                        event, username, result, dbResult, premiumSettings));
    }

    private void denyLoginOnApiFailure(PreLoginEvent event, String username) {
        logger.error("[SECURITY] Login DENIED for {} - cannot verify premium status (all API resolvers failed)",
                username);
        event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                messages.component("security.api_failure.denied", NamedTextColor.RED)));
    }

    private void applyPremiumDetectionResult(
            PreLoginEvent event,
            String username,
            PreLoginHandler.PremiumResolutionResult result,
            DbResult<RegisteredPlayer> dbResult,
            Settings.PremiumSettings premiumSettings) {
        if (dbResult == null || dbResult.isDatabaseError()) {
            handlePremiumLookupDatabaseError(event, username, result.premium(), dbResult);
            return;
        }

        if (hasNicknameConflict(event, result, dbResult.getValue())) {
            return;
        }

        boolean playerExistsInDb = dbResult.getValue() != null;
        setPremiumLoginMode(event, username, result.premium(), playerExistsInDb, premiumSettings);
    }

    private void handlePremiumLookupDatabaseError(
            PreLoginEvent event, String username, boolean isPremium, DbResult<RegisteredPlayer> dbResult) {
        logger.error("[DATABASE] Premium detection DB lookup failed for {}: {}",
                username, dbResult != null ? dbResult.getErrorMessage() : "null result");
        if (isPremium) {
            logger.warn("[SECURITY] Denying premium player {} - DB error would corrupt UUID in offline mode",
                    username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    messages.component(MSG_CONNECTION_ERROR_DATABASE, NamedTextColor.RED)));
        } else {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
        }
    }

    private boolean hasNicknameConflict(
            PreLoginEvent event,
            PreLoginHandler.PremiumResolutionResult result,
            RegisteredPlayer existingPlayer) {
        if (existingPlayer == null) {
            return false;
        }

        boolean existingIsPremium = databaseManager.isPlayerPremiumRuntime(existingPlayer);
        if (!preLoginHandler.isNicknameConflict(existingPlayer, result.premium(), existingIsPremium,
                result.premiumUuid())) {
            return false;
        }

        preLoginHandler.handleNicknameConflict(event, existingPlayer, result.premium(), result.premiumUuid());
        return true;
    }

    private void setPremiumLoginMode(
            PreLoginEvent event,
            String username,
            boolean premium,
            boolean playerExistsInDb,
            Settings.PremiumSettings premiumSettings) {
        if (!premium) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
            return;
        }

        // Premium nickname with no record in VeloAuth DB yet. Operators that explicitly accept
        // cracked players on premium nicks opt in via premium.allow-cracked-on-premium-nicks.
        // When that flag is set we skip Mojang session-server auth so a cracked client can
        // register the nickname first. Premium owners returning to a registered nick still
        // take the forceOnlineMode path below (their DB row matches their Mojang UUID).
        if (!playerExistsInDb && premiumSettings.isAllowCrackedOnPremiumNicks()) {
            logger.warn(SECURITY_MARKER,
                    "[PREMIUM BYPASS] Forcing offline mode for premium nick {} (no DB record, allow-cracked-on-premium-nicks=true)",
                    username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
            return;
        }

        event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
    }

    /**
     * Applies the UUID compatibility contract after Mojang has verified the profile.
     * Resolver results from PreLogin are deliberately not trusted for persistence or
     * nickname migration; this event carries the session-server authenticated identity.
     */
    @Subscribe(priority = Short.MAX_VALUE)
    public EventTask onGameProfileRequest(GameProfileRequestEvent event) {
        Settings.OperationSettings operationSettings = settings.captureOperationSettings();
        Settings.PremiumSettings premiumSettings = operationSettings.premium();
        Settings.FloodgateSettings floodgateSettings = operationSettings.floodgate();
        if (!premiumSettings.isCheckEnabled() || !event.isOnlineMode()) {
            return null;
        }

        UUID verifiedPremiumUuid = event.getOriginalProfile().getId();
        if (verifiedPremiumUuid == null || isBedrockProfile(verifiedPremiumUuid, floodgateSettings)) {
            return null;
        }

        String bindingKey = profileBindingKey(event.getUsername(), event.getConnection());
        CompletableFuture<Void> reconciliation = isFloodgatePreLoginAsync(
                event.getUsername(), floodgateSettings)
                .thenCompose(floodgatePlayer -> Boolean.TRUE.equals(floodgatePlayer)
                        ? CompletableFuture.completedFuture(null)
                        : reconcileVerifiedProfile(event, verifiedPremiumUuid, bindingKey));
        return EventTask.resumeWhenComplete(reconciliation);
    }

    private CompletableFuture<Void> reconcileVerifiedProfile(
            GameProfileRequestEvent event, UUID verifiedPremiumUuid, String bindingKey) {
        return databaseManager.reconcileVerifiedPremiumProfile(event.getUsername(), verifiedPremiumUuid)
                .handle((dbResult, throwable) -> {
                    if (throwable != null || dbResult == null || dbResult.isDatabaseError()
                            || dbResult.getValue() == null) {
                        rejectedProfileBindings.put(bindingKey, Boolean.TRUE);
                        logger.error(PREMIUM_MARKER,
                                "Unable to bind Mojang-verified profile for {} - login will be denied",
                                event.getUsername(), throwable);
                        return null;
                    }

                    DatabaseManager.PremiumProfileBinding binding = dbResult.getValue();
                    authCache.addPremiumPlayer(event.getUsername(), binding.verifiedPremiumUuid());
                    event.setGameProfile(event.getOriginalProfile().withId(binding.backendUuid()));
                    rejectedProfileBindings.invalidate(bindingKey);
                    return null;
                });
    }

    private static boolean isBedrockProfile(
            UUID profileUuid,
            Settings.FloodgateSettings floodgateSettings) {
        return floodgateSettings.isEnabled()
                && FloodgateDetector.isBedrockPlayer(profileUuid);
    }

    private String profileBindingKey(String username, InboundConnection connection) {
        SocketAddress remoteAddress = connection != null ? connection.getRemoteAddress() : null;
        return username.toLowerCase(Locale.ROOT) + '|' + remoteAddress;
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

        // CRITICAL SECURITY: Block login attempts until plugin is fully initialized
        if (!plugin.isInitialized()) {
            logger.warn(
                "STARTUP BLOCK: Player {} tried to login before VeloAuth fully initialized - login block",
                playerName);
            // Use English fallback - Messages may not be available yet
            event.setResult(ComponentResult.denied(localizedOrFallback(
                    "system.starting", "VeloAuth is starting. Please wait.", NamedTextColor.RED)));
            return;
        }

        String profileBindingKey = profileBindingKey(playerName, player);
        if (rejectedProfileBindings.getIfPresent(profileBindingKey) != null) {
            rejectedProfileBindings.invalidate(profileBindingKey);
            logger.warn(SECURITY_MARKER,
                    "Denying {} because the Mojang profile could not be safely bound to AUTH.UUID",
                    playerName);
            event.setResult(ComponentResult.denied(
                    messages.component(MSG_CONNECTION_ERROR_DATABASE, NamedTextColor.RED)));
            return;
        }

        logger.debug("LoginEvent for player {} (UUID: {}) from IP {}",
            playerName, playerUuid, playerIp);

        // 1. Check brute force block
        InetAddress playerAddress = PlayerAddressUtils.getPlayerAddress(player);
        if (preLoginHandler.isBruteForceBlocked(playerAddress, playerName)) {
            String playerAddressText = playerAddress != null ? playerAddress.getHostAddress() : "unknown";
            logger.warn(SECURITY_MARKER,
                    "Blocked connection for player {} from {} - too many failed login attempts",
                    playerName, playerAddressText);

            event.setResult(ComponentResult.denied(
                messages.component("security.brute_force.blocked", NamedTextColor.RED)));
            return;
        }

        // Premium check został przeniesiony do PreLoginEvent
        event.setResult(ComponentResult.allowed());
    }

    /**
     * Invalidates every connection-bound authentication state on disconnect. Offline UUIDs and
     * public IP addresses are not unique client credentials (multiple users can share one NAT),
     * so retaining authorization would let a new connection inherit a previous player's login.
     */
    @Subscribe(priority = 0) // NORMAL priority
    public void onDisconnect(DisconnectEvent event) {
        Player player = event.getPlayer();
        UUID playerUuid = player.getUniqueId();

        rejectedProfileBindings.invalidate(profileBindingKey(player.getUsername(), player));

        boolean allowUnownedCleanup = allowsUnownedDisconnectCleanup(event, player);
        if (!connectionLifecycleRegistry.retire(
                player, allowUnownedCleanup,
                () -> plugin.clearConnectionBoundState(player, authCache, connectionManager))) {
            logger.debug(SECURITY_MARKER,
                    "Ignoring {} disconnect cleanup for non-owning connection {} ({})",
                    event.getLoginStatus(), player.getUsername(), playerUuid);
            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug(SECURITY_MARKER,
                    "Player {} disconnected - authorization and pending authentication state invalidated",
                    player.getUsername());
        }
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals") // Player identity distinguishes same-UUID connections.
    private boolean allowsUnownedDisconnectCleanup(DisconnectEvent event, Player player) {
        DisconnectEvent.LoginStatus status = event.getLoginStatus();
        if (status != DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN
                && status != DisconnectEvent.LoginStatus.PRE_SERVER_JOIN) {
            return false;
        }

        return plugin.getServer().getPlayer(player.getUniqueId())
                .map(active -> active == player)
                .orElse(true);
    }

    /**
     * Obsługuje event po zalogowaniu gracza.
     * Kieruje gracza na odpowiedni serwer (auth server lub backend).
     */
    @Subscribe(priority = 0) // NORMAL priority
    public void onPostLogin(PostLoginEvent event) {
        Player player = event.getPlayer();
        UUID playerId = player.getUniqueId();
        String playerName = player.getUsername();
        Operation operation;
        try {
            operation = connectionLifecycleRegistry.activate(player,
                    previousConnection -> publishConnectionGeneration(
                            player, playerId, playerName, previousConnection));
        } catch (RuntimeException publicationFailure) {
            handlePostLoginPublicationFailure(player, playerName, publicationFailure);
            return;
        }
        if (operation == null) {
            logger.debug(SECURITY_MARKER,
                    "Ignoring late PostLoginEvent for {} after lifecycle shutdown",
                    playerName);
            return;
        }
        String playerIp = PlayerAddressUtils.getPlayerIp(player);

        logger.debug("PostLoginEvent for player {} with IP {}",
                player.getUsername(), playerIp);

        // DEFENSE-IN-DEPTH: Verify handlers are initialized
        if (postLoginHandler == null) {
            logger.error("CRITICAL: PostLoginHandler is null during event processing for player {}", 
                player.getUsername());
            connectionLifecycleRegistry.runIfCurrent(operation, () -> player.disconnect(localizedOrFallback(
                    "system.init_error", "System initialization error.", NamedTextColor.RED)));
            return;
        }

        try {
            // 🔥 USE_OFFLINE: Check for conflict resolution messages - delegate to PostLoginHandler
            // ASYNC: Run on virtual thread to avoid blocking Netty IO threads
            checkConflictMessageAsync(player, operation);

            // Delegate to PostLoginHandler based on player mode
            if (player.isOnlineMode()) {
                connectionLifecycleRegistry.runIfCurrent(operation,
                        () -> postLoginHandler.handlePremiumPlayer(player, playerIp));
                return;
            }

            // Handle offline player - delegate to PostLoginHandler
            connectionLifecycleRegistry.runIfCurrent(operation,
                    () -> postLoginHandler.handleOfflinePlayer(player, playerIp));

        } catch (RuntimeException e) {
            logger.error("Error handling PostLoginEvent for player: {}", event.getPlayer().getUsername(), e);

            connectionLifecycleRegistry.runIfCurrent(operation,
                    () -> event.getPlayer().disconnect(messages.component(
                            "connection.error.generic", NamedTextColor.RED)));
        }
    }

    private void publishConnectionGeneration(
            Player player, UUID playerId, String playerName, Player previousConnection) {
        try {
            connectionManager.beginTransferSession(player);
            if (previousConnection != null) {
                // Generation B is visible before A is invalidated, under the same UUID lifecycle lock.
                plugin.clearConnectionBoundState(
                        previousConnection, playerId, authCache, connectionManager);
                logger.debug(SECURITY_MARKER,
                        "Replaced stale connection owner for {} - previous auth state invalidated",
                        playerName);
            }
        } catch (RuntimeException publicationFailure) {
            // This callback still owns the lifecycle stripe. Clear partial B state here so a C
            // generation cannot publish between failure and UUID-scoped cleanup.
            try {
                plugin.clearConnectionBoundState(player, playerId, authCache, connectionManager);
            } catch (RuntimeException cleanupFailure) {
                publicationFailure.addSuppressed(cleanupFailure);
            }
            throw publicationFailure;
        }
    }

    private void handlePostLoginPublicationFailure(
            Player player, String playerName, RuntimeException publicationFailure) {
        logger.error(SECURITY_MARKER,
                "Failed to publish connection lifecycle for {} - disconnecting fail-secure",
                playerName, publicationFailure);
        try {
            player.disconnect(messages.component("connection.error.generic", NamedTextColor.RED));
        } catch (RuntimeException disconnectFailure) {
            logger.error(SECURITY_MARKER,
                    "Failed to disconnect {} after PostLogin publication failure",
                    playerName, disconnectFailure);
        }
    }

    CompletableFuture<Void> checkConflictMessageAsync(Player player, Operation operation) {
        try {
            return CompletableFuture.runAsync(() -> {
                if (!connectionLifecycleRegistry.isCurrent(operation)) {
                    return;
                }
                try {
                    if (postLoginHandler.shouldShowConflictMessage(player)) {
                        connectionLifecycleRegistry.runIfCurrent(operation,
                                () -> postLoginHandler.showConflictResolutionMessage(player));
                    }
                } catch (java.util.concurrent.CompletionException exception) {
                    logger.error("Error checking conflict message for {}", player.getUsername(), exception);
                }
            }, VirtualThreadExecutorProvider.getVirtualExecutor());
        } catch (RejectedExecutionException exception) {
            logger.debug("Skipping conflict lookup for {} during executor shutdown", player.getUsername());
            return CompletableFuture.completedFuture(null);
        }
    }

    /**
     * Obsługuje event przed połączeniem z serwerem.
     * Blokuje nieautoryzowane połączenia z serwerami backend.
     * <p>
     * KRYTYCZNE: Używamy maksymalny priorytet dla bezpieczeństwa.
     * Zapobiega obejściu autoryzacji przez race conditions.
     * <p>
     * FLOW dla nowych graczy (pierwszego połączenia):
     * - Velocity próbuje połączyć z pierwszym serwerem z listy try (np. 2b2t)
     * - Domyślnie przechwytujemy i przekierowujemy na auth server
     * - Mojang-verified premium może zachować target, gdy operator włączy jawny opt-in
     * - Po połączeniu z auth server, onServerConnected uruchomi auto-transfer
     * <p>
     * ASYNC: Returns {@link EventTask} (or null for synchronous fast-paths) to avoid
     * blocking Netty IO threads. Backend connection verification performs a database
     * UUID lookup and is therefore executed asynchronously via
     * {@link EventTask#resumeWhenComplete(java.util.concurrent.CompletableFuture)}.
     * Velocity suspends event processing until the returned future completes.
     */
    @Subscribe(priority = Short.MAX_VALUE)
    public EventTask onServerPreConnect(ServerPreConnectEvent event) {
        try {
            Player player = event.getPlayer();
            Operation operation = connectionLifecycleRegistry.capture(player);
            if (operation == null) {
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
                return null;
            }
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
            RegisteredServer targetServer = event.getOriginalServer();
            String targetServerName = targetServer.getServerInfo().getName();
            RegisteredServer previousServer = event.getPreviousServer();
            Settings.OperationSettings operationSettings = settings.captureOperationSettings();
            Settings.PremiumSettings premiumSettings = operationSettings.premium();
            Settings.FloodgateSettings floodgateSettings = operationSettings.floodgate();

            logger.debug("ServerPreConnectEvent for player {} -> server {}",
                    player.getUsername(), targetServerName);

            if (previousServer == null) {
                return handleFirstConnection(
                        event,
                        player,
                        targetServer,
                        targetServerName,
                        premiumSettings,
                        floodgateSettings,
                        operation);
            }

            // ✅ JEŚLI TO AUTH SERVER - SPRAWDŹ DODATKOWO AUTORYZACJĘ
            if (handleAuthServerConnection(event, player, targetServer, operation)) {
                return null;
            }

            // ✅ JEŚLI TO BACKEND - SPRAWDŹ AUTORYZACJĘ + SESJĘ + CACHE (async)
            return EventTask.resumeWhenComplete(verifyBackendConnectionAsync(
                    event, player, targetServerName, floodgateSettings, operation));

        } catch (RuntimeException e) {
            logger.error("Error in ServerPreConnect", e);
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
            return null;
        }
    }

    private EventTask handleFirstConnection(
            ServerPreConnectEvent event,
            Player player,
            RegisteredServer targetServer,
            String targetServerName,
            Settings.PremiumSettings premiumSettings,
            Settings.FloodgateSettings floodgateSettings,
            Operation operation) {
        boolean targetIsAuthServer = connectionManager.isAuthServer(targetServer);

        if (shouldBypassAuthServerForPremium(player, premiumSettings)) {
            if (targetIsAuthServer) {
                return EventTask.resumeWhenComplete(selectInitialBackendAsync(
                        event, player, () -> shouldBypassAuthServerForPremium(player, premiumSettings),
                        PREMIUM_MARKER, "Premium", operation));
            }
            logger.info(PREMIUM_MARKER, "Premium player {} -> {} (skipping auth server)",
                    player.getUsername(), targetServerName);
            allowServerIfCurrent(event, targetServer, operation);
            return null;
        }

        // ✅ BEDROCK/FLOODGATE: Skip auth server for Bedrock players.
        // Floodgate already authenticated the player via Xbox Live during the handshake
        // phase, before this event fires. Redirecting to limbo causes
        // ClientboundLevelChunkWithLightPacket translation failures in Geyser.
        if (shouldBypassAuthServer(player, floodgateSettings)) {
            if (targetIsAuthServer) {
                return EventTask.resumeWhenComplete(selectInitialBackendAsync(
                        event, player, () -> shouldBypassAuthServer(player, floodgateSettings),
                        AUTH_MARKER, "Floodgate", operation));
            }
            logger.info("[FLOODGATE] Bedrock player {} -> {} (skipping auth server)",
                    player.getUsername(), targetServerName);
            allowServerIfCurrent(event, targetServer, operation);
            return null;
        }

        // Jeśli cel to już auth server - pozwól
        if (targetIsAuthServer) {
            if (!prepareAuthServerConnectionIfCurrent(
                    event, player, targetServer, operation)) {
                return null;
            }
            logger.debug("First connection {} -> auth server - allowing", player.getUsername());
            return null;
        }

        // ✅ FORCED HOSTS: Zapamiętaj oryginalny target serwer przed przekierowaniem
        // Velocity resolved forced-hosts PRZED tym eventem, więc targetServerName
        // zawiera poprawny serwer z [forced-hosts] lub [servers.try]
        connectionLifecycleRegistry.runIfCurrent(operation,
                () -> connectionManager.setForcedHostTarget(player, targetServerName));

        // Przekieruj na auth server zamiast backend
        Optional<RegisteredServer> authServer = connectionManager.resolveAuthServer();
        if (authServer.isPresent()) {
            if (!prepareAuthServerConnectionIfCurrent(
                    event, player, authServer.get(), operation)) {
                return null;
            }
            logger.debug("First connection {} -> {} - redirecting to auth server (forced host target saved)",
                    player.getUsername(), targetServerName);
        } else {
            logger.error("Auth server '{}' not found! Player {} cannot connect.",
                    connectionManager.getAuthServerName(), player.getUsername());
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
        }
        return null;
    }

    private static boolean shouldBypassAuthServerForPremium(
            Player player,
            Settings.PremiumSettings premiumSettings) {
        return premiumSettings.isBypassAuthServer() && player.isOnlineMode();
    }

    private CompletableFuture<Void> selectInitialBackendAsync(
            ServerPreConnectEvent event, Player player, BooleanSupplier bypassStillAllowed,
            Marker marker, String bypassType, Operation operation) {
        return connectionManager.findAvailableBackendServerForInitialConnectionAsync()
                .handle((backend, throwable) -> {
                    boolean applied = connectionLifecycleRegistry.runIfCurrent(operation, () -> {
                        if (throwable != null) {
                            logger.error(marker, "Failed to select initial backend for {} player {}",
                                    bypassType, player.getUsername(), throwable);
                            event.setResult(ServerPreConnectEvent.ServerResult.denied());
                        } else if (!player.isActive()
                                || !isInitialBypassStillAllowed(bypassStillAllowed)) {
                            event.setResult(ServerPreConnectEvent.ServerResult.denied());
                        } else if (backend != null && backend.isPresent()) {
                            RegisteredServer target = backend.get();
                            logger.info(marker, "{} player {} -> {} (skipping auth server)",
                                    bypassType, player.getUsername(), target.getServerInfo().getName());
                            event.setResult(ServerPreConnectEvent.ServerResult.allowed(target));
                        } else {
                            logger.error(marker,
                                    "No backend available for {} player {} while bypassing auth server",
                                    bypassType, player.getUsername());
                            event.setResult(ServerPreConnectEvent.ServerResult.denied());
                        }
                    });
                    if (!applied) {
                        event.setResult(ServerPreConnectEvent.ServerResult.denied());
                    }
                    return null;
                });
    }

    private boolean isInitialBypassStillAllowed(BooleanSupplier bypassStillAllowed) {
        try {
            return bypassStillAllowed.getAsBoolean();
        } catch (RuntimeException exception) {
            logger.error(SECURITY_MARKER,
                    "Failed to revalidate auth-server bypass after backend selection", exception);
            return false;
        }
    }

    private boolean handleAuthServerConnection(
            ServerPreConnectEvent event, Player player, RegisteredServer targetServer,
            Operation operation) {
        if (!connectionManager.isAuthServer(targetServer)) {
            return false;
        }
        if (!connectionLifecycleRegistry.isCurrent(operation)) {
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
            return true;
        }
        // DODATKOWA WERYFIKACJA - sprawdź czy gracz nie jest już autoryzowany
        // Jeśli jest autoryzowany, nie powinien iść na auth server
        String playerIp = PlayerAddressUtils.getPlayerIp(player);
        boolean isAuthorized = authCache.isPlayerAuthorized(player.getUniqueId(), playerIp);
        if (isAuthorized) {
            // AUTORYZOWANY GRACZ NA AUTH SERVER - przekieruj na backend
            logger.debug("Authorized player {} tried to go to auth server - redirecting to backend",
                    player.getUsername());
            triggerAutoTransfer(player, operation);
            return true;
        }
        if (player.isOnlineMode()) {
            // H1: Premium player with expired cache — re-authorize and redirect to backend
            if (!refreshPremiumAuthorizationIfCurrent(player, playerIp, operation)) {
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
                return true;
            }
            logger.debug("Premium player {} re-authorized (expired cache) - redirecting to backend",
                    player.getUsername());
            triggerAutoTransfer(player, operation);
            return true;
        }
        if (prepareAuthServerConnectionIfCurrent(event, player, targetServer, operation)) {
            logger.debug("Auth server - allowing unauthenticated player");
        }
        return true;
    }

    private CompletableFuture<Void> verifyBackendConnectionAsync(
            ServerPreConnectEvent event,
            Player player,
            String targetServerName,
            Settings.FloodgateSettings floodgateSettings,
            Operation operation) {
        if (!connectionLifecycleRegistry.isCurrent(operation)) {
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
            return CompletableFuture.completedFuture(null);
        }
        if (shouldBypassAuthServer(player, floodgateSettings)) {
            logger.info("[FLOODGATE] Bedrock player {} -> {} (skipping auth server)",
                    player.getUsername(), targetServerName);
            allowServerIfCurrent(event, event.getOriginalServer(), operation);
            return CompletableFuture.completedFuture(null);
        }

        // H1: Premium players are cryptographically verified by Mojang — never block on expired cache
        if (player.isOnlineMode()) {
            String playerIp = PlayerAddressUtils.getPlayerIp(player);
            boolean authorized = authCache.isPlayerAuthorized(player.getUniqueId(), playerIp);
            boolean refreshed = authorized
                    || refreshPremiumAuthorizationIfCurrent(player, playerIp, operation);
            if (refreshed) {
                allowServerIfCurrent(event, event.getOriginalServer(), operation);
            } else {
                event.setResult(ServerPreConnectEvent.ServerResult.denied());
            }
            return CompletableFuture.completedFuture(null);
        }

        String playerIp = PlayerAddressUtils.getPlayerIp(player);

        // WERYFIKUJ UUID z bazą danych dla maksymalnego bezpieczeństwa - async, no IO thread blocking
        return uuidVerificationHandler.verifyPlayerUuid(player,
                        effect -> connectionLifecycleRegistry.runIfCurrent(operation, effect))
                .thenAccept(uuidMatches -> {
                    boolean decided = connectionLifecycleRegistry.runIfCurrent(operation, () ->
                            decideOfflineBackendConnection(
                                    event, player, targetServerName, playerIp, uuidMatches, operation));
                    if (!decided) {
                        event.setResult(ServerPreConnectEvent.ServerResult.denied());
                    }
                });
    }

    /** Runs inside the lifecycle guard; applies the authorization verdict to the event. */
    private void decideOfflineBackendConnection(
            ServerPreConnectEvent event, Player player, String targetServerName,
            String playerIp, boolean uuidMatches, Operation operation) {
        if (!player.isActive()) {
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
            return;
        }
        UUID playerUuid = player.getUniqueId();
        boolean isAuthorized = authCache.isPlayerAuthorized(playerUuid, playerIp);
        boolean hasActiveSession =
                authCache.hasActiveSession(playerUuid, player.getUsername(), playerIp);
        if (!isAuthorized || !hasActiveSession || !uuidMatches) {
            handleUnauthorizedConnection(event, player, targetServerName,
                    isAuthorized, hasActiveSession, uuidMatches, playerIp, operation);
        } else {
            // ✅ WSZYSTKIE WERYFIKACJE PRZESZŁY - POZWÓL
            logger.debug("Authorized player {} heading to {} (session: OK, UUID: OK)",
                    player.getUsername(), targetServerName);
            event.setResult(ServerPreConnectEvent.ServerResult.allowed(
                    event.getOriginalServer()));
        }
    }

    private void handleUnauthorizedConnection(
            ServerPreConnectEvent event, Player player, String targetServerName,
            boolean isAuthorized, boolean hasActiveSession, boolean uuidMatches, String playerIp,
            Operation operation) {
        // ❌ NIE AUTORYZOWANY LUB BRAK SESJI LUB UUID MISMATCH
        String reason = resolveBlockReason(isAuthorized, hasActiveSession);

        if (logger.isDebugEnabled()) {
            logger.debug("Blocked unauthorized backend access for {} -> {} (reason: {}, ip: {})",
                    player.getUsername(), targetServerName, reason, playerIp);
        }

        event.setResult(ServerPreConnectEvent.ServerResult.denied());
        connectionLifecycleRegistry.runIfCurrent(operation, () -> {
            player.sendMessage(Component.text()
                    .content("❌ ")
                    .color(NamedTextColor.RED)
                    .append(messages.component("auth.must_login", NamedTextColor.RED))
                    .build());

            // Jeśli UUID mismatch - usuń z cache dla bezpieczeństwa
            if (!uuidMatches) {
                authCache.removeAuthorizedPlayer(player.getUniqueId());
                authCache.endSession(player.getUniqueId());
            }
        });
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
            Operation operation = connectionLifecycleRegistry.capture(player);
            if (operation == null) {
                logger.debug(SECURITY_MARKER,
                        "Ignoring ServerConnectedEvent for retired connection {}",
                        player.getUsername());
                return;
            }
            String serverName = event.getServer().getServerInfo().getName();

            logger.debug("ServerConnectedEvent for player {} -> server {}",
                    player.getUsername(), serverName);

            if (!connectionManager.isAuthServer(event.getServer())) {
                handleBackendConnection(player, serverName, operation);
            } else {
                handleAuthServerConnection(player, operation);
            }
        } catch (RuntimeException e) {
            logger.error("Error in ServerConnected", e);
        }
    }

    private void handleBackendConnection(Player player, String serverName, Operation operation) {
        connectionLifecycleRegistry.runIfCurrent(operation, () -> {
            if (logger.isDebugEnabled()) {
                logger.debug(AUTH_MARKER, messages.get("player.connected.backend"),
                        player.getUsername(), serverName);
            }
            player.sendMessage(messages.component("general.welcome.full", NamedTextColor.GREEN));
        });
    }

    private void handleAuthServerConnection(Player player, Operation operation) {
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "ServerConnected to auth server: {}", player.getUsername());
        }

        String playerIp = PlayerAddressUtils.getPlayerIp(player);
        if (authCache.isPlayerAuthorized(player.getUniqueId(), playerIp)) {
            triggerAutoTransfer(player, operation);
            return;
        }

        // H1: Premium player landed on auth server with expired cache — re-authorize and transfer
        if (player.isOnlineMode()) {
            if (refreshPremiumAuthorizationIfCurrent(player, playerIp, operation)) {
                triggerAutoTransfer(player, operation);
            }
            return;
        }

        sendAuthInstructions(player, operation);
        connectionLifecycleRegistry.runIfCurrent(operation,
                () -> plugin.getAuthTimeoutScheduler().schedule(player));
    }

    private void triggerAutoTransfer(Player player, Operation operation) {
        connectionLifecycleRegistry.runIfCurrent(operation, () -> {
            if (logger.isDebugEnabled()) {
                logger.debug("Player {} is verified in cache - starting auto-transfer to backend",
                        player.getUsername());
            }
            connectionManager.autoTransferFromAuthServerToBackend(player);
        });
    }

    private void sendAuthInstructions(Player player, Operation operation) {
        AtomicReference<String> username = new AtomicReference<>();
        if (!connectionLifecycleRegistry.runIfCurrent(operation, () -> {
            username.set(player.getUsername());
            player.sendMessage(messages.component("auth.header", NamedTextColor.GOLD));
        })) {
            return;
        }

        databaseManager.findPlayerByNickname(username.get())
                .thenAccept(dbResult -> connectionLifecycleRegistry.runIfCurrent(operation,
                        () -> sendAuthPrompt(player, dbResult)))
                .exceptionally(e -> {
                    logger.error("Error sending auth prompt for {}", username.get(), e);
                    return null;
                });
    }

    private void sendAuthPrompt(Player player, DbResult<RegisteredPlayer> dbResult) {
        if (dbResult.isDatabaseError()) {
            player.sendMessage(messages.component("auth.prompt.generic", NamedTextColor.YELLOW));
            return;
        }

        RegisteredPlayer registeredPlayer = dbResult.getValue();
        if (registeredPlayer != null) {
            player.sendMessage(messages.component("auth.account_exists", NamedTextColor.GREEN));
        } else {
            player.sendMessage(messages.component("auth.first_time", NamedTextColor.AQUA));
        }
    }

    private Component localizedOrFallback(String key, String fallback, NamedTextColor fallbackColor) {
        if (messages == null) {
            return Component.text(fallback, fallbackColor);
        }
        return messages.component(key, fallbackColor);
    }

    private record PendingLoginAttempt(InboundConnection connection) {
    }


}
