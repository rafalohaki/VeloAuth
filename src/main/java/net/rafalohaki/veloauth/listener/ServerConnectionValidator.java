package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.util.Optional;

/**
 * Validates server connections and handles routing decisions.
 * Extracted from AuthListener to reduce complexity and improve testability.
 * 
 * <p><b>Responsibilities:</b>
 * <ul>
 *   <li>Validate PreLogin conditions (plugin init, username, brute force)</li>
 *   <li>Handle first connection routing to PicoLimbo</li>
 *   <li>Verify backend connection authorization</li>
 *   <li>Redirect unauthorized players appropriately</li>
 * </ul>
 * 
 * @since 2.1.0
 */
public class ServerConnectionValidator {

    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final VeloAuth plugin;
    private final AuthCache authCache;
    private final Settings settings;
    private final Messages messages;
    private final Logger logger;
    private final PreLoginHandler preLoginHandler;

    /**
     * Creates a new ServerConnectionValidator.
     *
     * @param plugin          VeloAuth plugin instance
     * @param authCache       Authorization cache
     * @param settings        Plugin settings
     * @param messages        i18n messages
     * @param logger          Logger instance
     * @param preLoginHandler Handler for pre-login validation
     */
    public ServerConnectionValidator(VeloAuth plugin, AuthCache authCache, Settings settings,
                                     Messages messages, Logger logger, PreLoginHandler preLoginHandler) {
        this.plugin = plugin;
        this.authCache = authCache;
        this.settings = settings;
        this.messages = messages;
        this.logger = logger;
        this.preLoginHandler = preLoginHandler;
    }

    // ==================== PreLogin Validation ====================

    /**
     * Validates all pre-login conditions.
     *
     * @param event    PreLogin event
     * @param username Player username
     * @return true if all conditions pass
     */
    public boolean validatePreLoginConditions(PreLoginEvent event, String username) {
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
            logger.warn("🔒 STARTUP BLOCK: Player {} tried to connect before VeloAuth fully initialized", username);
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

    // ==================== Server Connection Routing ====================

    /**
     * Handles first connection routing - redirects to PicoLimbo if needed.
     *
     * @param event            ServerPreConnect event
     * @param player           Player connecting
     * @param targetServerName Original target server name
     * @return true if handled (event was modified)
     */
    public boolean handleFirstConnection(ServerPreConnectEvent event, Player player, String targetServerName) {
        if (player.getCurrentServer().isPresent()) {
            return false; // Not first connection
        }

        String picoLimboName = settings.getPicoLimboServerName();

        // Already going to PicoLimbo
        if (targetServerName.equals(picoLimboName)) {
            logger.debug("First connection {} -> PicoLimbo - allowing", player.getUsername());
            return true;
        }

        // Redirect to PicoLimbo
        return redirectToPicoLimbo(event, player, targetServerName);
    }

    private boolean redirectToPicoLimbo(ServerPreConnectEvent event, Player player, String targetServerName) {
        String picoLimboName = settings.getPicoLimboServerName();
        Optional<RegisteredServer> picoLimbo = plugin.getServer().getServer(picoLimboName);

        if (picoLimbo.isPresent()) {
            logger.debug("First connection {} -> {} - redirecting to PicoLimbo",
                    player.getUsername(), targetServerName);
            event.setResult(ServerPreConnectEvent.ServerResult.allowed(picoLimbo.get()));
        } else {
            logger.error("PicoLimbo server '{}' not found! Player {} cannot connect.",
                    picoLimboName, player.getUsername());
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
        }
        return true;
    }

    /**
     * Handles PicoLimbo connection - redirects authorized players to backend.
     *
     * @param event            ServerPreConnect event
     * @param player           Player connecting
     * @param targetServerName Target server name
     * @return true if handled (target is PicoLimbo)
     */
    public boolean handlePicoLimboConnection(ServerPreConnectEvent event, Player player, String targetServerName) {
        if (!targetServerName.equals(settings.getPicoLimboServerName())) {
            return false;
        }

        String playerIp = PlayerAddressUtils.getPlayerIp(player);
        boolean isAuthorized = authCache.isPlayerAuthorized(player.getUniqueId(), playerIp);

        if (isAuthorized) {
            logger.debug("Authorized player {} trying to go to PicoLimbo - redirecting to backend",
                    player.getUsername());
            event.setResult(ServerPreConnectEvent.ServerResult.denied());
        } else {
            logger.debug("PicoLimbo - allowing (player not authorized)");
        }
        return true;
    }

    /**
     * Verifies backend connection authorization.
     *
     * @param event            ServerPreConnect event
     * @param player           Player connecting
     * @param targetServerName Target server name
     * @param uuidMatches      Whether UUID verification passed
     */
    public void verifyBackendConnection(ServerPreConnectEvent event, Player player,
                                        String targetServerName, boolean uuidMatches) {
        String playerIp = PlayerAddressUtils.getPlayerIp(player);
        boolean isAuthorized = authCache.isPlayerAuthorized(player.getUniqueId(), playerIp);
        boolean hasActiveSession = authCache.hasActiveSession(player.getUniqueId(), player.getUsername(), playerIp);

        if (!isAuthorized || !hasActiveSession || !uuidMatches) {
            handleUnauthorizedConnection(event, player, targetServerName, 
                    isAuthorized, hasActiveSession, uuidMatches, playerIp);
        } else {
            logger.debug("✅ Authorized player {} going to {} (session: OK, UUID: OK)",
                    player.getUsername(), targetServerName);
        }
    }

    private void handleUnauthorizedConnection(ServerPreConnectEvent event, Player player,
                                             String targetServerName, boolean isAuthorized,
                                             boolean hasActiveSession, boolean uuidMatches, String playerIp) {
        String reason = resolveBlockReason(isAuthorized, hasActiveSession);

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("player.blocked.unauthorized", 
                    player.getUsername(), targetServerName, reason, playerIp));
        }

        event.setResult(ServerPreConnectEvent.ServerResult.denied());

        player.sendMessage(Component.text()
                .content("❌ ")
                .color(NamedTextColor.RED)
                .append(Component.text(messages.get("auth.must_login")).color(NamedTextColor.RED))
                .build());

        if (!uuidMatches) {
            authCache.removeAuthorizedPlayer(player.getUniqueId());
            authCache.endSession(player.getUniqueId());
        }
    }

    private String resolveBlockReason(boolean isAuthorized, boolean hasActiveSession) {
        if (!isAuthorized) {
            return "unauthorized";
        }
        if (!hasActiveSession) {
            return "no active session";
        }
        return "UUID mismatch";
    }
}
