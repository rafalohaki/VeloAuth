package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.cache.AuthCache.PremiumCacheEntry;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.i18n.SimpleMessages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;

import java.util.Optional;
import java.util.UUID;

/**
 * Handles post-login routing and conflict resolution logic.
 * Extracted from AuthListener to reduce complexity and improve testability.
 */
public class PostLoginHandler {

    private final VeloAuth plugin;
    private final AuthCache authCache;
    private final ConnectionManager connectionManager;
    private final DatabaseManager databaseManager;
    private final Messages messages;
    private final Logger logger;
    private final SimpleMessages sm;

    /**
     * Creates a new PostLoginHandler.
     *
     * @param plugin            VeloAuth plugin instance
     * @param authCache         Cache for authorization and sessions
     * @param connectionManager Manager for server connections
     * @param databaseManager   Manager for database operations
     * @param messages          i18n message system
     * @param logger            Logger instance
     */
    public PostLoginHandler(VeloAuth plugin,
                           AuthCache authCache,
                           ConnectionManager connectionManager,
                           DatabaseManager databaseManager,
                           Messages messages,
                           Logger logger) {
        this.plugin = plugin;
        this.authCache = authCache;
        this.connectionManager = connectionManager;
        this.databaseManager = databaseManager;
        this.messages = messages;
        this.logger = logger;
        this.sm = new SimpleMessages(messages);
    }

    /**
     * Handles premium player post-login (authorization and session start).
     *
     * @param player   The premium player
     * @param playerIp Player's IP address
     */
    public void handlePremiumPlayer(Player player, String playerIp) {
        if (logger.isInfoEnabled()) {
            logger.info(messages.get("player.premium.verified"), player.getUsername());
        }

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
                premiumUuid);

        authCache.addAuthorizedPlayer(playerUuid, cachedUser);
        authCache.startSession(playerUuid, player.getUsername(), playerIp);

        // Auto-transfer premium player to backend
        transferToBackendAsync(player);
    }

    /**
     * Schedules async backend transfer for premium player.
     *
     * @param player The player to transfer
     */
    private void transferToBackendAsync(Player player) {
        plugin.getServer().getScheduler().buildTask(plugin, () -> {
            try {
                connectionManager.transferToBackend(player);
            } catch (Exception e) {
                logger.error("Error transferring premium player {} to backend", player.getUsername(), e);
            }
        }).schedule();
    }

    /**
     * Handles offline player post-login (authorization check or PicoLimbo transfer).
     *
     * @param player   The offline player
     * @param playerIp Player's IP address
     */
    public void handleOfflinePlayer(Player player, String playerIp) {
        if (authCache.isPlayerAuthorized(player.getUniqueId(), playerIp)) {
            if (logger.isDebugEnabled()) {
                logger.debug("\u2705 Gracz {} jest już autoryzowany - pozostaje na backendzie",
                        player.getUsername());
            }
            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("player.unauthorized.redirect"), player.getUsername());
        }

        transferToPicoLimboAsync(player);
    }

    /**
     * Shows conflict resolution message to premium players in conflict mode.
     *
     * @param player The premium player experiencing conflict
     */
    public void showConflictResolutionMessage(Player player) {
        Component message = Component.text()
                .append(Component.text(messages.get("player.conflict.header"), NamedTextColor.YELLOW))
                .append(Component.newline())
                .append(Component.text(messages.get("player.conflict.description"), NamedTextColor.RED))
                .append(Component.newline())
                .append(Component.text(messages.get("player.conflict.options"), NamedTextColor.WHITE))
                .append(Component.newline())
                .append(Component.text(messages.get("player.conflict.option1"), NamedTextColor.GRAY))
                .append(Component.newline())
                .append(Component.text(messages.get("player.conflict.option2"), NamedTextColor.GREEN))
                .append(Component.newline())
                .append(Component.text(messages.get("player.conflict.resolution"), NamedTextColor.AQUA))
                .build();

        player.sendMessage(message);
        logger.info("[CONFLICT MESSAGE] Sent conflict resolution message to premium player: {}", player.getUsername());
    }

    /**
     * Checks if player should see conflict resolution message.
     *
     * @param player The player to check
     * @return true if player is in conflict mode and is premium
     */
    public boolean shouldShowConflictMessage(Player player) {
        RegisteredPlayer registeredPlayer = databaseManager.findPlayerWithRuntimeDetection(player.getUsername())
                .join().getValue();
        
        if (registeredPlayer == null || !registeredPlayer.getConflictMode()) {
            return false;
        }

        return Optional.ofNullable(authCache.getPremiumStatus(player.getUsername()))
                .map(PremiumCacheEntry::isPremium)
                .orElse(false);
    }

    /**
     * Schedules async PicoLimbo transfer for player.
     *
     * @param player The player to transfer
     */
    private void transferToPicoLimboAsync(Player player) {
        plugin.getServer().getScheduler().buildTask(plugin, () -> {
            try {
                boolean success = connectionManager.transferToPicoLimbo(player);
                if (!success) {
                    logger.error("\u274C Błąd podczas przenoszenia gracza {} na PicoLimbo",
                            player.getUsername());

                    player.disconnect(sm.connectionErrorAuthConnect());
                }
            } catch (Exception e) {
                logger.error("❌ Błąd podczas przenoszenia gracza {} na PicoLimbo: {}",
                        player.getUsername(), e.getMessage(), e);

                player.disconnect(sm.connectionErrorAuthConnect());
            }
        }).schedule();
    }
}
