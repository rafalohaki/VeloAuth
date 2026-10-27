package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.dialog.DialogAuthService;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry.Operation;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.premium.PremiumNameAttemptTracker;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.util.UUID;

/**
 * Premium-nick ownership check for connections whose nickname belongs to a Mojang account that
 * has no VeloAuth record yet. PreLogin marks such a connection ({@link #shouldRunCheck}), PostLogin
 * hands it to the dialog service ({@link #startCheck}) and a verified owner is admitted in place.
 */
final class PremiumOwnershipCheckHandler {

    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final VeloAuth plugin;
    private final Settings settings;
    private final Messages messages;
    private final AuthCache authCache;
    private final DatabaseManager databaseManager;
    private final ConnectionManager connectionManager;
    private final ConnectionLifecycleRegistry connectionLifecycleRegistry;
    private final PremiumNameAttemptTracker premiumNameAttempts;
    private final Logger logger;

    PremiumOwnershipCheckHandler(VeloAuth plugin, Settings settings, Messages messages, AuthCache authCache,
                                 DatabaseManager databaseManager, ConnectionManager connectionManager,
                                 PremiumNameAttemptTracker premiumNameAttempts) {
        this.plugin = plugin;
        this.settings = settings;
        this.messages = messages;
        this.authCache = authCache;
        this.databaseManager = databaseManager;
        this.connectionManager = connectionManager;
        this.connectionLifecycleRegistry = plugin.getConnectionLifecycleRegistry();
        this.premiumNameAttempts = premiumNameAttempts;
        this.logger = plugin.getLogger();
    }

    /**
     * Unregistered premium nickname: the client is admitted offline for the ownership check on the
     * auth server, because a cracked client cannot survive an encryption request (it fails silently
     * on its own side) and nothing but the Mojang profile key can tell the two apart before that
     * request. A verified owner gets a premium record, so its later joins take Velocity's regular
     * Mojang handshake and go straight to the backend.
     */
    boolean shouldRunCheck(PreLoginEvent event, String username, UUID premiumUuid) {
        Settings.DialogSettings dialogSettings = settings.getDialogSettings();
        DialogAuthService dialogAuth = plugin.getDialogAuthService();
        if (dialogSettings == null || !dialogSettings.isPremiumNameNotice() || premiumUuid == null
                || dialogAuth == null || !dialogAuth.isPremiumCheckAvailable()) {
            return false;
        }
        InetAddress address = PlayerAddressUtils.getAddressFromPreLogin(event);
        if (address == null) {
            return false;
        }
        premiumNameAttempts.markCheck(address.getHostAddress(), username, premiumUuid);
        return true;
    }

    /**
     * Starts the ownership check for a connection marked in PreLogin. The player is routed to the
     * auth server by the regular unauthenticated flow; the dialog service takes over there.
     */
    void startCheck(Player player, UUID premiumUuid, Operation operation) {
        DialogAuthService dialogAuth = plugin.getDialogAuthService();
        String playerName = player.getUsername();
        String ip = PlayerAddressUtils.getPlayerIp(player);
        if (dialogAuth == null || !dialogAuth.supportsDialogs(player)) {
            String language = dialogAuth != null ? dialogAuth.languageFor(player) : messages.getCurrentLanguage();
            logger.info(SECURITY_MARKER, "[PREMIUM CHECK] {} cannot receive dialogs - disconnecting with premium-name notice (language {})",
                    playerName, language);
            connectionLifecycleRegistry.runIfCurrent(operation, () -> player.disconnect(
                    messages.componentForLanguage(language, "connection.premium_name.kick", NamedTextColor.RED, playerName)));
            return;
        }
        logger.info(SECURITY_MARKER, "[PREMIUM CHECK] {} uses premium nick without a VeloAuth record - verifying ownership on the auth server",
                playerName);
        connectionLifecycleRegistry.runIfCurrent(operation, () ->
                dialogAuth.beginPremiumCheck(player, premiumUuid, () -> admitVerifiedPremium(player, ip, premiumUuid)));
    }

    /**
     * The client proved ownership with its Mojang profile key (a Mojang-signed certificate that
     * names this exact profile UUID). That is cryptographic proof, so the player is admitted right
     * here: authorized in the cache, given a premium record (so the next joins take Velocity's
     * regular Mojang handshake and go straight to the backend) and moved on - no transfer packet,
     * no reconnect, no second auth-server visit.
     */
    private void admitVerifiedPremium(Player player, String ip, UUID premiumUuid) {
        String username = player.getUsername();
        premiumNameAttempts.clear(ip, username);
        PremiumAuthorizer.authorize(player, ip, authCache);

        RegisteredPlayer record = new RegisteredPlayer(username, null, ip, player.getUniqueId().toString());
        record.setPremiumUuid(premiumUuid.toString());
        databaseManager.registerPlayerIfAbsent(record)
                .whenComplete((result, throwable) -> logPremiumRecordOutcome(username, result, throwable));

        if (player.isActive()) {
            connectionManager.autoTransferFromAuthServerToBackend(player);
        }
    }

    private void logPremiumRecordOutcome(String username, DbResult<Boolean> result, Throwable throwable) {
        if (throwable != null) {
            logger.warn(SECURITY_MARKER, "[PREMIUM CHECK] Could not store premium record for {}: {}",
                    username, throwable.toString());
        } else if (result == null || result.isDatabaseError()) {
            logger.warn(SECURITY_MARKER, "[PREMIUM CHECK] Could not store premium record for {}: {}",
                    username, result == null ? "no result" : result.getErrorMessage());
        } else if (logger.isInfoEnabled()) {
            logger.info(SECURITY_MARKER, "[PREMIUM CHECK] {} verified via Mojang profile key - premium record {}",
                    username, Boolean.TRUE.equals(result.getValue()) ? "created" : "already present");
        }
    }

}
