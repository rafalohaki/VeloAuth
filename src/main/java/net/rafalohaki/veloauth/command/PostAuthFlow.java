package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/**
 * Shared post-authentication flow used by both LoginCommand and RegisterCommand.
 * Handles: premium check → cache update → session start → security reset → transfer.
 * <p>
 * Extracted to eliminate duplication between login and registration success paths.
 */
final class PostAuthFlow {

    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");

    private PostAuthFlow() {}

    /**
     * Executes the post-authentication flow after successful login or registration.
     *
     * @param ctx           shared command context
     * @param authContext   validated authentication context
     * @param player        the registered player entity to cache
     * @param operationName human-readable name for logging (e.g. "login", "registration")
     * @return true if the flow completed successfully, false on database error
     */
    static boolean execute(CommandContext ctx, AuthenticationContext authContext,
                           RegisteredPlayer player, String operationName) {
        DatabaseManager.DbResult<Boolean> premiumResult =
                ctx.checkPremiumStatus(authContext.player(), "Premium status check during " + operationName);
        if (premiumResult.isDatabaseError()) {
            return false;
        }

        boolean isPremium = Boolean.TRUE.equals(premiumResult.getValue());
        CachedAuthUser cachedUser = CachedAuthUser.fromRegisteredPlayer(player, isPremium);

        Player p = authContext.player();
        ctx.authCache().addAuthorizedPlayer(p.getUniqueId(), cachedUser);
        ctx.authCache().startSession(p.getUniqueId(), authContext.username(),
                PlayerAddressUtils.getPlayerIp(p));
        ctx.resetSecurityCounters(authContext.playerAddress());

        if (ctx.logger().isDebugEnabled()) {
            ctx.logger().debug(AUTH_MARKER, "Player {} {} successfully from IP {}",
                    authContext.username(), operationName, PlayerAddressUtils.getPlayerIp(p));
        }

        ctx.plugin().getConnectionManager().transferToBackend(p);
        return true;
    }
}
