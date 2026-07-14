package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import net.rafalohaki.veloauth.util.UuidUtils;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.UUID;

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

        // Offline auth paths (/login and /register) prove only password ownership for the
        // offline backend UUID. They must never persist or cache a resolver-sourced Mojang UUID
        // as authoritative premium identity. Reuse only an already-stored AUTH.PREMIUMUUID,
        // which can be authoritative because it was written by Mojang-verified reconciliation.
        CachedAuthUser cachedUser = CachedAuthUser.fromRegisteredPlayer(
                player, isPremium, storedPremiumUuid(player, isPremium));

        Player p = authContext.player();
        ctx.authCache().authorize(p.getUniqueId(), cachedUser, authContext.username(),
                PlayerAddressUtils.getPlayerIp(p));
        ctx.resetSecurityCounters(authContext.playerAddress(), authContext.username());
        // Cancel the auth-server timeout: player has successfully authenticated.
        ctx.plugin().getAuthTimeoutScheduler().cancel(p.getUniqueId());

        if (ctx.logger().isDebugEnabled()) {
            ctx.logger().debug(AUTH_MARKER, "Player {} {} successfully from IP {}",
                    authContext.username(), operationName, PlayerAddressUtils.getPlayerIp(p));
        }

        boolean transferred = ctx.plugin().getConnectionManager().transferToBackend(p);
        if (!transferred) {
            // Hard transfer failure: roll back authorization so the next /login attempt
            // does not skip auth on a stale cache entry. Background retry path returns true,
            // so reaching this branch means a real error (connection cancelled, retry limit, etc.).
            ctx.authCache().removeAuthorizedPlayer(p.getUniqueId());
            ctx.authCache().endSession(p.getUniqueId());
            if (ctx.logger().isWarnEnabled()) {
                ctx.logger().warn(AUTH_MARKER,
                        "{} succeeded for {} but backend transfer failed - rolled back cache/session",
                        operationName, authContext.username());
            }
            return false;
        }

        // Successful offline auth: clear any lingering CONFLICT_MODE so the next connection
        // runs full UUID verification. Without this, a single conflict mark would relax UUID
        // verification forever (the pre-1.3.3 hole). Persistence happens asynchronously with
        // one retry; ConflictModeService restores the in-memory state if both saves fail.
        ctx.conflictModeService().clearIfPresent(player, operationName)
                .exceptionally(throwable -> {
                    ctx.logger().error(AUTH_MARKER,
                            "Unexpected conflict-state cleanup failure for {} after {}",
                            authContext.username(), operationName, throwable);
                    return false;
        });
        return true;
    }

    private static UUID storedPremiumUuid(RegisteredPlayer player, boolean isPremium) {
        if (!isPremium) {
            return null;
        }
        return UuidUtils.parseUuidSafely(player.getPremiumUuid());
    }
}
