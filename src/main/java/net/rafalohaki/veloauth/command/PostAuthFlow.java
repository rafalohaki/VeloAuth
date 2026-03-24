package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.Optional;
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

        // Defense-in-depth: persist PREMIUMUUID for premium players who ended up in offline path
        UUID premiumUuid = resolvePremiumUuid(ctx, authContext.player());
        if (!persistPremiumUuid(ctx, authContext, player, isPremium, premiumUuid)) {
            return false;
        }

        CachedAuthUser cachedUser = CachedAuthUser.fromRegisteredPlayer(player, isPremium, premiumUuid);

        Player p = authContext.player();
        ctx.authCache().addAuthorizedPlayer(p.getUniqueId(), cachedUser);
        ctx.authCache().startSession(p.getUniqueId(), authContext.username(),
                PlayerAddressUtils.getPlayerIp(p));
        ctx.resetSecurityCounters(authContext.playerAddress(), authContext.username());

        if (ctx.logger().isDebugEnabled()) {
            ctx.logger().debug(AUTH_MARKER, "Player {} {} successfully from IP {}",
                    authContext.username(), operationName, PlayerAddressUtils.getPlayerIp(p));
        }

        ctx.plugin().getConnectionManager().transferToBackend(p);
        return true;
    }

    private static boolean persistPremiumUuid(CommandContext ctx, AuthenticationContext authContext,
                                              RegisteredPlayer player, boolean isPremium,
                                              UUID premiumUuid) {
        if (!isPremium || player.getPremiumUuid() != null || premiumUuid == null) {
            return true;
        }

        player.setPremiumUuid(premiumUuid.toString());

        try {
            var savePlayerResult = ctx.databaseManager().savePlayer(player).join();
            if (ctx.handleDatabaseError(savePlayerResult, authContext.player(),
                    "Persist premium UUID in AUTH table")) {
                return false;
            }
            if (!Boolean.TRUE.equals(savePlayerResult.getValue())) {
                logPremiumUuidFailure(ctx, authContext.username(),
                        "AUTH table update returned false while persisting PREMIUMUUID");
                ctx.sendDatabaseErrorMessage(authContext.player());
                return false;
            }

            var savePremiumUuidResult = ctx.databaseManager()
                    .savePremiumUuid(authContext.username(), premiumUuid)
                    .join();
            if (ctx.handleDatabaseError(savePremiumUuidResult, authContext.player(),
                    "Sync PREMIUM_UUIDS table")) {
                return false;
            }
            if (!Boolean.TRUE.equals(savePremiumUuidResult.getValue())) {
                logPremiumUuidFailure(ctx, authContext.username(),
                        "PREMIUM_UUIDS sync returned false");
                ctx.sendDatabaseErrorMessage(authContext.player());
                return false;
            }
        } catch (java.util.concurrent.CompletionException e) {
            logPremiumUuidFailure(ctx, authContext.username(), "Unexpected async premium UUID failure", e);
            ctx.sendDatabaseErrorMessage(authContext.player());
            return false;
        }

        if (ctx.logger().isInfoEnabled()) {
            ctx.logger().info(AUTH_MARKER,
                    "Persisted PREMIUMUUID for {} in AUTH and PREMIUM_UUIDS tables",
                    authContext.username());
        }
        return true;
    }

    private static void logPremiumUuidFailure(CommandContext ctx, String username, String message) {
        if (ctx.logger().isWarnEnabled()) {
            ctx.logger().warn(AUTH_MARKER, "{} for {}", message, username);
        }
    }

    private static void logPremiumUuidFailure(CommandContext ctx, String username,
                                              String message, Throwable throwable) {
        if (ctx.logger().isErrorEnabled()) {
            ctx.logger().error(AUTH_MARKER, "{} for {}", message, username, throwable);
        }
    }

    /**
     * Resolves premium UUID from AuthCache for the given player.
     *
     * @return premium UUID if available, null otherwise
     */
    private static UUID resolvePremiumUuid(CommandContext ctx, Player player) {
        return Optional.ofNullable(ctx.authCache().getPremiumStatus(player.getUsername()))
                .map(AuthCache.PremiumCacheEntry::getPremiumUuid)
                .orElse(null);
    }
}
