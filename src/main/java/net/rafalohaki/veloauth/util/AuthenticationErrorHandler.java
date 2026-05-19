package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.cache.AuthCache;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.UUID;

/**
 * Utility class for handling authentication verification errors.
 * Provides standardized error handling for UUID verification and session management failures.
 * <p>
 * Thread-safe: delegates to thread-safe components (AuthCache).
 */
public final class AuthenticationErrorHandler {

    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private AuthenticationErrorHandler() {
        // Utility class - prevent instantiation
    }

    /**
     * Handles UUID verification failure by cleaning up cache and logging the error.
     * This is a security-critical operation that ensures invalid sessions are removed.
     *
     * @param player    Player whose verification failed
     * @param uuid      Player's UUID
     * @param authCache AuthCache instance for session management
     * @param logger    Logger instance for error logging
     */
    public static void handleVerificationFailure(Player player, UUID uuid, 
                                                AuthCache authCache, Logger logger) {
        if (logger.isErrorEnabled()) {
            logger.error(SECURITY_MARKER, "[UUID VERIFICATION FAILED] Player: {} (UUID: {})",
                    player.getUsername(), uuid);
        }
        authCache.removeAuthorizedPlayer(uuid);
        authCache.endSession(uuid);
    }

    /**
     * Immutable context bundle for a UUID mismatch event. Replaces the long parameter list
     * that {@link #handleUuidMismatch} used to take so callers can build the payload once
     * and so this module stays under the project parameter-count budget.
     */
    public record UuidMismatchContext(Player player, UUID playerUuid, UUID storedUuid,
                                      UUID storedPremiumUuid,
                                      net.rafalohaki.veloauth.model.RegisteredPlayer dbPlayer) {
    }

    /**
     * Handles UUID mismatch between player connection and database.
     * Logs detailed security warning and cleans up invalid cache entries.
     * Enhanced logging includes both UUID and PREMIUMUUID comparison.
     */
    public static void handleUuidMismatch(UuidMismatchContext ctx, AuthCache authCache, Logger logger) {
        handleUuidMismatch(ctx, authCache, logger, null);
    }

    /**
     * Overload that also emits an UUID_MISMATCH audit event when {@code auditLogService}
     * is non-null and enabled.
     */
    public static void handleUuidMismatch(UuidMismatchContext ctx, AuthCache authCache, Logger logger,
                                          AuditLogService auditLogService) {
        Player player = ctx.player();
        UUID playerUuid = ctx.playerUuid();
        UUID storedUuid = ctx.storedUuid();
        UUID storedPremiumUuid = ctx.storedPremiumUuid();

        logger.warn(SECURITY_MARKER,
                "[UUID MISMATCH DETECTED] Nickname: {}, Connection UUID: {}, DB UUID: {}, DB PREMIUMUUID: {}, " +
                "ConflictMode: {}, IP: {}",
                player.getUsername(),
                playerUuid,
                storedUuid != null ? storedUuid : "null",
                storedPremiumUuid != null ? storedPremiumUuid : "null",
                ctx.dbPlayer() != null ? ctx.dbPlayer().getConflictMode() : "unknown",
                PlayerAddressUtils.getPlayerIp(player));

        if (logger.isDebugEnabled()) {
            logger.debug(SECURITY_MARKER,
                "[CACHE INVALIDATION] Removing player {} (UUID: {}) from cache due to UUID mismatch",
                player.getUsername(), playerUuid);
        }

        authCache.removeAuthorizedPlayer(playerUuid);
        authCache.endSession(playerUuid);

        if (auditLogService != null) {
            String details = "connection=" + playerUuid
                    + " stored=" + (storedUuid != null ? storedUuid : "null")
                    + " premium=" + (storedPremiumUuid != null ? storedPremiumUuid : "null");
            auditLogService.save(AuditEventType.UUID_MISMATCH, player.getUsername(),
                    PlayerAddressUtils.getPlayerIp(player), details);
        }
    }

    /**
     * Handles general verification errors with exception logging.
     *
     * @param player    Player whose verification failed
     * @param exception Exception that caused the failure
     * @param authCache AuthCache instance for session management
     * @param logger    Logger instance for error logging
     * @return false to indicate verification failure
     */
    public static boolean handleVerificationError(Player player, Exception exception,
                                                  AuthCache authCache, Logger logger) {
        if (logger.isErrorEnabled()) {
            logger.error("Error during player UUID verification: {}", player.getUsername(), exception);
        }
        authCache.removeAuthorizedPlayer(player.getUniqueId());
        authCache.endSession(player.getUniqueId());
        return false;
    }
}
