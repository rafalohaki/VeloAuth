package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.proxy.Player;
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
     * Handles UUID mismatch between player connection and database.
     * Logs detailed security warning and cleans up invalid cache entries.
     * Enhanced logging includes both UUID and PREMIUMUUID comparison.
     *
     * @param player            Player with UUID mismatch
     * @param playerUuid        UUID from player connection
     * @param storedUuid        UUID from database
     * @param storedPremiumUuid PREMIUMUUID from database (may be null)
     * @param dbPlayer          RegisteredPlayer from database for additional context
     * @param authCache         AuthCache instance for session management
     * @param logger            Logger instance for security logging
     */
    public static void handleUuidMismatch(Player player, UUID playerUuid, UUID storedUuid,
                                         UUID storedPremiumUuid, 
                                         net.rafalohaki.veloauth.model.RegisteredPlayer dbPlayer,
                                         AuthCache authCache, Logger logger) {
        // Enhanced logging with detailed UUID comparison (Requirements 8.2, 8.3)
        logger.warn(SECURITY_MARKER,
                "[UUID MISMATCH DETECTED] Nickname: {}, Connection UUID: {}, DB UUID: {}, DB PREMIUMUUID: {}, " +
                "ConflictMode: {}, IP: {}",
                player.getUsername(), 
                playerUuid, 
                storedUuid != null ? storedUuid : "null",
                storedPremiumUuid != null ? storedPremiumUuid : "null",
                dbPlayer != null ? dbPlayer.getConflictMode() : "unknown",
                PlayerAddressUtils.getPlayerIp(player));
        
        // Cache invalidation for security (Requirement 8.2)
        if (logger.isDebugEnabled()) {
            logger.debug(SECURITY_MARKER, 
                "[CACHE INVALIDATION] Removing player {} (UUID: {}) from cache due to UUID mismatch",
                player.getUsername(), playerUuid);
        }
        
        authCache.removeAuthorizedPlayer(playerUuid);
        authCache.endSession(playerUuid);
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
            logger.error("Błąd podczas weryfikacji UUID gracza: {}", player.getUsername(), exception);
        }
        authCache.removeAuthorizedPlayer(player.getUniqueId());
        authCache.endSession(player.getUniqueId());
        return false;
    }
}
