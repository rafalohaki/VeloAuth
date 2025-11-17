package net.rafalohaki.veloauth.util;

import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.util.UUID;

/**
 * Utility class for consistent cache operations across VeloAuth.
 * Centralizes auth cache management with proper error handling and logging.
 */
public final class CacheHelper {

    private CacheHelper() {
        // Utility class - prevent instantiation
    }

    /**
     * Adds a player to authorization cache with consistent logging.
     *
     * @param authCache  The auth cache to update
     * @param playerUuid Player's UUID
     * @param cachedUser Cached user data
     * @param logger     Logger for cache events
     * @param authMarker Authentication logging marker
     * @param playerName Player name for context
     */
    public static void addAuthorizedPlayer(
            AuthCache authCache, UUID playerUuid, CachedAuthUser cachedUser,
            Logger logger, Marker authMarker, String playerName) {

        try {
            authCache.addAuthorizedPlayer(playerUuid, cachedUser);
            logger.debug(authMarker, StringConstants.CACHE_ADD_PLAYER, playerName);
        } catch (Exception e) {
            logger.error(authMarker, StringConstants.CACHE_ERROR_ADD_PLAYER, playerName, e);
        }
    }

    /**
     * Creates and adds a new player to authorization cache.
     *
     * @param authCache        The auth cache to update
     * @param registeredPlayer Registered player data
     * @param isPremium        Whether player has premium status
     * @param logger           Logger for cache events
     * @param authMarker       Authentication logging marker
     */
    public static void addNewAuthorizedPlayer(
            AuthCache authCache, RegisteredPlayer registeredPlayer, boolean isPremium,
            Logger logger, Marker authMarker) {

        try {
            UUID playerUuid = UUID.fromString(registeredPlayer.getUuid());
            CachedAuthUser cachedUser = CachedAuthUser.fromRegisteredPlayer(registeredPlayer, isPremium);
            addAuthorizedPlayer(authCache, playerUuid, cachedUser, logger, authMarker, registeredPlayer.getNickname());
        } catch (Exception e) {
            logger.error(authMarker, StringConstants.CACHE_ERROR_CREATE_PLAYER, registeredPlayer.getNickname(), e);
        }
    }

    /**
     * Removes a player from authorization cache with consistent logging.
     *
     * @param authCache  The auth cache to update
     * @param playerUuid Player's UUID
     * @param logger     Logger for cache events
     * @param authMarker Authentication logging marker
     * @param playerName Player name for context
     */
    public static void removeAuthorizedPlayer(
            AuthCache authCache, UUID playerUuid, Logger logger, Marker authMarker, String playerName) {

        try {
            authCache.removeAuthorizedPlayer(playerUuid);
            logger.debug(authMarker, StringConstants.CACHE_REMOVE_PLAYER, playerName);
        } catch (Exception e) {
            logger.error(authMarker, StringConstants.CACHE_ERROR_REMOVE_PLAYER, playerName, e);
        }
    }

    /**
     * Starts a player session with consistent logging.
     *
     * @param authCache  The auth cache to update
     * @param playerUuid Player's UUID
     * @param playerName Player's username
     * @param playerIp   Player's IP address
     * @param logger     Logger for session events
     * @param authMarker Authentication logging marker
     */
    public static void startSession(
            AuthCache authCache, UUID playerUuid, String playerName, String playerIp,
            Logger logger, Marker authMarker) {

        try {
            authCache.startSession(playerUuid, playerName, playerIp);
            logger.debug(authMarker, StringConstants.SESSION_START, playerName, playerIp);
        } catch (Exception e) {
            logger.error(authMarker, StringConstants.SESSION_ERROR_START, playerName, e);
        }
    }

    /**
     * Ends a player session with consistent logging.
     *
     * @param authCache  The auth cache to update
     * @param playerUuid Player's UUID
     * @param playerName Player name for context
     * @param logger     Logger for session events
     * @param authMarker Authentication logging marker
     */
    public static void endSession(
            AuthCache authCache, UUID playerUuid, String playerName,
            Logger logger, Marker authMarker) {

        try {
            authCache.endSession(playerUuid);
            logger.debug(authMarker, StringConstants.SESSION_END, playerName);
        } catch (Exception e) {
            logger.error(authMarker, StringConstants.SESSION_ERROR_END, playerName, e);
        }
    }

    /**
     * Checks if a player is authorized with consistent error handling.
     *
     * @param authCache  The auth cache to check
     * @param playerUuid Player's UUID
     * @param playerIp   Player's IP address
     * @param logger     Logger for cache events
     * @param authMarker Authentication logging marker
     * @param playerName Player name for context
     * @return true if authorized, false otherwise
     */
    public static boolean isPlayerAuthorized(
            AuthCache authCache, UUID playerUuid, String playerIp,
            Logger logger, Marker authMarker, String playerName) {

        try {
            boolean authorized = authCache.isPlayerAuthorized(playerUuid, playerIp);
            logger.debug(authMarker, StringConstants.CACHE_CHECK_AUTH, playerName, authorized);
            return authorized;
        } catch (Exception e) {
            logger.error(authMarker, StringConstants.CACHE_ERROR_CHECK_AUTH, playerName, e);
            return false;
        }
    }

    /**
     * Removes premium player from cache with consistent logging.
     *
     * @param authCache  The auth cache to update
     * @param playerName Player's username
     * @param logger     Logger for cache events
     * @param authMarker Authentication logging marker
     */
    public static void removePremiumPlayer(
            AuthCache authCache, String playerName, Logger logger, Marker authMarker) {

        try {
            authCache.removePremiumPlayer(playerName);
            logger.debug(authMarker, StringConstants.CACHE_REMOVE_PREMIUM, playerName);
        } catch (Exception e) {
            logger.error(authMarker, StringConstants.CACHE_ERROR_REMOVE_PREMIUM, playerName, e);
        }
    }

    /**
     * Resets brute force attempts for a player with consistent logging.
     *
     * @param authCache     The auth cache to update
     * @param playerAddress Player's IP address
     * @param logger        Logger for security events
     * @param authMarker    Authentication logging marker
     */
    public static void resetBruteForceAttempts(
            AuthCache authCache, java.net.InetAddress playerAddress, Logger logger, Marker authMarker) {

        try {
            if (playerAddress != null) {
                authCache.resetLoginAttempts(playerAddress);
                logger.debug(authMarker, StringConstants.BRUTE_FORCE_RESET, playerAddress.getHostAddress());
            }
        } catch (Exception e) {
            logger.error(authMarker, StringConstants.CACHE_ERROR_RESET_BRUTE_FORCE, playerAddress != null ? playerAddress.getHostAddress() : StringConstants.UNKNOWN, e);
        }
    }

    /**
     * Performs complete cache cleanup for a player (authorization + session).
     *
     * @param authCache  The auth cache to update
     * @param playerUuid Player's UUID
     * @param playerName Player name for context
     * @param logger     Logger for cache events
     * @param authMarker Authentication logging marker
     */
    public static void completePlayerCleanup(
            AuthCache authCache, UUID playerUuid, String playerName,
            Logger logger, Marker authMarker) {

        try {
            // Remove from authorization cache
            removeAuthorizedPlayer(authCache, playerUuid, logger, authMarker, playerName);

            // End active session
            endSession(authCache, playerUuid, playerName, logger, authMarker);

            logger.info(authMarker, StringConstants.CACHE_CLEANUP_COMPLETE, playerName);
        } catch (Exception e) {
            logger.error(authMarker, StringConstants.CACHE_ERROR_CLEANUP, playerName, e);
        }
    }
}
