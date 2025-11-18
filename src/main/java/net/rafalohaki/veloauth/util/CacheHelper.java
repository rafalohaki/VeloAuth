package net.rafalohaki.veloauth.util;

import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.i18n.Messages;
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
     * @param messages   Messages system for i18n
     */
    public static void addAuthorizedPlayer(
            AuthCache authCache, UUID playerUuid, CachedAuthUser cachedUser,
            Logger logger, Marker authMarker, String playerName, Messages messages) {

        try {
            authCache.addAuthorizedPlayer(playerUuid, cachedUser);
            if (logger.isDebugEnabled()) {
            logger.debug(authMarker, messages.get("cache.add.player"), playerName);
        }
        } catch (Exception e) {
            logger.error(authMarker, messages.get("cache.error.add.player"), playerName, e);
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
     * @param messages         Messages system for i18n
     */
    public static void addNewAuthorizedPlayer(
            AuthCache authCache, RegisteredPlayer registeredPlayer, boolean isPremium,
            Logger logger, Marker authMarker, Messages messages) {

        try {
            UUID playerUuid = UUID.fromString(registeredPlayer.getUuid());
            CachedAuthUser cachedUser = CachedAuthUser.fromRegisteredPlayer(registeredPlayer, isPremium);
            addAuthorizedPlayer(authCache, playerUuid, cachedUser, logger, authMarker, registeredPlayer.getNickname(), messages);
        } catch (Exception e) {
            logger.error(authMarker, messages.get("cache.error.create.player"), registeredPlayer.getNickname(), e);
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
     * @param messages   Messages system for i18n
     */
    public static void removeAuthorizedPlayer(
            AuthCache authCache, UUID playerUuid, Logger logger, Marker authMarker, String playerName, Messages messages) {

        try {
            authCache.removeAuthorizedPlayer(playerUuid);
            if (logger.isDebugEnabled()) {
            logger.debug(authMarker, messages.get("cache.remove.player"), playerName);
        }
        } catch (Exception e) {
            logger.error(authMarker, messages.get("cache.error.remove.player"), playerName, e);
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
     * @param messages   Messages system for i18n
     */
    public static void startSession(
            AuthCache authCache, UUID playerUuid, String playerName, String playerIp,
            Logger logger, Marker authMarker, Messages messages) {

        try {
            authCache.startSession(playerUuid, playerName, playerIp);
            if (logger.isDebugEnabled()) {
            logger.debug(authMarker, messages.get("session.start"), playerName, playerIp);
        }
        } catch (Exception e) {
            logger.error(authMarker, messages.get("session.error.start"), playerName, e);
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
     * @param messages   Messages system for i18n
     */
    public static void endSession(
            AuthCache authCache, UUID playerUuid, String playerName,
            Logger logger, Marker authMarker, Messages messages) {

        try {
            authCache.endSession(playerUuid);
            if (logger.isDebugEnabled()) {
            logger.debug(authMarker, messages.get("session.end"), playerName);
        }
        } catch (Exception e) {
            logger.error(authMarker, messages.get("session.error.end"), playerName, e);
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
     * @param messages   Messages system for i18n
     * @return true if authorized, false otherwise
     */
    public static boolean isPlayerAuthorized(
            AuthCache authCache, UUID playerUuid, String playerIp,
            Logger logger, Marker authMarker, String playerName, Messages messages) {

        try {
            boolean authorized = authCache.isPlayerAuthorized(playerUuid, playerIp);
            if (logger.isDebugEnabled()) {
            logger.debug(authMarker, messages.get("cache.check.auth"), playerName, authorized);
        }
            return authorized;
        } catch (Exception e) {
            logger.error(authMarker, messages.get("cache.error.check.auth"), playerName, e);
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
     * @param messages   Messages system for i18n
     */
    public static void removePremiumPlayer(
            AuthCache authCache, String playerName, Logger logger, Marker authMarker, Messages messages) {

        try {
            authCache.removePremiumPlayer(playerName);
            if (logger.isDebugEnabled()) {
            logger.debug(authMarker, messages.get("cache.remove.premium"), playerName);
        }
        } catch (Exception e) {
            logger.error(authMarker, messages.get("cache.error.remove.premium"), playerName, e);
        }
    }

    /**
     * Resets brute force attempts for a player with consistent logging.
     *
     * @param authCache     The auth cache to update
     * @param playerAddress Player's IP address
     * @param logger        Logger for security events
     * @param authMarker    Authentication logging marker
     * @param messages      Messages system for i18n
     */
    public static void resetBruteForceAttempts(
            AuthCache authCache, java.net.InetAddress playerAddress, Logger logger, Marker authMarker, Messages messages) {

        try {
            if (playerAddress != null) {
                authCache.resetLoginAttempts(playerAddress);
                if (logger.isDebugEnabled()) {
            logger.debug(authMarker, messages.get("brute.force.reset"), playerAddress.getHostAddress());
        }
            }
        } catch (Exception e) {
            logger.error(authMarker, messages.get("cache.error.reset.brute.force"), playerAddress != null ? playerAddress.getHostAddress() : StringConstants.UNKNOWN, e);
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
     * @param messages   Messages system for i18n
     */
    public static void completePlayerCleanup(
            AuthCache authCache, UUID playerUuid, String playerName,
            Logger logger, Marker authMarker, Messages messages) {

        try {
            // Remove from authorization cache
            removeAuthorizedPlayer(authCache, playerUuid, logger, authMarker, playerName, messages);

            // End active session
            endSession(authCache, playerUuid, playerName, logger, authMarker, messages);

            logger.info(authMarker, messages.get("cache.cleanup.complete"), playerName);
        } catch (Exception e) {
            logger.error(authMarker, messages.get("cache.error.cleanup"), playerName, e);
        }
    }
}
