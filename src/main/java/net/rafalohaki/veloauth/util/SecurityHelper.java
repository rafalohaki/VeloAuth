package net.rafalohaki.veloauth.util;

import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.command.IPRateLimiter;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.net.InetAddress;

/**
 * Utility class for consistent security operations across VeloAuth.
 * Centralizes rate limiting, brute force protection, and security logging.
 */
public final class SecurityHelper {

    private SecurityHelper() {
        // Utility class - prevent instantiation
    }

    /**
     * Checks if player is blocked by rate limiting and logs the event.
     *
     * @param ipRateLimiter  The rate limiter to check
     * @param playerAddress  The player's IP address
     * @param logger         Logger for security events
     * @param securityMarker Security logging marker
     * @param playerName     Player name for context
     * @param operationType  Type of operation (login/register/changepassword)
     * @return true if rate limited, false otherwise
     */
    public static boolean checkRateLimit(
            IPRateLimiter ipRateLimiter, InetAddress playerAddress,
            Logger logger, Marker securityMarker, String playerName, String operationType) {

        if (playerAddress != null && ipRateLimiter.isRateLimited(playerAddress)) {
            String logMessage = String.format("[RATE_LIMIT] %s - %s zablokowany za rate limiting (%d prób w 5 min)",
                    playerName, operationType, ipRateLimiter.getAttempts(playerAddress));
            logger.warn(securityMarker, logMessage);
            return true;
        }
        return false;
    }

    /**
     * Increments rate limit counter for a player.
     *
     * @param ipRateLimiter The rate limiter to update
     * @param playerAddress The player's IP address
     */
    public static void incrementRateLimit(IPRateLimiter ipRateLimiter, InetAddress playerAddress) {
        if (playerAddress != null) {
            ipRateLimiter.incrementAttempts(playerAddress);
        }
    }

    /**
     * Checks if player is blocked by brute force protection and logs the event.
     *
     * @param authCache      The auth cache to check
     * @param playerAddress  The player's IP address
     * @param logger         Logger for security events
     * @param securityMarker Security logging marker
     * @param playerName     Player name for context
     * @param operationType  Type of operation
     * @return true if blocked, false otherwise
     */
    public static boolean checkBruteForceBlock(
            AuthCache authCache, InetAddress playerAddress,
            Logger logger, Marker securityMarker, String playerName, String operationType) {

        if (playerAddress != null && authCache.isBlocked(playerAddress)) {
            String logMessage = String.format("[BRUTE_FORCE_BLOCK] IP %s próbował %s",
                    playerAddress.getHostAddress(), operationType);
            logger.warn(securityMarker, logMessage);
            return true;
        }
        return false;
    }

    /**
     * Registers a failed login attempt and handles blocking.
     *
     * @param authCache      The auth cache to update
     * @param playerAddress  The player's IP address
     * @param logger         Logger for security events
     * @param securityMarker Security logging marker
     * @param playerName     Player name for context
     * @param playerIp       Player IP for logging
     * @return true if player is now blocked, false otherwise
     */
    public static boolean registerFailedLogin(
            AuthCache authCache, InetAddress playerAddress,
            Logger logger, Marker securityMarker, String playerName, String playerIp) {

        boolean blocked = false;
        if (playerAddress != null) {
            blocked = authCache.registerFailedLogin(playerAddress);
        }

        if (blocked) {
            String logMessage = String.format("[BRUTE_FORCE_BLOCKED] %s zablokowany za brute force z IP %s",
                    playerName, playerIp);
            logger.warn(securityMarker, logMessage);
        } else {
            String logMessage = String.format("[FAILED_LOGIN] Nieudana próba logowania gracza %s z IP %s",
                    playerName, playerIp);
            logger.debug(logMessage);
        }

        return blocked;
    }

    /**
     * Resets brute force attempts for a successful authentication.
     *
     * @param authCache     The auth cache to update
     * @param playerAddress The player's IP address
     */
    public static void resetBruteForceAttempts(AuthCache authCache, InetAddress playerAddress) {
        if (playerAddress != null) {
            authCache.resetLoginAttempts(playerAddress);
        }
    }

    /**
     * Logs a successful authentication event.
     *
     * @param logger        Logger for authentication events
     * @param authMarker    Authentication logging marker
     * @param playerName    Player name
     * @param playerIp      Player IP
     * @param operationType Type of operation (login/register/changepassword)
     */
    public static void logSuccessfulAuth(
            Logger logger, Marker authMarker, String playerName, String playerIp, String operationType) {

        String logMessage = String.format("[AUTH_SUCCESS] Gracz %s pomyślnie %s z IP %s",
                playerName, operationType, playerIp);
        logger.info(authMarker, logMessage);
    }

    /**
     * Logs a security event with standardized format.
     *
     * @param logger         Logger for security events
     * @param securityMarker Security logging marker
     * @param eventType      Type of security event
     * @param playerName     Player name
     * @param details        Additional details about the event
     */
    public static void logSecurityEvent(
            Logger logger, Marker securityMarker, String eventType, String playerName, String details) {

        String logMessage = String.format("[SECURITY] %s - %s: %s", eventType, playerName, details);
        logger.warn(securityMarker, logMessage);
    }

    /**
     * Performs comprehensive security checks for authentication operations.
     *
     * @param ipRateLimiter  Rate limiter to check
     * @param authCache      Auth cache for brute force checks
     * @param playerAddress  Player's IP address
     * @param logger         Logger for events
     * @param securityMarker Security logging marker
     * @param playerName     Player name
     * @param playerIp       Player IP string
     * @param operationType  Type of operation
     * @return SecurityCheckResult with check outcomes
     */
    public static SecurityCheckResult performSecurityChecks(
            IPRateLimiter ipRateLimiter, AuthCache authCache, InetAddress playerAddress,
            Logger logger, Marker securityMarker, String playerName, String playerIp, String operationType) {

        // Check rate limiting
        if (checkRateLimit(ipRateLimiter, playerAddress, logger, securityMarker, playerName, operationType)) {
            return new SecurityCheckResult(false, "rate_limited", "Zablokowany za zbyt wiele prób");
        }

        // Check brute force protection
        if (checkBruteForceBlock(authCache, playerAddress, logger, securityMarker, playerName, operationType)) {
            return new SecurityCheckResult(false, "brute_force_blocked", "Zablokowany za brute force");
        }

        // Increment rate limit counter
        incrementRateLimit(ipRateLimiter, playerAddress);

        return new SecurityCheckResult(true, "passed", "Wszystkie kontrole bezpieczeństwa zakończone sukcesem");
    }

    /**
         * Result of security checks with standardized format.
         */
        public record SecurityCheckResult(boolean passed, String reason, String message) {
    }
}
