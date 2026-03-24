package net.rafalohaki.veloauth.util;

import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.command.IPRateLimiter;

import java.net.InetAddress;

/**
 * Utility class for common security operations.
 * Provides reusable methods for security counter management and brute force protection.
 * <p>
 * Thread-safe: delegates to thread-safe components (AuthCache, IPRateLimiter).
 */
public final class SecurityUtils {

    private SecurityUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Resets all security counters for a given IP address and username.
     * This includes login attempt counters and rate limiting.
     * <p>
     * Typically called after successful authentication to clear any failed attempt history.
     *
     * @param address     IP address to reset counters for (null-safe)
     * @param username    Username to reset counters for (nullable)
     * @param authCache   AuthCache instance for login attempt tracking
     * @param rateLimiter IPRateLimiter instance for rate limiting
     */
    public static void resetSecurityCounters(InetAddress address, String username, AuthCache authCache, 
                                            IPRateLimiter rateLimiter) {
        if (address != null) {
            authCache.resetLoginAttempts(address, username);
            rateLimiter.reset(address);
        }
    }

    /**
     * Checks if an IP address or username is blocked due to brute force attempts.
     *
     * @param address   IP address to check (null-safe)
     * @param username  Username to check (nullable)
     * @param authCache AuthCache instance for brute force tracking
     * @return true if blocked, false otherwise
     */
    public static boolean isBruteForceBlocked(InetAddress address, String username, AuthCache authCache) {
        return address != null && authCache.isBlocked(address, username);
    }

    /**
     * Registers a failed login attempt and returns whether the IP or username is now blocked.
     *
     * @param address   IP address that failed login (null-safe)
     * @param username  Username that failed login (nullable)
     * @param authCache AuthCache instance for brute force tracking
     * @return true if IP or username is now blocked, false otherwise
     */
    public static boolean registerFailedLogin(InetAddress address, String username, AuthCache authCache) {
        return address != null && authCache.registerFailedLogin(address, username);
    }
}
