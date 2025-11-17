package net.rafalohaki.veloauth.command;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * IP-based rate limiting for authentication commands.
 * Thread-safe: uses ConcurrentHashMap and atomic operations.
 * Simple implementation without over-engineering.
 */
public class IPRateLimiter {

    /**
     * IP-based rate limiting entries - ALWAYS ConcurrentHashMap for thread-safety.
     */
    private final ConcurrentHashMap<InetAddress, RateLimitEntry> rateLimits;

    /**
     * Maximum attempts per IP within time window.
     */
    private final int maxAttempts;

    /**
     * Time window in minutes.
     */
    private final int timeoutMinutes;

    /**
     * Creates a new IPRateLimiter.
     *
     * @param maxAttempts    Maximum attempts per IP
     * @param timeoutMinutes Time window in minutes
     */
    public IPRateLimiter(int maxAttempts, int timeoutMinutes) {
        if (maxAttempts <= 0) {
            throw new IllegalArgumentException("Max attempts must be > 0");
        }
        if (timeoutMinutes <= 0) {
            throw new IllegalArgumentException("Timeout minutes must be > 0");
        }

        this.rateLimits = new ConcurrentHashMap<>();
        this.maxAttempts = maxAttempts;
        this.timeoutMinutes = timeoutMinutes;
    }

    /**
     * Checks if IP address is rate limited.
     *
     * @param address IP address to check
     * @return true if rate limited
     */
    public boolean isRateLimited(InetAddress address) {
        if (address == null) {
            return false;
        }

        RateLimitEntry entry = rateLimits.get(address);
        if (entry == null) {
            return false;
        }

        // Clean up expired entries
        if (entry.isExpired(timeoutMinutes)) {
            rateLimits.remove(address);
            return false;
        }

        return entry.getAttempts() >= maxAttempts;
    }

    /**
     * Increments attempt count for IP address.
     *
     * @param address IP address to increment for
     * @return current attempt count after increment
     */
    public int incrementAttempts(InetAddress address) {
        if (address == null) {
            return 0;
        }

        RateLimitEntry entry = rateLimits.computeIfAbsent(address, k -> new RateLimitEntry());

        // Reset if expired
        if (entry.isExpired(timeoutMinutes)) {
            entry.reset();
        }

        entry.increment();
        return entry.getAttempts();
    }

    /**
     * Resets rate limit for IP address.
     *
     * @param address IP address to reset
     */
    public void reset(InetAddress address) {
        if (address != null) {
            rateLimits.remove(address);
        }
    }

    /**
     * Gets current attempt count for IP address.
     *
     * @param address IP address to check
     * @return current attempt count (0 if not tracked)
     */
    public int getAttempts(InetAddress address) {
        if (address == null) {
            return 0;
        }

        RateLimitEntry entry = rateLimits.get(address);
        if (entry == null) {
            return 0;
        }

        // Clean up expired entries
        if (entry.isExpired(timeoutMinutes)) {
            rateLimits.remove(address);
            return 0;
        }

        return entry.getAttempts();
    }

    /**
     * Clears all rate limit entries.
     */
    public void clearAll() {
        rateLimits.clear();
    }

    /**
     * Gets the number of tracked IP addresses.
     *
     * @return number of tracked IPs
     */
    public int size() {
        return rateLimits.size();
    }

    /**
     * Rate limit entry for a single IP address.
     * Thread-safe: atomic operations for thread safety.
     * <p>
     * IMPORTANT: Uses AtomicInteger instead of volatile int to prevent race conditions.
     * The original volatile int attempts++ implementation had a concurrency bug where
     * concurrent requests could bypass rate limiting due to lost updates (e.g., 987/1000
     * increments recorded in testing). AtomicInteger.incrementAndGet() provides atomic
     * read-modify-write operations, preventing brute force bypass attacks.
     */
    private static class RateLimitEntry {
        private final AtomicInteger attempts = new AtomicInteger(0);
        private volatile long firstAttemptTime = System.currentTimeMillis();

        public void increment() {
            attempts.incrementAndGet();
        }

        public int getAttempts() {
            return attempts.get();
        }

        public void reset() {
            attempts.set(0);
            firstAttemptTime = System.currentTimeMillis();
        }

        public boolean isExpired(int timeoutMinutes) {
            long timeoutMillis = timeoutMinutes * 60L * 1000L;
            return (System.currentTimeMillis() - firstAttemptTime) > timeoutMillis;
        }
    }
}
