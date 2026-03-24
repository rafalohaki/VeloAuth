package net.rafalohaki.veloauth.command;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * IP-based rate limiting for authentication commands.
 * Thread-safe: uses ConcurrentHashMap and atomic operations.
 * Enforces a maximum entry count to prevent memory exhaustion under sustained attack.
 */
public class IPRateLimiter {

    private static final Logger logger = LoggerFactory.getLogger(IPRateLimiter.class);
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    /**
     * Maximum number of tracked IPs to prevent unbounded memory growth.
     */
    private static final int MAX_ENTRIES = 10_000;

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
            return true; // fail-closed: unknown IP is rate limited
        }

        RateLimitEntry entry = rateLimits.get(address);
        if (entry == null) {
            return false;
        }

        // Clean up expired entries
        if (entry.isExpired(timeoutMinutes)) {
            rateLimits.remove(address, entry);
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
            return Integer.MAX_VALUE; // fail-closed: unknown IP treated as max attempts
        }

        if (rateLimits.size() >= MAX_ENTRIES && !rateLimits.containsKey(address)) {
            cleanupExpired();
            if (rateLimits.size() >= MAX_ENTRIES) {
                logger.warn(SECURITY_MARKER,
                        "IP rate limiter at capacity ({} entries), rejecting new IP {}",
                        rateLimits.size(), address.getHostAddress());
                return Integer.MAX_VALUE; // fail-closed: treat as rate limited
            }
        }

        RateLimitEntry entry = rateLimits.compute(address, (k, existing) -> {
            if (existing == null || existing.isExpired(timeoutMinutes)) {
                RateLimitEntry fresh = new RateLimitEntry();
                fresh.increment();
                return fresh;
            }
            existing.increment();
            return existing;
        });

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
            rateLimits.remove(address, entry);
            return 0;
        }

        return entry.getAttempts();
    }

    /**
     * Removes all expired rate-limit entries.
     * Called periodically by AuthCache cleanup and on-demand when capacity is reached.
     *
     * @return number of removed entries
     */
    public int cleanupExpired() {
        int removed = 0;
        var iterator = rateLimits.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (entry.getValue().isExpired(timeoutMinutes)) {
                iterator.remove();
                removed++;
            }
        }
        if (removed > 0 && logger.isDebugEnabled()) {
            logger.debug(SECURITY_MARKER,
                    "IP rate limiter cleanup: removed {} expired entries, {} remaining",
                    removed, rateLimits.size());
        }
        return removed;
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
    private static final class RateLimitEntry {
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
