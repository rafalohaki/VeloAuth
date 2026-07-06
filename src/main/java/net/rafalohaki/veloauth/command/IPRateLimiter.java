package net.rafalohaki.veloauth.command;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * IP-based rate limiting for authentication commands. Caffeine-backed: W-TinyLFU evicts
 * LRU entries when the cache is at capacity, so a flood of distinct attacker IPs cannot
 * starve out legitimate users' entries — fresh attackers replace older attackers, not
 * legitimate users. Write-TTL bounds entry lifetime to the configured timeout window.
 * <p>
 * Replaces the previous {@code ConcurrentHashMap + manual cleanupExpired + fail-closed
 * at MAX_ENTRIES} implementation, which had a DoS surface: under a sustained attack from
 * ≥10k distinct IPs, every new legitimate user was reported as rate-limited.
 */
public class IPRateLimiter {

    private static final Logger logger = LoggerFactory.getLogger(IPRateLimiter.class);
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    /** Upper bound on tracked IPs. Caffeine evicts LRU when reached — no fail-closed surface. */
    private static final int MAX_ENTRIES = 10_000;

    private final Cache<InetAddress, RateLimitEntry> rateLimits;
    private final int maxAttempts;
    private final int timeoutMinutes;

    /**
     * Creates a new IPRateLimiter.
     *
     * @param maxAttempts    Maximum attempts per IP within the time window
     * @param timeoutMinutes Time window in minutes
     */
    public IPRateLimiter(int maxAttempts, int timeoutMinutes) {
        if (maxAttempts <= 0) {
            throw new IllegalArgumentException("Max attempts must be > 0");
        }
        if (timeoutMinutes <= 0) {
            throw new IllegalArgumentException("Timeout minutes must be > 0");
        }

        this.maxAttempts = maxAttempts;
        this.timeoutMinutes = timeoutMinutes;
        this.rateLimits = Caffeine.newBuilder()
                .maximumSize(MAX_ENTRIES)
                .expireAfterWrite(Duration.ofMinutes(timeoutMinutes))
                .build();
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
        RateLimitEntry entry = rateLimits.getIfPresent(address);
        if (entry == null) {
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
        RateLimitEntry entry = rateLimits.asMap().compute(address, (k, existing) -> {
            RateLimitEntry e = (existing != null) ? existing : new RateLimitEntry();
            e.increment();
            return e;
        });
        int attempts = entry.getAttempts();
        logThresholdActivity(address, attempts);
        return attempts;
    }

    /**
     * Logs threshold crossings and ongoing post-threshold hammering.
     * <ul>
     *   <li>{@code attempts == maxAttempts} — first breach, WARN once. Operator-actionable.</li>
     *   <li>{@code attempts > maxAttempts &&  attempts % maxAttempts == 0} — every additional
     *       {@code maxAttempts} hits past the threshold, WARN again. Gives visibility into
     *       sustained attacks without spamming the log on every increment.</li>
     *   <li>Otherwise — DEBUG. Quiet by default but available with debug enabled.</li>
     * </ul>
     */
    private void logThresholdActivity(InetAddress address, int attempts) {
        if (attempts < maxAttempts) {
            if (logger.isDebugEnabled()) {
                logger.debug(SECURITY_MARKER, "IP {} attempt {}/{}",
                        address.getHostAddress(), attempts, maxAttempts);
            }
            return;
        }
        if (attempts == maxAttempts) {
            if (logger.isWarnEnabled()) {
                logger.warn(SECURITY_MARKER, "IP {} reached rate limit ({} attempts in {}min)",
                        address.getHostAddress(), maxAttempts, timeoutMinutes);
            }
            return;
        }
        // attempts > maxAttempts — sustained hammering. Warn every maxAttempts hits to keep
        // log volume bounded; debug-log the rest so the trace is still available.
        if (attempts % maxAttempts == 0) {
            if (logger.isWarnEnabled()) {
                logger.warn(SECURITY_MARKER,
                        "IP {} still hammering — {} attempts past rate limit ({} total)",
                        address.getHostAddress(), attempts - maxAttempts, attempts);
            }
        } else if (logger.isDebugEnabled()) {
            logger.debug(SECURITY_MARKER, "IP {} blocked attempt {} (past threshold)",
                    address.getHostAddress(), attempts);
        }
    }

    /**
     * Resets rate limit for IP address.
     *
     * @param address IP address to reset
     */
    public void reset(InetAddress address) {
        if (address != null) {
            rateLimits.invalidate(address);
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
        RateLimitEntry entry = rateLimits.getIfPresent(address);
        return entry == null ? 0 : entry.getAttempts();
    }

    /**
     * Forces Caffeine maintenance (write-TTL eviction, size cap). Called from
     * {@code AuthCache.cleanupExpiredEntries()} on the periodic cleanup tick so the
     * legacy {@code cleanupExpired()} call site continues to work.
     *
     * @return always 0 — Caffeine evicts asynchronously, no precise count is available
     */
    public int cleanupExpired() {
        rateLimits.cleanUp();
        return 0;
    }

    /**
     * Clears all rate limit entries.
     */
    public void clearAll() {
        rateLimits.invalidateAll();
    }

    /**
     * No-op shutdown hook. Caffeine-backed storage is GC'd naturally and entries are
     * periodically cleaned via {@code AuthCache.cleanupExpiredEntries()}. Kept for
     * lifecycle symmetry with other components ({@code AuthCache}, {@code DatabaseManager},
     * etc.) so callers can shut down every collaborator through the same call site.
     */
    public void shutdown() {
        // Intentionally empty — see Javadoc.
    }

    /**
     * Gets the number of tracked IP addresses.
     *
     * @return number of tracked IPs (estimate — Caffeine eviction is asynchronous)
     */
    public int size() {
        rateLimits.cleanUp();
        return (int) Math.min(Integer.MAX_VALUE, rateLimits.estimatedSize());
    }

    /**
     * Rate limit entry for a single IP address.
     * <p>
     * Uses {@link AtomicInteger} so concurrent {@code incrementAttempts} cannot lose
     * updates — even though Caffeine's per-key compute already serializes writes,
     * defensive atomicity here keeps the contract obvious for reads outside compute.
     */
    private static final class RateLimitEntry {
        private final AtomicInteger attempts = new AtomicInteger(0);

        void increment() {
            attempts.incrementAndGet();
        }

        int getAttempts() {
            return attempts.get();
        }
    }
}
