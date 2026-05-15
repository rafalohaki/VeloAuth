package net.rafalohaki.veloauth.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.Scheduler;

import java.time.Duration;

/**
 * Centralized factory for Caffeine caches used inside VeloAuth.
 * <p>
 * Pinning every cache to the same builder ensures:
 * <ul>
 *   <li>identical eviction policy (W-TinyLFU, Caffeine default),</li>
 *   <li>identical scheduler ({@link Scheduler#systemScheduler()}, so time-based
 *       eviction is proactive instead of "lazy on next read"),</li>
 *   <li>a single place to tune executor / stats / weighing if we ever need to.</li>
 * </ul>
 * <p>
 * Public because {@code PremiumResolverService} (in the {@code premium/} package) also
 * builds its in-memory cache through this factory — keeping every Caffeine touchpoint
 * funneled through one place. No state, pure factory.
 */
public final class VeloAuthCaches {

    private VeloAuthCaches() {
        // Utility class.
    }

    /**
     * Builds a bounded cache that evicts the least-recently-accessed entry once
     * {@code maxSize} is exceeded, and drops entries after {@code accessTtl} of
     * inactivity. Best fit for short-lived state that should self-clean once a
     * player stops touching it (auth sessions, authorization tokens).
     */
    public static <K, V> Cache<K, V> accessTtl(int maxSize, Duration accessTtl) {
        return baseBuilder(maxSize)
                .expireAfterAccess(accessTtl)
                .build();
    }

    /**
     * Like {@link #accessTtl} but anchored to the write timestamp instead of the
     * last access. Best fit for entries that represent a fixed-window counter
     * (brute-force attempts, IP rate-limits) where touching the entry must
     * <em>not</em> extend its lifetime.
     */
    public static <K, V> Cache<K, V> writeTtl(int maxSize, Duration writeTtl) {
        return baseBuilder(maxSize)
                .expireAfterWrite(writeTtl)
                .build();
    }

    /**
     * Builds a bounded cache where each entry sets its own TTL via the supplied
     * {@link Expiry}. Best fit for caches where positive and negative results
     * have different lifetimes (premium hit-ttl vs miss-ttl, premium cache vs
     * negative premium cache, etc).
     */
    public static <K, V> Cache<K, V> variableTtl(int maxSize, Expiry<K, V> expiry) {
        return baseBuilder(maxSize)
                .expireAfter(expiry)
                .build();
    }

    /**
     * Shared base builder — applied to every cache so a future change to
     * the scheduler / executor / stats setup hits all of them at once.
     */
    private static <K, V> Caffeine<K, V> baseBuilder(int maxSize) {
        if (maxSize <= 0) {
            throw new IllegalArgumentException("maxSize must be > 0, got " + maxSize);
        }
        @SuppressWarnings("unchecked")
        Caffeine<K, V> b = (Caffeine<K, V>) Caffeine.newBuilder()
                .maximumSize(maxSize)
                .scheduler(Scheduler.systemScheduler());
        return b;
    }
}
