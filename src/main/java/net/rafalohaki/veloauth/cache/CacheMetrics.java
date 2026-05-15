package net.rafalohaki.veloauth.cache;

import java.util.Locale;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Hit / miss counter and hit-rate formatter shared by every VeloAuth cache.
 * <p>
 * Caffeine has its own {@code recordStats()} machinery but the on-by-default
 * snapshot is heavier than what we actually need (it tracks load times,
 * load failures, eviction weights, …). For our metric log lines we only
 * need hits + misses + percent; an explicit pair of {@link AtomicLong}s
 * keeps the value semantics identical to the pre-refactor code and avoids
 * paying for the unused stats machinery on every cache access.
 */
final class CacheMetrics {

    private final AtomicLong hits = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();

    void recordHit() {
        hits.incrementAndGet();
    }

    void recordMiss() {
        misses.incrementAndGet();
    }

    long getHits() {
        return hits.get();
    }

    long getMisses() {
        return misses.get();
    }

    long getTotalRequests() {
        return hits.get() + misses.get();
    }

    /**
     * Hit rate as a percentage in {@code [0.0, 100.0]}. Returns {@code 0.0}
     * when no requests have been recorded so callers don't have to special-case
     * the "fresh cache" log line.
     */
    double getHitRate() {
        long h = hits.get();
        long total = h + misses.get();
        return total == 0 ? 0.0 : (double) h / total * 100.0;
    }

    /**
     * "57.3" — formatted hit rate with one decimal, locale-independent.
     * Kept as a separate method so the format string lives in exactly one place.
     */
    String formatHitRate() {
        return String.format(Locale.US, "%.1f", getHitRate());
    }
}
