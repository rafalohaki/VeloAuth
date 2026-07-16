package net.rafalohaki.veloauth.premium;

import com.github.benmanes.caffeine.cache.Cache;
import net.rafalohaki.veloauth.cache.VeloAuthCaches;

import java.net.InetAddress;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Fixed-window admission budget for cold external premium lookups.
 * <p>
 * The source IP is used only as an abuse boundary; premium cache and database hits never
 * consume the budget. A {@code null} source identifies trusted internal refresh work.
 */
final class PremiumLookupAdmissionController {

    private static final int MAX_TRACKED_ADDRESSES = 100_000;
    private static final Duration WINDOW = Duration.ofMinutes(1);

    private final int maxLookupsPerWindow;
    private final Cache<InetAddress, AtomicInteger> counters =
            VeloAuthCaches.writeTtl(MAX_TRACKED_ADDRESSES, WINDOW);

    PremiumLookupAdmissionController(int maxLookupsPerWindow) {
        if (maxLookupsPerWindow <= 0) {
            throw new IllegalArgumentException("maxLookupsPerWindow must be > 0");
        }
        this.maxLookupsPerWindow = maxLookupsPerWindow;
    }

    boolean tryAcquire(InetAddress sourceAddress) {
        if (sourceAddress == null) {
            return true;
        }
        AtomicInteger counter = counters.get(sourceAddress, ignored -> new AtomicInteger());
        return counter.incrementAndGet() <= maxLookupsPerWindow;
    }

    void clear() {
        counters.invalidateAll();
        counters.cleanUp();
    }
}
