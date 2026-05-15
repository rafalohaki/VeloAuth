package net.rafalohaki.veloauth.cache;

import com.github.benmanes.caffeine.cache.Cache;
import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.time.Duration;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Tracks brute-force login attempts per IP and per username, and decides whether
 * a given (IP, username) pair is blocked.
 * <p>
 * Storage is Caffeine, configured with size + write-TTL. The legacy
 * {@code ConcurrentHashMap + LinkedHashMap + ReentrantLock + manual LRU} approach
 * was replaced; Caffeine's W-TinyLFU evicts in O(1) and {@code asMap().compute} +
 * {@code asMap().remove} synchronize on a per-key node lock, which is exactly the
 * coordination contract {@code BruteForceTrackerTest.testResetLoginAttempts_ConcurrentRegister_*}
 * pins.
 * <p>
 * Two complementary expiry mechanisms cooperate:
 * <ul>
 *   <li>Caffeine's {@code expireAfterWrite} bounds memory — entries Caffeine no longer needs
 *       are evicted automatically.</li>
 *   <li>{@link BruteForceEntry#isExpired(int)} bounds the <em>semantic</em> counter window
 *       (measured from the entry's {@code firstAttemptTime}). If Caffeine still has an entry
 *       whose counter window has elapsed, the compute lambda resets it before incrementing.</li>
 * </ul>
 */
class BruteForceTracker {

    private static final Logger logger = LoggerFactory.getLogger(BruteForceTracker.class);
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private static final int MAX_USERNAME_MAP_SIZE = 10_000;
    private static final int MAX_IP_MAP_SIZE = 100_000;

    private final Cache<InetAddress, BruteForceEntry> bruteForceAttempts;
    private final Cache<String, BruteForceEntry> usernameAttempts;
    private final int maxLoginAttempts;
    private final int bruteForceTimeoutMinutes;
    private final Messages messages;

    BruteForceTracker(int maxLoginAttempts, int bruteForceTimeoutMinutes, Messages messages) {
        this.maxLoginAttempts = maxLoginAttempts;
        this.bruteForceTimeoutMinutes = bruteForceTimeoutMinutes;
        this.messages = messages;
        Duration ttl = Duration.ofMinutes(Math.max(1, bruteForceTimeoutMinutes));
        this.bruteForceAttempts = VeloAuthCaches.writeTtl(MAX_IP_MAP_SIZE, ttl);
        this.usernameAttempts = VeloAuthCaches.writeTtl(MAX_USERNAME_MAP_SIZE, ttl);
    }

    /**
     * Records a failed login. Returns {@code true} iff either the per-IP or the per-username
     * counter has reached the {@code maxLoginAttempts} threshold.
     * <p>
     * The IP and username counters are updated under Caffeine's per-key node lock via
     * {@code asMap().compute}. A concurrent {@link #resetLoginAttempts} on the same key
     * waits until the compute lambda returns — preserving the lock contract pinned by
     * the {@code BruteForceTrackerTest} race tests.
     */
    boolean registerFailedLogin(InetAddress address, String username) {
        if (address == null) {
            logger.warn("Null IP address in registerFailedLogin - treating as blocked");
            return true;
        }
        try {
            BruteForceEntry ipEntry = touch(bruteForceAttempts, address);
            boolean ipBlocked = ipEntry.getAttempts() >= maxLoginAttempts;

            boolean usernameBlocked = false;
            if (username != null) {
                String lowerUsername = username.toLowerCase(Locale.ROOT);
                BruteForceEntry userEntry = touch(usernameAttempts, lowerUsername);
                usernameBlocked = userEntry.getAttempts() >= maxLoginAttempts;
            }

            boolean blocked = ipBlocked || usernameBlocked;
            logRegistration(address, ipEntry, blocked);
            return blocked;
        } catch (IllegalStateException e) {
            logger.error(SECURITY_MARKER, "{} {}", messages.get("cache.error.state.register_failed"), address, e);
            return true;
        } catch (IllegalArgumentException e) {
            logger.error(SECURITY_MARKER, "{} {}", messages.get("cache.error.args.register_failed"), address, e);
            return true;
        }
    }

    /**
     * Compute lambda body factored out: get-or-create, semantic-reset if the window expired,
     * then increment. Caffeine's compute holds a per-key lock for the lifetime of this call.
     */
    private <K> BruteForceEntry touch(Cache<K, BruteForceEntry> cache, K key) {
        return cache.asMap().compute(key, (k, existing) -> {
            BruteForceEntry entry = (existing != null) ? existing : new BruteForceEntry();
            if (entry.isExpired(bruteForceTimeoutMinutes)) {
                entry.reset();
            }
            entry.incrementAttempts();
            return entry;
        });
    }

    private void logRegistration(InetAddress address, BruteForceEntry entry, boolean blocked) {
        if (blocked) {
            if (logger.isWarnEnabled()) {
                logger.warn(messages.get("cache.warn.ip.blocked"),
                        address.getHostAddress(), entry.getAttempts());
            }
        } else if (logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.failed.login"),
                    address.getHostAddress(), entry.getAttempts(), maxLoginAttempts);
        }
    }

    /**
     * Returns {@code true} when the IP or the username is currently over the attempt threshold.
     * Caffeine's TTL eviction ensures {@code getIfPresent} never returns a semantically-expired
     * entry, so no explicit expiry check is needed on the read path.
     */
    boolean isBlocked(InetAddress address, String username) {
        if (address == null) {
            return true;
        }
        if (isOverThreshold(bruteForceAttempts.getIfPresent(address))) {
            return true;
        }
        if (username != null) {
            String lower = username.toLowerCase(Locale.ROOT);
            return isOverThreshold(usernameAttempts.getIfPresent(lower));
        }
        return false;
    }

    private boolean isOverThreshold(BruteForceEntry entry) {
        if (entry == null) {
            return false;
        }
        if (entry.isExpired(bruteForceTimeoutMinutes)) {
            return false;
        }
        return entry.getAttempts() >= maxLoginAttempts;
    }

    /**
     * Resets the attempt counters for the given IP and (optional) username. Synchronizes
     * with concurrent {@link #registerFailedLogin} on the same key via Caffeine's per-node lock.
     */
    void resetLoginAttempts(InetAddress address, String username) {
        if (address == null) {
            return;
        }
        BruteForceEntry removedIp = bruteForceAttempts.asMap().remove(address);
        BruteForceEntry removedUser = null;
        if (username != null) {
            removedUser = usernameAttempts.asMap().remove(username.toLowerCase(Locale.ROOT));
        }
        if ((removedIp != null || removedUser != null) && logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.reset.attempts"), address.getHostAddress());
        }
    }

    int size() {
        bruteForceAttempts.cleanUp();
        return (int) Math.min(Integer.MAX_VALUE, bruteForceAttempts.estimatedSize());
    }

    void clear() {
        bruteForceAttempts.invalidateAll();
        usernameAttempts.invalidateAll();
    }

    /**
     * Forces Caffeine to run pending maintenance (write-TTL eviction, size cap).
     * Called from {@link AuthCache#cleanupExpiredEntries()} on the periodic cleanup tick.
     */
    void cleanUp() {
        bruteForceAttempts.cleanUp();
        usernameAttempts.cleanUp();
    }

    /**
     * Brute-force counter entry. The {@code attempts} field is an {@link AtomicInteger}
     * historically — kept this way so existing tests (and any third-party reflection)
     * keep working, even though all increments now happen inside Caffeine's compute lock.
     */
    static class BruteForceEntry {
        private final AtomicInteger attempts = new AtomicInteger(0);
        private volatile long firstAttemptTime = System.currentTimeMillis();

        void incrementAttempts() {
            attempts.incrementAndGet();
        }

        int getAttempts() {
            return attempts.get();
        }

        void reset() {
            attempts.set(0);
            firstAttemptTime = System.currentTimeMillis();
        }

        boolean isExpired(int timeoutMinutes) {
            long timeoutMillis = timeoutMinutes * 60L * 1000L;
            return (System.currentTimeMillis() - firstAttemptTime) > timeoutMillis;
        }
    }
}
