package net.rafalohaki.veloauth.cache;

import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Manages brute-force login attempt tracking and IP blocking.
 * Tracks both per-IP and per-username failed login attempts.
 * Extracted from AuthCache for single-responsibility.
 */
class BruteForceTracker {

    private static final Logger logger = LoggerFactory.getLogger(BruteForceTracker.class);
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");
    private static final int MAX_USERNAME_MAP_SIZE = 10000;

    private final ConcurrentHashMap<InetAddress, BruteForceEntry> bruteForceAttempts;
    private final ConcurrentHashMap<String, BruteForceEntry> usernameAttempts;
    private final ReentrantLock lock;
    private final int maxLoginAttempts;
    private final int bruteForceTimeoutMinutes;
    private final Messages messages;

    BruteForceTracker(int maxLoginAttempts, int bruteForceTimeoutMinutes, Messages messages) {
        this.bruteForceAttempts = new ConcurrentHashMap<>();
        this.usernameAttempts = new ConcurrentHashMap<>();
        this.lock = new ReentrantLock();
        this.maxLoginAttempts = maxLoginAttempts;
        this.bruteForceTimeoutMinutes = bruteForceTimeoutMinutes;
        this.messages = messages;
    }

    /**
     * Rejestruje nieudaną próbę logowania.
     *
     * @param address  IP adres
     * @param username nazwa gracza (nullable — skips username tracking when null)
     * @return true jeśli przekroczono limit prób (IP or username)
     */
    boolean registerFailedLogin(InetAddress address, String username) {
        if (address == null) {
            logger.warn("Null IP address in registerFailedLogin - treating as blocked");
            return true;
        }

        try {
            lock.lock();
            try {
                BruteForceEntry entry = bruteForceAttempts.computeIfAbsent(
                        address,
                        k -> new BruteForceEntry()
                );

                if (entry.isExpired(bruteForceTimeoutMinutes)) {
                    entry.reset();
                }

                entry.incrementAttempts();

                boolean ipBlocked = entry.getAttempts() >= maxLoginAttempts;
                boolean usernameBlocked = false;

                if (username != null) {
                    String lowerUsername = username.toLowerCase(java.util.Locale.ROOT);
                    enforceUsernameMapSizeLimit();
                    BruteForceEntry usernameEntry = usernameAttempts.computeIfAbsent(
                            lowerUsername,
                            k -> new BruteForceEntry()
                    );

                    if (usernameEntry.isExpired(bruteForceTimeoutMinutes)) {
                        usernameEntry.reset();
                    }

                    usernameEntry.incrementAttempts();
                    usernameBlocked = usernameEntry.getAttempts() >= maxLoginAttempts;
                }

                boolean blocked = ipBlocked || usernameBlocked;
                if (blocked) {
                    if (logger.isWarnEnabled()) {
                        logger.warn(messages.get("cache.warn.ip.blocked"),
                                address.getHostAddress(), entry.getAttempts());
                    }
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(messages.get("cache.debug.failed.login"),
                                address.getHostAddress(), entry.getAttempts(), maxLoginAttempts);
                    }
                }

                return blocked;
            } finally {
                lock.unlock();
            }
        } catch (IllegalStateException e) {
            logger.error(SECURITY_MARKER, "{} {}", messages.get("cache.error.state.register_failed"), address, e);
            return true;
        } catch (IllegalArgumentException e) {
            logger.error(SECURITY_MARKER, "{} {}", messages.get("cache.error.args.register_failed"), address, e);
            return true;
        }
    }

    /**
     * Sprawdza czy IP lub username jest zablokowany za brute force.
     *
     * @param address  IP adres
     * @param username nazwa gracza (nullable — skips username check when null)
     * @return true jeśli zablokowany
     */
    boolean isBlocked(InetAddress address, String username) {
        if (address == null) {
            return true; // fail-closed: unknown IP is blocked
        }

        lock.lock();
        try {
            boolean ipBlocked = isIpBlocked(address);

            if (username != null) {
                String lowerUsername = username.toLowerCase(java.util.Locale.ROOT);
                BruteForceEntry usernameEntry = usernameAttempts.get(lowerUsername);
                if (usernameEntry != null) {
                    if (usernameEntry.isExpired(bruteForceTimeoutMinutes)) {
                        usernameAttempts.remove(lowerUsername);
                    } else if (usernameEntry.getAttempts() >= maxLoginAttempts) {
                        return true;
                    }
                }
            }

            return ipBlocked;
        } finally {
            lock.unlock();
        }
    }

    private boolean isIpBlocked(InetAddress address) {
        BruteForceEntry entry = bruteForceAttempts.get(address);
        if (entry == null) {
            return false;
        }

        if (entry.isExpired(bruteForceTimeoutMinutes)) {
            bruteForceAttempts.remove(address);
            return false;
        }

        return entry.getAttempts() >= maxLoginAttempts;
    }

    /**
     * Resetuje próby logowania dla IP i username.
     *
     * @param address  IP adres
     * @param username nazwa gracza (nullable — skips username reset when null)
     */
    void resetLoginAttempts(InetAddress address, String username) {
        if (address == null) {
            return;
        }

        BruteForceEntry removed;
        BruteForceEntry usernameRemoved = null;
        lock.lock();
        try {
            removed = bruteForceAttempts.remove(address);
            if (username != null) {
                usernameRemoved = usernameAttempts.remove(username.toLowerCase(java.util.Locale.ROOT));
            }
        } finally {
            lock.unlock();
        }

        if ((removed != null || usernameRemoved != null) && logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.reset.attempts"), address.getHostAddress());
        }
    }

    int size() {
        lock.lock();
        try {
            return bruteForceAttempts.size();
        } finally {
            lock.unlock();
        }
    }

    void clear() {
        lock.lock();
        try {
            bruteForceAttempts.clear();
            usernameAttempts.clear();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Enforces size limit on username attempts map.
     * Must be called while holding the lock.
     */
    private void enforceUsernameMapSizeLimit() {
        if (usernameAttempts.size() <= MAX_USERNAME_MAP_SIZE) {
            return;
        }

        // First pass: remove expired entries
        var iterator = usernameAttempts.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (entry.getValue().isExpired(bruteForceTimeoutMinutes)) {
                iterator.remove();
            }
        }

        // Second pass: if still over limit, evict oldest entries
        if (usernameAttempts.size() > MAX_USERNAME_MAP_SIZE) {
            int toRemove = usernameAttempts.size() - MAX_USERNAME_MAP_SIZE;
            var evictIterator = usernameAttempts.entrySet().iterator();
            while (evictIterator.hasNext() && toRemove > 0) {
                evictIterator.next();
                evictIterator.remove();
                toRemove--;
            }
        }
    }

    /**
     * Cleans up expired brute-force entries (both IP and username maps).
     *
     * @return number of removed entries
     */
    int cleanupExpired() {
        lock.lock();
        try {
            int removed = 0;
            var iterator = bruteForceAttempts.entrySet().iterator();
            while (iterator.hasNext()) {
                var entry = iterator.next();
                if (entry.getValue().isExpired(bruteForceTimeoutMinutes)) {
                    iterator.remove();
                    removed++;
                }
            }

            var usernameIterator = usernameAttempts.entrySet().iterator();
            while (usernameIterator.hasNext()) {
                var entry = usernameIterator.next();
                if (entry.getValue().isExpired(bruteForceTimeoutMinutes)) {
                    usernameIterator.remove();
                    removed++;
                }
            }

            return removed;
        } finally {
            lock.unlock();
        }
    }

    /**
     * Wpis brute force.
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
