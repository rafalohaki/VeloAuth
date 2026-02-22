package net.rafalohaki.veloauth.cache;

import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Manages brute-force login attempt tracking and IP blocking.
 * Extracted from AuthCache for single-responsibility.
 */
class BruteForceTracker {

    private static final Logger logger = LoggerFactory.getLogger(BruteForceTracker.class);

    private final ConcurrentHashMap<InetAddress, BruteForceEntry> bruteForceAttempts;
    private final ReentrantLock lock;
    private final int maxLoginAttempts;
    private final int bruteForceTimeoutMinutes;
    private final Messages messages;

    BruteForceTracker(int maxLoginAttempts, int bruteForceTimeoutMinutes, Messages messages) {
        this.bruteForceAttempts = new ConcurrentHashMap<>();
        this.lock = new ReentrantLock();
        this.maxLoginAttempts = maxLoginAttempts;
        this.bruteForceTimeoutMinutes = bruteForceTimeoutMinutes;
        this.messages = messages;
    }

    /**
     * Rejestruje nieudaną próbę logowania.
     *
     * @param address IP adres
     * @return true jeśli przekroczono limit prób
     */
    boolean registerFailedLogin(InetAddress address) {
        if (address == null) {
            return false;
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

                boolean blocked = entry.getAttempts() >= maxLoginAttempts;
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
            logger.error(messages.get("cache.error.state.register_failed") + address, e);
            return false;
        } catch (IllegalArgumentException e) {
            logger.error(messages.get("cache.error.args.register_failed") + address, e);
            return false;
        }
    }

    /**
     * Sprawdza czy IP jest zablokowany za brute force.
     */
    boolean isBlocked(InetAddress address) {
        if (address == null) {
            return false;
        }

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
     * Resetuje próby logowania dla IP.
     */
    void resetLoginAttempts(InetAddress address) {
        if (address != null) {
            BruteForceEntry removed = bruteForceAttempts.remove(address);
            if (removed != null && logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.debug.reset.attempts"), address.getHostAddress());
            }
        }
    }

    int size() {
        return bruteForceAttempts.size();
    }

    void clear() {
        bruteForceAttempts.clear();
    }

    /**
     * Cleans up expired brute-force entries.
     *
     * @return number of removed entries
     */
    int cleanupExpired() {
        int removed = 0;
        var iterator = bruteForceAttempts.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (entry.getValue().isExpired(bruteForceTimeoutMinutes)) {
                iterator.remove();
                removed++;
            }
        }
        return removed;
    }

    /**
     * Wpis brute force.
     */
    static class BruteForceEntry {
        private volatile int attempts = 0;
        private volatile long firstAttemptTime = System.currentTimeMillis();

        void incrementAttempts() {
            attempts++;
        }

        int getAttempts() {
            return attempts;
        }

        void reset() {
            attempts = 0;
            firstAttemptTime = System.currentTimeMillis();
        }

        boolean isExpired(int timeoutMinutes) {
            long timeoutMillis = timeoutMinutes * 60L * 1000L;
            return (System.currentTimeMillis() - firstAttemptTime) > timeoutMillis;
        }
    }
}
