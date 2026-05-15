package net.rafalohaki.veloauth.cache;

import com.github.benmanes.caffeine.cache.Cache;
import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.time.Duration;
import java.util.UUID;

/**
 * Manages active player sessions with anti-hijacking protection.
 * <p>
 * Storage is Caffeine, configured with size + access-TTL. The legacy
 * {@code ConcurrentHashMap + ReentrantLock + manual LRU eviction} approach
 * was replaced because (a) Caffeine's W-TinyLFU evicts in O(1), and (b)
 * the only lock we actually need — the one that makes {@code endSession}
 * wait for an in-flight {@link #hasActiveSession} to finish — is now
 * enforced by Caffeine's per-node synchronization on {@code asMap().computeIfPresent}
 * vs {@code invalidate}.
 */
class SessionManager {

    private static final Logger logger = LoggerFactory.getLogger(SessionManager.class);
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final Cache<UUID, AuthCache.ActiveSession> activeSessions;
    private final int sessionTimeoutMinutes;
    private final Messages messages;

    SessionManager(int maxSessions, int sessionTimeoutMinutes, Messages messages) {
        this.sessionTimeoutMinutes = sessionTimeoutMinutes;
        this.messages = messages;
        this.activeSessions = VeloAuthCaches.accessTtl(
                maxSessions, Duration.ofMinutes(Math.max(1, sessionTimeoutMinutes)));
    }

    /**
     * Starts an active player session. Caffeine auto-evicts the LRU entry if the
     * cache is at capacity; no explicit guard needed.
     */
    void startSession(UUID uuid, String nickname, String ip) {
        if (uuid == null || nickname == null) {
            return;
        }
        AuthCache.ActiveSession session = new AuthCache.ActiveSession(uuid, nickname, ip);
        activeSessions.put(uuid, session);
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.session.started"), nickname, uuid, ip);
        }
    }

    /**
     * Ends a session. Synchronizes with {@link #hasActiveSession} on the same key
     * via Caffeine's per-node lock — a concurrent {@code invalidate(uuid)} blocks until
     * an in-flight {@code computeIfPresent(uuid, …)} returns, preserving the contract
     * pinned by {@code SessionManagerTest.testHasActiveSession_ConcurrentEndSession_*}.
     */
    void endSession(UUID uuid) {
        if (uuid == null) {
            return;
        }
        AuthCache.ActiveSession removed = activeSessions.asMap().remove(uuid);
        if (removed != null && logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.session.ended"), removed.getNickname(), uuid);
        }
    }

    /**
     * Validates a session: must exist, be within the timeout window, and match nickname + IP.
     * Side-effect: hijack / IP-mismatch / timeout drops the entry; success extends activity.
     * <p>
     * The whole check-and-update runs inside Caffeine's {@code computeIfPresent}, which
     * holds a per-key lock for the duration of the lambda. That gives us atomicity with
     * {@link #endSession} — a concurrent removal blocks until this lambda returns — without
     * paying for a global {@link java.util.concurrent.locks.ReentrantLock}.
     */
    boolean hasActiveSession(UUID uuid, String nickname, String currentIp) {
        if (uuid == null || nickname == null || currentIp == null) {
            return false;
        }
        AuthCache.ActiveSession validated = activeSessions.asMap().computeIfPresent(uuid,
                (key, session) -> validateOrEvict(key, session, nickname, currentIp));
        return validated != null;
    }

    /** Returns the session if valid, or {@code null} to evict it under the compute lock. */
    private AuthCache.ActiveSession validateOrEvict(UUID uuid, AuthCache.ActiveSession session,
                                                    String nickname, String currentIp) {
        if (!session.isActive(sessionTimeoutMinutes)) {
            return null;
        }
        if (!session.getNickname().equalsIgnoreCase(nickname)) {
            if (logger.isWarnEnabled()) {
                logger.warn(SECURITY_MARKER, messages.get("security.session.hijack"),
                        uuid, session.getNickname(), nickname);
            }
            return null;
        }
        if (!session.getIp().equals(currentIp)) {
            if (logger.isWarnEnabled()) {
                logger.warn(SECURITY_MARKER, messages.get("security.session.ip.mismatch"),
                        uuid, session.getIp(), currentIp);
            }
            return null;
        }
        session.updateActivity();
        return session;
    }

    /**
     * Current session count. {@code cleanUp()} first so concurrent-startSession tests
     * see Caffeine-enforced bounds after their assertion, not a momentarily-over-capacity
     * intermediate state.
     */
    int size() {
        activeSessions.cleanUp();
        return (int) Math.min(Integer.MAX_VALUE, activeSessions.estimatedSize());
    }

    void clear() {
        activeSessions.invalidateAll();
    }

    /**
     * Forces Caffeine to run pending maintenance (TTL-expired eviction, size cap).
     * Called from {@link AuthCache#cleanupExpiredEntries()} on the periodic cleanup tick.
     */
    void cleanUp() {
        activeSessions.cleanUp();
    }
}
