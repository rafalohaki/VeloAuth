package net.rafalohaki.veloauth.cache;

import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages active player sessions with anti-hijacking protection.
 * Extracted from AuthCache for single-responsibility.
 */
class SessionManager {

    private static final Logger logger = LoggerFactory.getLogger(SessionManager.class);
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final ConcurrentHashMap<UUID, AuthCache.ActiveSession> activeSessions;
    private final int maxSessions;
    private final int sessionTimeoutMinutes;
    private final Messages messages;

    SessionManager(int maxSessions, int sessionTimeoutMinutes, Messages messages) {
        this.activeSessions = new ConcurrentHashMap<>();
        this.maxSessions = maxSessions;
        this.sessionTimeoutMinutes = sessionTimeoutMinutes;
        this.messages = messages;
    }

    /**
     * Rozpoczyna aktywną sesję gracza.
     */
    void startSession(UUID uuid, String nickname, String ip) {
        if (uuid == null || nickname == null) {
            return;
        }

        if (activeSessions.size() >= maxSessions && !activeSessions.containsKey(uuid)) {
            evictOldestSessionAtomic();
        }

        AuthCache.ActiveSession session = new AuthCache.ActiveSession(uuid, nickname, ip);
        activeSessions.put(uuid, session);
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.session.started"), nickname, uuid, ip);
        }
    }

    /**
     * Kończy aktywną sesję gracza.
     */
    void endSession(UUID uuid) {
        if (uuid == null) {
            return;
        }

        AuthCache.ActiveSession removed = activeSessions.remove(uuid);
        if (removed != null && logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.session.ended"), removed.getNickname(), uuid);
        }
    }

    /**
     * Sprawdza czy gracz ma aktywną sesję z weryfikacją nickname i IP.
     */
    boolean hasActiveSession(UUID uuid, String nickname, String currentIp) {
        if (uuid == null || nickname == null || currentIp == null) {
            return false;
        }
        AuthCache.ActiveSession session = activeSessions.get(uuid);
        if (session == null) {
            return false;
        }
        if (isNicknameMismatch(session, nickname, uuid)) {
            return false;
        }
        if (isIpMismatch(session, currentIp, uuid)) {
            return false;
        }
        session.updateActivity();
        return true;
    }

    private boolean isNicknameMismatch(AuthCache.ActiveSession session, String nickname, UUID uuid) {
        if (session.getNickname().equalsIgnoreCase(nickname)) {
            return false;
        }
        if (logger.isWarnEnabled()) {
            logger.warn(SECURITY_MARKER, messages.get("security.session.hijack"), uuid, session.getNickname(), nickname);
        }
        activeSessions.remove(uuid);
        return true;
    }

    private boolean isIpMismatch(AuthCache.ActiveSession session, String currentIp, UUID uuid) {
        if (session.getIp().equals(currentIp)) {
            return false;
        }
        if (logger.isWarnEnabled()) {
            logger.warn(SECURITY_MARKER, messages.get("security.session.ip.mismatch"), uuid, session.getIp(), currentIp);
        }
        activeSessions.remove(uuid);
        return true;
    }

    private void evictOldestSessionAtomic() {
        var oldest = activeSessions.entrySet().stream()
                .min(java.util.Comparator.comparingLong(e -> e.getValue().getLastActivityTime()))
                .orElse(null);
        if (oldest != null) {
            activeSessions.remove(oldest.getKey(), oldest.getValue());
        }
    }

    int size() {
        return activeSessions.size();
    }

    void clear() {
        activeSessions.clear();
    }

    /**
     * Cleans up inactive sessions.
     *
     * @return number of removed sessions
     */
    int cleanupExpired() {
        int removed = 0;
        var iterator = activeSessions.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (!entry.getValue().isActive(sessionTimeoutMinutes)) {
                iterator.remove();
                removed++;
            }
        }
        return removed;
    }
}
