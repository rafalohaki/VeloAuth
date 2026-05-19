package net.rafalohaki.veloauth.audit;

import net.rafalohaki.veloauth.database.AuditLogDao;
import net.rafalohaki.veloauth.model.AuditLogEntry;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.Locale;

/**
 * Async-safe audit log writer. Hot path callers (login, register, 2FA verify)
 * call {@link #record} and return immediately; persistence happens on a virtual thread.
 *
 * <p>Disabling via {@code settings.audit-log.enabled=false} short-circuits every call,
 * so no DB traffic is generated.
 */
public class AuditLogService {

    private static final Marker AUDIT_MARKER = MarkerFactory.getMarker("AUDIT");
    private static final Logger logger = LoggerFactory.getLogger(AuditLogService.class);
    private static final int MAX_DETAILS_LENGTH = 512;

    private final AuditLogDao dao;
    private final boolean enabled;

    public AuditLogService(AuditLogDao dao, boolean enabled) {
        this.dao = dao;
        this.enabled = enabled;
    }

    public boolean isEnabled() {
        return enabled && dao != null;
    }

    /**
     * Schedules an audit row for async write. Returns immediately;
     * persistence failures are logged but never surfaced to callers.
     */
    public void save(AuditEventType eventType, String playerLowercase, String ip, String details) {
        if (!isEnabled() || eventType == null) {
            return;
        }
        AuditLogEntry entry = new AuditLogEntry(
                eventType.storageValue(),
                normalizeNick(playerLowercase),
                ip,
                System.currentTimeMillis(),
                truncate(details)
        );

        boolean submitted = VirtualThreadExecutorProvider.submitTask(() -> {
            try {
                dao.save(entry);
            } catch (RuntimeException e) {
                logger.warn(AUDIT_MARKER, "Audit write failed for event {}", entry.getEventType(), e);
            }
        });

        if (!submitted && logger.isDebugEnabled()) {
            logger.debug(AUDIT_MARKER, "Audit submit skipped (executor shutting down) — dropping {}", eventType);
        }
    }

    /**
     * Convenience overload — no details.
     */
    public void save(AuditEventType eventType, String playerLowercase, String ip) {
        save(eventType, playerLowercase, ip, null);
    }

    /**
     * Removes entries older than {@code retentionDays} days. Returns deleted row count.
     */
    public int prune(int retentionDays) {
        if (!isEnabled()) {
            return 0;
        }
        long cutoff = System.currentTimeMillis() - retentionDaysToMillis(retentionDays);
        return dao.deleteOlderThan(cutoff);
    }

    private long retentionDaysToMillis(int days) {
        if (days < 1) {
            return Long.MAX_VALUE / 2;
        }
        return days * 24L * 60L * 60L * 1000L;
    }

    private String normalizeNick(String nick) {
        if (nick == null || nick.isBlank()) {
            return null;
        }
        return nick.toLowerCase(Locale.ROOT);
    }

    private String truncate(String details) {
        if (details == null) {
            return null;
        }
        return details.length() <= MAX_DETAILS_LENGTH ? details : details.substring(0, MAX_DETAILS_LENGTH);
    }
}
