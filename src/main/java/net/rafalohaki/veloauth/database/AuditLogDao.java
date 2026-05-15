package net.rafalohaki.veloauth.database;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.stmt.DeleteBuilder;
import com.j256.ormlite.support.ConnectionSource;
import net.rafalohaki.veloauth.model.AuditLogEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.sql.SQLException;

/**
 * Data Access Object for VELOAUTH_AUDIT_LOG.
 * Fail-open behavior: errors are logged but never propagated to callers — an
 * audit-log outage must not break authentication.
 */
public class AuditLogDao {

    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");
    private static final Logger logger = LoggerFactory.getLogger(AuditLogDao.class);

    private final Dao<AuditLogEntry, Long> dao;

    public AuditLogDao(ConnectionSource connectionSource) throws SQLException {
        this.dao = DaoManager.createDao(connectionSource, AuditLogEntry.class);
        logger.debug(DB_MARKER, "AuditLogDao initialized");
    }

    /**
     * Persists one entry. Returns true on success, false on any failure.
     */
    public boolean record(AuditLogEntry entry) {
        if (entry == null) {
            return false;
        }
        try {
            dao.create(entry);
            return true;
        } catch (SQLException e) {
            logger.error(DB_MARKER, "Failed to persist audit log entry (event={})", entry.getEventType(), e);
            return false;
        }
    }

    /**
     * Deletes rows older than {@code cutoffMillis}. Returns the number of
     * deleted rows, or 0 on failure.
     */
    public int deleteOlderThan(long cutoffMillis) {
        try {
            DeleteBuilder<AuditLogEntry, Long> builder = dao.deleteBuilder();
            builder.where().lt("TIMESTAMP", cutoffMillis);
            int deleted = builder.delete();
            if (deleted > 0 && logger.isInfoEnabled()) {
                logger.info(DB_MARKER, "Pruned {} audit log entries older than {}", deleted, cutoffMillis);
            }
            return deleted;
        } catch (SQLException e) {
            logger.error(DB_MARKER, "Failed to prune audit log", e);
            return 0;
        }
    }

    /**
     * Total row count, or -1 on failure.
     */
    public long count() {
        try {
            return dao.countOf();
        } catch (SQLException e) {
            logger.error(DB_MARKER, "Failed to count audit log rows", e);
            return -1L;
        }
    }
}
