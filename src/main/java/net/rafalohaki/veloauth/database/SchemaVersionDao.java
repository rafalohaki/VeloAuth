package net.rafalohaki.veloauth.database;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.support.ConnectionSource;
import net.rafalohaki.veloauth.model.SchemaVersion;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.sql.SQLException;
import java.util.List;
import java.util.Optional;

/**
 * Data Access Object for VELOAUTH_SCHEMA_VERSION.
 * Used by {@link DatabaseMigrationService} to track applied migrations.
 */
public class SchemaVersionDao {

    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");
    private static final Logger logger = LoggerFactory.getLogger(SchemaVersionDao.class);

    private final Dao<SchemaVersion, Integer> dao;

    public SchemaVersionDao(ConnectionSource connectionSource) throws SQLException {
        this.dao = DaoManager.createDao(connectionSource, SchemaVersion.class);
        logger.debug(DB_MARKER, "SchemaVersionDao initialized");
    }

    /**
     * Highest applied version, or empty if no migrations recorded yet.
     */
    public Optional<Integer> getCurrentVersion() {
        try {
            List<SchemaVersion> rows = dao.queryBuilder()
                    .orderBy("VERSION", false)
                    .limit(1L)
                    .query();
            if (rows.isEmpty()) {
                return Optional.empty();
            }
            return Optional.of(rows.get(0).getVersion());
        } catch (SQLException e) {
            logger.error(DB_MARKER, "Failed to read current schema version", e);
            return Optional.empty();
        }
    }

    /**
     * @return true if a row with this version already exists.
     */
    public boolean hasVersion(int version) {
        try {
            return dao.idExists(version);
        } catch (SQLException e) {
            logger.error(DB_MARKER, "Failed to check schema version {}", version, e);
            return false;
        }
    }

    /**
     * Records a version row. Idempotent: skips insert if the version is already present.
     */
    public boolean recordVersion(int version, String description) {
        try {
            if (dao.idExists(version)) {
                return true;
            }
            SchemaVersion entry = new SchemaVersion(version, System.currentTimeMillis(), description);
            dao.create(entry);
            if (logger.isInfoEnabled()) {
                logger.info(DB_MARKER, "Recorded schema version {} ({})", version, description);
            }
            return true;
        } catch (SQLException e) {
            logger.error(DB_MARKER, "Failed to record schema version {}", version, e);
            return false;
        }
    }
}
