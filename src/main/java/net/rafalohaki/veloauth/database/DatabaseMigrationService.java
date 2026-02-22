package net.rafalohaki.veloauth.database;

import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.table.TableUtils;
import net.rafalohaki.veloauth.model.PremiumUuid;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.sql.SQLException;

/**
 * Handles database schema creation, migration, and index management.
 * Extracted from DatabaseManager for single-responsibility.
 */
public class DatabaseMigrationService {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseMigrationService.class);
    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");

    private static final String ALTER_TABLE = "ALTER TABLE ";
    private static final String ADD_COLUMN = " ADD COLUMN ";
    private static final String AUTH_TABLE = "AUTH";

    private final DatabaseConfig config;

    public DatabaseMigrationService(DatabaseConfig config) {
        this.config = config;
    }

    /**
     * Creates tables if they don't exist and migrates schema for limboauth compatibility.
     */
    public void createTablesAndMigrate(ConnectionSource connectionSource, String createTablesMsg, String tablesCreatedMsg) throws SQLException {
        if (logger.isDebugEnabled()) {
            logger.debug(createTablesMsg);
        }

        createTablesQuietly(connectionSource);

        migrateAuthTableForLimboauth(connectionSource);
        createIndexesIfNotExists(connectionSource);

        if (logger.isDebugEnabled()) {
            logger.debug(tablesCreatedMsg);
        }
    }

    /**
     * Creates tables using ORMLite's createTableIfNotExists, suppressing ORMLite's
     * verbose INFO logging ("creating table 'AUTH'", SQL statements) which fires
     * on every startup even when tables already exist.
     *
     * Uses ORMLite's own Logger API since Velocity runs Log4j2 which ignores JUL setLevel calls.
     */
    private void createTablesQuietly(ConnectionSource connectionSource) throws SQLException {
        try {
            // Suppress ORMLite's internal INFO logs during table creation check
            com.j256.ormlite.logger.Logger.setGlobalLogLevel(com.j256.ormlite.logger.Level.WARNING);

            TableUtils.createTableIfNotExists(connectionSource, RegisteredPlayer.class);
            TableUtils.createTableIfNotExists(connectionSource, PremiumUuid.class);

            if (logger.isDebugEnabled()) {
                logger.debug(DB_MARKER, "Tables verified (CREATE TABLE IF NOT EXISTS)");
            }
        } finally {
            // Reset to default (null = no global override, use per-logger levels)
            com.j256.ormlite.logger.Logger.setGlobalLogLevel(null);
        }
    }

    private void migrateAuthTableForLimboauth(ConnectionSource connectionSource) throws SQLException {
        DatabaseConnection dbConnection = connectionSource.getReadWriteConnection(null);
        try {
            performColumnMigration(dbConnection);
        } finally {
            connectionSource.releaseConnection(dbConnection);
        }
    }

    private void performColumnMigration(DatabaseConnection dbConnection) throws SQLException {
        java.sql.Connection connection = dbConnection.getUnderlyingConnection();
        ColumnMigrationResult migrationResult = checkExistingColumns(connection);
        DatabaseType dbType = DatabaseType.fromName(config.getStorageType());
        String quote = dbType == DatabaseType.POSTGRESQL ? "\"" : "`";

        addMissingColumns(connection, migrationResult, quote);
        logMigrationComplete(migrationResult);
    }

    private ColumnMigrationResult checkExistingColumns(java.sql.Connection connection) throws SQLException {
        boolean hasPremiumUuid = columnExists(connection, AUTH_TABLE, "PREMIUMUUID");
        boolean hasTotpToken = columnExists(connection, AUTH_TABLE, "TOTPTOKEN");
        boolean hasIssuedTime = columnExists(connection, AUTH_TABLE, "ISSUEDTIME");
        boolean hasConflictMode = columnExists(connection, AUTH_TABLE, "CONFLICT_MODE");
        boolean hasConflictTimestamp = columnExists(connection, AUTH_TABLE, "CONFLICT_TIMESTAMP");
        boolean hasOriginalNickname = columnExists(connection, AUTH_TABLE, "ORIGINAL_NICKNAME");
        return new ColumnMigrationResult(hasPremiumUuid, hasTotpToken, hasIssuedTime, hasConflictMode, hasConflictTimestamp, hasOriginalNickname);
    }

    private void addMissingColumns(java.sql.Connection connection, ColumnMigrationResult result, String quote) throws SQLException {
        if (!result.hasPremiumUuid) {
            addColumn(connection, quote, "PREMIUMUUID", "VARCHAR(36)", "Added column PREMIUMUUID to AUTH table");
        }
        if (!result.hasTotpToken) {
            addColumn(connection, quote, "TOTPTOKEN", "VARCHAR(32)", "Added column TOTPTOKEN to AUTH table");
        }
        if (!result.hasIssuedTime) {
            addColumn(connection, quote, "ISSUEDTIME", "BIGINT DEFAULT 0", "Added column ISSUEDTIME to AUTH table");
        }
        if (!result.hasConflictMode) {
            addColumn(connection, quote, "CONFLICT_MODE", "BOOLEAN DEFAULT FALSE", "Added column CONFLICT_MODE to AUTH table");
        }
        if (!result.hasConflictTimestamp) {
            addColumn(connection, quote, "CONFLICT_TIMESTAMP", "BIGINT DEFAULT 0", "Added column CONFLICT_TIMESTAMP to AUTH table");
        }
        if (!result.hasOriginalNickname) {
            addColumn(connection, quote, "ORIGINAL_NICKNAME", "VARCHAR(16)", "Added column ORIGINAL_NICKNAME to AUTH table");
        }
    }

    private void addColumn(java.sql.Connection connection, String quote, String columnName, String columnDefinition, String logMessage) throws SQLException {
        String sql = ALTER_TABLE + quote + AUTH_TABLE + quote + ADD_COLUMN + quote + columnName + quote + " " + columnDefinition;
        try {
            executeAlterTable(connection, sql);
            if (logger.isInfoEnabled()) {
                logger.info(DB_MARKER, logMessage);
            }
        } catch (SQLException e) {
            if (e.getErrorCode() == 42121 || e.getMessage().toLowerCase().contains("duplicate column")) {
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "Column {} already exists in table {} - skipping (expected behavior)",
                              columnName, AUTH_TABLE);
                }
            } else {
                throw e;
            }
        }
    }

    private void logMigrationComplete(ColumnMigrationResult result) {
        if (logger.isDebugEnabled() && (!result.hasPremiumUuid || !result.hasTotpToken || !result.hasIssuedTime)) {
            logger.debug(DB_MARKER, "AUTH schema migration for limboauth completed");
        }
    }

    @SuppressWarnings("java:S2077")
    private void executeAlterTable(java.sql.Connection connection, String sql) throws SQLException {
        try (java.sql.Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    private boolean columnExists(java.sql.Connection connection, String tableName, String columnName) throws SQLException {
        java.sql.DatabaseMetaData metaData = connection.getMetaData();

        try (java.sql.ResultSet columns = metaData.getColumns(null, null, tableName, null)) {
            while (columns.next()) {
                String existingColumn = columns.getString("COLUMN_NAME");
                if (existingColumn != null && existingColumn.equalsIgnoreCase(columnName)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(DB_MARKER, "Column {} exists in table {} (found as: {})",
                                   columnName, tableName, existingColumn);
                    }
                    return true;
                }
            }
        }

        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, "Column {} does not exist in table {}", columnName, tableName);
        }
        return false;
    }

    private void createIndexesIfNotExists(ConnectionSource connectionSource) {
        DatabaseType dbType = DatabaseType.fromName(config.getStorageType());

        if (dbType == DatabaseType.POSTGRESQL) {
            createPostgreSqlIndexes(connectionSource);
        } else if (dbType == DatabaseType.MYSQL) {
            createMySqlIndexes(connectionSource);
        }
    }

    private void createPostgreSqlIndexes(ConnectionSource connectionSource) {
        createIndexSafely(connectionSource, "CREATE INDEX IF NOT EXISTS idx_auth_ip ON \"AUTH\" (\"IP\")");
        createIndexSafely(connectionSource, "CREATE INDEX IF NOT EXISTS idx_auth_uuid ON \"AUTH\" (\"UUID\")");
        createIndexSafely(connectionSource, "CREATE INDEX IF NOT EXISTS idx_auth_logindate ON \"AUTH\" (\"LOGINDATE\")");
        createIndexSafely(connectionSource, "CREATE INDEX IF NOT EXISTS idx_auth_regdate ON \"AUTH\" (\"REGDATE\")");
    }

    private void createMySqlIndexes(ConnectionSource connectionSource) {
        createIndexSafely(connectionSource, "CREATE INDEX IF NOT EXISTS idx_auth_ip ON `AUTH` (`IP`)");
        createIndexSafely(connectionSource, "CREATE INDEX IF NOT EXISTS idx_auth_uuid ON `AUTH` (`UUID`)");
        createIndexSafely(connectionSource, "CREATE INDEX IF NOT EXISTS idx_auth_logindate ON `AUTH` (`LOGINDATE`)");
        createIndexSafely(connectionSource, "CREATE INDEX IF NOT EXISTS idx_auth_regdate ON `AUTH` (`REGDATE`)");
    }

    private void createIndexSafely(ConnectionSource connectionSource, String sql) {
        try {
            executeUpdate(connectionSource, sql);
        } catch (SQLException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Index creation failed (may already exist): {}", e.getMessage());
            }
        }
    }

    private void executeUpdate(ConnectionSource connectionSource, String sql) throws SQLException {
        if (connectionSource != null) {
            DatabaseConnection connection = null;
            try {
                connection = connectionSource.getReadWriteConnection(null);
                connection.executeStatement(sql, 0);
            } finally {
                if (connection != null) {
                    connectionSource.releaseConnection(connection);
                }
            }
        }
    }

    private record ColumnMigrationResult(boolean hasPremiumUuid, boolean hasTotpToken, boolean hasIssuedTime,
                                         boolean hasConflictMode, boolean hasConflictTimestamp, boolean hasOriginalNickname) {
    }
}
