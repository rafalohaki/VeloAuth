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
import java.util.Locale;

/**
 * Handles database schema creation, migration, and index management.
 * Extracted from DatabaseManager for single-responsibility.
 */
class DatabaseMigrationService {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseMigrationService.class);
    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");

    private static final String ALTER_TABLE = "ALTER TABLE ";
    private static final String ADD_COLUMN = " ADD COLUMN ";
    private static final String AUTH_TABLE = "AUTH";

    private final DatabaseConfig config;

    DatabaseMigrationService(DatabaseConfig config) {
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
        String quote = identifierQuote(dbType);

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
            String normalizedMessage = normalizeSqlMessage(e);
            if (e.getErrorCode() == 42121
                    || normalizedMessage.contains("duplicate column")
                    || normalizedMessage.contains("already exists")) {
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
        if (logger.isDebugEnabled() && (!result.hasPremiumUuid || !result.hasTotpToken || !result.hasIssuedTime
                || !result.hasConflictMode || !result.hasConflictTimestamp || !result.hasOriginalNickname)) {
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
        String quote = identifierQuote(dbType);
        createIndexIfMissing(connectionSource, AUTH_TABLE, "idx_auth_ip",
                buildCreateIndexSql(quote, "idx_auth_ip", AUTH_TABLE, "IP"));
        createIndexIfMissing(connectionSource, AUTH_TABLE, "idx_auth_uuid",
                buildCreateIndexSql(quote, "idx_auth_uuid", AUTH_TABLE, "UUID"));
        createIndexIfMissing(connectionSource, AUTH_TABLE, "idx_auth_logindate",
                buildCreateIndexSql(quote, "idx_auth_logindate", AUTH_TABLE, "LOGINDATE"));
        createIndexIfMissing(connectionSource, AUTH_TABLE, "idx_auth_regdate",
                buildCreateIndexSql(quote, "idx_auth_regdate", AUTH_TABLE, "REGDATE"));
        createIndexIfMissing(connectionSource, "PREMIUM_UUIDS", "idx_premium_uuids_nickname",
                buildCreateIndexSql(quote, "idx_premium_uuids_nickname", "PREMIUM_UUIDS", "NICKNAME"));
        createIndexIfMissing(connectionSource, "PREMIUM_UUIDS", "idx_premium_uuids_last_seen",
                buildCreateIndexSql(quote, "idx_premium_uuids_last_seen", "PREMIUM_UUIDS", "LAST_SEEN"));
    }

    private String buildCreateIndexSql(String quote, String indexName, String tableName, String columnName) {
        return "CREATE INDEX " + indexName + " ON " + quoteIdentifier(quote, tableName)
                + " (" + quoteIdentifier(quote, columnName) + ")";
    }

    private String quoteIdentifier(String quote, String identifier) {
        return quote + identifier + quote;
    }

    private void createIndexIfMissing(ConnectionSource connectionSource, String tableName, String indexName, String sql) {
        if (connectionSource == null) {
            return;
        }
        DatabaseConnection connection = null;
        try {
            connection = connectionSource.getReadWriteConnection(null);
            java.sql.Connection underlyingConnection = connection.getUnderlyingConnection();
            if (indexExists(underlyingConnection, tableName, indexName)) {
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "Index {} already exists on table {}", indexName, tableName);
                }
                return;
            }
            connection.executeStatement(sql, DatabaseConnection.DEFAULT_RESULT_FLAGS);
        } catch (SQLException e) {
            String normalizedMessage = normalizeSqlMessage(e);
            if (normalizedMessage.contains("already exists") || normalizedMessage.contains("duplicate")) {
                logger.debug(DB_MARKER, "Index already exists: {}", e.getMessage());
            } else {
                logger.error(DB_MARKER, "Index creation FAILED (not a duplicate): {}", sql, e);
            }
        } finally {
            if (connection != null) {
                try {
                    connectionSource.releaseConnection(connection);
                } catch (SQLException e) {
                    logger.error(DB_MARKER, "Failed to release connection after index creation", e);
                }
            }
        }
    }

    private boolean indexExists(java.sql.Connection connection, String tableName, String indexName) throws SQLException {
        return indexExists(connection.getMetaData(), tableName, indexName)
                || indexExists(connection.getMetaData(), tableName.toUpperCase(Locale.ROOT), indexName)
                || indexExists(connection.getMetaData(), tableName.toLowerCase(Locale.ROOT), indexName);
    }

    private boolean indexExists(java.sql.DatabaseMetaData metaData, String tableName, String indexName) throws SQLException {
        try (java.sql.ResultSet indexes = metaData.getIndexInfo(null, null, tableName, false, false)) {
            while (indexes.next()) {
                String existingIndex = indexes.getString("INDEX_NAME");
                if (existingIndex != null && existingIndex.equalsIgnoreCase(indexName)) {
                    return true;
                }
            }
        }
        return false;
    }

    private String identifierQuote(DatabaseType dbType) {
        return dbType == DatabaseType.POSTGRESQL ? "\"" : "`";
    }

    private String normalizeSqlMessage(SQLException e) {
        String message = e.getMessage();
        return message == null ? "" : message.toLowerCase(Locale.ROOT);
    }

    private record ColumnMigrationResult(boolean hasPremiumUuid, boolean hasTotpToken, boolean hasIssuedTime,
                                         boolean hasConflictMode, boolean hasConflictTimestamp, boolean hasOriginalNickname) {
    }
}
