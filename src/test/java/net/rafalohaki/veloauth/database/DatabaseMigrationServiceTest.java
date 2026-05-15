package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DatabaseMigrationServiceTest {

    private DatabaseConfig config;
    private DatabaseManager manager;

    @BeforeEach
    void setUp() {
        Messages messages = new Messages();
        messages.setLanguage("en");
        config = DatabaseConfig.forLocalDatabase("H2", "migration_test_" + System.nanoTime());
        manager = new DatabaseManager(config, messages);
    }

    @AfterEach
    void tearDown() {
        manager.shutdown();
    }

    @Test
    void initialize_shouldCreateExpectedIndexesForH2() throws Exception {
        assertTrue(manager.initialize().join(), "Database should initialize");

        assertTrue(indexExists("AUTH", "idx_auth_ip"));
        assertTrue(indexExists("AUTH", "idx_auth_uuid"));
        assertTrue(indexExists("AUTH", "idx_auth_logindate"));
        assertTrue(indexExists("AUTH", "idx_auth_regdate"));
        assertTrue(indexExists("AUTH", "idx_auth_premiumuuid"));
        assertTrue(indexExists("PREMIUM_UUIDS", "idx_premium_uuids_nickname"));
        assertTrue(indexExists("PREMIUM_UUIDS", "idx_premium_uuids_last_seen"));
        assertTrue(indexExists("VELOAUTH_AUDIT_LOG", "idx_audit_player"));
        assertTrue(indexExists("VELOAUTH_AUDIT_LOG", "idx_audit_timestamp"));
    }

    @Test
    void initialize_shouldCreateSchemaVersionTableAndRecordBaseline() throws Exception {
        assertTrue(manager.initialize().join(), "Database should initialize");

        assertTrue(tableExists("VELOAUTH_SCHEMA_VERSION"));
        assertTrue(tableExists("VELOAUTH_AUDIT_LOG"));

        SchemaVersionDao schemaVersionDao = manager.getSchemaVersionDao();
        assertTrue(schemaVersionDao.getCurrentVersion().isPresent(),
                "Baseline schema version row should exist after first init");
        assertTrue(schemaVersionDao.hasVersion(1),
                "Baseline version 1 should be recorded");
    }

    @Test
    void initialize_shouldBeIdempotentAcrossMultipleRuns() throws Exception {
        assertTrue(manager.initialize().join());
        manager.shutdown();

        DatabaseManager second = new DatabaseManager(config, new Messages());
        try {
            assertTrue(second.initialize().join(), "Second init should succeed");
            assertTrue(second.getSchemaVersionDao().hasVersion(1),
                    "Baseline row must remain after second init");
        } finally {
            second.shutdown();
        }
        manager = new DatabaseManager(config, new Messages());
        assertTrue(manager.initialize().join(), "Third init should also succeed");
    }

    @Test
    void postgresCreateStatementIfNotExists_shouldMakeSequenceAndTableCreationIdempotent() {
        assertEquals(
                "CREATE SEQUENCE IF NOT EXISTS \"veloauth_audit_log_id_seq\"",
                DatabaseMigrationService.postgresCreateStatementIfNotExists(
                        "CREATE SEQUENCE \"veloauth_audit_log_id_seq\""));
        assertEquals(
                "CREATE TABLE IF NOT EXISTS \"VELOAUTH_AUDIT_LOG\" (\"ID\" BIGINT)",
                DatabaseMigrationService.postgresCreateStatementIfNotExists(
                        "CREATE TABLE \"VELOAUTH_AUDIT_LOG\" (\"ID\" BIGINT)"));
        assertEquals(
                "CREATE INDEX idx_audit_player ON \"VELOAUTH_AUDIT_LOG\" (\"PLAYER_LOWERCASE\")",
                DatabaseMigrationService.postgresCreateStatementIfNotExists(
                        "CREATE INDEX idx_audit_player ON \"VELOAUTH_AUDIT_LOG\" (\"PLAYER_LOWERCASE\")"));
    }

    private boolean tableExists(String tableName) throws SQLException {
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl())) {
            DatabaseMetaData metaData = connection.getMetaData();
            try (ResultSet tables = metaData.getTables(null, null, null, null)) {
                while (tables.next()) {
                    String existing = tables.getString("TABLE_NAME");
                    if (existing != null && existing.equalsIgnoreCase(tableName)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private boolean indexExists(String tableName, String indexName) throws SQLException {
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl())) {
            DatabaseMetaData metaData = connection.getMetaData();
            return indexExists(metaData, tableName, indexName)
                    || indexExists(metaData, tableName.toUpperCase(Locale.ROOT), indexName)
                    || indexExists(metaData, tableName.toLowerCase(Locale.ROOT), indexName);
        }
    }

    private boolean indexExists(DatabaseMetaData metaData, String tableName, String indexName) throws SQLException {
        try (ResultSet indexes = metaData.getIndexInfo(null, null, tableName, false, false)) {
            while (indexes.next()) {
                String existingIndex = indexes.getString("INDEX_NAME");
                if (existingIndex != null && existingIndex.equalsIgnoreCase(indexName)) {
                    return true;
                }
            }
        }
        return false;
    }
}
