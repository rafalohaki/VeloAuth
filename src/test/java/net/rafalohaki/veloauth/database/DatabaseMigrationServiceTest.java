package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
        assertTrue(columnExists("AUTH", "PRESERVE_UUID"),
                "UUID compatibility marker must exist for seamless LimboAuth upgrades");

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
    void initialize_existingLimboAuthTableShouldAddPreserveUuidWithoutChangingPlayerUuid() throws Exception {
        UUID historicalUuid = UUID.randomUUID();
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             PreparedStatement create = connection.prepareStatement(
                     "CREATE TABLE AUTH (LOWERCASENICKNAME VARCHAR(16) PRIMARY KEY, "
                             + "NICKNAME VARCHAR(16) NOT NULL, HASH VARCHAR(255), IP VARCHAR(45), "
                             + "LOGINIP VARCHAR(45), UUID VARCHAR(36), REGDATE BIGINT, LOGINDATE BIGINT, "
                             + "PREMIUMUUID VARCHAR(36), TOTPTOKEN VARCHAR(32), ISSUEDTIME BIGINT DEFAULT 0)")) {
            create.executeUpdate();
        }
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             PreparedStatement insert = connection.prepareStatement(
                     "INSERT INTO AUTH (LOWERCASENICKNAME, NICKNAME, HASH, IP, LOGINIP, UUID, "
                             + "REGDATE, LOGINDATE, PREMIUMUUID, TOTPTOKEN, ISSUEDTIME) "
                             + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            insert.setString(1, "legacyplayer");
            insert.setString(2, "LegacyPlayer");
            insert.setString(3, null);
            insert.setString(4, "127.0.0.1");
            insert.setString(5, "127.0.0.1");
            insert.setString(6, historicalUuid.toString());
            insert.setLong(7, 1L);
            insert.setLong(8, 1L);
            insert.setString(9, historicalUuid.toString());
            insert.setString(10, null);
            insert.setLong(11, 0L);
            insert.executeUpdate();
        }

        assertTrue(manager.initialize().join(), "Existing LimboAuth schema should migrate in place");

        assertTrue(columnExists("AUTH", "PRESERVE_UUID"));
        var stored = manager.findPlayerByNickname("LegacyPlayer").join();
        assertTrue(stored.isSuccess());
        assertNotNull(stored.getValue());
        assertEquals(historicalUuid.toString(), stored.getValue().getUuid(),
                "Schema migration must never rewrite historical AUTH.UUID");
        assertTrue(stored.getValue().isPreserveUuid(),
                "Imported passwordless rows must be marked before the first VeloAuth login");

        UUID verifiedPremiumUuid = UUID.randomUUID();
        var binding = manager.reconcileVerifiedPremiumProfile("LegacyPlayer", verifiedPremiumUuid).join();
        assertTrue(binding.isSuccess());
        assertNotNull(binding.getValue());
        assertEquals(historicalUuid, binding.getValue().backendUuid());
        assertEquals(verifiedPremiumUuid, binding.getValue().verifiedPremiumUuid());

        var reconciled = manager.findPlayerByNickname("LegacyPlayer").join();
        assertNotNull(reconciled.getValue());
        assertEquals(historicalUuid.toString(), reconciled.getValue().getUuid());
        assertEquals(verifiedPremiumUuid.toString(), reconciled.getValue().getPremiumUuid());
        assertTrue(reconciled.getValue().isPreserveUuid());
    }

    @Test
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    void initialize_existingVeloAuth13MarkerShouldBackfillOnlyLegacyPremiumCandidate() throws Exception {
        UUID historicalUuid = UUID.fromString("11111111-1111-4111-8111-111111111111");
        UUID offlineUuid = UUID.fromString("22222222-2222-4222-8222-222222222222");
        UUID mismatchBackendUuid = UUID.fromString("33333333-3333-4333-8333-333333333333");
        UUID mismatchPremiumUuid = UUID.fromString("44444444-4444-4444-8444-444444444444");
        UUID verifiedPremiumUuid = UUID.fromString("55555555-5555-4555-8555-555555555555");

        createPre14SchemaWithVeloAuth13Marker();
        insertAuth("legacycandidate", null, historicalUuid, historicalUuid, "totp-secret", 11L, 22L);
        insertAuth("offlinecontrol", "$2a$10$literalTestHash", offlineUuid, null, "offline-totp", 33L, 44L);
        insertAuth("mismatchcontrol", null, mismatchBackendUuid, mismatchPremiumUuid, null, 55L, 66L);

        assertTrue(manager.initialize().join(), "Existing VeloAuth 1.3 schema should initialize");

        AuthRow candidate = selectAuth("legacycandidate");
        assertTrue(candidate.preserveUuid(),
                "Passwordless row whose premium identity mirrors AUTH.UUID is lineage-safe");
        assertHistoryEquals(candidate, null, "totp-secret", 11L, 22L);

        AuthRow offlineControl = selectAuth("offlinecontrol");
        assertFalse(offlineControl.preserveUuid(), "Registered offline account must remain unmarked");
        assertHistoryEquals(offlineControl, "$2a$10$literalTestHash", "offline-totp", 33L, 44L);

        AuthRow mismatchControl = selectAuth("mismatchcontrol");
        assertFalse(mismatchControl.preserveUuid(),
                "A distinct stored premium identity must remain fail-closed and unmarked");
        assertHistoryEquals(mismatchControl, null, null, 55L, 66L);

        var binding = manager.reconcileVerifiedPremiumProfile("legacycandidate", verifiedPremiumUuid).join();
        assertFalse(binding.isDatabaseError(), "Lineage-safe candidate should reconcile after Mojang verification");
        assertNotNull(binding.getValue());
        assertEquals(historicalUuid, binding.getValue().backendUuid());
        assertEquals(verifiedPremiumUuid, binding.getValue().verifiedPremiumUuid());
        assertTrue(binding.getValue().legacyUuidPreserved());

        AuthRow reconciled = selectAuth("legacycandidate");
        assertEquals(historicalUuid.toString(), reconciled.uuid());
        assertEquals(verifiedPremiumUuid.toString(), reconciled.premiumUuid());
        assertTrue(reconciled.preserveUuid());
        assertHistoryEquals(reconciled, null, "totp-secret", 11L, 22L);
        assertEquals(mismatchPremiumUuid.toString(), selectAuth("mismatchcontrol").premiumUuid(),
                "Migration must not rewrite a non-candidate premium identity");
        assertTrue(manager.getSchemaVersionDao().hasVersion(1));
        assertTrue(manager.getSchemaVersionDao().hasVersion(2),
                "VA-1501 provenance must be recorded after the successful backfill");

        List<AuthRow> afterFirstInitialization = selectAllAuth();
        manager.shutdown();
        manager = new DatabaseManager(config, new Messages());
        assertTrue(manager.initialize().join(), "Repeated initialization should succeed");
        assertEquals(afterFirstInitialization, selectAllAuth(),
                "Repeated initialization must be a row-for-row no-op");
    }

    @Test
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    void initialize_existingVersion2ShouldRecoverEligibleDefaultFalseRow() throws Exception {
        UUID historicalUuid = UUID.fromString("66666666-6666-4666-8666-666666666666");

        createPre14SchemaWithVeloAuth13Marker();
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             PreparedStatement addMarker = connection.prepareStatement(
                     "ALTER TABLE AUTH ADD COLUMN PRESERVE_UUID BOOLEAN DEFAULT FALSE")) {
            addMarker.executeUpdate();
        }
        insertSchemaVersion(2, "VA-1501 legacy UUID preservation backfill");
        insertAuth("recoveryplayer", null, historicalUuid, historicalUuid,
                "recovery-totp", 101L, 202L);

        AuthRow beforeInitialization = selectAuth("recoveryplayer");
        assertFalse(beforeInitialization.preserveUuid(), "Fixture must exercise the default-false recovery state");

        assertTrue(manager.initialize().join(), "Version 2 is provenance, not a gate for the backfill");

        AuthRow recovered = selectAuth("recoveryplayer");
        assertTrue(recovered.preserveUuid(), "Eligible row must be recovered even when version 2 already exists");
        assertEquals(historicalUuid.toString(), recovered.uuid(), "Backend UUID must remain unchanged");
        assertEquals(historicalUuid.toString(), recovered.premiumUuid(), "Premium UUID must remain unchanged");
        assertHistoryEquals(recovered, null, "recovery-totp", 101L, 202L);
        assertTrue(manager.getSchemaVersionDao().hasVersion(2));
    }

    @Test
    void initialize_schemaVersion2WriteFailureShouldLeaveManagerDisconnected() throws Exception {
        createPre14SchemaWithVeloAuth13Marker();
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             PreparedStatement constrain = connection.prepareStatement(
                     "ALTER TABLE VELOAUTH_SCHEMA_VERSION ADD CONSTRAINT only_version_one CHECK (VERSION = 1)")) {
            constrain.executeUpdate();
        }

        assertFalse(manager.initialize().join(),
                "Initialization must fail when required VA-1501 provenance cannot be recorded");
        assertFalse(manager.isConnected(), "A provenance failure must leave the database fail-closed");
        assertFalse(manager.getSchemaVersionDao().hasVersion(2));
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

    private void createPre14SchemaWithVeloAuth13Marker() throws SQLException {
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             PreparedStatement createAuth = connection.prepareStatement(
                     "CREATE TABLE AUTH (LOWERCASENICKNAME VARCHAR(16) PRIMARY KEY, "
                             + "NICKNAME VARCHAR(16) NOT NULL, HASH VARCHAR(255), IP VARCHAR(45), "
                             + "LOGINIP VARCHAR(45), UUID VARCHAR(36), REGDATE BIGINT, LOGINDATE BIGINT, "
                             + "PREMIUMUUID VARCHAR(36), TOTPTOKEN VARCHAR(32), ISSUEDTIME BIGINT DEFAULT 0)");
             PreparedStatement createVersion = connection.prepareStatement(
                     "CREATE TABLE VELOAUTH_SCHEMA_VERSION (VERSION INTEGER PRIMARY KEY, "
                             + "APPLIED_AT BIGINT NOT NULL, DESCRIPTION VARCHAR(255))")) {
            createAuth.executeUpdate();
            createVersion.executeUpdate();
        }
        insertSchemaVersion(1, "baseline v1.2.0 schema");
    }

    private void insertSchemaVersion(int version, String description) throws SQLException {
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             PreparedStatement insertVersion = connection.prepareStatement(
                     "INSERT INTO VELOAUTH_SCHEMA_VERSION (VERSION, APPLIED_AT, DESCRIPTION) VALUES (?, ?, ?)")) {
            insertVersion.setInt(1, version);
            insertVersion.setLong(2, version);
            insertVersion.setString(3, description);
            insertVersion.executeUpdate();
        }
    }

    private void insertAuth(String nickname, String hash, UUID uuid, UUID premiumUuid,
                            String totpToken, long regDate, long loginDate) throws SQLException {
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             PreparedStatement insert = connection.prepareStatement(
                     "INSERT INTO AUTH (LOWERCASENICKNAME, NICKNAME, HASH, IP, LOGINIP, UUID, "
                             + "REGDATE, LOGINDATE, PREMIUMUUID, TOTPTOKEN, ISSUEDTIME) "
                             + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            insert.setString(1, nickname);
            insert.setString(2, nickname);
            insert.setString(3, hash);
            insert.setString(4, "198.51.100.10");
            insert.setString(5, "203.0.113.20");
            insert.setString(6, uuid.toString());
            insert.setLong(7, regDate);
            insert.setLong(8, loginDate);
            insert.setString(9, premiumUuid == null ? null : premiumUuid.toString());
            insert.setString(10, totpToken);
            insert.setLong(11, 77L);
            insert.executeUpdate();
        }
    }

    private AuthRow selectAuth(String nickname) throws SQLException {
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             PreparedStatement query = connection.prepareStatement(
                     "SELECT LOWERCASENICKNAME, HASH, IP, LOGINIP, UUID, REGDATE, LOGINDATE, "
                             + "PREMIUMUUID, TOTPTOKEN, ISSUEDTIME, PRESERVE_UUID "
                             + "FROM AUTH WHERE LOWERCASENICKNAME = ?")) {
            query.setString(1, nickname);
            try (ResultSet result = query.executeQuery()) {
                assertTrue(result.next(), "Expected AUTH fixture " + nickname);
                return mapAuthRow(result);
            }
        }
    }

    private List<AuthRow> selectAllAuth() throws SQLException {
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             PreparedStatement query = connection.prepareStatement(
                     "SELECT LOWERCASENICKNAME, HASH, IP, LOGINIP, UUID, REGDATE, LOGINDATE, "
                             + "PREMIUMUUID, TOTPTOKEN, ISSUEDTIME, PRESERVE_UUID "
                             + "FROM AUTH ORDER BY LOWERCASENICKNAME");
             ResultSet result = query.executeQuery()) {
            List<AuthRow> rows = new ArrayList<>();
            while (result.next()) {
                rows.add(mapAuthRow(result));
            }
            return rows;
        }
    }

    private AuthRow mapAuthRow(ResultSet result) throws SQLException {
        return new AuthRow(
                result.getString("LOWERCASENICKNAME"),
                result.getString("HASH"),
                result.getString("IP"),
                result.getString("LOGINIP"),
                result.getString("UUID"),
                result.getLong("REGDATE"),
                result.getLong("LOGINDATE"),
                result.getString("PREMIUMUUID"),
                result.getString("TOTPTOKEN"),
                result.getLong("ISSUEDTIME"),
                result.getBoolean("PRESERVE_UUID"));
    }

    private void assertHistoryEquals(AuthRow row, String hash, String totpToken,
                                     long regDate, long loginDate) {
        assertEquals(hash, row.hash());
        assertEquals("198.51.100.10", row.ip());
        assertEquals("203.0.113.20", row.loginIp());
        assertEquals(totpToken, row.totpToken());
        assertEquals(regDate, row.regDate());
        assertEquals(loginDate, row.loginDate());
        assertEquals(77L, row.issuedTime());
        if (hash == null) {
            assertNull(row.hash());
        }
    }

    private record AuthRow(String nickname, String hash, String ip, String loginIp,
                           String uuid, long regDate, long loginDate, String premiumUuid,
                           String totpToken, long issuedTime, boolean preserveUuid) {
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

    private boolean columnExists(String tableName, String columnName) throws SQLException {
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             ResultSet columns = connection.getMetaData().getColumns(null, null, null, null)) {
            while (columns.next()) {
                String existingTable = columns.getString("TABLE_NAME");
                String existing = columns.getString("COLUMN_NAME");
                if (existingTable != null && existingTable.equalsIgnoreCase(tableName)
                        && existing != null && existing.equalsIgnoreCase(columnName)) {
                    return true;
                }
            }
        }
        return false;
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
