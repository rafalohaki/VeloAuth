package net.rafalohaki.veloauth.database;

import com.j256.ormlite.jdbc.JdbcConnectionSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Opt-in migration coverage against the real PostgreSQL and MySQL dialects.
 * Normal unit-test runs intentionally exclude classes ending in {@code IT}.
 */
class DatabaseMigrationDatabaseIT {

    private static final UUID HISTORICAL_UUID =
            UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID OFFLINE_UUID =
            UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID MISMATCH_BACKEND_UUID =
            UUID.fromString("33333333-3333-4333-8333-333333333333");
    private static final UUID MISMATCH_PREMIUM_UUID =
            UUID.fromString("44444444-4444-4444-8444-444444444444");
    private static final String REGISTRATION_IP_HISTORY = "literal-registration-ip";
    private static final String LOGIN_IP_HISTORY = "literal-login-ip";

    private String databaseType;
    private String databaseUrl;
    private String databaseUser;
    private String databasePassword;
    private String schemaName;
    private String scopedUrl;
    private String quote;
    private JdbcConnectionSource connectionSource;

    @BeforeEach
    void setUp() throws SQLException {
        databaseType = requiredProperty("veloauth.database.type");
        databaseUrl = requiredProperty("veloauth.database.url");
        databaseUser = requiredProperty("veloauth.database.user");
        databasePassword = requiredProperty("veloauth.database.password");
        quote = isPostgreSql() ? "\"" : "`";

        if (isPostgreSql()) {
            schemaName = "veloauth_migration_it_" + UUID.randomUUID().toString().replace("-", "");
            try (Connection connection = openBaseConnection();
                 Statement statement = connection.createStatement()) {
                statement.executeUpdate("CREATE SCHEMA " + schemaName);
            }
            scopedUrl = databaseUrl + (databaseUrl.contains("?") ? "&" : "?")
                    + "currentSchema=" + schemaName;
        } else {
            scopedUrl = databaseUrl;
            dropMigrationTables();
        }

        createInterruptedVersion2Schema();
        connectionSource = new JdbcConnectionSource(scopedUrl, databaseUser, databasePassword);
    }

    @AfterEach
    void tearDown() throws SQLException {
        try {
            if (connectionSource != null) {
                connectionSource.close();
            }
        } catch (Exception exception) {
            throw new SQLException("Failed to close migration integration connection", exception);
        } finally {
            if (isPostgreSql() && schemaName != null) {
                try (Connection connection = openBaseConnection();
                     Statement statement = connection.createStatement()) {
                    statement.executeUpdate("DROP SCHEMA " + schemaName + " CASCADE");
                }
            } else if (scopedUrl != null) {
                dropMigrationTables();
            }
        }
    }

    @Test
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    void existingVersion2MarkerShouldBackfillOnlyLineageSafeCandidateAndRemainIdempotent()
            throws SQLException {
        insertAuth("legacycandidate", null, HISTORICAL_UUID, HISTORICAL_UUID,
                "totp-secret", 11L, 22L);
        insertAuth("offlinecontrol", "$2a$10$literalTestHash", OFFLINE_UUID, null,
                "offline-totp", 33L, 44L);
        insertAuth("mismatchcontrol", null, MISMATCH_BACKEND_UUID, MISMATCH_PREMIUM_UUID,
                null, 55L, 66L);

        DatabaseConfig config = DatabaseConfig.forRemoteJdbcUrl(
                databaseType, scopedUrl, databaseUser, databasePassword);
        DatabaseMigrationService migrationService = new DatabaseMigrationService(config);
        DatabaseMigrationService.MigrationResult firstMigration = migrationService.createTablesAndMigrate(
                connectionSource, "Creating dialect migration tables", "Dialect migration tables created");
        assertEquals(1, firstMigration.legacyUuidCandidates(), "Exactly one row is lineage-safe");
        assertEquals(1, firstMigration.legacyUuidRowsMarked(), "Exactly one row should be marked");

        List<AuthRow> afterFirstMigration = selectAllAuth();
        AuthRow candidate = findRow(afterFirstMigration, "legacycandidate");
        assertTrue(candidate.preserveUuid(),
                "Existing schema provenance must not suppress the lineage-safe backfill");
        assertHistoryEquals(candidate, null, "totp-secret", 11L, 22L);
        assertEquals(HISTORICAL_UUID.toString(), candidate.uuid(), "Candidate backend UUID must remain unchanged");
        assertEquals(HISTORICAL_UUID.toString(), candidate.premiumUuid(),
                "Candidate premium UUID must remain unchanged before verification");

        AuthRow offlineControl = findRow(afterFirstMigration, "offlinecontrol");
        assertFalse(offlineControl.preserveUuid(), "Registered offline account must remain unmarked");
        assertHistoryEquals(offlineControl, "$2a$10$literalTestHash", "offline-totp", 33L, 44L);
        assertEquals(OFFLINE_UUID.toString(), offlineControl.uuid(), "Offline UUID must remain unchanged");
        assertNull(offlineControl.premiumUuid(), "Offline account must not gain a premium identity");

        AuthRow mismatchControl = findRow(afterFirstMigration, "mismatchcontrol");
        assertFalse(mismatchControl.preserveUuid(), "Mismatched premium identity must remain unmarked");
        assertHistoryEquals(mismatchControl, null, null, 55L, 66L);
        assertEquals(MISMATCH_BACKEND_UUID.toString(), mismatchControl.uuid(),
                "Mismatch backend UUID must remain unchanged");
        assertEquals(MISMATCH_PREMIUM_UUID.toString(), mismatchControl.premiumUuid(),
                "Mismatch premium identity must remain unchanged");

        DatabaseMigrationService.MigrationResult repeatedMigration = migrationService.createTablesAndMigrate(
                connectionSource, "Repeating dialect migration", "Dialect migration repeated");
        assertEquals(0, repeatedMigration.legacyUuidCandidates(), "No candidate should remain after backfill");
        assertEquals(0, repeatedMigration.legacyUuidRowsMarked(), "Repeated migration must mark no rows");
        assertEquals(afterFirstMigration, selectAllAuth(),
                "A second migration must be a row-for-row no-op");
    }

    private void createInterruptedVersion2Schema() throws SQLException {
        try (Connection connection = openScopedConnection();
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE TABLE " + identifier("AUTH") + " ("
                    + identifier("LOWERCASENICKNAME") + " VARCHAR(16) PRIMARY KEY, "
                    + identifier("NICKNAME") + " VARCHAR(16) NOT NULL, "
                    + identifier("HASH") + " VARCHAR(255), "
                    + identifier("IP") + " VARCHAR(45), "
                    + identifier("LOGINIP") + " VARCHAR(45), "
                    + identifier("UUID") + " VARCHAR(36), "
                    + identifier("REGDATE") + " BIGINT, "
                    + identifier("LOGINDATE") + " BIGINT, "
                    + identifier("PREMIUMUUID") + " VARCHAR(36), "
                    + identifier("TOTPTOKEN") + " VARCHAR(32), "
                    + identifier("ISSUEDTIME") + " BIGINT DEFAULT 0, "
                    + identifier("PRESERVE_UUID") + " BOOLEAN DEFAULT FALSE)");
            statement.executeUpdate("CREATE TABLE " + identifier("VELOAUTH_SCHEMA_VERSION") + " ("
                    + identifier("VERSION") + " INTEGER PRIMARY KEY, "
                    + identifier("APPLIED_AT") + " BIGINT NOT NULL, "
                    + identifier("DESCRIPTION") + " VARCHAR(255))");
        }
        try (Connection connection = openScopedConnection();
             PreparedStatement insert = connection.prepareStatement(
                     "INSERT INTO " + identifier("VELOAUTH_SCHEMA_VERSION") + " ("
                             + identifier("VERSION") + ", " + identifier("APPLIED_AT") + ", "
                             + identifier("DESCRIPTION") + ") VALUES (?, ?, ?)")) {
            insert.setInt(1, 1);
            insert.setLong(2, 1L);
            insert.setString(3, "baseline v1.2.0 schema");
            insert.executeUpdate();
            insert.setInt(1, 2);
            insert.setLong(2, 2L);
            insert.setString(3, "VA-1501 legacy UUID preservation backfill");
            insert.executeUpdate();
        }
    }

    private void insertAuth(String nickname, String hash, UUID uuid, UUID premiumUuid,
                            String totpToken, long regDate, long loginDate) throws SQLException {
        String sql = "INSERT INTO " + identifier("AUTH") + " (" + identifierList(
                "LOWERCASENICKNAME", "NICKNAME", "HASH", "IP", "LOGINIP", "UUID",
                "REGDATE", "LOGINDATE", "PREMIUMUUID", "TOTPTOKEN", "ISSUEDTIME") + ") "
                + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection connection = openScopedConnection();
             PreparedStatement insert = connection.prepareStatement(sql)) {
            insert.setString(1, nickname);
            insert.setString(2, nickname);
            insert.setString(3, hash);
            insert.setString(4, REGISTRATION_IP_HISTORY);
            insert.setString(5, LOGIN_IP_HISTORY);
            insert.setString(6, uuid.toString());
            insert.setLong(7, regDate);
            insert.setLong(8, loginDate);
            insert.setString(9, premiumUuid == null ? null : premiumUuid.toString());
            insert.setString(10, totpToken);
            insert.setLong(11, 77L);
            insert.executeUpdate();
        }
    }

    private List<AuthRow> selectAllAuth() throws SQLException {
        String sql = "SELECT " + identifierList(
                "LOWERCASENICKNAME", "HASH", "IP", "LOGINIP", "UUID", "REGDATE",
                "LOGINDATE", "PREMIUMUUID", "TOTPTOKEN", "ISSUEDTIME", "PRESERVE_UUID")
                + " FROM " + identifier("AUTH") + " ORDER BY " + identifier("LOWERCASENICKNAME");
        try (Connection connection = openScopedConnection();
             PreparedStatement query = connection.prepareStatement(sql);
             ResultSet result = query.executeQuery()) {
            List<AuthRow> rows = new ArrayList<>();
            while (result.next()) {
                rows.add(new AuthRow(
                        result.getString(1), result.getString(2), result.getString(3),
                        result.getString(4), result.getString(5), result.getLong(6),
                        result.getLong(7), result.getString(8), result.getString(9),
                        result.getLong(10), result.getBoolean(11)));
            }
            return rows;
        }
    }

    private AuthRow findRow(List<AuthRow> rows, String nickname) {
        return rows.stream()
                .filter(row -> row.nickname().equals(nickname))
                .findFirst()
                .orElseThrow(() -> new AssertionError("Missing AUTH fixture " + nickname));
    }

    private void assertHistoryEquals(AuthRow row, String hash, String totpToken,
                                     long regDate, long loginDate) {
        assertEquals(hash, row.hash(), "Password history must remain literal-equal");
        assertEquals(REGISTRATION_IP_HISTORY, row.ip(), "Registration IP history must remain literal-equal");
        assertEquals(LOGIN_IP_HISTORY, row.loginIp(), "Login IP history must remain literal-equal");
        assertEquals(totpToken, row.totpToken(), "TOTP history must remain literal-equal");
        assertEquals(regDate, row.regDate(), "Registration time must remain literal-equal");
        assertEquals(loginDate, row.loginDate(), "Login time must remain literal-equal");
        assertEquals(77L, row.issuedTime(), "Issued time must remain literal-equal");
    }

    private Connection openBaseConnection() throws SQLException {
        return DriverManager.getConnection(databaseUrl, databaseUser, databasePassword);
    }

    private Connection openScopedConnection() throws SQLException {
        return DriverManager.getConnection(scopedUrl, databaseUser, databasePassword);
    }

    private void dropMigrationTables() throws SQLException {
        try (Connection connection = openScopedConnection();
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("DROP TABLE IF EXISTS " + identifier("VELOAUTH_AUDIT_LOG"));
            statement.executeUpdate("DROP TABLE IF EXISTS " + identifier("PREMIUM_UUIDS"));
            statement.executeUpdate("DROP TABLE IF EXISTS " + identifier("VELOAUTH_SCHEMA_VERSION"));
            statement.executeUpdate("DROP TABLE IF EXISTS " + identifier("AUTH"));
        }
    }

    private boolean isPostgreSql() {
        return "POSTGRESQL".equalsIgnoreCase(databaseType);
    }

    private String identifier(String name) {
        return quote + name + quote;
    }

    private String identifierList(String... names) {
        StringJoiner identifiers = new StringJoiner(", ");
        for (String name : names) {
            identifiers.add(identifier(name));
        }
        return identifiers.toString();
    }

    private static String requiredProperty(String name) {
        String value = System.getProperty(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing database integration property: " + name);
        }
        return value;
    }

    private record AuthRow(String nickname, String hash, String ip, String loginIp,
                           String uuid, long regDate, long loginDate, String premiumUuid,
                           String totpToken, long issuedTime, boolean preserveUuid) {
    }
}
