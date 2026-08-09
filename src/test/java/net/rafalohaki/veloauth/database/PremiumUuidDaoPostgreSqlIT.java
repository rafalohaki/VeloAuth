package net.rafalohaki.veloauth.database;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.table.TableUtils;
import net.rafalohaki.veloauth.model.PremiumUuid;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Opt-in integration test against a real PostgreSQL driver/server. The class name intentionally
 * ends in {@code IT}, so normal Surefire runs do not require Docker or a database. Use
 * {@code scripts/test-postgresql.sh} or pass the documented system properties explicitly.
 */
class PremiumUuidDaoPostgreSqlIT {

    private String databaseUrl;
    private String databaseUser;
    private String databasePassword;
    private String schemaName;
    private String scopedUrl;
    private JdbcConnectionSource connectionSource;
    private PremiumUuidDao premiumUuidDao;

    @BeforeEach
    void setUp() throws java.sql.SQLException {
        databaseUrl = requiredProperty("veloauth.postgres.url");
        databaseUser = requiredProperty("veloauth.postgres.user");
        databasePassword = requiredProperty("veloauth.postgres.password");
        schemaName = "veloauth_it_" + UUID.randomUUID().toString().replace("-", "");

        try (Connection connection = DriverManager.getConnection(databaseUrl, databaseUser, databasePassword);
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("CREATE SCHEMA " + schemaName);
        }

        String separator = databaseUrl.contains("?") ? "&" : "?";
        scopedUrl = databaseUrl + separator + "currentSchema=" + schemaName;
        connectionSource = new JdbcConnectionSource(scopedUrl, databaseUser, databasePassword);
        TableUtils.createTableIfNotExists(connectionSource, PremiumUuid.class);
        premiumUuidDao = new PremiumUuidDao(connectionSource);
    }

    @AfterEach
    void tearDown() throws java.sql.SQLException {
        try {
            if (connectionSource != null) {
                try {
                    connectionSource.close();
                } catch (Exception exception) {
                    throw new IllegalStateException("Failed to close PostgreSQL integration connection", exception);
                }
            }
        } finally {
            if (schemaName != null) {
                try (Connection connection = DriverManager.getConnection(databaseUrl, databaseUser, databasePassword);
                     Statement statement = connection.createStatement()) {
                    statement.executeUpdate("DROP SCHEMA " + schemaName + " CASCADE");
                }
            }
        }
    }

    @Test
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    void saveOrUpdateStrictMultipleCaseVariantConflictsKeepsOnlyAuthoritativeUuid()
            throws java.sql.SQLException {
        Dao<PremiumUuid, String> rawDao = DaoManager.createDao(connectionSource, PremiumUuid.class);
        rawDao.create(new PremiumUuid(UUID.randomUUID(), "Alice"));
        rawDao.create(new PremiumUuid(UUID.randomUUID(), "ALICE"));
        UUID authoritativeUuid = UUID.randomUUID();

        assertTrue(premiumUuidDao.saveOrUpdateStrict(authoritativeUuid, "aLiCe"),
                "PostgreSQL reconciliation should complete successfully");

        Optional<PremiumUuid> resolved = premiumUuidDao.findByNicknameStrict("ALICE");
        List<PremiumUuid> rows = premiumUuidDao.findAll();
        assertTrue(resolved.isPresent(), "Case-insensitive lookup should resolve the reconciled nickname");
        assertEquals(authoritativeUuid, resolved.get().getUuid(),
                "Lookup should return the Mojang-authoritative UUID");
        assertEquals(1, rows.size(), "PostgreSQL IN delete should remove every conflicting UUID in one batch");
        assertEquals(authoritativeUuid, rows.get(0).getUuid(),
                "The surviving row should use the authoritative UUID");

        assertTrue(premiumUuidDao.saveOrUpdateStrict(authoritativeUuid, "RenamedAlice"),
                "Renaming the authoritative mapping should succeed");
        assertTrue(premiumUuidDao.findByNicknameStrict("alice").isEmpty(),
                "PostgreSQL case-sensitive storage must not leave the previous nickname mapping");
        assertEquals(authoritativeUuid,
                premiumUuidDao.findByNicknameStrict("RENAMEDALICE").orElseThrow().getUuid(),
                "Case-insensitive lookup should resolve the renamed mapping");
    }

    @Test
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    void legacyLimboAuthMigrationPreservesHistoricalUuidAndIsIdempotentOnPostgreSql()
            throws java.sql.SQLException {
        UUID historicalUuid = UUID.randomUUID();
        try (Connection connection = openScopedConnection();
             Statement statement = connection.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE "AUTH" (
                        "LOWERCASENICKNAME" VARCHAR(16) PRIMARY KEY,
                        "NICKNAME" VARCHAR(16) NOT NULL,
                        "HASH" VARCHAR(255),
                        "IP" VARCHAR(45),
                        "LOGINIP" VARCHAR(45),
                        "UUID" VARCHAR(36),
                        "REGDATE" BIGINT,
                        "LOGINDATE" BIGINT,
                        "PREMIUMUUID" VARCHAR(36),
                        "TOTPTOKEN" VARCHAR(32),
                        "ISSUEDTIME" BIGINT DEFAULT 0
                    )
                    """);
        }
        try (Connection connection = openScopedConnection();
             PreparedStatement insert = connection.prepareStatement("""
                     INSERT INTO "AUTH" ("LOWERCASENICKNAME", "NICKNAME", "HASH", "IP", "LOGINIP",
                         "UUID", "REGDATE", "LOGINDATE", "PREMIUMUUID", "TOTPTOKEN", "ISSUEDTIME")
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                     """)) {
            String loopbackAddress = InetAddress.getLoopbackAddress().getHostAddress();
            insert.setString(1, "legacyplayer");
            insert.setString(2, "LegacyPlayer");
            insert.setString(3, null);
            insert.setString(4, loopbackAddress);
            insert.setString(5, loopbackAddress);
            insert.setString(6, historicalUuid.toString());
            insert.setLong(7, 1L);
            insert.setLong(8, 1L);
            insert.setString(9, historicalUuid.toString());
            insert.setString(10, null);
            insert.setLong(11, 0L);
            insert.executeUpdate();
        }

        DatabaseConfig postgresConfig = DatabaseConfig.forRemoteDatabase(
                "POSTGRESQL", "unused", 5432, "unused", "unused", "unused", 1);
        DatabaseMigrationService migrationService = new DatabaseMigrationService(postgresConfig);
        migrationService.createTablesAndMigrate(connectionSource, "Creating PostgreSQL test tables",
                "PostgreSQL test tables created");
        migrationService.createTablesAndMigrate(connectionSource, "Repeating PostgreSQL test migration",
                "PostgreSQL test migration repeated");

        try (Connection connection = openScopedConnection();
             PreparedStatement query = connection.prepareStatement("""
                     SELECT "UUID", "PREMIUMUUID", "PRESERVE_UUID"
                     FROM "AUTH" WHERE "LOWERCASENICKNAME" = ?
                     """)) {
            query.setString(1, "legacyplayer");
            try (ResultSet result = query.executeQuery()) {
                int rowCount = 0;
                while (result.next()) {
                    rowCount++;
                    assertEquals(historicalUuid.toString(), result.getString("UUID"),
                            "Migration must preserve the historical backend UUID");
                    assertEquals(historicalUuid.toString(), result.getString("PREMIUMUUID"),
                            "Migration must not rewrite the existing premium identity before handshake");
                    assertTrue(result.getBoolean("PRESERVE_UUID"),
                            "Passwordless LimboAuth row should be marked for backend UUID preservation");
                }
                assertEquals(1, rowCount,
                        "Migrated LimboAuth row should remain readable and must not be duplicated");
            }
        }
    }

    private Connection openScopedConnection() throws java.sql.SQLException {
        return DriverManager.getConnection(scopedUrl, databaseUser, databasePassword);
    }

    private static String requiredProperty(String name) {
        String value = System.getProperty(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing required PostgreSQL integration property: " + name);
        }
        return value;
    }
}
