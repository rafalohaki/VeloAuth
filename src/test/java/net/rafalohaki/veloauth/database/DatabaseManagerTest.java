package net.rafalohaki.veloauth.database;

import com.zaxxer.hikari.HikariDataSource;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Locale;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("null") // Eclipse JDT false positives: assertNotNull / isDatabaseError guarantee non-null but JDT cannot track these contracts
class DatabaseManagerTest {

    private Messages messages;
    private DatabaseManager manager;

    @BeforeEach
    void setUp() {
        messages = new Messages();
        messages.setLanguage("en");
        manager = new DatabaseManager(
                DatabaseConfig.forLocalDatabase("H2", "dbtest_" + System.nanoTime()),
                messages
        );
    }

    @AfterEach
    void tearDown() {
        manager.shutdown();
    }

    @Test
    void countQueries_shouldTreatEmptyHashPlayersAsPremiumAcrossRuntimeAndStatistics() throws Exception {
        assertTrue(manager.initialize().join(), "Database should initialize");

        save(player("PremiumByNullHash", null, null));
        insertRawPlayer("PremiumByEmptyHash", "", null);
        save(player("PremiumByUuid", "$2a$10$offlinehashvalueofflinehashvalueofflinehashval", UUID.randomUUID().toString()));
        save(player("OfflineA", "$2a$10$offlinehashvalueofflinehashvalueofflinehashval", null));
        save(player("OfflineB", "$2a$10$offlinehashvalueofflinehashvalueofflinehashval", null));

        DatabaseManager.DbResult<RegisteredPlayer> runtimeResult = manager.findPlayerByNickname("PremiumByEmptyHash").join();

        assertFalse(runtimeResult.isDatabaseError());
        assertNotNull(runtimeResult.getValue());
        assertTrue(manager.isPlayerPremiumRuntime(runtimeResult.getValue()));
        assertNull(runtimeResult.getValue().getHash());

        assertEquals(5, manager.getTotalRegisteredAccounts().join());
        assertEquals(3, manager.getTotalPremiumAccounts().join());
        assertEquals(3, manager.getTotalNonPremiumAccounts().join());
    }

    @Test
    void isPremium_legacyAuthRowShouldBeAuthoritativeWithoutPremiumCacheEntry() throws Exception {
        assertTrue(manager.initialize().join(), "Database should initialize");
        insertRawPlayer("LegacyAuthPremium", null, null);

        DatabaseManager.DbResult<Boolean> result = manager.isPremium("LegacyAuthPremium").join();

        assertFalse(result.isDatabaseError());
        assertEquals(Boolean.TRUE, result.getValue());
    }

    @Test
    void findPlayersInConflictMode_shouldReturnPersistedConflictPlayers() {
        assertTrue(manager.initialize().join(), "Database should initialize");

        insertRawConflictPlayer(
                "ConflictPlayer",
                "$2a$10$offlinehashvalueofflinehashvalueofflinehashval",
                null,
                true,
                1_234_567_890L,
                "OriginalConflict"
        );
        save(player("RegularPlayer", "$2a$10$offlinehashvalueofflinehashvalueofflinehashval", null));

        var conflicts = manager.findPlayersInConflictMode().join();

        assertEquals(1, conflicts.size());
        RegisteredPlayer storedConflict = conflicts.get(0);
        assertEquals("ConflictPlayer", storedConflict.getNickname());
        assertTrue(storedConflict.getConflictMode());
        assertEquals(1_234_567_890L, storedConflict.getConflictTimestamp());
        assertEquals("OriginalConflict", storedConflict.getOriginalNickname());
    }

    @Test
    void findPlayerByNickname_sqlExceptionShouldReturnGenericDatabaseError() throws Exception {
        JdbcAuthDao jdbcAuthDao = mock(JdbcAuthDao.class);
        when(jdbcAuthDao.findPlayerByLowercaseNickname("alice"))
                .thenThrow(new SQLException("sensitive SQL details"));

        manager.setConnectedForTesting(true);
        manager.setJdbcAuthDaoForTesting(jdbcAuthDao);

        DatabaseManager.DbResult<RegisteredPlayer> result = manager.findPlayerByNickname("Alice").join();

        assertTrue(result.isDatabaseError());
        assertEquals(messages.get("database.error"), result.getErrorMessage());
        assertFalse(result.getErrorMessage().contains("sensitive SQL details"));
    }

    @Test
    void savePlayer_sqlExceptionShouldReturnGenericDatabaseError() throws Exception {
        JdbcAuthDao jdbcAuthDao = mock(JdbcAuthDao.class);
        when(jdbcAuthDao.upsertPlayer(org.mockito.ArgumentMatchers.any(RegisteredPlayer.class)))
                .thenThrow(new SQLException("jdbc:h2:mem:secret"));

        manager.setConnectedForTesting(true);
        manager.setJdbcAuthDaoForTesting(jdbcAuthDao);

        DatabaseManager.DbResult<Boolean> result = manager.savePlayer(player("SaveUser", "$2a$10$offlinehashvalueofflinehashvalueofflinehashval", null)).join();

        assertTrue(result.isDatabaseError());
        assertEquals(messages.get("database.error"), result.getErrorMessage());
        assertFalse(result.getErrorMessage().contains("jdbc:h2:mem:secret"));
    }

    @Test
    void databaseConfigToString_shouldNeverExposeJdbcUrl() {
        DatabaseConfig sensitiveConfig = DatabaseConfig.forLocalDatabase(
                "H2", "support-report;PASSWORD=do-not-log-this");

        String rendered = sensitiveConfig.toString();

        assertFalse(rendered.contains("do-not-log-this"));
        assertFalse(rendered.contains("jdbc:h2:"));
        assertTrue(rendered.contains("jdbcUrl='<redacted>'"));
    }

    @Test
    void registerPlayerIfAbsent_existingOwnerShouldReturnFalseWithoutDatabaseError() throws Exception {
        JdbcAuthDao jdbcAuthDao = mock(JdbcAuthDao.class);
        RegisteredPlayer player = player(
                "RegisterUser", "$2a$10$offlinehashvalueofflinehashvalueofflinehashval", null);
        when(jdbcAuthDao.insertPlayerIfAbsent(player)).thenReturn(false);

        manager.setConnectedForTesting(true);
        manager.setJdbcAuthDaoForTesting(jdbcAuthDao);

        DatabaseManager.DbResult<Boolean> result = manager.registerPlayerIfAbsent(player).join();

        assertFalse(result.isDatabaseError());
        assertEquals(Boolean.FALSE, result.getValue());
    }

    @Test
    void registerPlayerIfAbsent_sqlExceptionShouldReturnGenericDatabaseError() throws Exception {
        JdbcAuthDao jdbcAuthDao = mock(JdbcAuthDao.class);
        RegisteredPlayer player = player(
                "RegisterUser", "$2a$10$offlinehashvalueofflinehashvalueofflinehashval", null);
        when(jdbcAuthDao.insertPlayerIfAbsent(player))
                .thenThrow(new SQLException("duplicate details with secret values"));

        manager.setConnectedForTesting(true);
        manager.setJdbcAuthDaoForTesting(jdbcAuthDao);

        DatabaseManager.DbResult<Boolean> result = manager.registerPlayerIfAbsent(player).join();

        assertTrue(result.isDatabaseError());
        assertEquals(messages.get("database.error"), result.getErrorMessage());
        assertFalse(result.getErrorMessage().contains("secret values"));
    }

    @Test
    void isPremium_runtimeExceptionShouldReturnGenericDatabaseError() {
        PremiumUuidDao premiumUuidDao = mock(PremiumUuidDao.class);
        try {
            when(premiumUuidDao.findByNicknameStrict("Alice"))
                    .thenThrow(new SQLException("org.h2.jdbc.JdbcSQLSyntaxErrorException: leaked details"));
        } catch (SQLException e) {
            throw new AssertionError(e);
        }

        manager.setConnectedForTesting(true);
        manager.setPremiumUuidDaoForTesting(premiumUuidDao);

        DatabaseManager.DbResult<Boolean> result = manager.isPremium("Alice").join();

        assertTrue(result.isDatabaseError());
        assertEquals(messages.get("database.error"), result.getErrorMessage());
        assertFalse(result.getErrorMessage().contains("leaked details"));
    }

    @Test
    void savePremiumUuid_sqlExceptionShouldReturnGenericDatabaseError() throws Exception {
        PremiumUuidDao premiumUuidDao = mock(PremiumUuidDao.class);
        UUID premiumUuid = UUID.randomUUID();
        when(premiumUuidDao.saveOrUpdateStrict(premiumUuid, "Alice"))
                .thenThrow(new SQLException("insert into premium_uuids values (...)"));

        manager.setConnectedForTesting(true);
        manager.setPremiumUuidDaoForTesting(premiumUuidDao);

        DatabaseManager.DbResult<Boolean> result = manager.savePremiumUuid("Alice", premiumUuid).join();

        assertTrue(result.isDatabaseError());
        assertEquals(messages.get("database.error"), result.getErrorMessage());
        assertFalse(result.getErrorMessage().contains("insert into premium_uuids"));
    }

    @Test
    void countRegistrationsByIp_sqlExceptionShouldReturnDbErrorAndFailSecureLegacyCount() throws Exception {
        JdbcAuthDao jdbcAuthDao = mock(JdbcAuthDao.class);
        when(jdbcAuthDao.countRegistrationsByIp("127.0.0.1"))
                .thenThrow(new SQLException("select count(*) from auth"));

        manager.setConnectedForTesting(true);
        manager.setJdbcAuthDaoForTesting(jdbcAuthDao);

        DatabaseManager.DbResult<Long> result = manager.countRegistrationsByIpResult("127.0.0.1").join();

        assertTrue(result.isDatabaseError());
        assertEquals(messages.get("database.error"), result.getErrorMessage());
        assertEquals(Long.MAX_VALUE, manager.countRegistrationsByIp("127.0.0.1").join());
    }

    @Test
    void reconcileVerifiedPremiumProfile_shouldAtomicallyMigrateNicknameToNewLowercaseId() throws Exception {
        assertTrue(manager.initialize().join(), "Database should initialize");

        UUID premiumUuid = UUID.randomUUID();
        insertRawPlayer("OldNick", null, premiumUuid.toString());

        DatabaseManager.DbResult<DatabaseManager.PremiumProfileBinding> migrated =
                manager.reconcileVerifiedPremiumProfile("NewNick", premiumUuid).join();

        assertFalse(migrated.isDatabaseError(), "Migration must not surface a DB error");
        assertNotNull(migrated.getValue(), "Player should be located via verified premium UUID");
        assertEquals(premiumUuid, migrated.getValue().backendUuid());

        // Post-commit state is consistent — both columns reflect the new nickname.
        DatabaseManager.DbResult<RegisteredPlayer> byNew = manager.findPlayerByNickname("NewNick").join();
        assertFalse(byNew.isDatabaseError());
        assertNotNull(byNew.getValue());
        assertEquals("NewNick", byNew.getValue().getNickname());

        // Old lowercase id is gone — no orphan row left from a non-atomic update.
        DatabaseManager.DbResult<RegisteredPlayer> byOld = manager.findPlayerByNickname("OldNick").join();
        assertFalse(byOld.isDatabaseError());
        assertNull(byOld.getValue(), "Old nickname should no longer resolve");
    }

    @Test
    void findPlayerByNicknameOrPremiumUuidReadOnly_shouldNotMigrateResolverResult() throws Exception {
        assertTrue(manager.initialize().join(), "Database should initialize");

        UUID premiumUuid = UUID.randomUUID();
        insertRawPlayer("OldVerifiedNick", null, premiumUuid.toString());

        DatabaseManager.DbResult<RegisteredPlayer> lookup = manager
                .findPlayerByNicknameOrPremiumUuidReadOnly("UnverifiedNewNick", premiumUuid)
                .join();

        assertFalse(lookup.isDatabaseError());
        assertNotNull(lookup.getValue());
        assertEquals("OldVerifiedNick", lookup.getValue().getNickname());
        assertNotNull(manager.findPlayerByNickname("OldVerifiedNick").join().getValue());
        assertNull(manager.findPlayerByNickname("UnverifiedNewNick").join().getValue(),
                "Resolver UUID must not mutate AUTH before Mojang verification");
    }

    @Test
    void reconcileVerifiedPremiumProfile_legacyLimboAuthRowShouldPreserveHistoricalUuid() throws Exception {
        assertTrue(manager.initialize().join(), "Database should initialize");

        String username = "LegacyPremium";
        UUID historicalBackendUuid = UUID.nameUUIDFromBytes(
                ("OfflinePlayer:" + username).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        UUID verifiedPremiumUuid = UUID.randomUUID();
        insertRawPlayer(username, null, null, historicalBackendUuid);

        DatabaseManager.DbResult<DatabaseManager.PremiumProfileBinding> result = manager
                .reconcileVerifiedPremiumProfile("LegacyPremium", verifiedPremiumUuid)
                .join();

        assertFalse(result.isDatabaseError());
        assertNotNull(result.getValue());
        assertEquals(historicalBackendUuid, result.getValue().backendUuid());
        assertEquals(verifiedPremiumUuid, result.getValue().verifiedPremiumUuid());
        assertTrue(result.getValue().legacyUuidPreserved());

        DatabaseManager.DbResult<RegisteredPlayer> stored = manager
                .findPlayerByNickname("LegacyPremium")
                .join();
        assertFalse(stored.isDatabaseError());
        assertNotNull(stored.getValue());
        assertEquals(historicalBackendUuid.toString(), stored.getValue().getUuid());
        assertEquals(verifiedPremiumUuid.toString(), stored.getValue().getPremiumUuid());
        assertTrue(stored.getValue().isPreserveUuid());

        DatabaseManager.DbResult<DatabaseManager.PremiumProfileBinding> repeated = manager
                .reconcileVerifiedPremiumProfile("LegacyPremium", verifiedPremiumUuid)
                .join();
        assertFalse(repeated.isDatabaseError());
        assertNotNull(repeated.getValue());
        assertEquals(historicalBackendUuid, repeated.getValue().backendUuid(),
                "Persisted flag must keep UUID stable after PREMIUMUUID backfill");
    }

    @Test
    void reconcileVerifiedPremiumProfile_legacyLimboAuthHistoricalPremiumUuidShouldBeReboundOnce()
            throws Exception {
        assertTrue(manager.initialize().join(), "Database should initialize");

        String username = "LegacySavedUuid";
        UUID historicalBackendUuid = UUID.nameUUIDFromBytes(
                ("OfflinePlayer:" + username).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        UUID verifiedPremiumUuid = UUID.randomUUID();
        insertRawPlayer(username, null, historicalBackendUuid.toString(), historicalBackendUuid);

        var result = manager.reconcileVerifiedPremiumProfile(username, verifiedPremiumUuid).join();

        assertFalse(result.isDatabaseError());
        assertNotNull(result.getValue());
        assertEquals(historicalBackendUuid, result.getValue().backendUuid());
        assertEquals(verifiedPremiumUuid, result.getValue().verifiedPremiumUuid());
        assertTrue(result.getValue().legacyUuidPreserved());

        var stored = manager.findPlayerByNickname(username).join();
        assertNotNull(stored.getValue());
        assertEquals(verifiedPremiumUuid.toString(), stored.getValue().getPremiumUuid());
        assertTrue(stored.getValue().isPreserveUuid());

        UUID differentVerifiedIdentity = UUID.randomUUID();
        var secondIdentity = manager
                .reconcileVerifiedPremiumProfile(username, differentVerifiedIdentity)
                .join();
        assertTrue(secondIdentity.isDatabaseError(),
                "After one verified binding, a different Mojang identity must be rejected");
        var unchanged = manager.findPlayerByNickname(username).join();
        assertNotNull(unchanged.getValue());
        assertEquals(verifiedPremiumUuid.toString(), unchanged.getValue().getPremiumUuid());
    }

    @Test
    void reconcileVerifiedPremiumProfile_importMarkerWithMatchingUuidShouldClearPreservationFlag()
            throws Exception {
        assertTrue(manager.initialize().join(), "Database should initialize");

        String username = "ImportedStandardPremium";
        UUID verifiedPremiumUuid = UUID.randomUUID();
        insertRawPlayer(username, null, verifiedPremiumUuid.toString(), verifiedPremiumUuid);
        setPreserveUuid(username, true);

        var result = manager.reconcileVerifiedPremiumProfile(username, verifiedPremiumUuid).join();

        assertFalse(result.isDatabaseError());
        assertNotNull(result.getValue());
        assertEquals(verifiedPremiumUuid, result.getValue().backendUuid());
        assertFalse(result.getValue().legacyUuidPreserved());
        var stored = manager.findPlayerByNickname(username).join();
        assertNotNull(stored.getValue());
        assertFalse(stored.getValue().isPreserveUuid(),
                "A matching imported Mojang UUID needs no long-term compatibility exception");
    }

    @Test
    void reconcileVerifiedPremiumProfile_existingVeloAuthRowShouldKeepMojangUuidBehavior() throws Exception {
        assertTrue(manager.initialize().join(), "Database should initialize");

        UUID oldStoredUuid = UUID.randomUUID();
        UUID verifiedPremiumUuid = UUID.randomUUID();
        insertRawPlayer("ExistingVeloAuth", null, verifiedPremiumUuid.toString(), oldStoredUuid);

        DatabaseManager.DbResult<DatabaseManager.PremiumProfileBinding> result = manager
                .reconcileVerifiedPremiumProfile("ExistingVeloAuth", verifiedPremiumUuid)
                .join();

        assertFalse(result.isDatabaseError());
        assertNotNull(result.getValue());
        assertEquals(verifiedPremiumUuid, result.getValue().backendUuid());
        assertFalse(result.getValue().legacyUuidPreserved());

        DatabaseManager.DbResult<RegisteredPlayer> stored = manager
                .findPlayerByNickname("ExistingVeloAuth")
                .join();
        assertNotNull(stored.getValue());
        assertFalse(stored.getValue().isPreserveUuid(),
                "Additive migration must not flip existing VeloAuth accounts");
    }

    @Test
    void reconcileVerifiedPremiumProfile_storedPremiumIdentityMismatchShouldFailClosed() throws Exception {
        assertTrue(manager.initialize().join(), "Database should initialize");

        UUID storedPremiumUuid = UUID.randomUUID();
        UUID verifiedPremiumUuid = UUID.randomUUID();
        insertRawPlayer("IdentityMismatch", null, storedPremiumUuid.toString(), UUID.randomUUID());

        DatabaseManager.DbResult<DatabaseManager.PremiumProfileBinding> result = manager
                .reconcileVerifiedPremiumProfile("IdentityMismatch", verifiedPremiumUuid)
                .join();

        assertTrue(result.isDatabaseError(), "A verified identity mismatch must deny the login");
        DatabaseManager.DbResult<RegisteredPlayer> stored = manager
                .findPlayerByNickname("IdentityMismatch")
                .join();
        assertNotNull(stored.getValue());
        assertEquals(storedPremiumUuid.toString(), stored.getValue().getPremiumUuid(),
                "Mismatch handling must not overwrite the existing owner identity");
        assertFalse(stored.getValue().isPreserveUuid());
    }

    @Test
    void shutdown_shouldCloseConfiguredHikariDataSource() {
        DatabaseConfig hikariConfig = DatabaseConfig.forRemoteWithHikari(HikariConfigParams.builder()
                .storageType("H2")
                .database("hikari_shutdown_" + System.nanoTime())
                .user("sa")
                .password("")
                .connectionPoolSize(10)
                .maxLifetime(1_800_000)
                .build());
        DatabaseManager hikariManager = new DatabaseManager(hikariConfig, messages);
        HikariDataSource dataSource = (HikariDataSource) hikariConfig.getDataSource();

        try {
            assertTrue(hikariManager.initialize().join(), "Hikari-backed database should initialize");
            assertFalse(dataSource.isClosed());
        } finally {
            hikariManager.shutdown();
        }

        assertTrue(dataSource.isClosed(), "HikariDataSource should be closed on shutdown");
    }

    private RegisteredPlayer player(String nickname, String hash, String premiumUuid) {
        RegisteredPlayer player = new RegisteredPlayer(
                nickname,
                hash,
                "127.0.0.1",
                UUID.randomUUID().toString()
        );
        player.setPremiumUuid(premiumUuid);
        return player;
    }

    private void save(RegisteredPlayer player) {
        DatabaseManager.DbResult<Boolean> result = manager.savePlayer(player).join();
        assertFalse(result.isDatabaseError(), "Insert should not fail for fixture " + player.getNickname());
        assertEquals(Boolean.TRUE, result.getValue());
    }

    private void insertRawPlayer(String nickname, String hash, String premiumUuid) throws Exception {
        insertRawPlayer(nickname, hash, premiumUuid, UUID.randomUUID());
    }

    private void insertRawPlayer(String nickname, String hash, String premiumUuid, UUID backendUuid)
            throws Exception {
        try (Connection connection = DriverManager.getConnection(manager.getConfig().getJdbcUrl());
             PreparedStatement statement = connection.prepareStatement(
                      "INSERT INTO AUTH (LOWERCASENICKNAME, NICKNAME, HASH, IP, LOGINIP, UUID, REGDATE, LOGINDATE, PREMIUMUUID, TOTPTOKEN, ISSUEDTIME) "
                              + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            statement.setString(1, nickname.toLowerCase(Locale.ROOT));
            statement.setString(2, nickname);
            statement.setString(3, hash);
            statement.setString(4, "127.0.0.1");
            statement.setString(5, "127.0.0.1");
            statement.setString(6, backendUuid.toString());
            statement.setLong(7, System.currentTimeMillis());
            statement.setLong(8, System.currentTimeMillis());
            statement.setString(9, premiumUuid);
            statement.setString(10, null);
            statement.setLong(11, 0L);
            statement.executeUpdate();
        }
    }

    private void setPreserveUuid(String nickname, boolean preserveUuid) throws Exception {
        try (Connection connection = DriverManager.getConnection(manager.getConfig().getJdbcUrl());
             PreparedStatement statement = connection.prepareStatement(
                     "UPDATE AUTH SET PRESERVE_UUID = ? WHERE LOWERCASENICKNAME = ?")) {
            statement.setBoolean(1, preserveUuid);
            statement.setString(2, nickname.toLowerCase(java.util.Locale.ROOT));
            statement.executeUpdate();
        }
    }

    private void insertRawConflictPlayer(String nickname, String hash, String premiumUuid,
                                         boolean conflictMode, long conflictTimestamp,
                                         String originalNickname) {
        try (Connection connection = DriverManager.getConnection(manager.getConfig().getJdbcUrl());
             PreparedStatement statement = connection.prepareStatement(
                     "INSERT INTO AUTH (LOWERCASENICKNAME, NICKNAME, HASH, IP, LOGINIP, UUID, REGDATE, LOGINDATE, PREMIUMUUID, TOTPTOKEN, ISSUEDTIME, CONFLICT_MODE, CONFLICT_TIMESTAMP, ORIGINAL_NICKNAME) "
                             + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            statement.setString(1, nickname.toLowerCase(Locale.ROOT));
            statement.setString(2, nickname);
            statement.setString(3, hash);
            statement.setString(4, "127.0.0.1");
            statement.setString(5, "127.0.0.1");
            statement.setString(6, UUID.randomUUID().toString());
            statement.setLong(7, System.currentTimeMillis());
            statement.setLong(8, System.currentTimeMillis());
            statement.setString(9, premiumUuid);
            statement.setString(10, null);
            statement.setLong(11, 0L);
            statement.setBoolean(12, conflictMode);
            statement.setLong(13, conflictTimestamp);
            statement.setString(14, originalNickname);
            statement.executeUpdate();
        } catch (Exception e) {
            throw new AssertionError("Failed to insert conflict player fixture", e);
        }
    }

}
