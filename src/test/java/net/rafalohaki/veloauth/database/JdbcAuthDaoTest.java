package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JdbcAuthDaoTest {

    private static final String OFFLINE_HASH = "$2a$10$offlinehashvalueofflinehashvalueofflinehashval";

    private DatabaseConfig config;
    private DatabaseManager manager;
    private JdbcAuthDao dao;

    @BeforeEach
    void setUp() {
        Messages messages = new Messages();
        messages.setLanguage("en");
        config = DatabaseConfig.forLocalDatabase("H2", "jdbc_auth_test_" + System.nanoTime());
        manager = new DatabaseManager(config, messages);
        assertTrue(manager.initialize().join(), "Database should initialize");
        dao = new JdbcAuthDao(config);
    }

    @AfterEach
    void tearDown() {
        manager.shutdown();
    }

    @Test
    void findPlayerByLowercaseNickname_emptyNicknameRowShouldThrowSQLException() throws Exception {
        insertRawAuthRow("", "broken-empty", OFFLINE_HASH, UUID.randomUUID().toString(), null);

        assertThrows(SQLException.class, () -> dao.findPlayerByLowercaseNickname("broken-empty"));
    }

    @Test
    void findPlayerByLowercaseNickname_invalidUuidRowShouldThrowSQLException() throws Exception {
        insertRawAuthRow("BrokenUuid", "brokenuuid", OFFLINE_HASH, "not-a-uuid", null);

        assertThrows(SQLException.class, () -> dao.findPlayerByLowercaseNickname("brokenuuid"));
    }

    @Test
    void upsertPlayer_existingPlayerShouldUpdateWithoutCreatingDuplicateRow() throws Exception {
        RegisteredPlayer player = new RegisteredPlayer(
                "Alice",
                OFFLINE_HASH,
                "127.0.0.1",
                UUID.randomUUID().toString()
        );

        assertTrue(dao.upsertPlayer(player));

        player.setHash("$2a$10$updatedhashvalueupdatedhashvalueupdatedhashva");
        assertTrue(dao.upsertPlayer(player));

        assertEquals(1, countAuthRows("alice"));
        assertEquals("$2a$10$updatedhashvalueupdatedhashvalueupdatedhashva",
                dao.findPlayerByLowercaseNickname("alice").getHash());
    }

    @Test
    void insertPlayerIfAbsent_existingNicknameShouldNotOverwriteAccountOwner() throws Exception {
        RegisteredPlayer owner = new RegisteredPlayer(
                "Alice",
                OFFLINE_HASH,
                "127.0.0.1",
                UUID.randomUUID().toString()
        );
        RegisteredPlayer competingRegistration = new RegisteredPlayer(
                "Alice",
                "$2a$10$attackerhashvalueattackerhashvalueattackerha",
                "127.0.0.2",
                UUID.randomUUID().toString()
        );

        assertTrue(dao.insertPlayerIfAbsent(owner));
        assertFalse(dao.insertPlayerIfAbsent(competingRegistration));

        RegisteredPlayer stored = dao.findPlayerByLowercaseNickname("alice");
        assertEquals(OFFLINE_HASH, stored.getHash());
        assertEquals(owner.getUuid(), stored.getUuid());
        assertEquals(1, countAuthRows("alice"));
    }

    @Test
    void upsertPlayer_duplicateRaceShouldRecoverInFreshTransaction() throws Exception {
        DatabaseConfig remoteConfig = mock(DatabaseConfig.class);
        DataSource dataSource = mock(DataSource.class);
        Connection failedTransaction = mock(Connection.class);
        Connection recoveryTransaction = mock(Connection.class);
        PreparedStatement initialUpdate = mock(PreparedStatement.class);
        PreparedStatement competingInsert = mock(PreparedStatement.class);
        PreparedStatement recoveryUpdate = mock(PreparedStatement.class);
        when(remoteConfig.getStorageType()).thenReturn("POSTGRESQL");
        when(remoteConfig.getDataSource()).thenReturn(dataSource);
        when(dataSource.getConnection()).thenReturn(failedTransaction, recoveryTransaction);
        when(failedTransaction.getAutoCommit()).thenReturn(true);
        when(recoveryTransaction.getAutoCommit()).thenReturn(true);
        when(failedTransaction.prepareStatement(startsWith("UPDATE"))).thenReturn(initialUpdate);
        when(failedTransaction.prepareStatement(startsWith("INSERT"))).thenReturn(competingInsert);
        when(recoveryTransaction.prepareStatement(startsWith("UPDATE"))).thenReturn(recoveryUpdate);
        when(initialUpdate.executeUpdate()).thenReturn(0);
        when(competingInsert.executeUpdate()).thenThrow(new SQLException("duplicate key", "23505"));
        when(recoveryUpdate.executeUpdate()).thenReturn(1);
        RegisteredPlayer player = new RegisteredPlayer(
                "ConcurrentAlice",
                OFFLINE_HASH,
                "127.0.0.1",
                UUID.randomUUID().toString()
        );

        assertTrue(new JdbcAuthDao(remoteConfig).upsertPlayer(player));

        verify(failedTransaction).rollback();
        verify(failedTransaction, never()).commit();
        verify(recoveryTransaction).commit();
        verify(dataSource, times(2)).getConnection();
    }

    @Test
    void upsertPlayer_deadlockShouldRetryOnFreshTransaction() throws Exception {
        DatabaseConfig remoteConfig = mock(DatabaseConfig.class);
        DataSource dataSource = mock(DataSource.class);
        Connection deadlockedTransaction = mock(Connection.class);
        Connection retryTransaction = mock(Connection.class);
        PreparedStatement initialUpdate = mock(PreparedStatement.class);
        PreparedStatement deadlockedInsert = mock(PreparedStatement.class);
        PreparedStatement retryUpdate = mock(PreparedStatement.class);
        when(remoteConfig.getStorageType()).thenReturn("MYSQL");
        when(remoteConfig.getDataSource()).thenReturn(dataSource);
        when(dataSource.getConnection()).thenReturn(deadlockedTransaction, retryTransaction);
        when(deadlockedTransaction.getAutoCommit()).thenReturn(true);
        when(retryTransaction.getAutoCommit()).thenReturn(true);
        when(deadlockedTransaction.prepareStatement(startsWith("UPDATE"))).thenReturn(initialUpdate);
        when(deadlockedTransaction.prepareStatement(startsWith("INSERT"))).thenReturn(deadlockedInsert);
        when(retryTransaction.prepareStatement(startsWith("UPDATE"))).thenReturn(retryUpdate);
        when(initialUpdate.executeUpdate()).thenReturn(0);
        when(deadlockedInsert.executeUpdate()).thenThrow(
                new SQLException("Deadlock found when trying to get lock", "40001", 1213));
        when(retryUpdate.executeUpdate()).thenReturn(1);
        RegisteredPlayer player = new RegisteredPlayer(
                "DeadlockAlice",
                OFFLINE_HASH,
                "127.0.0.1",
                UUID.randomUUID().toString()
        );

        assertTrue(new JdbcAuthDao(remoteConfig).upsertPlayer(player));

        verify(deadlockedTransaction).rollback();
        verify(retryTransaction).commit();
        verify(dataSource, times(2)).getConnection();
    }

    private void insertRawAuthRow(String nickname, String lowercaseNickname, String hash, String uuid, String premiumUuid)
            throws Exception {
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             PreparedStatement statement = connection.prepareStatement(
                     "INSERT INTO AUTH (LOWERCASENICKNAME, NICKNAME, HASH, IP, LOGINIP, UUID, REGDATE, LOGINDATE, PREMIUMUUID, TOTPTOKEN, ISSUEDTIME) "
                             + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {
            statement.setString(1, lowercaseNickname.toLowerCase(Locale.ROOT));
            statement.setString(2, nickname);
            statement.setString(3, hash);
            statement.setString(4, "127.0.0.1");
            statement.setString(5, "127.0.0.1");
            statement.setString(6, uuid);
            statement.setLong(7, 1L);
            statement.setLong(8, 1L);
            statement.setString(9, premiumUuid);
            statement.setString(10, null);
            statement.setLong(11, 0L);
            statement.executeUpdate();
        }
    }

    private int countAuthRows(String lowercaseNickname) throws Exception {
        try (Connection connection = DriverManager.getConnection(config.getJdbcUrl());
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT COUNT(*) FROM AUTH WHERE LOWERCASENICKNAME = ?")) {
            statement.setString(1, lowercaseNickname);
            try (ResultSet resultSet = statement.executeQuery()) {
                resultSet.next();
                return resultSet.getInt(1);
            }
        }
    }
}
