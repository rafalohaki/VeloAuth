package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.sql.SQLException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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
    void countQueries_shouldMatchExistingPremiumSemantics() {
        assertTrue(manager.initialize().join(), "Database should initialize");

        save(player("PremiumByNullHash", null, null));
        save(player("PremiumByUuid", "$2a$10$offlinehashvalueofflinehashvalueofflinehashval", UUID.randomUUID().toString()));
        save(player("OfflineA", "$2a$10$offlinehashvalueofflinehashvalueofflinehashval", null));
        save(player("OfflineB", "$2a$10$offlinehashvalueofflinehashvalueofflinehashval", null));

        assertEquals(4, manager.getTotalRegisteredAccounts().join());
        assertEquals(2, manager.getTotalPremiumAccounts().join());
        assertEquals(3, manager.getTotalNonPremiumAccounts().join());
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
    void isPremium_runtimeExceptionShouldReturnGenericDatabaseError() throws Exception {
        PremiumUuidDao premiumUuidDao = mock(PremiumUuidDao.class);
        when(premiumUuidDao.findByNickname("Alice"))
                .thenThrow(new RuntimeException("org.h2.jdbc.JdbcSQLSyntaxErrorException: leaked details"));

        manager.setConnectedForTesting(true);
        manager.setPremiumUuidDaoForTesting(premiumUuidDao);

        DatabaseManager.DbResult<Boolean> result = manager.isPremium("Alice").join();

        assertTrue(result.isDatabaseError());
        assertEquals(messages.get("database.error"), result.getErrorMessage());
        assertFalse(result.getErrorMessage().contains("leaked details"));
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

}