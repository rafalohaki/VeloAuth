package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.SQLException;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DatabaseConfigTest {

    private static final String FIRST_HASH = "$2a$10$firsthashvaluefirsthashvaluefirsthashvaluefi";
    private static final String SECOND_HASH = "$2a$10$secondhashvaluesecondhashvaluesecondhashval";

    @TempDir
    Path tempDir;

    @Test
    void forLocalDatabase_defaultSqlitePath_shouldRemainUpgradeCompatible() {
        DatabaseConfig config = DatabaseConfig.forLocalDatabase("SQLITE", "veloauth");

        assertEquals("jdbc:sqlite:./data/veloauth.db", config.getJdbcUrl());
    }

    @Test
    void initialize_freshSqliteInstallation_shouldCreateParentDirectoryAndDatabase() {
        Path databaseDirectory = tempDir.resolve("fresh-data");
        DatabaseConfig config = DatabaseConfig.forLocalDatabase(
                "SQLITE", "veloauth", databaseDirectory);
        Messages messages = new Messages();
        messages.setLanguage("en");
        DatabaseManager manager = new DatabaseManager(config, messages);

        assertFalse(Files.exists(databaseDirectory));
        try {
            assertTrue(manager.initialize().join(), "Fresh SQLite database should initialize");
            assertTrue(Files.isDirectory(databaseDirectory));
            assertTrue(Files.isRegularFile(databaseDirectory.resolve("veloauth.db")));
        } finally {
            manager.shutdown();
        }
    }

    @Test
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    void insertPlayerIfAbsent_concurrentSqliteRegistrationsShouldKeepOneOwner()
            throws SQLException, InterruptedException, ExecutionException {
        DatabaseConfig config = DatabaseConfig.forLocalDatabase(
                "SQLITE", "registration-race", tempDir.resolve("sqlite-race"));
        Messages messages = new Messages();
        messages.setLanguage("en");
        DatabaseManager manager = new DatabaseManager(config, messages);
        assertTrue(manager.initialize().join(), "SQLite schema should initialize");
        JdbcAuthDao dao = new JdbcAuthDao(config);
        String address = InetAddress.getLoopbackAddress().getHostAddress();
        RegisteredPlayer first = new RegisteredPlayer(
                "SqliteOwner", FIRST_HASH, address, UUID.randomUUID().toString());
        RegisteredPlayer second = new RegisteredPlayer(
                "SqliteOwner", SECOND_HASH, address, UUID.randomUUID().toString());
        CountDownLatch start = new CountDownLatch(1);

        try {
            try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
                Future<Boolean> firstResult = executor.submit(() -> insertAfterLatch(dao, start, first));
                Future<Boolean> secondResult = executor.submit(() -> insertAfterLatch(dao, start, second));
                start.countDown();
                boolean firstCreated = firstResult.get();
                boolean secondCreated = secondResult.get();

                assertTrue(firstCreated ^ secondCreated,
                        "Exactly one concurrent registration must acquire nickname ownership");
                RegisteredPlayer stored = dao.findPlayerByLowercaseNickname("sqliteowner");
                assertEquals(firstCreated ? FIRST_HASH : SECOND_HASH, stored.getHash(),
                        "Stored row must belong to the writer that won the insert");
            }
        } finally {
            manager.shutdown();
        }
    }

    private boolean insertAfterLatch(JdbcAuthDao dao, CountDownLatch start, RegisteredPlayer player)
            throws InterruptedException, SQLException {
        start.await();
        return dao.insertPlayerIfAbsent(player);
    }
}
