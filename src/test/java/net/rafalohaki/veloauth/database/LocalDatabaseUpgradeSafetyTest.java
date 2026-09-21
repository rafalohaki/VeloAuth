package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.helpers.NOPLogger;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Upgrade safety for existing player databases (PR #56): the SQLite activity guard must
 * never strand or corrupt an existing database. A blocked migration keeps the legacy
 * location fully usable; a clean database still migrates with every row intact.
 */
class LocalDatabaseUpgradeSafetyTest {

    private static final String DB_NAME = "upgrade_safety";

    @TempDir
    Path tempDir;

    private static Messages messages() {
        Messages messages = new Messages();
        messages.setLanguage("en");
        return messages;
    }

    private static DatabaseManager openManager(DatabaseType type, Path directory) {
        DatabaseConfig config = DatabaseConfig.forLocalDatabase(
                type.getName(), DB_NAME, directory);
        DatabaseManager manager = new DatabaseManager(config, messages());
        assertTrue(manager.initialize().join(), "Database must initialize at " + directory);
        return manager;
    }

    private static RegisteredPlayer seedPlayer(DatabaseManager manager) {
        RegisteredPlayer player = new RegisteredPlayer(
                "UpgradeGracz", "$2a$10$abcdefghijklmnopqrstuv1234567890abcdefghijklmnopqrstu",
                "192.0.2.10", UUID.randomUUID().toString());
        assertTrue(manager.registerPlayerIfAbsent(player).join().getValue(),
                "Seed registration must succeed");
        return player;
    }

    @Test
    void sqliteWithWalLeftovers_keepsLegacyDatabaseAndDataIntact() throws Exception {
        Path legacy = Files.createDirectories(tempDir.resolve("legacy-data"));
        Path target = tempDir.resolve("plugin-data");

        // Populate a database at the legacy location, close it, then simulate an unclean
        // shutdown's leftover WAL/SHM artifacts.
        DatabaseManager first = openManager(DatabaseType.SQLITE, legacy);
        RegisteredPlayer seeded = seedPlayer(first);
        first.shutdown();
        Files.writeString(legacy.resolve(DB_NAME + ".db-wal"), "unclean-leftover");
        Files.writeString(legacy.resolve(DB_NAME + ".db-shm"), "unclean-leftover");

        Path resolved = LocalDatabaseMigrator.resolveDataDirectory(
                DatabaseType.SQLITE, DB_NAME, legacy, target, Files::move, NOPLogger.NOP_LOGGER);
        assertEquals(legacy.toAbsolutePath().normalize(), resolved,
                "Guard must keep the legacy location while WAL artifacts exist");

        // The plugin must open the legacy database and see every row, and writes must work.
        DatabaseManager reopened = openManager(DatabaseType.SQLITE, legacy);
        try {
            RegisteredPlayer loaded = reopened.findPlayerByNickname("UpgradeGracz").join().getValue();
            assertNotNull(loaded, "Player row must survive the blocked migration");
            assertEquals(seeded.getUuid(), loaded.getUuid());
            assertEquals(seeded.getHash(), loaded.getHash());
            loaded.updateLoginData("192.0.2.11");
            assertTrue(reopened.savePlayer(loaded).join().getValue(),
                    "Writes must keep working from the legacy location");
        } finally {
            reopened.shutdown();
        }
        assertTrue(Files.exists(legacy.resolve(DB_NAME + ".db")),
                "Legacy database file must remain in place");
    }

    @Test
    void sqliteCleanShutdown_migratesWithAllDataIntact() throws Exception {
        Path legacy = Files.createDirectories(tempDir.resolve("legacy-data"));
        Path target = tempDir.resolve("plugin-data");

        DatabaseManager first = openManager(DatabaseType.SQLITE, legacy);
        RegisteredPlayer seeded = seedPlayer(first);
        first.shutdown();

        Path resolved = LocalDatabaseMigrator.resolveDataDirectory(
                DatabaseType.SQLITE, DB_NAME, legacy, target, Files::move, NOPLogger.NOP_LOGGER);
        assertEquals(target.toAbsolutePath().normalize(), resolved,
                "Clean database must migrate to the plugin data directory");

        DatabaseManager reopened = openManager(DatabaseType.SQLITE, target);
        try {
            RegisteredPlayer loaded = reopened.findPlayerByNickname("UpgradeGracz").join().getValue();
            assertNotNull(loaded, "Player row must survive the migration");
            assertEquals(seeded.getUuid(), loaded.getUuid());
            assertEquals(seeded.getHash(), loaded.getHash());
            assertTrue(reopened.getSchemaVersionDao().hasVersion(2),
                    "Schema version markers must survive the migration");
        } finally {
            reopened.shutdown();
        }
    }

    @Test
    void h2ExistingDatabase_reopensWithDataAndSchemaMarkersIntact() {
        Path directory = tempDir.resolve("h2-data");

        DatabaseManager first = openManager(DatabaseType.H2, directory);
        RegisteredPlayer seeded = seedPlayer(first);
        first.shutdown();

        // Same code path a server takes on restart: open the existing database again.
        DatabaseManager reopened = openManager(DatabaseType.H2, directory);
        try {
            RegisteredPlayer loaded = reopened.findPlayerByNickname("UpgradeGracz").join().getValue();
            assertNotNull(loaded);
            assertEquals(seeded.getUuid(), loaded.getUuid());
            assertTrue(reopened.getSchemaVersionDao().hasVersion(1));
            assertTrue(reopened.getSchemaVersionDao().hasVersion(2));
        } finally {
            reopened.shutdown();
        }
    }
}
