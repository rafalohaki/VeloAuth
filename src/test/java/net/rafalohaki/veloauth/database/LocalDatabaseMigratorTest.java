package net.rafalohaki.veloauth.database;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.helpers.NOPLogger;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Upgrade-safety contract for relocating legacy {@code ./data} H2/SQLite files into the
 * plugin data directory. Existing installations must never lose or duplicate their database.
 */
class LocalDatabaseMigratorTest {

    private static final String DB_NAME = "veloauth";

    @TempDir
    Path tempDir;

    private Path legacyDir;
    private Path targetDir;

    private Path resolve(DatabaseType dbType) {
        return LocalDatabaseMigrator.resolveDataDirectory(
                dbType, DB_NAME, legacyDir, targetDir, Files::move, NOPLogger.NOP_LOGGER);
    }

    private void initDirs() throws IOException {
        legacyDir = tempDir.resolve("cwd-data");
        targetDir = tempDir.resolve("plugins").resolve("veloauth").resolve("data");
        Files.createDirectories(legacyDir);
    }

    @Test
    void resolveDataDirectory_FreshInstall_ReturnsTargetDirectory() throws IOException {
        initDirs();

        Path resolved = resolve(DatabaseType.H2);

        assertEquals(targetDir.toAbsolutePath().normalize(), resolved);
        assertFalse(Files.exists(targetDir.resolve(DB_NAME + ".mv.db")),
                "Fresh install must not fabricate database files");
    }

    @Test
    void resolveDataDirectory_LegacyH2Files_MovesThemToTargetDirectory() throws IOException {
        initDirs();
        Files.writeString(legacyDir.resolve(DB_NAME + ".mv.db"), "main");
        Files.writeString(legacyDir.resolve(DB_NAME + ".trace.db"), "trace");

        Path resolved = resolve(DatabaseType.H2);

        assertEquals(targetDir.toAbsolutePath().normalize(), resolved);
        assertEquals("main", Files.readString(targetDir.resolve(DB_NAME + ".mv.db")));
        assertEquals("trace", Files.readString(targetDir.resolve(DB_NAME + ".trace.db")));
        assertFalse(Files.exists(legacyDir.resolve(DB_NAME + ".mv.db")),
                "Legacy main file must be moved, not copied");
        assertFalse(Files.exists(legacyDir.resolve(DB_NAME + ".trace.db")),
                "Legacy trace file must be moved, not copied");
    }

    @Test
    void resolveDataDirectory_SqliteWalFamily_MovesEveryCompanionFile() throws IOException {
        initDirs();
        Files.writeString(legacyDir.resolve(DB_NAME + ".db"), "main");
        Files.writeString(legacyDir.resolve(DB_NAME + ".db-wal"), "wal");
        Files.writeString(legacyDir.resolve(DB_NAME + ".db-shm"), "shm");

        Path resolved = resolve(DatabaseType.SQLITE);

        assertEquals(targetDir.toAbsolutePath().normalize(), resolved);
        assertEquals("main", Files.readString(targetDir.resolve(DB_NAME + ".db")));
        assertEquals("wal", Files.readString(targetDir.resolve(DB_NAME + ".db-wal")));
        assertEquals("shm", Files.readString(targetDir.resolve(DB_NAME + ".db-shm")));
        assertFalse(Files.exists(legacyDir.resolve(DB_NAME + ".db")));
    }

    @Test
    void resolveDataDirectory_TargetAlreadyPopulated_PrefersTargetAndLeavesLegacyUntouched()
            throws IOException {
        initDirs();
        Files.createDirectories(targetDir);
        Files.writeString(targetDir.resolve(DB_NAME + ".mv.db"), "current");
        Files.writeString(legacyDir.resolve(DB_NAME + ".mv.db"), "stale");

        Path resolved = resolve(DatabaseType.H2);

        assertEquals(targetDir.toAbsolutePath().normalize(), resolved);
        assertEquals("current", Files.readString(targetDir.resolve(DB_NAME + ".mv.db")),
                "An already-migrated database must never be overwritten");
        assertEquals("stale", Files.readString(legacyDir.resolve(DB_NAME + ".mv.db")),
                "Stale legacy files are left for the operator to remove");
    }

    @Test
    void resolveDataDirectory_H2LockFilePresent_KeepsLegacyDirectory() throws IOException {
        initDirs();
        Files.writeString(legacyDir.resolve(DB_NAME + ".mv.db"), "main");
        Files.writeString(legacyDir.resolve(DB_NAME + ".lock.db"), "lock");

        Path resolved = resolve(DatabaseType.H2);

        assertEquals(legacyDir.toAbsolutePath().normalize(), resolved,
                "A lock file may mean another process owns the database - do not move it");
        assertTrue(Files.exists(legacyDir.resolve(DB_NAME + ".mv.db")));
        assertFalse(Files.exists(targetDir.resolve(DB_NAME + ".mv.db")));
    }

    @Test
    void resolveDataDirectory_MainFileMoveFails_RollsBackAndReturnsLegacyDirectory()
            throws IOException {
        initDirs();
        Files.writeString(legacyDir.resolve(DB_NAME + ".mv.db"), "main");
        Files.writeString(legacyDir.resolve(DB_NAME + ".trace.db"), "trace");
        LocalDatabaseMigrator.FileMover failOnMainFile = (source, target) -> {
            if (source.getFileName().toString().equals(DB_NAME + ".mv.db")) {
                throw new IOException("simulated move failure");
            }
            Files.move(source, target);
        };

        Path resolved = LocalDatabaseMigrator.resolveDataDirectory(
                DatabaseType.H2, DB_NAME, legacyDir, targetDir, failOnMainFile,
                NOPLogger.NOP_LOGGER);

        assertEquals(legacyDir.toAbsolutePath().normalize(), resolved,
                "A failed migration must fall back to the working legacy directory");
        assertEquals("main", Files.readString(legacyDir.resolve(DB_NAME + ".mv.db")));
        assertEquals("trace", Files.readString(legacyDir.resolve(DB_NAME + ".trace.db")),
                "Companion files moved before the failure must be rolled back");
        assertFalse(Files.exists(targetDir.resolve(DB_NAME + ".trace.db")));
    }
}
