package net.rafalohaki.veloauth.database;

import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Relocates legacy working-directory {@code ./data} H2/SQLite files into the plugin data
 * directory exactly once, falling back to the legacy location whenever a move is unsafe.
 * <p>
 * Upgrade-safety contract (existing installations keep working in every branch):
 * <ul>
 *   <li>Target already holds the database → target wins, legacy files stay untouched.</li>
 *   <li>H2 lock file present in legacy → another process may own it; keep using legacy.</li>
 *   <li>Any move fails → already-moved companion files are rolled back and legacy stays
 *       the active directory.</li>
 * </ul>
 */
final class LocalDatabaseMigrator {

    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");

    private LocalDatabaseMigrator() {
    }

    /** Test seam for simulating filesystem move failures. */
    @FunctionalInterface
    interface FileMover {
        void move(Path source, Path target) throws IOException;
    }

    static Path resolveDataDirectory(
            DatabaseType dbType,
            String database,
            Path legacyDirectory,
            Path targetDirectory,
            FileMover mover,
            Logger logger) {
        Path legacy = legacyDirectory.toAbsolutePath().normalize();
        Path target = targetDirectory.toAbsolutePath().normalize();
        if (legacy.equals(target)) {
            return target;
        }

        String mainFile = mainFileName(dbType, database);
        if (Files.exists(target.resolve(mainFile))) {
            if (Files.exists(legacy.resolve(mainFile))) {
                logger.warn(DB_MARKER,
                        "Database already migrated to {} but a stale copy remains in {} - "
                                + "the stale copy is ignored and can be removed manually",
                        target, legacy);
            }
            return target;
        }
        if (!Files.exists(legacy.resolve(mainFile))) {
            return target;
        }
        if (dbType == DatabaseType.H2 && Files.exists(legacy.resolve(database + ".lock.db"))) {
            logger.warn(DB_MARKER,
                    "H2 lock file found in {} - skipping migration because another process "
                            + "may be using the database; keeping the legacy location",
                    legacy);
            return legacy;
        }
        return migrate(dbType, database, legacy, target, mover, logger) ? target : legacy;
    }

    private static boolean migrate(
            DatabaseType dbType,
            String database,
            Path legacy,
            Path target,
            FileMover mover,
            Logger logger) {
        List<Path> movedFiles = new ArrayList<>();
        String mainFile = mainFileName(dbType, database);
        try {
            Files.createDirectories(target);
            for (String companion : companionFileNames(dbType, database)) {
                Path source = legacy.resolve(companion);
                if (Files.exists(source)) {
                    mover.move(source, target.resolve(companion));
                    movedFiles.add(target.resolve(companion));
                }
            }
            mover.move(legacy.resolve(mainFile), target.resolve(mainFile));
            logger.info(DB_MARKER,
                    "Migrated local database '{}' from {} to {} ({} companion files)",
                    database, legacy, target, movedFiles.size());
            return true;
        } catch (IOException migrationFailure) {
            rollback(movedFiles, legacy, mover, logger);
            logger.warn(DB_MARKER,
                    "Could not migrate local database '{}' from {} to {} - "
                            + "continuing with the legacy location",
                    database, legacy, target, migrationFailure);
            return false;
        }
    }

    private static void rollback(List<Path> movedFiles, Path legacy, FileMover mover, Logger logger) {
        for (Path moved : movedFiles) {
            try {
                mover.move(moved, legacy.resolve(moved.getFileName()));
            } catch (IOException rollbackFailure) {
                logger.error(DB_MARKER,
                        "Failed to roll back partially migrated file {} to {}",
                        moved, legacy, rollbackFailure);
            }
        }
    }

    private static String mainFileName(DatabaseType dbType, String database) {
        return dbType == DatabaseType.H2 ? database + ".mv.db" : database + ".db";
    }

    private static List<String> companionFileNames(DatabaseType dbType, String database) {
        if (dbType == DatabaseType.H2) {
            return List.of(database + ".trace.db");
        }
        return List.of(database + ".db-journal", database + ".db-wal", database + ".db-shm");
    }
}
