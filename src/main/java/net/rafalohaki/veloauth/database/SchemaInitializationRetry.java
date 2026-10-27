package net.rafalohaki.veloauth.database;

import java.sql.SQLException;
import java.util.ConcurrentModificationException;

/** Retries only the transient H2 DDL race, leaving every other startup failure fail-fast. */
final class SchemaInitializationRetry {

    private static final int MAX_ATTEMPTS = 3;
    private static final long RETRY_BASE_DELAY_MS = 50L;

    private SchemaInitializationRetry() {
    }

    static boolean execute(String storageType, Initialization initialization, Runnable cleanup) throws SQLException {
        for (int attempt = 1; ; attempt++) {
            try {
                return initialization.run();
            } catch (SQLException exception) {
                if (attempt >= MAX_ATTEMPTS || !isH2SchemaRace(storageType, exception)) {
                    throw exception;
                }
                cleanup.run();
                delayBeforeRetry(attempt, exception);
            }
        }
    }

    private static boolean isH2SchemaRace(String storageType, SQLException exception) {
        if (DatabaseType.fromName(storageType) != DatabaseType.H2) {
            return false;
        }
        Throwable cause = exception;
        while (cause != null) {
            if (cause instanceof ConcurrentModificationException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    private static void delayBeforeRetry(int attempt, SQLException initializationFailure) throws SQLException {
        try {
            Thread.sleep(RETRY_BASE_DELAY_MS * attempt);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            SQLException failure = new SQLException("Interrupted during H2 schema initialization retry", interrupted);
            failure.addSuppressed(initializationFailure);
            throw failure;
        }
    }

    @FunctionalInterface
    interface Initialization {
        boolean run() throws SQLException;
    }
}
