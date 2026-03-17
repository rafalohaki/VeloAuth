package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Manual performance tests for DatabaseManager hot paths.
 * Run explicitly with -Dveloauth.benchmark=true.
 */
class DatabaseManagerPerformanceTest {

    private static final int PLAYER_COUNT = 5000;
    private static final int PREMIUM_PLAYER_COUNT = PLAYER_COUNT / 2;
    private static final int WARMUP_RUNS = 3;
    private static final int MEASURED_RUNS = 10;

    @Test
    void benchmarkGetTotalPremiumAccounts() {
        assumeTrue(Boolean.getBoolean("veloauth.benchmark"),
                "Manual benchmark disabled. Run with -Dveloauth.benchmark=true");

        Messages messages = new Messages();
        messages.setLanguage("en");

        String databaseName = "benchmark_" + System.nanoTime();
        DatabaseManager manager = new DatabaseManager(
                DatabaseConfig.forLocalDatabase("H2", databaseName),
                messages
        );

        try {
            assertTrue(manager.initialize().join(), "Database should initialize for benchmark");
            populatePlayers(manager);

            for (int run = 0; run < WARMUP_RUNS; run++) {
                assertEquals(PREMIUM_PLAYER_COUNT, manager.getTotalPremiumAccounts().join());
            }

            long startedAt = System.nanoTime();
            for (int run = 0; run < MEASURED_RUNS; run++) {
                assertEquals(PREMIUM_PLAYER_COUNT, manager.getTotalPremiumAccounts().join());
            }
            long elapsedNanos = System.nanoTime() - startedAt;

            double averageMillis = elapsedNanos / 1_000_000.0 / MEASURED_RUNS;
            System.out.printf("BENCHMARK getTotalPremiumAccounts avg=%.3fms players=%d runs=%d%n",
                    averageMillis, PLAYER_COUNT, MEASURED_RUNS);
        } finally {
            manager.shutdown();
        }
    }

    private void populatePlayers(DatabaseManager manager) {
        for (int index = 0; index < PLAYER_COUNT; index++) {
            boolean premium = index % 2 == 0;
            String nickname = "BenchPlayer" + index;
            RegisteredPlayer player = new RegisteredPlayer(
                    nickname,
                    premium ? null : "$2a$10$offlinehashvalueofflinehashvalueofflinehashval",
                    "127.0.0.1",
                    UUID.randomUUID().toString()
            );

            if (premium) {
                player.setPremiumUuid(UUID.randomUUID().toString());
            }

            DatabaseManager.DbResult<Boolean> result = manager.savePlayer(player).join();
            assertTrue(!result.isDatabaseError() && Boolean.TRUE.equals(result.getValue()),
                    "Benchmark fixture insert should succeed for " + nickname);
        }
    }
}