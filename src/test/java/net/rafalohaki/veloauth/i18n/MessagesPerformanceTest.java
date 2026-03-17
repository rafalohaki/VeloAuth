package net.rafalohaki.veloauth.i18n;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Manual benchmark for message formatting hot paths.
 * Run explicitly with -Dveloauth.benchmark=true.
 */
class MessagesPerformanceTest {

    private static final int WARMUP_RUNS = 10_000;
    private static final int MEASURED_RUNS = 100_000;

    @Test
    void benchmarkExternalMessageFormatting() throws IOException {
        assumeTrue(Boolean.getBoolean("veloauth.benchmark"),
                "Manual benchmark disabled. Run with -Dveloauth.benchmark=true");

        Path tempDir = Files.createTempDirectory("veloauth-messages-benchmark");
        Messages messages = new Messages(tempDir, "en");

        for (int run = 0; run < WARMUP_RUNS; run++) {
            String formatted = messages.get("connection.manager.initialized", "auth");
            assertFalse(formatted.isEmpty(), "Warmup result should not be empty");
        }

        long startedAt = System.nanoTime();
        for (int run = 0; run < MEASURED_RUNS; run++) {
            String formatted = messages.get("connection.manager.initialized", "auth");
            assertFalse(formatted.isEmpty(), "Formatted result should not be empty");
        }
        long elapsedNanos = System.nanoTime() - startedAt;

        double averageMicros = elapsedNanos / 1_000.0 / MEASURED_RUNS;
        System.out.printf("BENCHMARK formatMessageSafely avg=%.3fus runs=%d%n",
                averageMicros, MEASURED_RUNS);
    }
}