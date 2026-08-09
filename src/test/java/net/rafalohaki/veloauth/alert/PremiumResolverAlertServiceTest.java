package net.rafalohaki.veloauth.alert;

import net.rafalohaki.veloauth.config.Settings;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PremiumResolverAlertServiceTest {

    @Test
    void failedDiscordDelivery_shouldNotConsumeCooldownAndShouldRetryNextFailure() throws Exception {
        Settings.AlertSettings settings = mock(Settings.AlertSettings.class);
        when(settings.isEnabled()).thenReturn(true);
        when(settings.isDiscordEnabled()).thenReturn(true);
        when(settings.getFailureRateThreshold()).thenReturn(0.5);
        when(settings.getMinRequestsForAlert()).thenReturn(1);
        when(settings.getCheckIntervalMinutes()).thenReturn(60);
        when(settings.getAlertCooldownMinutes()).thenReturn(30);
        SequencedDiscordClient discordClient = new SequencedDiscordClient();

        try (PremiumResolverAlertService service =
                     new PremiumResolverAlertService(settings, discordClient)) {
            service.recordResolution("mojang", false);
            discordClient.firstAttempt().get(2, TimeUnit.SECONDS);

            assertEquals(0L, service.getMetrics().lastAlertTime(),
                    "A failed delivery must not start the cooldown");

            service.recordResolution("mojang", false);
            discordClient.secondAttempt().get(2, TimeUnit.SECONDS);

            assertTrue(awaitCooldownPublication(service, 2, TimeUnit.SECONDS),
                    "The next failure should retry and a successful delivery should start cooldown");
        }
    }

    private static boolean awaitCooldownPublication(
            PremiumResolverAlertService service, long timeout, TimeUnit unit) throws InterruptedException {
        long deadline = System.nanoTime() + unit.toNanos(timeout);
        while (System.nanoTime() < deadline) {
            if (service.getMetrics().lastAlertTime() > 0) {
                return true;
            }
            TimeUnit.MILLISECONDS.sleep(5);
        }
        return service.getMetrics().lastAlertTime() > 0;
    }

    private static final class SequencedDiscordClient extends DiscordWebhookClient {
        private final AtomicInteger attempts = new AtomicInteger();
        private final CompletableFuture<Void> firstAttempt = new CompletableFuture<>();
        private final CompletableFuture<Void> secondAttempt = new CompletableFuture<>();

        private SequencedDiscordClient() {
            super("https://discord.com/api/webhooks/123/test-token");
        }

        @Override
        public boolean sendEmbed(DiscordEmbed embed) {
            int attempt = attempts.incrementAndGet();
            if (attempt == 1) {
                firstAttempt.complete(null);
                return false;
            }
            secondAttempt.complete(null);
            return true;
        }

        @Override
        public void close() {
            // No request was sent; avoid closing the shared test client's selector twice.
        }

        CompletableFuture<Void> firstAttempt() {
            return firstAttempt;
        }

        CompletableFuture<Void> secondAttempt() {
            return secondAttempt;
        }
    }
}
