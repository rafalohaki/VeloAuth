package net.rafalohaki.veloauth.alert;

import net.rafalohaki.veloauth.config.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Alert service for premium resolver failures.
 * Monitors failure rates and sends Discord alerts when thresholds exceeded.
 * Thread-safe implementation with configurable thresholds.
 */
public class PremiumResolverAlertService implements AutoCloseable {

    private static final Logger logger = LoggerFactory.getLogger(PremiumResolverAlertService.class);

    private final Settings.AlertSettings alertSettings;
    private final DiscordWebhookClient discordClient;
    private final ScheduledExecutorService scheduler;

    // Metrics
    private final AtomicInteger totalRequests = new AtomicInteger(0);
    private final AtomicInteger failedRequests = new AtomicInteger(0);
    private final ConcurrentHashMap<String, AtomicInteger> failuresByResolver = new ConcurrentHashMap<>();
    private final AtomicLong lastAlertTime = new AtomicLong(0);
    private final AtomicLong lastResetTime = new AtomicLong(System.currentTimeMillis());

    /**
     * Creates alert service.
     *
     * @param settings Plugin settings
     */
    public PremiumResolverAlertService(Settings settings) {
        this.alertSettings = settings.getAlertSettings();

        // Initialize Discord client if enabled
        if (alertSettings.isDiscordEnabled() && alertSettings.getDiscordWebhookUrl() != null) {
            this.discordClient = new DiscordWebhookClient(alertSettings.getDiscordWebhookUrl());
        } else {
            this.discordClient = null;
        }

        // Scheduler for periodic checks and metric resets
        this.scheduler = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "VeloAuth-AlertService");
            t.setDaemon(true);
            return t;
        });

        // Schedule metric reset every configured interval
        scheduler.scheduleAtFixedRate(
                this::resetMetrics,
                alertSettings.getCheckIntervalMinutes(),
                alertSettings.getCheckIntervalMinutes(),
                TimeUnit.MINUTES
        );

        logger.info("Alert service initialized (Discord: {}, Check interval: {}min)",
                discordClient != null ? "enabled" : "disabled",
                alertSettings.getCheckIntervalMinutes());
    }

    /**
     * Records a premium resolution attempt.
     *
     * @param resolver Resolver name (mojang, ashcon, wpme)
     * @param success  Whether resolution was successful
     */
    public void recordResolution(String resolver, boolean success) {
        if (!alertSettings.isEnabled()) {
            return;
        }

        totalRequests.incrementAndGet();

        if (!success) {
            failedRequests.incrementAndGet();
            failuresByResolver.computeIfAbsent(resolver, k -> new AtomicInteger(0)).incrementAndGet();

            // Check if we should send alert
            checkAndSendAlert();
        }
    }

    /**
     * Checks failure rate and sends alert if threshold exceeded.
     */
    private void checkAndSendAlert() {
        int total = totalRequests.get();
        int failed = failedRequests.get();

        // Need minimum requests before alerting
        if (total < alertSettings.getMinRequestsForAlert()) {
            return;
        }

        // Calculate failure rate
        double failureRate = (double) failed / total;

        // Check if threshold exceeded
        if (failureRate < alertSettings.getFailureRateThreshold()) {
            return;
        }

        // Check cooldown (avoid alert spam)
        long now = System.currentTimeMillis();
        long timeSinceLastAlert = now - lastAlertTime.get();
        long cooldownMs = alertSettings.getAlertCooldownMinutes() * 60_000L;

        if (timeSinceLastAlert < cooldownMs) {
            logger.debug("Alert cooldown active, skipping ({}s remaining)",
                    (cooldownMs - timeSinceLastAlert) / 1000);
            return;
        }

        // Send alert
        sendFailureAlert(total, failed, failureRate);
        lastAlertTime.set(now);
    }

    /**
     * Sends failure alert to Discord.
     *
     * @param total       Total requests
     * @param failed      Failed requests
     * @param failureRate Failure rate (0.0-1.0)
     */
    private void sendFailureAlert(int total, int failed, double failureRate) {
        if (discordClient == null) {
            logger.warn("⚠️ Premium resolver failure rate: {}/{} ({:.1f}%) - Discord disabled",
                    failed, total, failureRate * 100);
            return;
        }

        try {
            DiscordWebhookClient.DiscordEmbed embed = new DiscordWebhookClient.DiscordEmbed()
                    .title("⚠️ VeloAuth Premium Resolver Alert")
                    .description("High failure rate detected in premium resolver service")
                    .color(0xFFA500) // Orange
                    .timestamp(Instant.now().toString())
                    .fields(java.util.List.of(
                            new DiscordWebhookClient.EmbedField(
                                    "Failure Rate",
                                    String.format("%.1f%% (%d/%d)", failureRate * 100, failed, total),
                                    true
                            ),
                            new DiscordWebhookClient.EmbedField(
                                    "Threshold",
                                    String.format("%.1f%%", alertSettings.getFailureRateThreshold() * 100),
                                    true
                            ),
                            new DiscordWebhookClient.EmbedField(
                                    "Time Window",
                                    String.format("%d minutes", alertSettings.getCheckIntervalMinutes()),
                                    true
                            ),
                            new DiscordWebhookClient.EmbedField(
                                    "Failures by Resolver",
                                    buildFailureBreakdown(),
                                    false
                            ),
                            new DiscordWebhookClient.EmbedField(
                                    "Recommendation",
                                    "Check resolver API status and network connectivity",
                                    false
                            )
                    ));

            boolean sent = discordClient.sendEmbed(embed);
            if (sent) {
                logger.warn("⚠️ Premium resolver alert sent to Discord: {}/{} ({:.1f}% failure rate)",
                        failed, total, failureRate * 100);
            } else {
                logger.error("Failed to send Discord alert (check webhook URL)");
            }

        } catch (Exception e) {
            logger.error("Error sending Discord alert", e);
        }
    }

    /**
     * Builds failure breakdown by resolver.
     *
     * @return Formatted string with failures per resolver
     */
    private String buildFailureBreakdown() {
        if (failuresByResolver.isEmpty()) {
            return "No data";
        }

        StringBuilder sb = new StringBuilder();
        failuresByResolver.forEach((resolver, count) -> {
            sb.append("**").append(resolver).append("**: ").append(count.get()).append(" failures\n");
        });
        return sb.toString().trim();
    }

    /**
     * Resets metrics for new time window.
     */
    private void resetMetrics() {
        int previousTotal = totalRequests.getAndSet(0);
        int previousFailed = failedRequests.getAndSet(0);
        failuresByResolver.clear();
        lastResetTime.set(System.currentTimeMillis());

        if (previousTotal > 0) {
            double failureRate = (double) previousFailed / previousTotal;
            logger.debug("Metrics reset: {}/{} requests failed ({:.1f}%) in last window",
                    previousFailed, previousTotal, failureRate * 100);
        }
    }

    /**
     * Gets current metrics for monitoring.
     *
     * @return Alert metrics
     */
    public AlertMetrics getMetrics() {
        int total = totalRequests.get();
        int failed = failedRequests.get();
        double failureRate = total > 0 ? (double) failed / total : 0.0;

        return new AlertMetrics(
                total,
                failed,
                failureRate,
                System.currentTimeMillis() - lastResetTime.get(),
                lastAlertTime.get()
        );
    }

    @Override
    public void close() {
        logger.info("Shutting down alert service...");
        scheduler.shutdown();
        try {
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            scheduler.shutdownNow();
        }
        logger.info("Alert service shut down");
    }

    /**
     * Alert metrics data.
     */
    public record AlertMetrics(
            int totalRequests,
            int failedRequests,
            double failureRate,
            long windowAgeMs,
            long lastAlertTime
    ) {
    }
}
