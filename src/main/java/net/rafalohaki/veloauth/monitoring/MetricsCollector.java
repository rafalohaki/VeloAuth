package net.rafalohaki.veloauth.monitoring;

import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.database.DatabaseManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicLong;

/**
 * Production metrics collector for VeloAuth.
 * Provides Prometheus-compatible metrics for authentication operations,
 * cache performance, and database health monitoring.
 */
public class MetricsCollector {

    private static final Logger logger = LoggerFactory.getLogger(MetricsCollector.class);

    private final VeloAuth plugin;
    private final DatabaseManager databaseManager;
    private final AuthCache authCache;

    // Authentication metrics
    private final AtomicLong loginAttempts = new AtomicLong(0);
    private final AtomicLong successfulLogins = new AtomicLong(0);
    private final AtomicLong failedLogins = new AtomicLong(0);
    private final AtomicLong registrationAttempts = new AtomicLong(0);
    private final AtomicLong successfulRegistrations = new AtomicLong(0);
    private final AtomicLong passwordChanges = new AtomicLong(0);

    // Security metrics
    private final AtomicLong bruteForceBlocks = new AtomicLong(0);
    private final AtomicLong premiumChecks = new AtomicLong(0);

    // Database metrics
    private volatile long lastDatabaseHealthCheck = 0;
    private volatile boolean databaseHealthy = false;

    public MetricsCollector(VeloAuth plugin, DatabaseManager databaseManager, AuthCache authCache) {
        this.plugin = plugin;
        this.databaseManager = databaseManager;
        this.authCache = authCache;
    }

    // Authentication event counters
    public void incrementLoginAttempts() {
        loginAttempts.incrementAndGet();
    }

    public void incrementSuccessfulLogins() {
        successfulLogins.incrementAndGet();
    }

    public void incrementFailedLogins() {
        failedLogins.incrementAndGet();
    }

    public void incrementRegistrationAttempts() {
        registrationAttempts.incrementAndGet();
    }

    public void incrementSuccessfulRegistrations() {
        successfulRegistrations.incrementAndGet();
    }

    public void incrementPasswordChanges() {
        passwordChanges.incrementAndGet();
    }

    // Security event counters
    public void incrementBruteForceBlocks() {
        bruteForceBlocks.incrementAndGet();
    }

    public void incrementPremiumChecks() {
        premiumChecks.incrementAndGet();
    }

    // Database health tracking
    public void updateDatabaseHealth(boolean healthy) {
        this.databaseHealthy = healthy;
        this.lastDatabaseHealthCheck = System.currentTimeMillis();
    }

    /**
     * Generates Prometheus-compatible metrics output.
     * Format follows Prometheus exposition format specification.
     */
    @SuppressWarnings({"java:S138", "PMD.ConsecutiveAppendsShouldReuse", "PMD.ConsecutiveLiteralAppends"}) // Prometheus metrics - standard exposition format
    public String generatePrometheusMetrics() {
        StringBuilder metrics = new StringBuilder();

        // Help and type information for Prometheus
        metrics.append("# HELP veloauth_login_attempts_total Total number of login attempts\n");
        metrics.append("# TYPE veloauth_login_attempts_total counter\n");
        metrics.append("veloauth_login_attempts_total ").append(loginAttempts.get()).append("\n\n");

        metrics.append("# HELP veloauth_login_successes_total Total number of successful logins\n");
        metrics.append("# TYPE veloauth_login_successes_total counter\n");
        metrics.append("veloauth_login_successes_total ").append(successfulLogins.get()).append("\n\n");

        metrics.append("# HELP veloauth_login_failures_total Total number of failed logins\n");
        metrics.append("# TYPE veloauth_login_failures_total counter\n");
        metrics.append("veloauth_login_failures_total ").append(failedLogins.get()).append("\n\n");

        metrics.append("# HELP veloauth_registration_attempts_total Total number of registration attempts\n");
        metrics.append("# TYPE veloauth_registration_attempts_total counter\n");
        metrics.append("veloauth_registration_attempts_total ").append(registrationAttempts.get()).append("\n\n");

        metrics.append("# HELP veloauth_registration_successes_total Total number of successful registrations\n");
        metrics.append("# TYPE veloauth_registration_successes_total counter\n");
        metrics.append("veloauth_registration_successes_total ").append(successfulRegistrations.get()).append("\n\n");

        metrics.append("# HELP veloauth_password_changes_total Total number of password changes\n");
        metrics.append("# TYPE veloauth_password_changes_total counter\n");
        metrics.append("veloauth_password_changes_total ").append(passwordChanges.get()).append("\n\n");

        // Security metrics
        metrics.append("# HELP veloauth_brute_force_blocks_total Total number of brute force blocks\n");
        metrics.append("# TYPE veloauth_brute_force_blocks_total counter\n");
        metrics.append("veloauth_brute_force_blocks_total ").append(bruteForceBlocks.get()).append("\n\n");

        metrics.append("# HELP veloauth_premium_checks_total Total number of premium status checks\n");
        metrics.append("# TYPE veloauth_premium_checks_total counter\n");
        metrics.append("veloauth_premium_checks_total ").append(premiumChecks.get()).append("\n\n");

        // Cache metrics
        var cacheStats = authCache.getStats();
        metrics.append("# HELP veloauth_cache_size Current number of entries in authorization cache\n");
        metrics.append("# TYPE veloauth_cache_size gauge\n");
        metrics.append("veloauth_cache_size ").append(cacheStats.authorizedPlayersCount()).append("\n\n");

        metrics.append("# HELP veloauth_cache_max_size Maximum size of authorization cache\n");
        metrics.append("# TYPE veloauth_cache_max_size gauge\n");
        metrics.append("veloauth_cache_max_size ").append(cacheStats.maxSize()).append("\n\n");

        metrics.append("# HELP veloauth_cache_hit_rate Cache hit rate percentage\n");
        metrics.append("# TYPE veloauth_cache_hit_rate gauge\n");
        metrics.append("veloauth_cache_hit_rate ").append(String.format("%.2f", cacheStats.getHitRate())).append("\n\n");

        metrics.append("# HELP veloauth_cache_requests_total Total number of cache requests\n");
        metrics.append("# TYPE veloauth_cache_requests_total counter\n");
        metrics.append("veloauth_cache_requests_total ").append(cacheStats.getTotalRequests()).append("\n\n");

        metrics.append("# HELP veloauth_brute_force_entries Current number of brute force entries\n");
        metrics.append("# TYPE veloauth_brute_force_entries gauge\n");
        metrics.append("veloauth_brute_force_entries ").append(cacheStats.bruteForceEntriesCount()).append("\n\n");

        metrics.append("# HELP veloauth_active_sessions Current number of active sessions\n");
        metrics.append("# TYPE veloauth_active_sessions gauge\n");
        metrics.append("veloauth_active_sessions ").append(countActiveSessions()).append("\n\n");

        // Database metrics
        metrics.append("# HELP veloauth_database_connected Database connection status (1 = connected, 0 = disconnected)\n");
        metrics.append("# TYPE veloauth_database_connected gauge\n");
        metrics.append("veloauth_database_connected ").append(databaseManager.isConnected() ? 1 : 0).append("\n\n");

        metrics.append("# HELP veloauth_database_healthy Database health status (1 = healthy, 0 = unhealthy)\n");
        metrics.append("# TYPE veloauth_database_healthy gauge\n");
        metrics.append("veloauth_database_healthy ").append(databaseHealthy ? 1 : 0).append("\n\n");

        metrics.append("# HELP veloauth_database_last_health_check_timestamp Timestamp of last database health check (Unix epoch milliseconds)\n");
        metrics.append("# TYPE veloauth_database_last_health_check_timestamp gauge\n");
        metrics.append("veloauth_database_last_health_check_timestamp ").append(lastDatabaseHealthCheck).append("\n\n");

        metrics.append("# HELP veloauth_database_cache_size Current database cache size\n");
        metrics.append("# TYPE veloauth_database_cache_size gauge\n");
        metrics.append("veloauth_database_cache_size ").append(databaseManager.getCacheSize()).append("\n\n");

        // JVM metrics (basic)
        Runtime runtime = Runtime.getRuntime();
        metrics.append("# HELP veloauth_jvm_memory_used_bytes Used JVM memory in bytes\n");
        metrics.append("# TYPE veloauth_jvm_memory_used_bytes gauge\n");
        metrics.append("veloauth_jvm_memory_used_bytes ").append(runtime.totalMemory() - runtime.freeMemory()).append("\n\n");

        metrics.append("# HELP veloauth_jvm_memory_max_bytes Maximum JVM memory in bytes\n");
        metrics.append("# TYPE veloauth_jvm_memory_max_bytes gauge\n");
        metrics.append("veloauth_jvm_memory_max_bytes ").append(runtime.maxMemory()).append("\n\n");

        metrics.append("# HELP veloauth_jvm_threads_count Number of active threads\n");
        metrics.append("# TYPE veloauth_jvm_threads_count gauge\n");
        metrics.append("veloauth_jvm_threads_count ").append(Thread.activeCount()).append("\n\n");

        // Plugin info
        metrics.append("# HELP veloauth_plugin_info Plugin version and build info\n");
        metrics.append("# TYPE veloauth_plugin_info gauge\n");
        metrics.append("veloauth_plugin_info{version=\"").append(plugin.getVersion()).append("\",java_version=\"")
                .append(System.getProperty("java.version")).append("\"} 1\n\n");

        return metrics.toString();
    }

    /**
     * Returns current active sessions count.
     */
    private int countActiveSessions() {
        // This would require access to active sessions from AuthCache
        // For now, return authorized players count as approximation
        return authCache.getStats().authorizedPlayersCount();
    }

    /**
     * Resets all metrics counters.
     * Useful for testing or manual metric resets.
     */
    public void resetMetrics() {
        loginAttempts.set(0);
        successfulLogins.set(0);
        failedLogins.set(0);
        registrationAttempts.set(0);
        successfulRegistrations.set(0);
        passwordChanges.set(0);
        bruteForceBlocks.set(0);
        premiumChecks.set(0);

        if (logger.isInfoEnabled()) {
            logger.info("VeloAuth metrics reset");
        }
    }

    /**
     * Get current metrics summary for debugging.
     */
    public String getMetricsSummary() {
        return String.format(
                "VeloAuth Metrics - Login: %d/%d/%d (attempts/success/fail), " +
                        "Registration: %d/%d (attempts/success), " +
                        "Security: %d brute blocks, %d premium checks, " +
                        "Cache: %d/%d entries (%.1f%% hit rate), " +
                        "DB: %s",
                loginAttempts.get(), successfulLogins.get(), failedLogins.get(),
                registrationAttempts.get(), successfulRegistrations.get(),
                bruteForceBlocks.get(), premiumChecks.get(),
                authCache.getStats().authorizedPlayersCount(), authCache.getStats().maxSize(),
                authCache.getStats().getHitRate(),
                databaseManager.isConnected() ? "connected" : "disconnected"
        );
    }
}