package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Manages periodic database health checks (connectivity monitoring).
 * Extracted from DatabaseManager for single-responsibility.
 */
public class DatabaseHealthCheck {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseHealthCheck.class);
    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");

    private final JdbcAuthDao jdbcAuthDao;
    private final Messages messages;
    private final ScheduledExecutorService healthCheckExecutor;

    private volatile long lastHealthCheckTime;
    private volatile boolean lastHealthCheckPassed;

    public DatabaseHealthCheck(JdbcAuthDao jdbcAuthDao, Messages messages) {
        this.jdbcAuthDao = jdbcAuthDao;
        this.messages = messages;
        this.healthCheckExecutor = Executors.newSingleThreadScheduledExecutor();
        this.lastHealthCheckTime = 0;
        this.lastHealthCheckPassed = false;
    }

    /**
     * Starts periodic database health checks.
     */
    public void start() {
        healthCheckExecutor.scheduleAtFixedRate(() -> {
            try {
                performHealthCheck();
            } catch (RuntimeException e) {
                if (logger.isErrorEnabled()) {
                    logger.error(DB_MARKER, "Error during database health check", e);
                }
            }
        }, 30, 30, TimeUnit.SECONDS);

        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, messages.get("database.manager.health_checks_started"));
        }
    }

    /**
     * Performs a database health check.
     */
    void performHealthCheck() {
        try {
            boolean healthy = jdbcAuthDao.healthCheck();
            lastHealthCheckTime = System.currentTimeMillis();
            lastHealthCheckPassed = healthy;

            if (!healthy) {
                if (logger.isWarnEnabled()) {
                    logger.warn(DB_MARKER, "\u274C Database health check FAILED - connection may be unstable");
                }
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "\u2705 Database health check PASSED");
                }
            }

        } catch (RuntimeException e) {
            lastHealthCheckTime = System.currentTimeMillis();
            lastHealthCheckPassed = false;
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "❌ Database health check FAILED with exception: {}", e.getMessage());
            }
        }
    }

    /**
     * Checks if the database is healthy (last health check passed).
     */
    public boolean isHealthy() {
        return lastHealthCheckPassed;
    }

    public long getLastHealthCheckTime() {
        return lastHealthCheckTime;
    }

    public boolean wasLastHealthCheckPassed() {
        return lastHealthCheckPassed;
    }

    /**
     * Stops health checks gracefully.
     */
    public void stop() {
        if (!healthCheckExecutor.isShutdown()) {
            healthCheckExecutor.shutdown();
            try {
                if (!healthCheckExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    healthCheckExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                healthCheckExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
            if (logger.isInfoEnabled()) {
                logger.info(DB_MARKER, "Health checks stopped");
            }
        }
    }
}
