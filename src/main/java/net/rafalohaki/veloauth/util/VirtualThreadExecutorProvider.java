package net.rafalohaki.veloauth.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Provider for Virtual Thread executor services.
 * Centralizes Virtual Thread management for optimal resource usage in Java 21+.
 */
public final class VirtualThreadExecutorProvider {

    private static final Logger logger = LoggerFactory.getLogger(VirtualThreadExecutorProvider.class);

    /**
     * Shared Virtual Thread executor for async operations.
     * Uses Virtual Thread Per Task execution model for optimal scalability.
     */
    private static final ExecutorService VIRTUAL_EXECUTOR = Executors.newVirtualThreadPerTaskExecutor();

    private VirtualThreadExecutorProvider() {
        // Utility class - prevent instantiation
    }

    /**
     * Returns the shared Virtual Thread executor.
     *
     * @return ExecutorService using Virtual Threads
     */
    public static ExecutorService getVirtualExecutor() {
        return VIRTUAL_EXECUTOR;
    }

    /**
     * Shuts down the Virtual Thread executor.
     * Should be called during plugin shutdown.
     */
    public static void shutdown() {
        try {
            VIRTUAL_EXECUTOR.shutdown();
            logger.info("Virtual Thread executor shutdown completed");
        } catch (Exception e) {
            logger.error("Error during Virtual Thread executor shutdown", e);
        }
    }
}
