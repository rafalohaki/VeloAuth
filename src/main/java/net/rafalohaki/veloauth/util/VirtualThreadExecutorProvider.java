package net.rafalohaki.veloauth.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Provider for Virtual Thread executor services with graceful shutdown support.
 * Centralizes Virtual Thread management for optimal resource usage in Java 21+.
 * 
 * <p>This provider implements a robust shutdown sequence to prevent RejectedExecutionException
 * during plugin shutdown. The shutdown process includes:
 * <ul>
 *   <li>Rejection of new tasks via SHUTDOWN_INITIATED flag</li>
 *   <li>10-second graceful termination period for pending tasks</li>
 *   <li>Forced shutdown with task count logging if timeout expires</li>
 *   <li>Additional 5-second wait after forced shutdown</li>
 * </ul>
 * 
 * <p><b>Thread Safety:</b> All methods are thread-safe and can be called concurrently.
 * 
 * <p><b>Usage Example:</b>
 * <pre>{@code
 * // Get executor for async operations
 * ExecutorService executor = VirtualThreadExecutorProvider.getVirtualExecutor();
 * CompletableFuture.runAsync(() -> {
 *     // Your async task
 * }, executor);
 * 
 * // During plugin shutdown
 * VirtualThreadExecutorProvider.shutdown();
 * }</pre>
 * 
 * @since 2.0.0
 */
public final class VirtualThreadExecutorProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(VirtualThreadExecutorProvider.class);

    /**
     * Shared Virtual Thread executor for async operations.
     * Uses Virtual Thread Per Task execution model for optimal scalability.
     */
    private static final ExecutorService VIRTUAL_EXECUTOR = Executors.newVirtualThreadPerTaskExecutor();

    /**
     * Flag to track if shutdown has been initiated.
     * Used to reject new tasks during shutdown process.
     */
    private static final AtomicBoolean SHUTDOWN_INITIATED = new AtomicBoolean(false);

    private VirtualThreadExecutorProvider() {
        // Utility class - prevent instantiation
    }

    /**
     * Returns the shared Virtual Thread executor.
     *
     * @return ExecutorService using Virtual Threads
     * @throws RejectedExecutionException if shutdown has been initiated
     */
    public static ExecutorService getVirtualExecutor() {
        if (SHUTDOWN_INITIATED.get()) {
            throw new RejectedExecutionException("Executor is shutting down");
        }
        return VIRTUAL_EXECUTOR;
    }

    /**
     * Executes a task on the shared Virtual Thread executor if it's not shutting down.
     *
     * @param task Runnable to execute
     * @return true if task was submitted, false if executor is shutting down
     */
    public static boolean submitTask(Runnable task) {
        if (SHUTDOWN_INITIATED.get()) {
            return false;
        }
        try {
            VIRTUAL_EXECUTOR.execute(task);
            return true;
        } catch (RejectedExecutionException e) {
            return false;
        }
    }

    /**
     * Checks if the executor has been shut down.
     *
     * @return true if shutdown has been initiated, false otherwise
     */
    public static boolean isShutdown() {
        return SHUTDOWN_INITIATED.get();
    }

    /**
     * Shuts down the Virtual Thread executor gracefully with timeout handling.
     * Should be called during plugin shutdown to ensure clean termination.
     * 
     * <p><b>Shutdown Sequence:</b>
     * <ol>
     *   <li>Set SHUTDOWN_INITIATED flag to reject new tasks</li>
     *   <li>Call shutdown() to stop accepting new tasks</li>
     *   <li>Wait up to 10 seconds for tasks to complete gracefully</li>
     *   <li>Force shutdown if timeout expires</li>
     *   <li>Log number of dropped tasks if forced shutdown occurs</li>
     *   <li>Wait additional 5 seconds for forced shutdown to complete</li>
     *   <li>Log error if executor still doesn't terminate</li>
     * </ol>
     * 
     * <p><b>Idempotency:</b> Multiple calls to this method are safe - subsequent calls
     * will log a warning and return immediately.
     * 
     * <p><b>Thread Safety:</b> This method is thread-safe and uses atomic compare-and-set
     * to ensure only one shutdown sequence executes.
     * 
     * @throws SecurityException if a security manager exists and shutting down
     *         this ExecutorService may manipulate threads that the caller is not
     *         permitted to modify
     * @since 2.0.0
     */
    public static void shutdown() {
        if (!SHUTDOWN_INITIATED.compareAndSet(false, true)) {
            LOGGER.warn("Shutdown already initiated");
            return;
        }

        try {
            LOGGER.info("Initiating graceful shutdown of Virtual Thread executor...");
            VIRTUAL_EXECUTOR.shutdown();

            if (VIRTUAL_EXECUTOR.awaitTermination(10, java.util.concurrent.TimeUnit.SECONDS)) {
                LOGGER.info("Virtual Thread executor shutdown completed successfully");
            } else {
                if (LOGGER.isWarnEnabled()) {
                    LOGGER.warn("Executor did not terminate within 10 seconds, forcing shutdown...");
                }
                java.util.List<Runnable> droppedTasks = VIRTUAL_EXECUTOR.shutdownNow();
                if (LOGGER.isWarnEnabled()) {
                    LOGGER.warn("Forced shutdown - {} tasks were dropped", droppedTasks.size());
                }

                // Final termination check after forced shutdown
                if (!VIRTUAL_EXECUTOR.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS) && LOGGER.isErrorEnabled()) {
                    LOGGER.error("Executor did not terminate after forced shutdown");
                }
            }
        } catch (InterruptedException e) {
            LOGGER.error("Shutdown interrupted", e);
            VIRTUAL_EXECUTOR.shutdownNow();
            Thread.currentThread().interrupt();
        } catch (SecurityException e) {
            if (LOGGER.isErrorEnabled()) {
                LOGGER.error("Error during Virtual Thread executor shutdown", e);
            }
        }
    }
}
