package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.ConnectionRequestBuilder;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

/**
 * Handles retry logic for failed server transfers including timeout handling 
 * and PicoLimbo fallback coordination.
 * 
 * <p><b>Responsibilities:</b>
 * <ul>
 *   <li>Track retry attempts per player</li>
 *   <li>Schedule timeout retries with exponential backoff</li>
 *   <li>Coordinate PicoLimbo fallback transfers</li>
 *   <li>Manage pending transfer tasks for cancellation</li>
 * </ul>
 * 
 * <p><b>Thread Safety:</b> Uses ConcurrentHashMap for all state tracking.
 * 
 * @since 2.1.0
 */
public class TransferRetryHandler {

    private static final int MAX_RETRY_ATTEMPTS = 3;
    private static final long CONNECT_TIMEOUT_SECONDS = 15;
    private static final long RETRY_DELAY_MS = 400;
    private static final long FALLBACK_DELAY_MS = 300;

    private final Map<UUID, Integer> retryAttempts = new ConcurrentHashMap<>();
    private final Map<UUID, Boolean> timeoutRetryScheduled = new ConcurrentHashMap<>();
    private final Map<UUID, ScheduledTask> pendingTransfers = new ConcurrentHashMap<>();

    private final VeloAuth plugin;
    private final Logger logger;
    private final Messages messages;
    private final Supplier<RegisteredServer> picoLimboServerSupplier;

    /**
     * Creates a new TransferRetryHandler.
     *
     * @param plugin                  VeloAuth plugin instance
     * @param logger                  Logger instance
     * @param messages                i18n messages
     * @param picoLimboServerSupplier Supplier for PicoLimbo server (avoids circular dep)
     */
    public TransferRetryHandler(VeloAuth plugin, Logger logger, Messages messages,
                                Supplier<RegisteredServer> picoLimboServerSupplier) {
        this.plugin = plugin;
        this.logger = logger;
        this.messages = messages;
        this.picoLimboServerSupplier = picoLimboServerSupplier;
    }

    /**
     * Gets current retry attempts for player.
     */
    public int getRetryAttempts(UUID playerUuid) {
        return retryAttempts.getOrDefault(playerUuid, 0);
    }

    /**
     * Gets maximum retry attempts allowed.
     */
    public int getMaxRetryAttempts() {
        return MAX_RETRY_ATTEMPTS;
    }

    /**
     * Clears all retry state for a player.
     */
    public void clearRetryState(UUID playerUuid) {
        retryAttempts.remove(playerUuid);
        timeoutRetryScheduled.remove(playerUuid);
        cancelPendingTransfer(playerUuid);
    }

    /**
     * Cancels pending transfer for player.
     */
    public void cancelPendingTransfer(UUID playerUuid) {
        ScheduledTask pending = pendingTransfers.remove(playerUuid);
        if (pending != null) {
            pending.cancel();
            if (logger.isDebugEnabled()) {
                logger.debug("Cancelled pending transfer for player UUID: {}", playerUuid);
            }
        }
    }

    /**
     * Handles timeout retry by scheduling an async retry with delay.
     *
     * @param player       Player to retry
     * @param targetServer Target server
     * @param serverName   Server name for logging
     * @param attempts     Current attempt count
     * @return true if retry was scheduled
     */
    public boolean handleTimeoutRetry(Player player, RegisteredServer targetServer, 
                                      String serverName, int attempts) {
        if (!validateTimeoutRetryConditions(player, attempts)) {
            return false;
        }

        retryAttempts.put(player.getUniqueId(), attempts + 1);
        player.sendMessage(Component.text(messages.get("connection.retry"), NamedTextColor.YELLOW));

        scheduleTimeoutRetry(player, targetServer, serverName);
        return true;
    }

    private boolean validateTimeoutRetryConditions(Player player, int attempts) {
        if (!player.isActive()) {
            return false;
        }
        if (timeoutRetryScheduled.putIfAbsent(player.getUniqueId(), Boolean.TRUE) != null) {
            return false;
        }
        if (attempts >= MAX_RETRY_ATTEMPTS) {
            timeoutRetryScheduled.remove(player.getUniqueId());
            return false;
        }
        return true;
    }

    private void scheduleTimeoutRetry(Player player, RegisteredServer targetServer, String serverName) {
        plugin.getServer().getScheduler().buildTask(plugin, () ->
                executeTimeoutRetry(player, targetServer, serverName)
        ).delay(RETRY_DELAY_MS, TimeUnit.MILLISECONDS).schedule();
    }

    private void executeTimeoutRetry(Player player, RegisteredServer targetServer, String serverName) {
        try {
            player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .whenComplete((result, ex) -> handleTimeoutRetryResult(player, serverName, result, ex));
        } catch (Exception retryEx) {
            timeoutRetryScheduled.remove(player.getUniqueId());
            logger.error("Error scheduling retry after timeout for {}: {}", 
                    player.getUsername(), retryEx.getMessage());
        }
    }

    private void handleTimeoutRetryResult(Player player, String serverName,
                                         ConnectionRequestBuilder.Result result, Throwable ex) {
        timeoutRetryScheduled.remove(player.getUniqueId());

        if (ex != null) {
            logger.warn("Retry after timeout failed for {} -> {}: {}", 
                    player.getUsername(), serverName, ex.getMessage());
            sendErrorMessage(player);
            return;
        }

        if (result != null && result.isSuccessful()) {
            retryAttempts.remove(player.getUniqueId());
            if (logger.isDebugEnabled()) {
                logger.debug("Retry after timeout succeeded for {} -> {}", player.getUsername(), serverName);
            }
        } else {
            Component reason = result != null ? 
                    result.getReasonComponent().orElse(Component.text("unknown")) : 
                    Component.text("unknown");
            logger.warn("Retry after timeout not successful for {} -> {}: {}", 
                    player.getUsername(), serverName, reason);
            sendErrorMessage(player);
        }
    }

    /**
     * Attempts PicoLimbo fallback when backend transfer fails.
     *
     * @param player       Player to fallback
     * @param targetServer Original target server
     * @param serverName   Server name for logging
     * @param attempts     Current attempt count
     * @return true if fallback was initiated
     */
    public boolean attemptFallback(Player player, RegisteredServer targetServer, 
                                   String serverName, int attempts) {
        RegisteredServer picoLimbo = picoLimboServerSupplier.get();
        if (picoLimbo == null || isPlayerOnServer(player, picoLimbo)) {
            return false;
        }

        retryAttempts.put(player.getUniqueId(), attempts + 1);
        if (logger.isInfoEnabled()) {
            logger.info("Attempting fallback for player {} (attempt {}/{}): send to PicoLimbo then retry backend {}",
                    player.getUsername(), attempts + 1, MAX_RETRY_ATTEMPTS, serverName);
        }

        schedulePicoLimboFallback(player, picoLimbo, targetServer, serverName);
        return true;
    }

    private boolean isPlayerOnServer(Player player, RegisteredServer server) {
        return player.getCurrentServer()
                .map(conn -> conn.getServerInfo().getName().equals(server.getServerInfo().getName()))
                .orElse(false);
    }

    private void schedulePicoLimboFallback(Player player, RegisteredServer picoLimbo,
                                           RegisteredServer targetServer, String serverName) {
        player.createConnectionRequest(picoLimbo)
                .connect()
                .orTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .whenComplete((limboResult, ex) ->
                        handlePicoLimboFallbackResult(player, targetServer, serverName, limboResult, ex));
    }

    private void handlePicoLimboFallbackResult(Player player, RegisteredServer targetServer, String serverName,
                                               ConnectionRequestBuilder.Result limboResult, Throwable ex) {
        if (ex != null || limboResult == null || !limboResult.isSuccessful()) {
            logFallbackFailure(player, limboResult, ex);
            sendErrorMessage(player);
            return;
        }
        scheduleBackendRetryAfterLimbo(player, targetServer, serverName);
    }

    private void logFallbackFailure(Player player, ConnectionRequestBuilder.Result limboResult, Throwable ex) {
        String reason = ex != null ? ex.getMessage() :
                (limboResult == null ? "null result" : 
                        limboResult.getReasonComponent().map(Component::toString).orElse("unknown"));
        logger.warn("Fallback to PicoLimbo for {} failed: {}", player.getUsername(), reason);
    }

    private void scheduleBackendRetryAfterLimbo(Player player, RegisteredServer targetServer, String serverName) {
        plugin.getServer().getScheduler().buildTask(plugin, () ->
                executeBackendRetryAfterLimbo(player, targetServer, serverName)
        ).delay(FALLBACK_DELAY_MS, TimeUnit.MILLISECONDS).schedule();
    }

    private void executeBackendRetryAfterLimbo(Player player, RegisteredServer targetServer, String serverName) {
        try {
            var retry = player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .join();
            if (!retry.isSuccessful()) {
                logger.warn("Retry to connect {} to {} after PicoLimbo failed: {}",
                        player.getUsername(), serverName, 
                        retry.getReasonComponent().orElse(Component.text("unknown")));
                sendErrorMessage(player);
            }
        } catch (Exception retryEx) {
            logger.error("Error while retrying backend transfer for {}: {}",
                    player.getUsername(), retryEx.getMessage(), retryEx);
            sendErrorMessage(player);
        }
    }

    private void sendErrorMessage(Player player) {
        player.sendMessage(Component.text(
                messages.get("connection.error.game_server"), NamedTextColor.RED));
    }

    /**
     * Registers a pending transfer task.
     */
    public void registerPendingTransfer(UUID playerUuid, ScheduledTask task) {
        pendingTransfers.put(playerUuid, task);
    }

    /**
     * Removes pending transfer after execution.
     */
    public void removePendingTransfer(UUID playerUuid) {
        pendingTransfers.remove(playerUuid);
    }

    /**
     * Shuts down the handler, cancelling all pending transfers.
     */
    public void shutdown() {
        pendingTransfers.values().forEach(ScheduledTask::cancel);
        pendingTransfers.clear();
        retryAttempts.clear();
        timeoutRetryScheduled.clear();
    }
}
