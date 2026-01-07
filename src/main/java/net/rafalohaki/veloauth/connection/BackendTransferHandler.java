package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.ConnectionRequestBuilder;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;

import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Handles backend server transfer operations with retry logic and error handling.
 * Extracted from ConnectionManager to reduce complexity and improve testability.
 * 
 * <p><b>Responsibilities:</b>
 * <ul>
 *   <li>Execute player transfers to backend servers</li>
 *   <li>Handle successful and failed transfer results</li>
 *   <li>Coordinate with retry handler for timeout scenarios</li>
 *   <li>Provide consistent error messaging to players</li>
 * </ul>
 * 
 * @since 2.1.0
 */
public class BackendTransferHandler {

    private static final long CONNECT_TIMEOUT_SECONDS = 15;
    private static final String CONNECTION_ERROR_GAME_SERVER = "connection.error.game_server";

    private final Logger logger;
    private final Messages messages;
    private final TransferRetryHandler retryHandler;

    /**
     * Creates a new BackendTransferHandler.
     *
     * @param logger       Logger instance
     * @param messages     i18n messages
     * @param retryHandler Handler for retry operations
     */
    public BackendTransferHandler(Logger logger, Messages messages, TransferRetryHandler retryHandler) {
        this.logger = logger;
        this.messages = messages;
        this.retryHandler = retryHandler;
    }

    /**
     * Executes transfer to backend server with validation and retry support.
     *
     * @param player       Player to transfer
     * @param targetServer Target backend server
     * @param serverName   Server name for logging
     * @return true if transfer succeeded or retry was scheduled
     */
    public boolean executeTransfer(Player player, RegisteredServer targetServer, String serverName) {
        if (!validatePlayerActive(player, serverName)) {
            return false;
        }

        int attempts = retryHandler.getRetryAttempts(player.getUniqueId());
        if (!validateRetryLimit(player, attempts)) {
            return false;
        }

        return performTransfer(player, targetServer, serverName, attempts);
    }

    private boolean validatePlayerActive(Player player, String serverName) {
        if (!player.isActive()) {
            if (logger.isDebugEnabled()) {
                logger.debug("Player {} is no longer active - skipping transfer to {}",
                        player.getUsername(), serverName);
            }
            return false;
        }
        return true;
    }

    private boolean validateRetryLimit(Player player, int attempts) {
        if (attempts >= retryHandler.getMaxRetryAttempts()) {
            logger.warn("Player {} exceeded retry limit ({}) - aborting",
                    player.getUsername(), retryHandler.getMaxRetryAttempts());
            retryHandler.clearRetryState(player.getUniqueId());
            sendErrorMessage(player);
            return false;
        }
        return true;
    }

    private boolean performTransfer(Player player, RegisteredServer targetServer, 
                                   String serverName, int attempts) {
        try {
            if (!player.isActive()) {
                logger.debug("Player {} disconnected before transfer started", player.getUsername());
                return false;
            }

            var result = player.createConnectionRequest(targetServer)
                    .connect()
                    .orTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                    .join();

            return handleTransferResult(player, targetServer, serverName, attempts, result);
        } catch (CompletionException e) {
            return handleCompletionException(player, targetServer, serverName, attempts, e);
        } catch (Exception e) {
            logTransferError(player, serverName, e);
            sendErrorMessage(player);
            return false;
        }
    }

    /**
     * Handles transfer result - success or failure.
     */
    public boolean handleTransferResult(Player player, RegisteredServer targetServer, 
                                        String serverName, int attempts,
                                        ConnectionRequestBuilder.Result result) {
        if (result.isSuccessful()) {
            return handleSuccessfulTransfer(player, serverName);
        }
        return handleFailedTransfer(player, targetServer, serverName, attempts, result);
    }

    private boolean handleSuccessfulTransfer(Player player, String serverName) {
        retryHandler.clearRetryState(player.getUniqueId());
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("player.transfer.backend.success", player.getUsername(), serverName));
        }
        return true;
    }

    private boolean handleFailedTransfer(Player player, RegisteredServer targetServer, 
                                        String serverName, int attempts,
                                        ConnectionRequestBuilder.Result result) {
        if (logger.isWarnEnabled()) {
            logger.warn("Failed to transfer player {} to server {}: {}",
                    player.getUsername(), serverName,
                    result.getReasonComponent().orElse(createUnknownErrorComponent()));
        }

        // Let retry handler attempt PicoLimbo fallback
        if (retryHandler.attemptFallback(player, targetServer, serverName, attempts)) {
            return true;
        }

        sendErrorMessage(player);
        return false;
    }

    private boolean handleCompletionException(Player player, RegisteredServer targetServer,
                                             String serverName, int attempts, CompletionException e) {
        if (e.getCause() instanceof TimeoutException) {
            if (retryHandler.handleTimeoutRetry(player, targetServer, serverName, attempts)) {
                return true;
            }
        }
        logger.error("Error transferring player {} to server {}: {}", 
                player.getUsername(), serverName, e.getMessage());
        sendErrorMessage(player);
        return false;
    }

    private void logTransferError(Player player, String serverName, Exception e) {
        if (logger.isErrorEnabled()) {
            logger.error("Error transferring player {} to server {}: {}",
                    player.getUsername(), serverName, e.getMessage(), e);
        }
    }

    /**
     * Sends error message to player.
     */
    public void sendErrorMessage(Player player) {
        player.sendMessage(Component.text(messages.get(CONNECTION_ERROR_GAME_SERVER), NamedTextColor.RED));
    }

    /**
     * Creates component for unknown error.
     */
    public Component createUnknownErrorComponent() {
        return Component.text(messages.get("error.unknown"), NamedTextColor.RED);
    }
}
