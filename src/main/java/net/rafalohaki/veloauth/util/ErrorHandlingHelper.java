package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.command.ValidationUtils;
import net.rafalohaki.veloauth.constants.StringConstants;
import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/**
 * Utility class for consistent error handling patterns across VeloAuth.
 * Centralizes exception handling, logging, and user feedback to reduce code duplication.
 */
public final class ErrorHandlingHelper {

    private ErrorHandlingHelper() {
        // Utility class - prevent instantiation
    }

    /**
     * Handles exceptions in asynchronous operations consistently.
     *
     * @param logger        The logger to use for error reporting
     * @param marker        The marker for categorized logging
     * @param operationName Name of the operation for error messages
     * @param player        The player to send error message to (can be null)
     * @param throwable     The exception that occurred
     * @param messages      The i18n messages system
     */
    public static void handleAsyncException(Logger logger, Marker marker,
                                            String operationName, Player player,
                                            Throwable throwable, Messages messages) {
        String errorMessage = "Error during " + operationName + ": " +
                (player != null ? player.getUsername() : StringConstants.UNKNOWN);

        logger.error(marker, errorMessage, throwable);

        if (player != null) {
            String userMessage = messages.get(StringConstants.ERROR_DATABASE_QUERY);
            PlayerHelper.sendErrorMessage(player, userMessage);
        }
    }

    /**
     * Creates a standard exception handler for CompletableFuture operations.
     *
     * @param logger        The logger to use
     * @param marker        The marker for categorized logging
     * @param operationName Name of the operation
     * @param player        The player involved (can be null)
     * @param messages      The i18n messages system
     * @return Function to handle exceptions
     */
    public static Function<Throwable, Void> createAsyncExceptionHandler(
            Logger logger, Marker marker, String operationName, Player player, Messages messages) {
        return throwable -> {
            handleAsyncException(logger, marker, operationName, player, throwable, messages);
            return null;
        };
    }

    /**
     * Handles database operation errors consistently.
     *
     * @param logger         The logger to use
     * @param marker         The marker for database operations
     * @param operationName  Name of the database operation
     * @param player         The player to send error to
     * @param e              The exception that occurred
     * @param messages       The i18n messages system
     */
    public static void handleDatabaseError(Logger logger, Marker marker,
                                           String operationName, Player player,
                                           Exception e, Messages messages) {
        String errorMessage = "Database error during " + operationName + ": " +
                (player != null ? player.getUsername() : StringConstants.UNKNOWN);

        logger.error(marker, errorMessage, e);

        if (player != null) {
            player.sendMessage(ValidationUtils.createErrorComponent(messages.get(StringConstants.ERROR_DATABASE_QUERY)));
        }
    }

    /**
     * Handles validation errors consistently.
     *
     * @param player            The player to send validation error to
     * @param validationMessage The validation error message
     */
    public static void handleValidationError(Player player, String validationMessage) {
        if (player != null && validationMessage != null) {
            player.sendMessage(ValidationUtils.createErrorComponent(validationMessage));
        }
    }

    /**
     * Handles security-related errors (brute force, rate limiting, etc.).
     *
     * @param logger    The logger to use
     * @param marker    The security marker
     * @param eventType Type of security event
     * @param player    The player involved
     * @param details   Additional details about the event
     */
    public static void handleSecurityEvent(Logger logger, Marker marker,
                                           String eventType, Player player,
                                           String details) {
        String logMessage = String.format("[SECURITY] %s - %s: %s",
                eventType,
                PlayerHelper.createPlayerInfo(player),
                details != null ? details : "");

        logger.warn(marker, logMessage);
    }

    /**
     * Creates a CompletableFuture with standard error handling.
     *
     * @param future        The future to add error handling to
     * @param logger        The logger to use
     * @param marker        The marker for logging
     * @param operationName Name of the operation
     * @param player        The player involved
     * @param messages      The i18n messages system
     * @return Future with error handling attached
     */
    public static CompletableFuture<Void> withErrorHandling(
            CompletableFuture<Void> future, Logger logger, Marker marker,
            String operationName, Player player, Messages messages) {
        return future.exceptionally(
                createAsyncExceptionHandler(logger, marker, operationName, player, messages)
        );
    }
}
