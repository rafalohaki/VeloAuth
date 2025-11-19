package net.rafalohaki.veloauth.util;

import net.rafalohaki.veloauth.database.DatabaseManager;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.sql.SQLException;
import java.util.concurrent.CompletableFuture;

/**
 * Centralized error handling utility for VeloAuth.
 * Provides consistent error handling across all components to eliminate code duplication.
 * <p>
 * This utility ensures that all database errors are handled consistently
 * with proper logging and fail-secure behavior.
 */
public final class VeloAuthErrorHandler {

    private VeloAuthErrorHandler() {
        // Utility class - prevent instantiation
    }

    /**
     * Handles database errors consistently across all components.
     * This method centralizes database error handling to ensure fail-secure behavior
     * and consistent logging throughout the application.
     *
     * @param throwable The exception that occurred
     * @param operation The operation being performed (for logging)
     * @param logger    The logger to use for error reporting
     * @param marker    Optional marker for categorized logging
     * @param messages  Messages instance for error message generation
     * @param context   Additional context information (username, player info, etc.)
     * @return CompletableFuture with database error result
     */
    public static <T> CompletableFuture<DatabaseManager.DbResult<T>> handleDatabaseError(
            Throwable throwable,
            String operation,
            Logger logger,
            Marker marker,
            net.rafalohaki.veloauth.i18n.Messages messages,
            String context) {

        // Log the error with full context
        String errorMessage = String.format("Database operation failed during %s%s",
                operation, context != null && !context.isEmpty() ? " for " + context : "");

        if (marker != null) {
            if (logger.isErrorEnabled()) {
                logger.error(marker, "{}: {}", errorMessage, throwable.getMessage(), throwable);
            }
        } else {
            if (logger.isErrorEnabled()) {
                logger.error("{}: {}", errorMessage, throwable.getMessage(), throwable);
            }
        }

        // Create user-friendly error message
        String userMessage = messages != null
                ? messages.get("database.error.general")
                : "Database error occurred. Please try again later.";

        // Return fail-secure database error result
        return CompletableFuture.completedFuture(
                DatabaseManager.DbResult.databaseError(userMessage + ": " + throwable.getMessage())
        );
    }

    /**
     * Handles database errors with default logging.
     *
     * @param throwable The exception that occurred
     * @param operation The operation being performed
     * @param logger    The logger to use
     * @param messages  Messages instance for error message generation
     * @return CompletableFuture with database error result
     */
    public static <T> CompletableFuture<DatabaseManager.DbResult<T>> handleDatabaseError(
            Throwable throwable,
            String operation,
            Logger logger,
            net.rafalohaki.veloauth.i18n.Messages messages) {

        return handleDatabaseError(throwable, operation, logger, null, messages, null);
    }

    /**
     * Handles database errors with context information.
     *
     * @param throwable The exception that occurred
     * @param operation The operation being performed
     * @param logger    The logger to use
     * @param messages  Messages instance for error message generation
     * @param context   Additional context (username, etc.)
     * @return CompletableFuture with database error result
     */
    public static <T> CompletableFuture<DatabaseManager.DbResult<T>> handleDatabaseError(
            Throwable throwable,
            String operation,
            Logger logger,
            net.rafalohaki.veloauth.i18n.Messages messages,
            String context) {

        return handleDatabaseError(throwable, operation, logger, null, messages, context);
    }

    /**
     * Creates a standardized error message for database operations.
     *
     * @param operation The operation that failed
     * @param context   Additional context information
     * @return Formatted error message
     */
    public static String formatDatabaseError(String operation, String context) {
        if (context != null && !context.isEmpty()) {
            return String.format("Database error during %s for %s", operation, context);
        }
        return String.format("Database error during %s", operation);
    }

    /**
     * Checks if a throwable is a critical database error that should trigger fail-secure behavior.
     *
     * @param throwable The exception to check
     * @return true if this is a critical database error
     */
    public static boolean isCriticalDatabaseError(Throwable throwable) {
        if (throwable == null) {
            return false;
        }

        // Check for connection-related errors
        if (throwable instanceof SQLException sqlException) {
            return hasCriticalDatabaseMessage(sqlException.getMessage()) ||
                    isConnectionErrorCode(sqlException.getErrorCode());
        }

        // Check for common database connectivity issues
        return hasCriticalDatabaseMessage(throwable.getMessage()) ||
                hasPoolRelatedMessage(throwable.getMessage());
    }
    
    private static boolean hasCriticalDatabaseMessage(String message) {
        if (message == null) return false;
        String lowerMessage = message.toLowerCase();
        return lowerMessage.contains("connection") ||
                lowerMessage.contains("timeout") ||
                lowerMessage.contains("network") ||
                lowerMessage.contains("communication");
    }
    
    private static boolean hasPoolRelatedMessage(String message) {
        if (message == null) return false;
        String lowerMessage = message.toLowerCase();
        return lowerMessage.contains("pool") ||
                lowerMessage.contains("datasource");
    }

    /**
     * Checks if SQL error code indicates a connection problem.
     *
     * @param errorCode The SQL error code
     * @return true if this is a connection-related error code
     */
    private static final java.util.Set<Integer> CONNECTION_ERROR_CODES = new java.util.HashSet<>(java.util.Arrays.asList(
            0, 8001, 8003, 8006, 8007, 17002, 17410, 12514, 12541, 12560
    ));

    private static boolean isConnectionErrorCode(int errorCode) {
        return CONNECTION_ERROR_CODES.contains(errorCode);
    }

    /**
     * Logs security-related database errors with appropriate severity.
     *
     * @param throwable      The exception that occurred
     * @param operation      The operation being performed
     * @param logger         The logger to use
     * @param securityMarker Security marker for categorized logging
     * @param context        Security context (username, IP, etc.)
     */
    public static void handleSecurityDatabaseError(
            Throwable throwable,
            String operation,
            Logger logger,
            Marker securityMarker,
            String context) {

        String errorMessage = String.format("Security database operation failed: %s%s",
                operation, context != null ? " for " + context : "");

        logger.error(securityMarker, "[SECURITY] {}: {}", errorMessage, throwable.getMessage(), throwable);

        // For security errors, we might want additional monitoring or alerting
        if (isCriticalDatabaseError(throwable)) {
            logger.error(securityMarker, "[CRITICAL] Database connectivity issue detected during security operation: {}", operation);
        }
    }
}
