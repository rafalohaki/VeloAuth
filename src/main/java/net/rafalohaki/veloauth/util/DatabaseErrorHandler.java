package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.command.ValidationUtils;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.i18n.SimpleMessages;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/**
 * Utility class for consistent database error handling across the application.
 * Provides standardized error logging and user messaging for database operations.
 * <p>
 * Thread-safe: stateless utility methods.
 */
public final class DatabaseErrorHandler {

    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private DatabaseErrorHandler() {
        // Utility class - prevent instantiation
    }

    private static final String DEFAULT_ERROR_KEY = "error.database.query";

    /**
     * Handles database errors for Player commands with standardized logging and messaging.
     *
     * @param result    Database result to check for errors
     * @param player    Player to send error message to
     * @param operation Description of the operation being performed
     * @param logger    Logger instance for error logging
     * @param messages  Messages instance for localized error messages
     * @return true if there was a database error (handled), false if operation can continue
     */
    public static boolean handleError(DbResult<?> result, Player player, String operation,
                                     Logger logger, Messages messages) {
        return handleErrorWithKey(result, player, operation, logger, messages, DEFAULT_ERROR_KEY);
    }

    /**
     * Handles database errors for CommandSource (admin commands) with standardized logging and messaging.
     *
     * @param result     Database result to check for errors
     * @param source     CommandSource to send error message to
     * @param identifier Identifier for the operation (e.g., player nickname)
     * @param operation  Description of the operation being performed
     * @param logger     Logger instance for error logging
     * @param messages   Messages instance for localized error messages
     * @return true if there was a database error (handled), false if operation can continue
     */
    public static boolean handleError(DbResult<?> result, CommandSource source, String identifier,
                                     String operation, Logger logger, Messages messages) {
        return handleErrorCore(result, identifier, operation, logger, messages, DEFAULT_ERROR_KEY,
                msg -> source.sendMessage(ValidationUtils.createErrorComponent(msg)));
    }

    /**
     * Handles database errors with custom error message key.
     *
     * @param result    Database result to check for errors
     * @param player    Player to send error message to
     * @param operation Description of the operation being performed
     * @param logger    Logger instance for error logging
     * @param messages  Messages instance for localized error messages
     * @param errorKey  Custom message key for error message
     * @return true if there was a database error (handled), false if operation can continue
     */
    public static boolean handleErrorWithKey(DbResult<?> result, Player player, String operation,
                                            Logger logger, Messages messages, String errorKey) {
        return handleErrorCore(result, player.getUsername(), operation, logger, messages, errorKey,
                msg -> player.sendMessage(ValidationUtils.createErrorComponent(msg)));
    }

    /**
     * Core error handling logic shared by all handleError variants.
     */
    private static boolean handleErrorCore(DbResult<?> result, String identifier, String operation,
                                          Logger logger, Messages messages, String errorKey,
                                          java.util.function.Consumer<String> messageSender) {
        if (!result.isDatabaseError()) {
            return false;
        }
        logDatabaseError(logger, operation, identifier, result.getErrorMessage());
        messageSender.accept(messages.get(errorKey));
        return true;
    }

    /**
     * Logs database error with standardized format.
     */
    private static void logDatabaseError(Logger logger, String operation, String identifier, String errorMessage) {
        if (logger.isErrorEnabled()) {
            logger.error(SECURITY_MARKER, "[DATABASE ERROR] {} failed for {}: {}",
                    operation, identifier, errorMessage);
        }
    }
}
