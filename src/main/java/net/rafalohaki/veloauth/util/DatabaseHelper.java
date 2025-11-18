package net.rafalohaki.veloauth.util;

import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/**
 * Utility methods for database operations with centralized error handling.
 * This class provides helper methods for common database operations
 * while maintaining consistent error handling throughout the application.
 */
public final class DatabaseHelper {

    private DatabaseHelper() {
        // Utility class - prevent instantiation
    }

    /**
     * Finds a player by nickname with consistent error handling.
     * This method uses the centralized VeloAuthErrorHandler to ensure
     * fail-secure behavior and consistent logging.
     *
     * @param databaseManager Database manager instance
     * @param nickname Player nickname to search for
     * @param logger Logger for error reporting
     * @param marker Optional marker for categorized logging
     * @param messages Messages instance for error message generation
     * @return CompletableFuture containing the registered player or null if not found
     */
    public static CompletableFuture<RegisteredPlayer> findPlayerByNickname(
            DatabaseManager databaseManager, String nickname, Logger logger, Marker marker, Messages messages) {

        // Let DatabaseManager handle normalization internally to prevent cache inconsistencies
        return databaseManager.findPlayerByNickname(nickname)
                .thenApply(dbResult -> {
                    // CRITICAL: Fail-secure on database errors
                    if (dbResult.isDatabaseError()) {
                        // Use centralized error handling
                        VeloAuthErrorHandler.handleDatabaseError(
                                new RuntimeException(dbResult.getErrorMessage()),
                                "player lookup",
                                logger,
                                marker,
                                messages,
                                "nickname: " + nickname
                        );
                        return null;
                    }
                    return dbResult.getValue();
                })
                .exceptionally(throwable -> {
                    // Use centralized error handling for exceptions
                    VeloAuthErrorHandler.handleDatabaseError(
                            throwable,
                            "player lookup",
                            logger,
                            marker,
                            messages,
                            "nickname: " + nickname
                    );
                    return null;
                });
    }

    /**
     * Simplified version without marker for backward compatibility.
     *
     * @param databaseManager Database manager instance
     * @param nickname Player nickname to search for
     * @param logger Logger for error reporting
     * @param messages Messages instance for error message generation
     * @return CompletableFuture containing the registered player or null if not found
     */
    public static CompletableFuture<RegisteredPlayer> findPlayerByNickname(
            DatabaseManager databaseManager, String nickname, Logger logger, Messages messages) {

        return findPlayerByNickname(databaseManager, nickname, logger, null, messages);
    }

    /**
     * Validates database operation result with centralized error handling.
     *
     * @param dbResult Database result to validate
     * @param operation Operation description for error logging
     * @param logger Logger for error reporting
     * @param marker Optional marker for categorized logging
     * @param messages Messages instance for error message generation
     * @param context Additional context information
     * @param <T> Result type
     * @return The value if successful, null if database error occurred
     */
    public static <T> T validateDbResult(
            DatabaseManager.DbResult<T> dbResult,
            String operation,
            Logger logger,
            Marker marker,
            Messages messages,
            String context) {

        if (dbResult.isDatabaseError()) {
            VeloAuthErrorHandler.handleDatabaseError(
                    new RuntimeException(dbResult.getErrorMessage()),
                    operation,
                    logger,
                    marker,
                    messages,
                    context
            );
            return null;
        }
        return dbResult.getValue();
    }

    /**
     * Simplified version without marker for backward compatibility.
     *
     * @param dbResult Database result to validate
     * @param operation Operation description for error logging
     * @param logger Logger for error reporting
     * @param messages Messages instance for error message generation
     * @param context Additional context information
     * @param <T> Result type
     * @return The value if successful, null if database error occurred
     */
    public static <T> T validateDbResult(
            DatabaseManager.DbResult<T> dbResult,
            String operation,
            Logger logger,
            Messages messages,
            String context) {

        return validateDbResult(dbResult, operation, logger, null, messages, context);
    }

    /**
     * Saves a player to database with consistent error handling.
     *
     * @param databaseManager The database manager to use
     * @param player          The player to save
     * @param logger          Logger for error reporting
     * @param marker          Marker for categorized logging
     * @param messages        Messages system for i18n
     * @return CompletableFuture containing true if successful, false otherwise
     */
    public static CompletableFuture<Boolean> savePlayer(
            DatabaseManager databaseManager, RegisteredPlayer player, Logger logger, Marker marker, Messages messages) {

        return databaseManager.savePlayer(player)
                .thenApply(dbResult -> {
                    // CRITICAL: Fail-secure on database errors
                    if (dbResult.isDatabaseError()) {
                        // Use centralized error handling
                        VeloAuthErrorHandler.handleDatabaseError(
                                new RuntimeException(dbResult.getErrorMessage()),
                                "player save",
                                logger,
                                marker,
                                messages,
                                "player: " + player.getNickname()
                        );
                        return false;
                    }
                    return dbResult.getValue();
                })
                .exceptionally(throwable -> {
                    logger.error(marker, messages.get("database.error.saving") + player.getNickname(), throwable);
                    return false;
                });
    }

    /**
     * Deletes a player by nickname with consistent error handling.
     *
     * @param databaseManager The database manager to use
     * @param nickname        The player nickname (case-insensitive)
     * @param logger          Logger for error reporting
     * @param marker          Marker for categorized logging
     * @param messages        Messages system for i18n
     * @return CompletableFuture containing true if successful, false otherwise
     */
    public static CompletableFuture<Boolean> deletePlayer(
            DatabaseManager databaseManager, String nickname, Logger logger, Marker marker, Messages messages) {

        String lowercaseNick = nickname.toLowerCase();
        return databaseManager.deletePlayer(lowercaseNick)
                .thenApply(dbResult -> {
                    // CRITICAL: Fail-secure on database errors
                    if (dbResult.isDatabaseError()) {
                        logger.error(marker, "Database error deleting player {}: {}",
                                lowercaseNick, dbResult.getErrorMessage());
                        return false;
                    }
                    return dbResult.getValue();
                })
                .exceptionally(throwable -> {
                    logger.error(marker, messages.get("database.error.deleting") + lowercaseNick, throwable);
                    return false;
                });
    }

    /**
     * Checks if a player has premium status with consistent error handling.
     *
     * @param databaseManager The database manager to use
     * @param username        The player username
     * @param logger          Logger for error reporting
     * @param marker          Marker for categorized logging
     * @param messages        Messages system for i18n
     * @return CompletableFuture containing true if premium, false otherwise
     */
    public static CompletableFuture<Boolean> isPremium(
            DatabaseManager databaseManager, String username, Logger logger, Marker marker, Messages messages) {

        return databaseManager.isPremium(username)
                .thenApply(dbResult -> {
                    // CRITICAL: Fail-secure on database errors
                    if (dbResult.isDatabaseError()) {
                        logger.warn(marker, "Database error checking premium status for {}: {}",
                                username, dbResult.getErrorMessage());
                        return false; // Default to non-premium on error
                    }
                    return dbResult.getValue();
                })
                .exceptionally(throwable -> {
                    logger.warn(marker, messages.get("database.error.checking_premium") + username, throwable);
                    return false; // Default to non-premium on error
                });
    }

    /**
     * Executes a database transaction with consistent error handling.
     *
     * @param databaseManager The database manager to use
     * @param operation       The transaction operation to execute
     * @param logger          Logger for error reporting
     * @param marker          Marker for categorized logging
     * @param operationName   Name of the operation for logging
     * @param messages        Messages system for i18n
     * @return CompletableFuture containing the transaction result
     */
    public static CompletableFuture<Boolean> executeTransaction(
            DatabaseManager databaseManager,
            Callable<Boolean> operation,
            Logger logger,
            Marker marker,
            String operationName,
            Messages messages) {

        return databaseManager.executeInTransaction(operation)
                .exceptionally(throwable -> {
                    logger.error(marker, messages.get("database.error.transaction") + operationName, throwable);
                    return false;
                });
    }

    /**
     * Updates player login data and saves with consistent error handling.
     *
     * @param databaseManager The database manager to use
     * @param player          The player to update
     * @param playerIp        The player's current IP
     * @param logger          Logger for error reporting
     * @param marker          Marker for categorized logging
     * @param messages        Messages system for i18n
     * @return CompletableFuture containing true if successful, false otherwise
     */
    public static CompletableFuture<Boolean> updatePlayerLoginData(
            DatabaseManager databaseManager, RegisteredPlayer player, String playerIp,
            Logger logger, Marker marker, Messages messages) {

        try {
            player.updateLoginData(playerIp);
            return savePlayer(databaseManager, player, logger, marker, messages);
        } catch (Exception e) {
            logger.error(marker, messages.get("database.error.updating_login") + player.getNickname(), e);
            return CompletableFuture.completedFuture(false);
        }
    }

    /**
     * Creates a standardized database error handler.
     *
     * @param logger        Logger for error reporting
     * @param marker        Marker for categorized logging
     * @param operationName Name of the operation
     * @param playerName    Player name for context
     * @param messages      Messages system for i18n
     * @return Function to handle database exceptions
     */
    public static Function<Throwable, Void> createDatabaseErrorHandler(
            Logger logger, Marker marker, String operationName, String playerName, Messages messages) {

        return throwable -> {
            logger.error(marker, messages.get("database.error.operation", operationName, playerName), throwable);
            return null;
        };
    }
}
