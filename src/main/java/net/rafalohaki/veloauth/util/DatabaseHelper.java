package net.rafalohaki.veloauth.util;

import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/**
 * Utility class for consistent database operations across VeloAuth.
 * Centralizes common database patterns with proper error handling and logging.
 */
public final class DatabaseHelper {

    private DatabaseHelper() {
        // Utility class - prevent instantiation
    }

    /**
     * Finds a player by nickname with consistent error handling.
     *
     * @param databaseManager The database manager to use
     * @param nickname        The player nickname (case-insensitive)
     * @param logger          Logger for error reporting
     * @param marker          Marker for categorized logging
     * @return CompletableFuture containing the player or null if not found
     */
    public static CompletableFuture<RegisteredPlayer> findPlayerByNickname(
            DatabaseManager databaseManager, String nickname, Logger logger, Marker marker) {

        String lowercaseNick = nickname.toLowerCase();
        return databaseManager.findPlayerByNickname(lowercaseNick)
                .thenApply(dbResult -> {
                    // CRITICAL: Fail-secure on database errors
                    if (dbResult.isDatabaseError()) {
                        logger.error(marker, "Database error finding player {}: {}", 
                                lowercaseNick, dbResult.getErrorMessage());
                        return null;
                    }
                    return dbResult.getValue();
                })
                .exceptionally(throwable -> {
                    logger.error(marker, "Błąd wyszukiwania gracza: " + lowercaseNick, throwable);
                    return null;
                });
    }

    /**
     * Saves a player to database with consistent error handling.
     *
     * @param databaseManager The database manager to use
     * @param player          The player to save
     * @param logger          Logger for error reporting
     * @param marker          Marker for categorized logging
     * @return CompletableFuture containing true if successful, false otherwise
     */
    public static CompletableFuture<Boolean> savePlayer(
            DatabaseManager databaseManager, RegisteredPlayer player, Logger logger, Marker marker) {

        return databaseManager.savePlayer(player)
                .thenApply(dbResult -> {
                    // CRITICAL: Fail-secure on database errors
                    if (dbResult.isDatabaseError()) {
                        logger.error(marker, "Database error saving player {}: {}", 
                                player.getNickname(), dbResult.getErrorMessage());
                        return false;
                    }
                    return dbResult.getValue();
                })
                .exceptionally(throwable -> {
                    logger.error(marker, "Błąd zapisu gracza: " + player.getNickname(), throwable);
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
     * @return CompletableFuture containing true if successful, false otherwise
     */
    public static CompletableFuture<Boolean> deletePlayer(
            DatabaseManager databaseManager, String nickname, Logger logger, Marker marker) {

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
                    logger.error(marker, "Błąd usuwania gracza: " + lowercaseNick, throwable);
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
     * @return CompletableFuture containing true if premium, false otherwise
     */
    public static CompletableFuture<Boolean> isPremium(
            DatabaseManager databaseManager, String username, Logger logger, Marker marker) {

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
                    logger.warn(marker, "Błąd sprawdzania statusu premium dla: " + username, throwable);
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
     * @return CompletableFuture containing the transaction result
     */
    public static CompletableFuture<Boolean> executeTransaction(
            DatabaseManager databaseManager,
            Callable<Boolean> operation,
            Logger logger,
            Marker marker,
            String operationName) {

        return databaseManager.executeInTransaction(operation)
                .exceptionally(throwable -> {
                    logger.error(marker, "Błąd transakcji: " + operationName, throwable);
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
     * @return CompletableFuture containing true if successful, false otherwise
     */
    public static CompletableFuture<Boolean> updatePlayerLoginData(
            DatabaseManager databaseManager, RegisteredPlayer player, String playerIp,
            Logger logger, Marker marker) {

        try {
            player.updateLoginData(playerIp);
            return savePlayer(databaseManager, player, logger, marker);
        } catch (Exception e) {
            logger.error(marker, "Błąd aktualizacji danych logowania gracza: " + player.getNickname(), e);
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
     * @return Function to handle database exceptions
     */
    public static Function<Throwable, Void> createDatabaseErrorHandler(
            Logger logger, Marker marker, String operationName, String playerName) {

        return throwable -> {
            logger.error(marker, "Błąd bazy danych podczas " + operationName + ": " + playerName, throwable);
            return null;
        };
    }
}
