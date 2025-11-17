package net.rafalohaki.veloauth.util;

import at.favre.lib.crypto.bcrypt.BCrypt;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.util.concurrent.CompletableFuture;

/**
 * Utility class for common authentication operations across VeloAuth.
 * Centralizes password hashing, verification, and auth flow patterns.
 */
public final class AuthenticationHelper {

    private AuthenticationHelper() {
        // Utility class - prevent instantiation
    }

    /**
     * Hashes a password using BCrypt with consistent settings.
     *
     * @param password The password to hash
     * @param settings Plugin settings for BCrypt cost
     * @return Hashed password string
     */
    public static String hashPassword(String password, Settings settings) {
        return BCrypt.with(BCrypt.Version.VERSION_2Y)
                .hashToString(settings.getBcryptCost(), password.toCharArray());
    }

    /**
     * Verifies a password against a BCrypt hash.
     *
     * @param password The password to verify
     * @param hash     The hash to verify against
     * @return true if password matches, false otherwise
     */
    public static boolean verifyPassword(String password, String hash) {
        BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), hash);
        return result.verified;
    }

    /**
     * Creates a new RegisteredPlayer with consistent data structure.
     *
     * @param username       Player's username
     * @param hashedPassword Hashed password
     * @param playerIp       Player's IP address
     * @param playerUuid     Player's UUID as string
     * @return New RegisteredPlayer instance
     */
    public static RegisteredPlayer createRegisteredPlayer(
            String username, String hashedPassword, String playerIp, String playerUuid) {

        return new RegisteredPlayer(username, hashedPassword, playerIp, playerUuid);
    }

    /**
     * Performs complete registration flow with database operations.
     *
     * @param databaseManager Database manager for operations
     * @param username        Player's username
     * @param password        Plain text password
     * @param playerIp        Player's IP address
     * @param playerUuid      Player's UUID
     * @param settings        Plugin settings
     * @param logger          Logger for events
     * @param dbMarker        Database logging marker
     * @return CompletableFuture containing the registered player or null if failed
     */
    public static CompletableFuture<RegisteredPlayer> performRegistration(
            DatabaseManager databaseManager, String username, String password,
            String playerIp, String playerUuid, Settings settings,
            Logger logger, Marker dbMarker) {

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Check if player already exists
                String lowercaseNick = username.toLowerCase();
                var existingResult = databaseManager.findPlayerByNickname(lowercaseNick).join();
                
                // CRITICAL: Fail-secure on database errors
                if (existingResult.isDatabaseError()) {
                    logger.error(dbMarker, "Database error during registration check for {}: {}", 
                            username, existingResult.getErrorMessage());
                    return null;
                }
                
                RegisteredPlayer existingPlayer = existingResult.getValue();
                if (existingPlayer != null) {
                    logger.debug(dbMarker, StringConstants.PLAYER_ALREADY_EXISTS_IN_DATABASE, username);
                    return null;
                }

                // Hash password
                String hashedPassword = hashPassword(password, settings);

                // Create new player
                RegisteredPlayer newPlayer = createRegisteredPlayer(username, hashedPassword, playerIp, playerUuid);

                // Save to database
                var saveResult = databaseManager.savePlayer(newPlayer).join();
                
                // CRITICAL: Fail-secure on database errors
                if (saveResult.isDatabaseError()) {
                    logger.error(dbMarker, "Database error during registration save for {}: {}", 
                            username, saveResult.getErrorMessage());
                    return null;
                }
                
                boolean saved = saveResult.getValue();
                if (!saved) {
                    logger.error(dbMarker, StringConstants.FAILED_TO_SAVE_PLAYER, username);
                    return null;
                }

                logger.info(dbMarker, StringConstants.PLAYER_SUCCESSFULLY_REGISTERED, username);
                return newPlayer;

            } catch (Exception e) {
                logger.error(dbMarker, StringConstants.ERROR_DURING_PLAYER_REGISTRATION, username, e);
                return null;
            }
        });
    }

    /**
     * Performs login verification with database lookup.
     *
     * @param databaseManager Database manager for operations
     * @param username        Player's username
     * @param password        Plain text password
     * @param logger          Logger for events
     * @param dbMarker        Database logging marker
     * @return CompletableFuture containing the registered player if credentials valid, null otherwise
     */
    public static CompletableFuture<RegisteredPlayer> performLogin(
            DatabaseManager databaseManager, String username, String password,
            Logger logger, Marker dbMarker) {

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Find player in database
                String lowercaseNick = username.toLowerCase();
                var playerResult = databaseManager.findPlayerByNickname(lowercaseNick).join();
                
                // CRITICAL: Fail-secure on database errors
                if (playerResult.isDatabaseError()) {
                    logger.error(dbMarker, "Database error during login lookup for {}: {}", 
                            username, playerResult.getErrorMessage());
                    return null;
                }
                
                RegisteredPlayer registeredPlayer = playerResult.getValue();
                if (registeredPlayer == null) {
                    logger.debug(dbMarker, StringConstants.PLAYER_NOT_FOUND_IN_DATABASE, username);
                    return null;
                }

                // Verify password
                if (!verifyPassword(password, registeredPlayer.getHash())) {
                    logger.debug(dbMarker, StringConstants.INVALID_PASSWORD_FOR_PLAYER, username);
                    return null;
                }

                logger.info(dbMarker, StringConstants.PLAYER_SUCCESSFULLY_VERIFIED, username);
                return registeredPlayer;

            } catch (Exception e) {
                logger.error(dbMarker, StringConstants.ERROR_DURING_PLAYER_LOGIN, username, e);
                return null;
            }
        });
    }

    /**
     * Performs password change with verification.
     *
     * @param databaseManager Database manager for operations
     * @param username        Player's username
     * @param oldPassword     Current password
     * @param newPassword     New password
     * @param settings        Plugin settings
     * @param logger          Logger for events
     * @param dbMarker        Database logging marker
     * @return CompletableFuture containing true if successful, false otherwise
     */
    public static CompletableFuture<Boolean> performPasswordChange(
            DatabaseManager databaseManager, String username, String oldPassword, String newPassword,
            Settings settings, Logger logger, Marker dbMarker) {

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Find player in database
                String lowercaseNick = username.toLowerCase();
                var playerResult = databaseManager.findPlayerByNickname(lowercaseNick).join();
                
                // CRITICAL: Fail-secure on database errors
                if (playerResult.isDatabaseError()) {
                    logger.error(dbMarker, "Database error during password change lookup for {}: {}", 
                            username, playerResult.getErrorMessage());
                    return false;
                }
                
                RegisteredPlayer registeredPlayer = playerResult.getValue();
                if (registeredPlayer == null) {
                    logger.debug(dbMarker, StringConstants.PLAYER_NOT_FOUND_IN_DATABASE, username);
                    return false;
                }

                // Verify old password
                if (!verifyPassword(oldPassword, registeredPlayer.getHash())) {
                    logger.debug(dbMarker, StringConstants.INVALID_OLD_PASSWORD_FOR_PLAYER, username);
                    return false;
                }

                // Hash new password
                String newHashedPassword = hashPassword(newPassword, settings);

                // Update player
                registeredPlayer.setHash(newHashedPassword);
                var saveResult = databaseManager.savePlayer(registeredPlayer).join();
                
                // CRITICAL: Fail-secure on database errors
                if (saveResult.isDatabaseError()) {
                    logger.error(dbMarker, "Database error during password change save for {}: {}", 
                            username, saveResult.getErrorMessage());
                    return false;
                }
                
                boolean saved = saveResult.getValue();
                if (saved) {
                    logger.info(dbMarker, StringConstants.PLAYER_SUCCESSFULLY_CHANGED_PASSWORD, username);
                    return true;
                } else {
                    logger.error(dbMarker, StringConstants.FAILED_TO_SAVE_NEW_PASSWORD, username);
                    return false;
                }

            } catch (Exception e) {
                logger.error(dbMarker, StringConstants.ERROR_DURING_PASSWORD_CHANGE, username, e);
                return false;
            }
        });
    }

    /**
     * Performs account deletion with verification.
     *
     * @param databaseManager Database manager for operations
     * @param username        Player's username
     * @param password        Password for verification
     * @param logger          Logger for events
     * @param dbMarker        Database logging marker
     * @return CompletableFuture containing true if successful, false otherwise
     */
    public static CompletableFuture<Boolean> performAccountDeletion(
            DatabaseManager databaseManager, String username, String password,
            Logger logger, Marker dbMarker) {

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Find player in database
                String lowercaseNick = username.toLowerCase();
                var playerResult = databaseManager.findPlayerByNickname(lowercaseNick).join();
                
                // CRITICAL: Fail-secure on database errors
                if (playerResult.isDatabaseError()) {
                    logger.error(dbMarker, "Database error during account deletion lookup for {}: {}", 
                            username, playerResult.getErrorMessage());
                    return false;
                }
                
                RegisteredPlayer registeredPlayer = playerResult.getValue();

                if (registeredPlayer == null) {
                    logger.debug(dbMarker, StringConstants.PLAYER_NOT_FOUND_IN_DATABASE, username);
                    return false;
                }

                // Verify password
                if (!verifyPassword(password, registeredPlayer.getHash())) {
                    logger.debug(dbMarker, StringConstants.INVALID_PASSWORD_FOR_ACCOUNT_DELETION, username);
                    return false;
                }

                // Delete player
                var deleteResult = databaseManager.deletePlayer(lowercaseNick).join();
                
                // CRITICAL: Fail-secure on database errors
                if (deleteResult.isDatabaseError()) {
                    logger.error(dbMarker, "Database error during account deletion for {}: {}", 
                            username, deleteResult.getErrorMessage());
                    return false;
                }
                
                boolean deleted = deleteResult.getValue();

                if (deleted) {
                    logger.info(dbMarker, StringConstants.PLAYER_SUCCESSFULLY_DELETED_ACCOUNT, username);
                    return true;
                } else {
                    logger.error(dbMarker, StringConstants.FAILED_TO_DELETE_PLAYER_ACCOUNT, username);
                    return false;
                }

            } catch (Exception e) {
                logger.error(dbMarker, StringConstants.ERROR_DURING_ACCOUNT_DELETION, username, e);
                return false;
            }
        });
    }
}
