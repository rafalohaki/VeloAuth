package net.rafalohaki.veloauth.util;

import at.favre.lib.crypto.bcrypt.BCrypt;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.util.concurrent.CompletableFuture;

/**
 * Utility class for common authentication operations across VeloAuth.
 * Centralizes password hashing, verification, and auth flow patterns.
 */
public final class AuthenticationHelper {

    // Stałe dla wiadomości
    private static final String PLAYER_NOT_FOUND = "player.not.found";

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
     * @param context Authentication context containing all required parameters
     * @return CompletableFuture containing the registered player or null if failed
     */
    public static CompletableFuture<RegisteredPlayer> performRegistration(AuthenticationContext context) {

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Check if player already exists
                var existingResult = context.databaseManager().findPlayerByNickname(context.username()).join();

                // CRITICAL: Fail-secure on database errors
                if (existingResult.isDatabaseError()) {
                    context.logger().error(context.dbMarker(), "Database error during registration check for {}: {}",
                            context.username(), existingResult.getErrorMessage());
                    return null;
                }

                RegisteredPlayer existingPlayer = existingResult.getValue();
                if (existingPlayer != null) {
                    context.logger().debug(context.dbMarker(), context.messages().get("player.already_exists"), context.username());
                    return null;
                }

                // Hash password
                String hashedPassword = hashPassword(context.password(), context.settings());

                // Create new player
                RegisteredPlayer newPlayer = createRegisteredPlayer(context.username(), hashedPassword, context.playerIp(), context.playerUuid());

                // Save to database
                var saveResult = context.databaseManager().savePlayer(newPlayer).join();

                // CRITICAL: Fail-secure on database errors
                if (saveResult.isDatabaseError()) {
                    context.logger().error(context.dbMarker(), "Database error during registration save for {}: {}",
                            context.username(), saveResult.getErrorMessage());
                    return null;
                }

                boolean saved = saveResult.getValue();
                if (!saved) {
                    context.logger().error(context.dbMarker(), context.messages().get("player.save.failed"), context.username());
                    return null;
                }

                context.logger().info(context.dbMarker(), context.messages().get("player.registered.success"), context.username());
                return newPlayer;

            } catch (Exception e) {
                context.logger().error(context.dbMarker(), context.messages().get("player.registration.error"), context.username(), e);
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
            Logger logger, Marker dbMarker, Messages messages) {

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Find player in database
                var playerResult = databaseManager.findPlayerByNickname(username).join();

                // CRITICAL: Fail-secure on database errors
                if (playerResult.isDatabaseError()) {
                    logger.error(dbMarker, "Database error during login lookup for {}: {}",
                            username, playerResult.getErrorMessage());
                    return null;
                }

                RegisteredPlayer registeredPlayer = playerResult.getValue();
                if (registeredPlayer == null) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(dbMarker, messages.get(PLAYER_NOT_FOUND), username);
                    }
                    return null;
                }

                // Verify password
                if (!verifyPassword(password, registeredPlayer.getHash())) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(dbMarker, messages.get("player.password.invalid"), username);
                    }
                    return null;
                }

                logger.info(dbMarker, messages.get("player.verified.success"), username);
                return registeredPlayer;

            } catch (Exception e) {
                logger.error(dbMarker, messages.get("player.login.error"), username, e);
                return null;
            }
        });
    }

    /**
     * Performs password change with verification.
     *
     * @param context Password change context containing all required parameters
     * @return CompletableFuture containing true if successful, false otherwise
     */
    public static CompletableFuture<Boolean> performPasswordChange(PasswordChangeContext context) {

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Find player in database
                var playerResult = context.databaseManager().findPlayerByNickname(context.username()).join();

                // CRITICAL: Fail-secure on database errors
                if (playerResult.isDatabaseError()) {
                    context.logger().error(context.dbMarker(), "Database error during password change lookup for {}: {}",
                            context.username(), playerResult.getErrorMessage());
                    return false;
                }

                RegisteredPlayer registeredPlayer = playerResult.getValue();
                if (registeredPlayer == null) {
                    context.logger().debug(context.dbMarker(), context.messages().get(PLAYER_NOT_FOUND), context.username());
                    return false;
                }

                // Verify old password
                if (!verifyPassword(context.oldPassword(), registeredPlayer.getHash())) {
                    context.logger().debug(context.dbMarker(), context.messages().get("player.old_password.invalid"), context.username());
                    return false;
                }

                // Hash new password
                String newHashedPassword = hashPassword(context.newPassword(), context.settings());

                // Update player
                registeredPlayer.setHash(newHashedPassword);
                var saveResult = context.databaseManager().savePlayer(registeredPlayer).join();

                // CRITICAL: Fail-secure on database errors
                if (saveResult.isDatabaseError()) {
                    context.logger().error(context.dbMarker(), "Database error during password change save for {}: {}",
                            context.username(), saveResult.getErrorMessage());
                    return false;
                }

                boolean saved = saveResult.getValue();
                if (saved) {
                    context.logger().info(context.dbMarker(), context.messages().get("player.password.changed.success"), context.username());
                    return true;
                } else {
                    context.logger().error(context.dbMarker(), context.messages().get("player.password.save.failed"), context.username());
                    return false;
                }

            } catch (Exception e) {
                context.logger().error(context.dbMarker(), context.messages().get("player.password.change.error"), context.username(), e);
                return false;
            }
        });
    }

    /**
     * Validates player for deletion - checks existence and password verification.
     *
     * @param context Account deletion context
     * @return RegisteredPlayer if valid, null if invalid
     */
    private static RegisteredPlayer validatePlayerForDeletion(AccountDeletionContext context) {
        // Find player in database
        var playerResult = context.databaseManager().findPlayerByNickname(context.username()).join();

        // CRITICAL: Fail-secure on database errors
        if (playerResult.isDatabaseError()) {
            context.logger().error(context.dbMarker(), "Database error during account deletion lookup for {}: {}",
                    context.username(), playerResult.getErrorMessage());
            return null;
        }

        RegisteredPlayer registeredPlayer = playerResult.getValue();
        if (registeredPlayer == null) {
            if (context.logger().isDebugEnabled()) {
                context.logger().debug(context.dbMarker(), context.messages().get(PLAYER_NOT_FOUND), context.username());
            }
            return null;
        }

        // Verify password
        if (!verifyPassword(context.password(), registeredPlayer.getHash())) {
            if (context.logger().isDebugEnabled()) {
                context.logger().debug(context.dbMarker(), context.messages().get("player.password.invalid.deletion"), context.username());
            }
            return null;
        }

        return registeredPlayer;
    }

    /**
     * Executes the actual deletion operation.
     *
     * @param context       Account deletion context
     * @param lowercaseNick Lowercase nickname for database operation
     * @return true if deletion successful, false otherwise
     */
    private static boolean executeDeletion(AccountDeletionContext context, String lowercaseNick) {
        // Delete player
        var deleteResult = context.databaseManager().deletePlayer(lowercaseNick).join();

        // CRITICAL: Fail-secure on database errors
        if (deleteResult.isDatabaseError()) {
            context.logger().error(context.dbMarker(), "Database error during account deletion for {}: {}",
                    context.username(), deleteResult.getErrorMessage());
            return false;
        }

        boolean deleted = deleteResult.getValue();
        if (deleted) {
            if (context.logger().isInfoEnabled()) {
                context.logger().info(context.dbMarker(), context.messages().get("player.account.deleted.success"), context.username());
            }
            return true;
        } else {
            if (context.logger().isErrorEnabled()) {
                context.logger().error(context.dbMarker(), context.messages().get("player.account.delete.failed"), context.username());
            }
            return false;
        }
    }

    /**
     * Performs account deletion with verification.
     *
     * @param context Account deletion context
     * @return CompletableFuture containing true if successful, false otherwise
     */
    public static CompletableFuture<Boolean> performAccountDeletion(AccountDeletionContext context) {

        return CompletableFuture.supplyAsync(() -> {
            try {
                // Validate player exists and password is correct
                RegisteredPlayer registeredPlayer = validatePlayerForDeletion(context);
                if (registeredPlayer == null) {
                    return false;
                }

                // Execute the deletion
                return executeDeletion(context, context.username());

            } catch (Exception e) {
                context.logger().error(context.dbMarker(), context.messages().get("player.account.deletion.error"), context.username(), e);
                return false;
            }
        });
    }

    /**
     * Authentication context containing parameters for registration operations.
     * Reduces parameter count and improves maintainability.
     */
    public record AuthenticationContext(
            DatabaseManager databaseManager,
            String username,
            String password,
            String playerIp,
            String playerUuid,
            Settings settings,
            Logger logger,
            Marker dbMarker,
            Messages messages
    ) {
    }

    /**
     * Password change context containing parameters for password change operations.
     */
    public record PasswordChangeContext(
            DatabaseManager databaseManager,
            String username,
            String oldPassword,
            String newPassword,
            Settings settings,
            Logger logger,
            Marker dbMarker,
            Messages messages
    ) {
    }

    /**
     * Account deletion context containing parameters for account deletion operations.
     */
    public record AccountDeletionContext(
            DatabaseManager databaseManager,
            String username,
            String password,
            Logger logger,
            Marker dbMarker,
            Messages messages
    ) {
    }
}
