package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.util.StringConstants;

import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * Utility class for common validation operations across commands.
 * Thread-safe: stateless utility methods.
 */
public final class ValidationUtils {

    private ValidationUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Validates password according to settings configuration.
     *
     * @param password Password to validate
     * @param settings Settings instance for validation rules
     * @return ValidationResult with validation status and message
     */
    public static ValidationResult validatePassword(String password, Settings settings) {
        if (password == null || password.isEmpty()) {
            return ValidationResult.error("Hasło nie może być puste!");
        }

        if (password.length() < settings.getMinPasswordLength()) {
            return ValidationResult.error(
                    "Hasło jest za krótkie! Minimum " + settings.getMinPasswordLength() + " znaków."
            );
        }

        if (password.length() > settings.getMaxPasswordLength()) {
            return ValidationResult.error(
                    "Hasło jest za długie! Maksimum " + settings.getMaxPasswordLength() + " znaków."
            );
        }

        int byteLength = password.getBytes(java.nio.charset.StandardCharsets.UTF_8).length;
        if (byteLength > 72) {
            return ValidationResult.error(
                    "Hasło jest zbyt długie w UTF-8 (" + byteLength + 
                    ") bajtów, limit BCrypt to 72 bajty. Użyj krótszego hasła lub mniej znaków Unicode."
            );
        }

        return ValidationResult.success();
    }

    /**
     * Validates password confirmation match.
     *
     * @param password        Original password
     * @param confirmPassword Password confirmation
     * @return ValidationResult with validation status and message
     */
    public static ValidationResult validatePasswordMatch(String password, String confirmPassword) {
        if (!password.equals(confirmPassword)) {
            return ValidationResult.error("Hasła nie są identyczne!");
        }
        return ValidationResult.success();
    }

    /**
     * Extracts IP address from player as string.
     *
     * @param player Player to extract IP from
     * @return IP address string or "unknown" if unavailable
     */
    public static String getPlayerIp(Player player) {
        var address = player.getRemoteAddress();
        if (address instanceof InetSocketAddress inetAddress) {
            return inetAddress.getAddress().getHostAddress();
        }
        return StringConstants.UNKNOWN;
    }

    /**
     * Extracts InetAddress from player.
     *
     * @param player Player to extract InetAddress from
     * @return InetAddress or null if unavailable
     */
    public static InetAddress getPlayerAddress(Player player) {
        var address = player.getRemoteAddress();
        if (address instanceof InetSocketAddress inetAddress) {
            return inetAddress.getAddress();
        }
        return null;
    }

    /**
     * Validates command source is a player.
     *
     * @param source Command source to validate
     * @return ValidationResult with validation status and message
     */
    public static ValidationResult validatePlayerSource(com.velocitypowered.api.command.CommandSource source) {
        if (!(source instanceof Player)) {
            return ValidationResult.error("Ta komenda jest tylko dla graczy!");
        }
        return ValidationResult.success();
    }

    /**
     * Validates command argument count.
     *
     * @param args          Command arguments array
     * @param expectedCount Expected number of arguments
     * @param usage         Usage message for invalid count
     * @return ValidationResult with validation status and message
     */
    public static ValidationResult validateArgumentCount(String[] args, int expectedCount, String usage) {
        if (args.length != expectedCount) {
            return ValidationResult.error(usage);
        }
        return ValidationResult.success();
    }

    /**
     * Creates a formatted error component.
     *
     * @param message Error message
     * @return Component with red text formatting
     */
    public static Component createErrorComponent(String message) {
        return Component.text(message, NamedTextColor.RED);
    }

    /**
     * Creates a formatted success component.
     *
     * @param message Success message
     * @return Component with green text formatting
     */
    public static Component createSuccessComponent(String message) {
        return Component.text(message, NamedTextColor.GREEN);
    }

    /**
     * Creates a formatted warning component.
     *
     * @param message Warning message
     * @return Component with yellow text formatting
     */
    public static Component createWarningComponent(String message) {
        return Component.text(message, NamedTextColor.YELLOW);
    }

    /**
     * Result of validation operation.
     * Thread-safe: immutable record.
     */
    public record ValidationResult(
            boolean valid,
            String message
    ) {
        /**
         * Creates a valid result.
         *
         * @return Valid ValidationResult
         */
        public static ValidationResult success() {
            return new ValidationResult(true, null);
        }

        /**
         * Creates an invalid result with message.
         *
         * @param message Error message
         * @return Invalid ValidationResult
         */
        public static ValidationResult error(String message) {
            return new ValidationResult(false, message);
        }

        /**
         * Gets the error message (null if valid).
         *
         * @return Error message or null
         */
        public String getErrorMessage() {
            return message;
        }
    }
}
