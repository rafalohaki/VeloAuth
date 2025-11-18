package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.net.InetAddress;
import java.util.regex.Pattern;

/**
 * Comprehensive input validation utility for VeloAuth.
 * Provides security-focused validation for usernames, passwords, IPs, and other inputs.
 * <p>
 * This class implements fail-secure validation to prevent injection attacks,
 * buffer overflow attempts, and other security vulnerabilities.
 */
public final class VeloAuthValidator {

    // Minecraft username validation (official Minecraft username rules)
    private static final Pattern USERNAME_PATTERN = Pattern.compile("^\\w{1,16}$");
    
    // Password validation - allow most characters but limit length and prevent injection
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^.{3,100}$");
    
    // IP validation handled via InetAddress parsing to reduce regex complexity

    private VeloAuthValidator() {
        // Utility class - prevent instantiation
    }

    /**
     * Validates Minecraft username according to official specifications.
     * This method implements strict validation to prevent username-based attacks.
     *
     * @param username The username to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidUsername(String username) {
        if (username == null || username.isEmpty()) {
            return false;
        }

        // Check length first (quick check)
        if (username.length() > 16) {
            return false;
        }

        // Check for valid characters
        if (!USERNAME_PATTERN.matcher(username).matches()) {
            return false;
        }

        // Additional security checks
        return !hasSuspiciousPatterns(username);
    }

    /**
     * Validates password for security requirements.
     * Implements reasonable restrictions while allowing user freedom.
     *
     * @param password The password to validate
     * @return ValidationResult with details
     */
    public static ValidationResult validatePassword(String password) {
        if (password == null) {
            return ValidationResult.invalid("Password cannot be null");
        }

        if (password.length() < 3) {
            return ValidationResult.invalid("Password must be at least 3 characters long");
        }

        if (password.length() > 100) {
            return ValidationResult.invalid("Password cannot exceed 100 characters");
        }

        if (!PASSWORD_PATTERN.matcher(password).matches()) {
            return ValidationResult.invalid("Password contains invalid characters");
        }

        // Check for common weak passwords
        if (isCommonWeakPassword(password)) {
            return ValidationResult.invalid("Password is too common. Please choose a stronger password");
        }

        return ValidationResult.valid();
    }

    /**
     * Validates IP address for security and logging purposes.
     *
     * @param ipAddress The IP address string to validate
     * @return ValidationResult with details
     */
    public static ValidationResult validateIpAddress(String ipAddress) {
        if (ipAddress == null || ipAddress.isEmpty()) {
            return ValidationResult.invalid("IP address cannot be null or empty");
        }

        try {
            InetAddress.getByName(ipAddress);
            return ValidationResult.valid();
        } catch (Exception e) {
            return ValidationResult.invalid("Invalid IP address format");
        }
    }

    /**
     * Validates InetAddress object for security checks.
     *
     * @param address The InetAddress to validate
     * @return true if valid for authentication purposes
     */
    public static boolean isValidInetAddress(InetAddress address) {
        return address != null && !address.isAnyLocalAddress();
    }

    /**
     * Validates player object for security and consistency.
     *
     * @param player The player to validate
     * @return ValidationResult with details
     */
    public static ValidationResult validatePlayer(Player player) {
        if (player == null) {
            return ValidationResult.invalid("Player cannot be null");
        }

        String username = player.getUsername();
        if (!isValidUsername(username)) {
            return ValidationResult.invalid("Invalid player username: " + username);
        }

        if (player.getUniqueId() == null) {
            return ValidationResult.invalid("Player UUID cannot be null");
        }

        return ValidationResult.valid();
    }

    /**
     * Creates a user-friendly error message for validation failures.
     *
     * @param validationResult The validation result
     * @param inputType The type of input that failed (username, password, etc.)
     * @return Component with formatted error message
     */
    public static Component createErrorMessage(ValidationResult validationResult, String inputType) {
        String message = validationResult.getErrorMessage();
        
        // Create user-friendly messages based on input type
        switch (inputType.toLowerCase()) {
            case "username":
                if (message.contains("invalid format")) {
                    return Component.text("Nieprawidłowy format nazwy użytkownika! Użyj tylko liter, cyfr i podkreślenia (max 16 znaków).", NamedTextColor.RED);
                }
                break;
            case "password":
                if (message.contains("at least 3 characters")) {
                    return Component.text("Hasło musi mieć co najmniej 3 znaki!", NamedTextColor.RED);
                }
                if (message.contains("too common")) {
                    return Component.text("Hasło jest zbyt popularne. Wybierz silniejsze hasło.", NamedTextColor.RED);
                }
                break;
            default:
                // Default case for unknown input types - return generic validation error
                break;
        }
        
        return Component.text("Błąd walidacji: " + message, NamedTextColor.RED);
    }

    /**
     * Logs security validation failures for monitoring.
     *
     * @param validationResult The failed validation result
     * @param inputType The type of input that failed
     * @param context Additional context (username, IP, etc.)
     * @param logger Logger for reporting
     * @param securityMarker Security marker for categorization
     */
    public static void logValidationFailure(
            ValidationResult validationResult,
            String inputType,
            String context,
            Logger logger,
            Marker securityMarker) {

        logger.warn(securityMarker, "[SECURITY] Validation failed for {}: {} - Context: {}",
                inputType, validationResult.getErrorMessage(), context);
    }

    /**
     * Checks for suspicious patterns in usernames that might indicate attacks.
     *
     * @param username The username to check
     * @return true if suspicious patterns found
     */
    private static boolean hasSuspiciousPatterns(String username) {
        // Check for common attack patterns
        String lowerUsername = username.toLowerCase();
        
        return lowerUsername.contains("drop") || lowerUsername.contains("delete") ||
               lowerUsername.contains("insert") || lowerUsername.contains("update") ||
               lowerUsername.contains("select") || lowerUsername.contains("'") ||
               lowerUsername.contains("\"") || lowerUsername.contains(";") ||
               lowerUsername.contains("cmd") || lowerUsername.contains("powershell") ||
               lowerUsername.contains("bash") || lowerUsername.contains("sh") ||
               lowerUsername.contains("$") || lowerUsername.contains("`") ||
               lowerUsername.contains("../") || lowerUsername.contains("..\\") ||
               lowerUsername.contains("/") || lowerUsername.contains("\\");
    }

    /**
     * Checks if password is commonly used and should be rejected.
     *
     * @param password The password to check
     * @return true if it's a common weak password
     */
    private static boolean isCommonWeakPassword(String password) {
        String lowerPassword = password.toLowerCase();
        
        // List of common weak passwords
        String[] weakPasswords = {
            "123", "1234", "12345", "123456", "password", "qwerty",
            "abc", "test", "guest", "user", "admin", "root",
            "pass", "temp", "default", "login", "letmein"
        };

        for (String weak : weakPasswords) {
            if (lowerPassword.equals(weak) || lowerPassword.contains(weak)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Validation result class for detailed error reporting.
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String errorMessage;

        private ValidationResult(boolean valid, String errorMessage) {
            this.valid = valid;
            this.errorMessage = errorMessage;
        }

        public static ValidationResult valid() {
            return new ValidationResult(true, null);
        }

        public static ValidationResult invalid(String errorMessage) {
            return new ValidationResult(false, errorMessage);
        }

        public boolean isValid() {
            return valid;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }
}
