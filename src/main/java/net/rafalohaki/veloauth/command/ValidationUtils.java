package net.rafalohaki.veloauth.command;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

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
    public static ValidationResult validatePassword(String password, Settings settings, Messages messages) {
        return validatePassword(password, settings.getPasswordSettings(), messages);
    }

    static ValidationResult validatePassword(
            String password,
            Settings.PasswordSettings passwordSettings,
            Messages messages) {
        if (password == null || password.isEmpty()) {
            return ValidationResult.localized(messages, "validation.password.empty");
        }

        if (password.length() < passwordSettings.minLength()) {
            return ValidationResult.localized(messages, "validation.password.too_short",
                    passwordSettings.minLength());
        }

        if (password.length() > passwordSettings.maxLength()) {
            return ValidationResult.localized(messages, "validation.password.too_long",
                    passwordSettings.maxLength());
        }

        int byteLength = password.getBytes(StandardCharsets.UTF_8).length;
        if (byteLength > 72) {
            return ValidationResult.localized(
                    messages, "validation.password.utf8_too_long", byteLength);
        }

        return validateComplexity(password, passwordSettings.policy(), messages);
    }

    private static ValidationResult validateComplexity(String password,
                                                       Settings.PasswordPolicy policy,
                                                       Messages messages) {
        if (!policy.isAnyComplexityRequired()) {
            return ValidationResult.success();
        }

        CharCounts counts = countChars(password);

        if (counts.digits < policy.getMinDigits()) {
            return ValidationResult.localized(messages, "validation.password.needs_digit",
                    policy.getMinDigits());
        }
        if (counts.uppercase < policy.getMinUppercase()) {
            return ValidationResult.localized(messages, "validation.password.needs_upper",
                    policy.getMinUppercase());
        }
        if (counts.lowercase < policy.getMinLowercase()) {
            return ValidationResult.localized(messages, "validation.password.needs_lower",
                    policy.getMinLowercase());
        }
        if (counts.special < policy.getMinSpecial()) {
            return ValidationResult.localized(messages, "validation.password.needs_special",
                    policy.getMinSpecial());
        }
        return ValidationResult.success();
    }

    private static CharCounts countChars(String password) {
        CharCounts counts = new CharCounts();
        for (int i = 0; i < password.length(); i++) {
            counts.tally(password.charAt(i));
        }
        return counts;
    }

    private static final class CharCounts {
        int digits;
        int uppercase;
        int lowercase;
        int special;

        void tally(char c) {
            if (Character.isDigit(c)) {
                digits++;
            } else if (Character.isUpperCase(c)) {
                uppercase++;
            } else if (Character.isLowerCase(c)) {
                lowercase++;
            } else {
                special++;
            }
        }
    }

    /**
     * Validates password confirmation match.
     *
     * @param password        Original password
     * @param confirmPassword Password confirmation
     * @return ValidationResult with validation status and message
     */
    public static ValidationResult validatePasswordMatch(String password,
                                                         String confirmPassword,
                                                         Messages messages) {
        if (!Objects.equals(password, confirmPassword)) {
            return ValidationResult.localized(messages, "validation.password.mismatch");
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
            String message,
            @javax.annotation.Nullable String messageKey,
            List<Object> messageArguments
    ) {
        public ValidationResult {
            messageArguments = messageArguments == null
                    ? List.of()
                    : List.copyOf(messageArguments);
        }

        /**
         * Creates a valid result.
         *
         * @return Valid ValidationResult
         */
        public static ValidationResult success() {
            return new ValidationResult(true, null, null, List.of());
        }

        /**
         * Creates an invalid result with a pre-rendered message (used for non-i18n text).
         *
         * @param message Error message
         * @return Invalid ValidationResult
         */
        public static ValidationResult error(String message) {
            return new ValidationResult(false, message, null, List.of());
        }

        /**
         * Creates an invalid result that remembers the message key and arguments so callers
         * can render it in the player's client locale.
         */
        static ValidationResult localized(Messages messages, String key, Object... args) {
            return new ValidationResult(false, messages.get(key, args), key,
                    args.length == 0 ? List.of() : Arrays.asList(args));
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
