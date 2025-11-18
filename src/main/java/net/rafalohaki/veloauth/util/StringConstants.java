package net.rafalohaki.veloauth.util;

/**
 * Constants for internal system messages and values.
 * This class now contains only internal/debug messages that don't need internationalization.
 * <p>
 * User-facing messages have been moved to the Messages i18n system.
 * Internal messages like cache operations and session logs remain here for developer use.
 * <p>
 * Note: SonarQube rule S2068 (PASSWORD detection) is suppressed because
 * these are internal logging templates, not hardcoded passwords.
 */
@SuppressWarnings("java:S2068")
public final class StringConstants {

    /**
     * Default value used when player information cannot be determined.
     * This is an internal fallback value, not user-facing.
     */
    public static final String UNKNOWN = "unknown";

    private StringConstants() {
        // Utility class - prevent instantiation
    }
}
