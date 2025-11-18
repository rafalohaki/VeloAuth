package net.rafalohaki.veloauth.constants;

/**
 * Centralized constants for i18n message keys to avoid duplication.
 * Improves maintainability and reduces SonarCloud duplication warnings.
 */
public final class StringConstants {

    private StringConstants() {
        // Utility class - prevent instantiation
    }

    // Error message keys
    public static final String ERROR_PLAYER_ONLY = "error.player_only";
    public static final String ERROR_DATABASE_QUERY = "error.database.query";
    public static final String SECURITY_BRUTE_FORCE_BLOCKED = "security.brute_force.blocked";
    public static final String DATABASE_ERROR = "database.error";
    public static final String ADMIN_STATS_CACHE_SIZE = "admin.stats.cache_size";
    public static final String PLAYER_NOT_FOUND = "player.not_found";

    // Common string values
    public static final String UNKNOWN = "unknown";
}