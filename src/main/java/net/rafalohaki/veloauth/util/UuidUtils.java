package net.rafalohaki.veloauth.util;

import java.util.UUID;

/**
 * Utility class for safe UUID parsing operations.
 * Provides null-safe methods to convert UUID strings to UUID objects.
 * <p>
 * Thread-safe: stateless utility methods.
 */
public final class UuidUtils {

    private UuidUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Safely parses a UUID string, returning null for invalid or empty strings.
     * This method consolidates UUID parsing logic used across multiple model classes.
     *
     * @param uuidString UUID string to parse (may be null or empty)
     * @return UUID object or null if string is null, empty, or invalid format
     */
    @javax.annotation.Nullable
    public static UUID parseUuidSafely(@javax.annotation.Nullable String uuidString) {
        if (uuidString == null || uuidString.isEmpty()) {
            return null;
        }
        try {
            return UUID.fromString(uuidString);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Checks if a string is a valid UUID format.
     *
     * @param uuidString String to validate
     * @return true if string is a valid UUID, false otherwise
     */
    public static boolean isValidUuid(@javax.annotation.Nullable String uuidString) {
        return parseUuidSafely(uuidString) != null;
    }
}
