package net.rafalohaki.veloauth.premium;

import java.util.Locale;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Utility for converting raw 32-character UUID strings returned by Mojang API into canonical UUIDs.
 */
final class PremiumUuidFormatter {

    private static final Pattern HEX_32 = Pattern.compile("^[0-9a-fA-F]{32}$");

    private PremiumUuidFormatter() {
        // Utility class
    }

    static UUID parseRaw32Uuid(String rawUuid) {
        if (rawUuid == null || !HEX_32.matcher(rawUuid).matches()) {
            return null;
        }

        String normalized = rawUuid.toLowerCase(Locale.ROOT);
        String formatted = normalized.replaceFirst(
                "([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{12})",
                "$1-$2-$3-$4-$5"
        );

        try {
            return UUID.fromString(formatted);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }
}
