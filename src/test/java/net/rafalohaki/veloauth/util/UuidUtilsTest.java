package net.rafalohaki.veloauth.util;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Unit tests for {@link UuidUtils}.
 * Covers null input, empty string, invalid format, and valid UUID strings.
 */
class UuidUtilsTest {

    private static final String VALID_UUID_STRING = "550e8400-e29b-41d4-a716-446655440000";
    private static final String INVALID_UUID_STRING = "not-a-valid-uuid";
    private static final String EMPTY_STRING = "";

    // --- parseUuidSafely ---

    @Test
    void parseUuidSafely_nullInput_returnsNull() {
        assertNull(UuidUtils.parseUuidSafely(null));
    }

    @Test
    void parseUuidSafely_emptyString_returnsNull() {
        assertNull(UuidUtils.parseUuidSafely(EMPTY_STRING));
    }

    @Test
    void parseUuidSafely_invalidString_returnsNull() {
        assertNull(UuidUtils.parseUuidSafely(INVALID_UUID_STRING));
    }

    @Test
    void parseUuidSafely_validUuidString_returnsUuid() {
        UUID result = UuidUtils.parseUuidSafely(VALID_UUID_STRING);
        assertNotNull(result);
        assertEquals(UUID.fromString(VALID_UUID_STRING), result);
    }

    // --- additional edge cases ---

    @Test
    void parseUuidSafely_randomUuid_roundtrip() {
        UUID original = UUID.randomUUID();
        UUID parsed = UuidUtils.parseUuidSafely(original.toString());
        assertNotNull(parsed);
        assertEquals(original, parsed);
    }

}
