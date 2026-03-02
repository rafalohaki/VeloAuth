package net.rafalohaki.veloauth.util;

import org.junit.jupiter.api.Test;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class UuidUtilsTest {

    @Test
    void testParseUuidSafely_ValidUuid() {
        String validUuidString = "123e4567-e89b-12d3-a456-426614174000";
        UUID result = UuidUtils.parseUuidSafely(validUuidString);
        assertNotNull(result);
        assertEquals(UUID.fromString(validUuidString), result);
    }

    @Test
    void testParseUuidSafely_InvalidUuid() {
        String invalidUuidString = "invalid-uuid-string";
        UUID result = UuidUtils.parseUuidSafely(invalidUuidString);
        assertNull(result);
    }

    @Test
    void testParseUuidSafely_NullInput() {
        UUID result = UuidUtils.parseUuidSafely(null);
        assertNull(result);
    }

    @Test
    void testParseUuidSafely_EmptyInput() {
        UUID result = UuidUtils.parseUuidSafely("");
        assertNull(result);
    }

    @Test
    void testIsValidUuid_ValidUuid() {
        String validUuidString = "123e4567-e89b-12d3-a456-426614174000";
        assertTrue(UuidUtils.isValidUuid(validUuidString));
    }

    @Test
    void testIsValidUuid_InvalidUuid() {
        String invalidUuidString = "invalid-uuid-string";
        assertFalse(UuidUtils.isValidUuid(invalidUuidString));
    }

    @Test
    void testIsValidUuid_NullInput() {
        assertFalse(UuidUtils.isValidUuid(null));
    }

    @Test
    void testIsValidUuid_EmptyInput() {
        assertFalse(UuidUtils.isValidUuid(""));
    }
}
