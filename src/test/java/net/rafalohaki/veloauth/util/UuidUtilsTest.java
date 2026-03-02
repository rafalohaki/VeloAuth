package net.rafalohaki.veloauth.util;

import org.junit.jupiter.api.Test;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class UuidUtilsTest {

    @Test
    void testParseUuidSafely_ValidUuid() {
        String uuidStr = "550e8400-e29b-41d4-a716-446655440000";
        UUID result = UuidUtils.parseUuidSafely(uuidStr);
        assertNotNull(result);
        assertEquals(UUID.fromString(uuidStr), result);
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
    void testParseUuidSafely_InvalidFormat() {
        UUID result = UuidUtils.parseUuidSafely("invalid-uuid-format");
        assertNull(result);
    }

    @Test
    void testIsValidUuid_ValidUuid() {
        String uuidStr = "550e8400-e29b-41d4-a716-446655440000";
        assertTrue(UuidUtils.isValidUuid(uuidStr));
    }

    @Test
    void testIsValidUuid_NullInput() {
        assertFalse(UuidUtils.isValidUuid(null));
    }

    @Test
    void testIsValidUuid_EmptyInput() {
        assertFalse(UuidUtils.isValidUuid(""));
    }

    @Test
    void testIsValidUuid_InvalidFormat() {
        assertFalse(UuidUtils.isValidUuid("not-a-uuid"));
    }
}
