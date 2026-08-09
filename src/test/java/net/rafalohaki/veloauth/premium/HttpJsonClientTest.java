package net.rafalohaki.veloauth.premium;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HttpJsonClientTest {

    @Test
    void extractStringFieldReturnsValueWhenPresent() {
        String payload = "{\"id\":\"abcdef\",\"name\":\"Steve\"}";

        String value = HttpJsonClient.extractStringField(payload, "name");

        assertEquals("Steve", value);
    }

    @Test
    void extractStringFieldHandlesFieldsWithWhitespace() {
        String payload = "{ \"uuid\" : \"1234\" , \"extra\" : \"value\" }";

        String value = HttpJsonClient.extractStringField(payload, "uuid");

        assertEquals("1234", value);
    }

    @Test
    void extractStringFieldReturnsNullWhenFieldMissing() {
        String payload = "{\"id\":\"abcdef\"}";

        assertNull(HttpJsonClient.extractStringField(payload, "name"));
    }

    @Test
    void extractStringFieldReturnsNullWhenBodyNull() {
        assertNull(HttpJsonClient.extractStringField(null, "id"));
    }

    @Test
    void extractStringFieldConvertsNumericValueToString() {
        String payload = "{\"id\":\"abcdef\",\"name\":123}";

        assertEquals("123", HttpJsonClient.extractStringField(payload, "name"));
    }

    @Test
    void readBody_responseAboveLimitShouldBeRejectedWithoutUnboundedAllocation() {
        byte[] oversized = "x".repeat(64 * 1024 + 1).getBytes(StandardCharsets.UTF_8);

        assertThrows(IOException.class, () -> HttpJsonClient.readBody(
                new ByteArrayInputStream(oversized), -1L));
    }

    @Test
    void readBody_contentLengthAboveLimitShouldBeRejected() {
        byte[] smallBody = "{}".getBytes(StandardCharsets.UTF_8);

        assertThrows(IOException.class, () -> HttpJsonClient.readBody(
                new ByteArrayInputStream(smallBody), 64L * 1024L + 1L));
    }
}
