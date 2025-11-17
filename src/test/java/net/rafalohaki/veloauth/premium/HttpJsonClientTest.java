package net.rafalohaki.veloauth.premium;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

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
    void extractStringFieldReturnsNullWhenFieldIncomplete() {
        String payload = "{\"id\":\"abcdef\",\"name\":123}";

        assertNull(HttpJsonClient.extractStringField(payload, "name"));
    }
}
