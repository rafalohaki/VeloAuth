package net.rafalohaki.veloauth.premium;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * HTTP GET client with Jackson-based JSON field extraction for premium resolver APIs.
 */
final class HttpJsonClient {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private HttpJsonClient() {
    }

    @SuppressWarnings("java:S5144") // Safe: URL constructed from trusted internal endpoint enum and encoded username
    static HttpJsonResponse get(String endpoint, String username, int timeoutMs) throws IOException {
        // Encode username to prevent URL injection attacks
        String encodedUsername = URLEncoder.encode(username, StandardCharsets.UTF_8);
        URL url = URI.create(endpoint + encodedUsername).toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(timeoutMs);
        connection.setReadTimeout(timeoutMs);
        connection.setUseCaches(false);

        try {
            int status = connection.getResponseCode();
            String body = null;
            if (status == HttpURLConnection.HTTP_OK) {
                body = readBody(connection);
            }
            return new HttpJsonResponse(status, body);
        } finally {
            connection.disconnect();
        }
    }

    static String extractStringField(String body, String field) {
        if (body == null || body.isEmpty()) {
            return null;
        }
        try {
            JsonNode node = MAPPER.readTree(body);
            JsonNode value = node.get(field);
            if (value == null || value.isNull()) {
                return null;
            }
            return value.asText();
        } catch (IOException e) {
            return null;
        }
    }

    private static String readBody(HttpURLConnection connection) throws IOException {
        try (InputStream input = connection.getInputStream()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    record HttpJsonResponse(int statusCode, String body) {
    }
}
