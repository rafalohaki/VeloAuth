package net.rafalohaki.veloauth.premium;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Minimal helper for performing HTTP GET calls and extracting simple JSON string fields.
 * Keeps resolver code focused on business logic without introducing extra dependencies.
 */
final class HttpJsonClient {

    private HttpJsonClient() {
        // Utility class
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
        String token = '"' + field + '"';
        int idx = body.indexOf(token);
        if (idx == -1) {
            return null;
        }
        int colon = body.indexOf(':', idx + token.length());
        if (colon == -1) {
            return null;
        }
        int quoteStart = body.indexOf('"', colon + 1);
        int quoteEnd = body.indexOf('"', quoteStart + 1);
        if (quoteStart == -1 || quoteEnd == -1) {
            return null;
        }
        return body.substring(quoteStart + 1, quoteEnd);
    }

    private static String readBody(HttpURLConnection connection) throws IOException {
        try (InputStream input = connection.getInputStream()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    record HttpJsonResponse(int statusCode, String body) {
    }
}
