package net.rafalohaki.veloauth.premium;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * HTTP GET client with proxy-provided Gson field extraction for premium resolver APIs.
 */
final class HttpJsonClient {

    private static final int MAX_RESPONSE_BYTES = 64 * 1024;

    private HttpJsonClient() {
    }

    @SuppressWarnings("java:S5144") // Safe: URL constructed from trusted internal endpoint enum and encoded username
    static HttpJsonResponse get(String endpoint, String username, int timeoutMs) throws IOException {
        // Encode username to prevent URL injection attacks
        String encodedUsername = URLEncoder.encode(username, StandardCharsets.UTF_8);
        URL url = URI.create(endpoint + encodedUsername).toURL();
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setInstanceFollowRedirects(false);
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
            JsonElement document = JsonParser.parseString(body);
            if (!document.isJsonObject()) {
                return null;
            }
            JsonObject object = document.getAsJsonObject();
            JsonElement value = object.get(field);
            if (value == null || value.isJsonNull() || !value.isJsonPrimitive()) {
                return null;
            }
            return value.getAsString();
        } catch (JsonParseException | IllegalStateException | UnsupportedOperationException e) {
            return null;
        }
    }

    private static String readBody(HttpURLConnection connection) throws IOException {
        try (InputStream input = connection.getInputStream()) {
            return readBody(input, connection.getContentLengthLong());
        }
    }

    static String readBody(InputStream input, long contentLength) throws IOException {
        if (contentLength > MAX_RESPONSE_BYTES) {
            throw new IOException("Premium resolver response exceeds maximum size");
        }
        byte[] bytes = input.readNBytes(MAX_RESPONSE_BYTES + 1);
        if (bytes.length > MAX_RESPONSE_BYTES) {
            throw new IOException("Premium resolver response exceeds maximum size");
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    record HttpJsonResponse(int statusCode, String body) {
    }
}
