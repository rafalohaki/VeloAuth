package net.rafalohaki.veloauth.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Client for the mclo.gs log paste API ({@code https://api.mclo.gs/1/log}).
 * <p>
 * Posts log content + metadata as JSON and returns the public URL on success.
 * All I/O is blocking — callers must run on a virtual thread, never on a Velocity event thread.
 * <p>
 * The mclo.gs API caps content at 10 MiB / 25 000 lines; the caller is responsible for
 * truncating before calling.
 */
final class McLogsClient {

    private static final String API_URL = "https://api.mclo.gs/1/log";
    private static final String SOURCE = "VeloAuth";
    private static final int TIMEOUT_MS = 15_000;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Result of a mclo.gs upload. */
    record UploadResult(boolean success, String url, String error) {
        static UploadResult ok(String url) {
            return new UploadResult(true, url, null);
        }

        static UploadResult fail(String error) {
            return new UploadResult(false, null, error);
        }
    }

    /**
     * Uploads the given content to mclo.gs and returns the public URL.
     *
     * @param content  log / report content (must be &lt;= 10 MiB)
     * @param metadata list of metadata entries (key/value/label/visible); may be empty
     * @return {@link UploadResult} with the URL on success or an error message on failure
     */
    static UploadResult upload(String content, List<MetadataEntry> metadata) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) URI.create(API_URL).toURL().openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            connection.setRequestProperty("User-Agent", "VeloAuth/" + net.rafalohaki.veloauth.BuildConstants.VERSION);
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            connection.setDoOutput(true);
            connection.setUseCaches(false);

            byte[] body = serializeBody(content, metadata);
            try (OutputStream out = connection.getOutputStream()) {
                out.write(body);
            }

            int status = connection.getResponseCode();
            String responseBody;
            try (InputStream input = status >= 200 && status < 300
                    ? connection.getInputStream()
                    : connection.getErrorStream()) {
                responseBody = input == null ? "" : new String(input.readAllBytes(), StandardCharsets.UTF_8);
            }
            if (status < 200 || status >= 300) {
                return UploadResult.fail("HTTP " + status + ": " + responseBody);
            }
            return parseResponse(responseBody);
        } catch (IOException e) {
            return UploadResult.fail("Network error: " + e.getMessage());
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static byte[] serializeBody(String content, List<MetadataEntry> metadata) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("content", content);
        body.put("source", SOURCE);
        if (metadata != null && !metadata.isEmpty()) {
            List<Map<String, Object>> metaList = metadata.stream()
                    .map(MetadataEntry::toMap)
                    .toList();
            body.put("metadata", metaList);
        }
        return MAPPER.writeValueAsBytes(body);
    }

    private static UploadResult parseResponse(String body) {
        try {
            JsonNode root = MAPPER.readTree(body);
            boolean success = root.path("success").asBoolean(false);
            if (!success) {
                String error = root.path("error").asText("Unknown error");
                return UploadResult.fail(error);
            }
            String url = root.path("url").asText(null);
            if (url == null || url.isEmpty()) {
                return UploadResult.fail("Response missing url field");
            }
            return UploadResult.ok(url);
        } catch (IOException e) {
            return UploadResult.fail("Failed to parse response: " + e.getMessage());
        }
    }

    private McLogsClient() {
    }

    /** Metadata entry for the mclo.gs API. */
    record MetadataEntry(String key, Object value, String label, boolean visible) {
        Map<String, Object> toMap() {
            Map<String, Object> map = new LinkedHashMap<>();
            map.put("key", key);
            map.put("value", value);
            if (label != null) {
                map.put("label", label);
            }
            map.put("visible", visible);
            return map;
        }

        static MetadataEntry visible(String key, Object value, String label) {
            return new MetadataEntry(key, value, label, true);
        }

        static MetadataEntry hidden(String key, Object value) {
            return new MetadataEntry(key, value, null, false);
        }
    }
}
