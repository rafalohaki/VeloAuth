package net.rafalohaki.veloauth.report;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Client for the mclo.gs log paste API ({@code https://api.mclo.gs/1/log}).
 * <p>
 * Posts log content + metadata as JSON and returns the public URL on success.
 * Uses {@link HttpClient} (Java 11+) to match the project's HTTP convention
 * ({@code DiscordWebhookClient}, {@code HttpJsonClient}).
 * All I/O is blocking — callers must run on a virtual thread, never on a Velocity event thread.
 * <p>
 * The mclo.gs API caps content at 10 MiB / 25 000 lines; the caller is responsible for
 * truncating before calling.
 */
final class McLogsClient {

    private static final String API_URL = "https://api.mclo.gs/1/log";
    private static final String SOURCE = "VeloAuth";
    private static final Duration TIMEOUT = Duration.ofSeconds(15);
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
        try (HttpClient client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build()) {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(API_URL))
                    .header("Content-Type", "application/json; charset=UTF-8")
                    .header("User-Agent", "VeloAuth/" + net.rafalohaki.veloauth.BuildConstants.VERSION)
                    .timeout(TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(serializeBody(content, metadata)))
                    .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status < 200 || status >= 300) {
                return UploadResult.fail("HTTP " + status + ": " + response.body());
            }
            return parseResponse(response.body());
        } catch (IOException e) {
            return UploadResult.fail("Network error: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return UploadResult.fail("Upload interrupted");
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
