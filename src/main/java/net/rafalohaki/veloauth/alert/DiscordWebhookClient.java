package net.rafalohaki.veloauth.alert;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Discord webhook client for sending alerts.
 * Thread-safe implementation using Java 11 HttpClient.
 */
public class DiscordWebhookClient {

    private static final Logger logger = LoggerFactory.getLogger(DiscordWebhookClient.class);
    private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
    private static final int MAX_CONTENT_LENGTH = 2000; // Discord limit
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(5);

    private final String webhookUrl;
    private final HttpClient httpClient;

    /**
     * Creates Discord webhook client.
     *
     * @param webhookUrl Discord webhook URL
     * @throws IllegalArgumentException if webhook URL format is invalid
     */
    public DiscordWebhookClient(String webhookUrl) {
        this.webhookUrl = Objects.requireNonNull(webhookUrl, "webhookUrl");
        
        // SECURITY: Validate webhook URL format without logging sensitive data
        if (!isValidDiscordWebhookUrl(webhookUrl)) {
            throw new IllegalArgumentException("Invalid Discord webhook URL format (must start with https://discord.com/api/webhooks/ or https://discordapp.com/api/webhooks/)");
        }
        
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(REQUEST_TIMEOUT)
                .build();
        
        if (logger.isDebugEnabled()) {
            logger.debug("Discord webhook client initialized (webhook: {})", maskWebhookUrl());
        }
    }
    
    /**
     * Validates Discord webhook URL format.
     *
     * @param url Webhook URL to validate
     * @return true if valid Discord webhook URL
     */
    private static boolean isValidDiscordWebhookUrl(String url) {
        return url.startsWith("https://discord.com/api/webhooks/") ||
               url.startsWith("https://discordapp.com/api/webhooks/");
    }
    
    /**
     * Masks webhook URL for safe logging (shows only last 8 characters).
     * Example: https://discord.com/api/webhooks/[MASKED]/[MASKED]/[TOKEN_TAIL]
     *
     * @return Masked webhook URL safe for logging
     */
    private String maskWebhookUrl() {
        if (webhookUrl == null || webhookUrl.length() < 50) {
            return "***MASKED***";
        }
        // Show only last 8 chars for debugging purposes
        return "https://discord.com/api/webhooks/***/***/***" + 
               webhookUrl.substring(webhookUrl.length() - 8);
    }

    /**
     * Sends a simple text message to Discord.
     *
     * @param content Message content (max 2000 chars)
     * @return true if sent successfully
     */
    public boolean sendMessage(String content) {
        if (content == null || content.isBlank()) {
            logger.warn("Discord webhook: empty content, skipping");
            return false;
        }

        // Truncate if too long
        String truncated = content.length() > MAX_CONTENT_LENGTH
                ? content.substring(0, MAX_CONTENT_LENGTH - 3) + "..."
                : content;

        Map<String, Object> payload = Map.of("content", truncated);
        return sendPayload(payload);
    }

    /**
     * Sends an embed message to Discord (rich formatting).
     *
     * @param embed Embed data
     * @return true if sent successfully
     */
    public boolean sendEmbed(DiscordEmbed embed) {
        Objects.requireNonNull(embed, "embed");

        Map<String, Object> payload = Map.of("embeds", List.of(embed.toMap()));
        return sendPayload(payload);
    }

    /**
     * Sends payload to Discord webhook.
     *
     * @param payload JSON payload as Map
     * @return true if sent successfully
     */
    private boolean sendPayload(Map<String, Object> payload) {
        try {
            String jsonBody = JSON_MAPPER.writeValueAsString(payload);

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(webhookUrl))
                    .header("Content-Type", "application/json")
                    .timeout(REQUEST_TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 204 || response.statusCode() == 200) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Discord webhook sent successfully (webhook: {})", maskWebhookUrl());
                }
                return true;
            }
            
            // SECURITY: Handle rate limiting (Discord limit: 30 requests/minute)
            if (response.statusCode() == 429) {
                String retryAfter = response.headers().firstValue("Retry-After").orElse("unknown");
                logger.warn("Discord webhook rate limited, retry after: {} seconds (webhook: {})", 
                        retryAfter, maskWebhookUrl());
                return false;
            }

            // SECURITY: Don't log response body (may contain sensitive data)
            logger.warn("Discord webhook failed: HTTP {} (webhook: {})", 
                    response.statusCode(), maskWebhookUrl());
            return false;

        } catch (IOException e) {
            logger.warn("Discord webhook IO error: {} (webhook: {})", 
                    e.getMessage(), maskWebhookUrl());
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("Discord webhook interrupted: {} (webhook: {})", 
                    e.getMessage(), maskWebhookUrl());
            return false;
        } catch (Exception e) {
            // SECURITY: Don't log exception with webhook URL in message
            logger.error("Discord webhook unexpected error (webhook: {})", maskWebhookUrl(), e);
            return false;
        }
    }

    /**
     * Discord embed (rich message format).
     */
    public static class DiscordEmbed {
        private String title;
        private String description;
        private Integer color;
        private List<EmbedField> fields;
        private String timestamp;

        public DiscordEmbed title(String title) {
            this.title = title;
            return this;
        }

        public DiscordEmbed description(String description) {
            this.description = description;
            return this;
        }

        public DiscordEmbed color(int color) {
            this.color = color;
            return this;
        }

        public DiscordEmbed fields(List<EmbedField> fields) {
            this.fields = fields;
            return this;
        }

        public DiscordEmbed timestamp(String timestamp) {
            this.timestamp = timestamp;
            return this;
        }

        Map<String, Object> toMap() {
            Map<String, Object> map = new java.util.HashMap<>();
            if (title != null) map.put("title", title);
            if (description != null) map.put("description", description);
            if (color != null) map.put("color", color);
            if (fields != null) map.put("fields", fields.stream().map(EmbedField::toMap).toList());
            if (timestamp != null) map.put("timestamp", timestamp);
            return map;
        }
    }

    /**
     * Discord embed field.
     */
    public static class EmbedField {
        private final String name;
        private final String value;
        private final boolean inline;

        public EmbedField(String name, String value, boolean inline) {
            this.name = name;
            this.value = value;
            this.inline = inline;
        }

        public EmbedField(String name, String value) {
            this(name, value, false);
        }

        Map<String, Object> toMap() {
            return Map.of(
                    "name", name,
                    "value", value,
                    "inline", inline
            );
        }
    }
}
