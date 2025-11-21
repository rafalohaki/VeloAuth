package net.rafalohaki.veloauth.alert;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for DiscordWebhookClient security features.
 */
class DiscordWebhookClientTest {

    @Test
    void shouldAcceptValidDiscordWebhookUrl() {
        // Given: Valid Discord webhook URLs
        String validUrl1 = "https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz";
        String validUrl2 = "https://discordapp.com/api/webhooks/987654321/zyxwvutsrqponmlkjihgfedcba";

        // When/Then: Should create client without exception
        assertDoesNotThrow(() -> new DiscordWebhookClient(validUrl1));
        assertDoesNotThrow(() -> new DiscordWebhookClient(validUrl2));
    }

    @Test
    void shouldRejectInvalidWebhookUrl() {
        // Given: Invalid webhook URLs
        String invalidUrl1 = "http://discord.com/api/webhooks/123/abc"; // HTTP not HTTPS
        String invalidUrl2 = "https://example.com/webhooks/123/abc"; // Wrong domain
        String invalidUrl3 = "https://discord.com/wrong/path/123/abc"; // Wrong path
        String invalidUrl4 = "not-a-url"; // Completely invalid

        // When/Then: Should throw IllegalArgumentException
        assertThrows(IllegalArgumentException.class, 
                () -> new DiscordWebhookClient(invalidUrl1),
                "Should reject HTTP URLs");
        
        assertThrows(IllegalArgumentException.class, 
                () -> new DiscordWebhookClient(invalidUrl2),
                "Should reject non-Discord domains");
        
        assertThrows(IllegalArgumentException.class, 
                () -> new DiscordWebhookClient(invalidUrl3),
                "Should reject invalid webhook paths");
        
        assertThrows(IllegalArgumentException.class, 
                () -> new DiscordWebhookClient(invalidUrl4),
                "Should reject malformed URLs");
    }

    @Test
    void shouldRejectNullWebhookUrl() {
        // When/Then: Should throw NullPointerException
        assertThrows(NullPointerException.class, 
                () -> new DiscordWebhookClient(null),
                "Should reject null webhook URL");
    }

    @Test
    void shouldRejectEmptyWebhookUrl() {
        // Given: Empty webhook URL
        String emptyUrl = "";

        // When/Then: Should throw IllegalArgumentException
        assertThrows(IllegalArgumentException.class, 
                () -> new DiscordWebhookClient(emptyUrl),
                "Should reject empty webhook URL");
    }

    @Test
    void shouldHandleBlankContent() {
        // Given: Valid webhook client
        String validUrl = "https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz";
        DiscordWebhookClient client = new DiscordWebhookClient(validUrl);

        // When: Sending blank content
        boolean result1 = client.sendMessage(null);
        boolean result2 = client.sendMessage("");
        boolean result3 = client.sendMessage("   ");

        // Then: Should return false without making request
        assertFalse(result1, "Should reject null content");
        assertFalse(result2, "Should reject empty content");
        assertFalse(result3, "Should reject blank content");
    }

    @Test
    void shouldTruncateLongContent() {
        // Given: Valid webhook client and very long content
        String validUrl = "https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz";
        DiscordWebhookClient client = new DiscordWebhookClient(validUrl);
        
        String longContent = "A".repeat(3000); // 3000 chars (Discord limit is 2000)

        // When/Then: Should not throw exception (content truncated internally)
        // Note: Will fail to send (invalid webhook), but should handle truncation
        assertDoesNotThrow(() -> client.sendMessage(longContent));
    }

    @Test
    void shouldRejectNullEmbed() {
        // Given: Valid webhook client
        String validUrl = "https://discord.com/api/webhooks/123456789/abcdefghijklmnopqrstuvwxyz";
        DiscordWebhookClient client = new DiscordWebhookClient(validUrl);

        // When/Then: Should throw NullPointerException
        assertThrows(NullPointerException.class, 
                () -> client.sendEmbed(null),
                "Should reject null embed");
    }

    @Test
    void shouldCreateValidEmbed() {
        // Given: Embed with fields
        DiscordWebhookClient.DiscordEmbed embed = new DiscordWebhookClient.DiscordEmbed()
                .title("Test Alert")
                .description("Test description")
                .color(0xFF0000);

        // When: Converting to map
        var map = embed.toMap();

        // Then: Should contain all fields
        assertEquals("Test Alert", map.get("title"));
        assertEquals("Test description", map.get("description"));
        assertEquals(0xFF0000, map.get("color"));
    }

    @Test
    void shouldCreateEmbedField() {
        // Given: Embed field
        DiscordWebhookClient.EmbedField field1 = new DiscordWebhookClient.EmbedField("Name", "Value");
        DiscordWebhookClient.EmbedField field2 = new DiscordWebhookClient.EmbedField("Inline Name", "Inline Value", true);

        // When: Converting to map
        var map1 = field1.toMap();
        var map2 = field2.toMap();

        // Then: Should contain correct values
        assertEquals("Name", map1.get("name"));
        assertEquals("Value", map1.get("value"));
        assertFalse((Boolean) map1.get("inline"));

        assertEquals("Inline Name", map2.get("name"));
        assertEquals("Inline Value", map2.get("value"));
        assertTrue((Boolean) map2.get("inline"));
    }
}
