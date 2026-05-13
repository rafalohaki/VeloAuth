package net.rafalohaki.veloauth.i18n;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for Messages class with external language files.
 */
class MessagesExternalFilesTest {

    @TempDir
    Path tempDir;

    private Messages messages;

    @BeforeEach
    void setUp() throws IOException {
        // Messages will initialize language files automatically
        messages = new Messages(tempDir, "en");
    }

    @AfterEach
    void tearDown() {
        // Cleanup is handled by @TempDir
    }

    /**
     * Helper method to assert that a message was successfully loaded.
     * Reduces code duplication in message loading tests.
     */
    private void assertMessageLoaded(String message, String description) {
        assertNotNull(message, description + " should not be null");
        assertFalse(message.isEmpty(), description + " should not be empty");
        assertFalse(message.startsWith("Missing:"), description + " should be found");
    }

    @Test
    void testExternalFiles_LoadsEnglish() {
        // When
        String message = messages.get("auth.login.success");

        // Then
        assertMessageLoaded(message, "English message");
    }

    @Test
    void testExternalFiles_LoadsPolish() throws IOException {
        // Given
        messages = new Messages(tempDir, "pl");

        // When
        String message = messages.get("auth.login.success");

        // Then
        assertMessageLoaded(message, "Polish message");
    }

    @Test
    void testExternalFiles_HandlesMissingKey() {
        // When
        String message = messages.get("non.existing.key");

        // Then
        assertNotNull(message, "Message should not be null");
        assertTrue(message.startsWith("Missing:"), "Should return missing key indicator");
    }

    @Test
    void testExternalFiles_FormatsWithArguments() {
        // When
        String message = messages.get("auth.login.success");

        // Then
        assertNotNull(message, "Message should not be null");
        assertFalse(message.isEmpty(), "Message should not be empty");
    }

    @Test
    void testExternalFiles_ResolvesDeprecatedKeys() {
        assertEquals(messages.get("validation.password.too_short", 8),
                messages.get("auth.register.password_too_short", 8));
        assertEquals(messages.get("connection.error.generic"),
                messages.get("error.connection.generic"));
    }

    @Test
    void testExternalFiles_FormatsQuotedPlaceholdersAndApostrophes() throws IOException {
        messages = new Messages(tempDir, "fr");

        assertEquals("Le serveur auth server 'auth' n'est pas enregistré !",
                messages.get("connection.picolimbo.error", "auth"));

        messages = new Messages(tempDir, "tr");
        assertEquals("✅ Oyuncu Alex başarıyla auth server'ya aktarıldı",
                messages.get("player.transfer.success", "Alex"));
    }

    @Test
    void testReload_ReloadsLanguageFiles() throws IOException {
        // Given
        String originalMessage = messages.get("auth.login.success");

        // When
        messages.reload();
        String reloadedMessage = messages.get("auth.login.success");

        // Then
        assertNotNull(reloadedMessage, "Reloaded message should not be null");
        assertEquals(originalMessage, reloadedMessage, "Message should be the same after reload");
    }

    @Test
    void testSetLanguage_ChangesLanguage() {
        // Given
        String englishMessage = messages.get("auth.login.success");

        // When
        messages.setLanguage("pl");
        String polishMessage = messages.get("auth.login.success");

        // Then
        assertNotNull(englishMessage, "English message should not be null");
        assertNotNull(polishMessage, "Polish message should not be null");
        // Messages might be different or the same depending on translation
        assertFalse(englishMessage.isEmpty(), "English message should not be empty");
        assertFalse(polishMessage.isEmpty(), "Polish message should not be empty");
    }

    @Test
    void testFallbackToEnglish_WhenLanguageNotFound() {
        // When - request non-existent language
        messages.setLanguage("de");
        String message = messages.get("auth.login.success");

        // Then - should fall back to English
        assertNotNull(message, "Message should not be null");
        assertFalse(message.isEmpty(), "Message should not be empty");
        assertFalse(message.startsWith("Missing:"), "Message should be found in fallback");
    }

    /**
     * Regression for the "Missing: key" leak: when the active language file is missing a key
     * (corrupted edit, partial translation, key added between releases without backfill),
     * external mode must per-key fall back to English instead of returning literal
     * {@code "Missing: …"} to the player.
     */
    @Test
    void getFromBundle_keyMissingInActiveLanguage_fallsBackToEnglish() throws IOException {
        // Set up: switch to Polish, then nuke a key from the Polish file on disk.
        messages.setLanguage("pl");
        Path plFile = tempDir.resolve("lang").resolve("messages_pl.properties");
        assertTrue(Files.exists(plFile), "Polish file should be present after setLanguage");

        String original = Files.readString(plFile, StandardCharsets.UTF_8);
        // Remove a known key. auth.login.success exists in every language file.
        String stripped = original.lines()
                .filter(line -> !line.startsWith("auth.login.success="))
                .reduce((a, b) -> a + "\n" + b)
                .orElse("");
        Files.writeString(plFile, stripped, StandardCharsets.UTF_8);
        messages.reload();

        String message = messages.get("auth.login.success");

        assertFalse(message.startsWith("Missing:"),
                "Missing key in active language must fall back to English text, got: " + message);
        assertFalse(message.isEmpty(), "Fallback message must not be empty");
    }

    /**
     * Regression for {@code isLanguageSupported} silently creating a custom-language file
     * when the operator typed the {@code language} setting wrong (e.g. {@code pll}).
     * The method must NOT touch the filesystem.
     */
    @Test
    void isLanguageSupported_typoLanguageCode_returnsFalseAndDoesNotCreateFile() {
        Path langDir = tempDir.resolve("lang");
        Path bogusFile = langDir.resolve("messages_pll.properties");

        boolean supported = messages.isLanguageSupported("pll");

        assertFalse(supported, "Typo 'pll' must NOT be reported as supported");
        assertFalse(Files.exists(bogusFile),
                "isLanguageSupported must not create messages_pll.properties — it is a pure query");
    }

    /**
     * Confirms the upstream effect of fix #2: setLanguage with a typo falls back to English
     * with a warning, no language switch, no file created.
     */
    @Test
    void setLanguage_typoLanguageCode_keepsEnglishAndDoesNotCreateFile() {
        Path bogusFile = tempDir.resolve("lang").resolve("messages_pll.properties");

        messages.setLanguage("pll");

        assertEquals("en", messages.getCurrentLanguage(),
                "Typo language code must fall back to 'en'");
        assertFalse(Files.exists(bogusFile),
                "Typo must not produce a custom messages_pll.properties file");
    }
}
