package net.rafalohaki.veloauth.i18n;

import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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

    /**
     * A reload that loads the active bundle but fails on the English fallback must not
     * publish a half-built generation: language, rendered text and the per-locale cache all
     * stay on the previous snapshot.
     */
    @Test
    void failedReload_preservesRenderedOutputAndActiveLocale() throws IOException {
        messages.setLanguage("pl");
        PlainTextComponentSerializer plain = PlainTextComponentSerializer.plainText();
        Locale german = Locale.forLanguageTag("de-DE");
        String activeBefore = messages.get("auth.login.success");
        String playerBefore = plain.serialize(
                messages.componentForLocale(german, "auth.account_exists", NamedTextColor.WHITE));

        Path langDir = tempDir.resolve("lang");
        rewriteProperty(langDir.resolve("messages_pl.properties"),
                "auth.login.success", "CHANGED-ACTIVE");
        rewriteProperty(langDir.resolve("messages_de.properties"),
                "auth.account_exists", "CHANGED-PLAYER");

        // Active bundle (de) and its English fallback are loaded in that order. A directory
        // where the English properties file is expected makes the fallback bundle fail after
        // the active bundle has already loaded.
        Path english = langDir.resolve("messages_en.properties");
        Files.delete(english);
        Files.createDirectories(english);

        assertThrows(IOException.class, () -> messages.reloadWithLanguage("de"),
                "A failed reload must surface the IO failure to the caller");

        assertEquals("pl", messages.getCurrentLanguage(),
                "Failed reload must keep the previously active language");
        assertEquals(activeBefore, messages.get("auth.login.success"),
                "Failed reload must keep the previously active bundle");
        assertEquals(playerBefore, plain.serialize(
                        messages.componentForLocale(german, "auth.account_exists", NamedTextColor.WHITE)),
                "Failed reload must keep the per-locale cache from the previous generation");
    }

    private static void rewriteProperty(Path file, String key, String value) throws IOException {
        String prefix = key + "=";
        StringBuilder rewritten = new StringBuilder();
        boolean replaced = false;
        for (String line : Files.readAllLines(file, StandardCharsets.UTF_8)) {
            if (line.startsWith(prefix)) {
                rewritten.append(prefix).append(value);
                replaced = true;
            } else {
                rewritten.append(line);
            }
            rewritten.append('\n');
        }
        if (!replaced) {
            throw new IOException("Property '" + key + "' not found in " + file);
        }
        Files.writeString(file, rewritten.toString(), StandardCharsets.UTF_8);
    }

    /**
     * Malformed external properties surface from {@code Properties.load} as
     * {@link IllegalArgumentException}; the reload caller handles {@link IOException}, so the
     * failure must be converted without publishing the broken generation.
     */
    @Test
    void reload_malformedActiveTranslation_throwsIOExceptionAndKeepsPublishedGeneration() throws IOException {
        messages.setLanguage("pl");
        String activeBefore = messages.get("auth.login.success");
        Path polish = tempDir.resolve("lang").resolve("messages_pl.properties");
        Files.writeString(polish,
                Files.readString(polish, StandardCharsets.UTF_8) + "malformed=\\uZZZZ\n",
                StandardCharsets.UTF_8);

        assertThrows(IOException.class, messages::reload,
                "Malformed properties must surface as IOException to the reload caller");

        assertEquals("pl", messages.getCurrentLanguage(),
                "Malformed reload must keep the previously active language");
        assertEquals(activeBefore, messages.get("auth.login.success"),
                "Malformed reload must keep the previously active bundle");
    }

    @Test
    void reload_existingLangDir_doesNotRecreateRemovedBuiltInFile() throws IOException {
        Path polish = tempDir.resolve("lang").resolve("messages_pl.properties");
        assertTrue(Files.exists(polish), "Polish template should exist after first-run extraction");
        Files.delete(polish);

        messages.reload();

        assertFalse(Files.exists(polish), "Reload must not regenerate a deliberately removed bundled file");
        assertMessageLoaded(messages.get("auth.login.success"), "English after reload");
    }

    @Test
    void constructingWithExistingEmptyLangDir_loadsFromJarWithoutExtracting() throws IOException {
        Path emptyData = tempDir.resolve("empty");
        Path emptyLang = emptyData.resolve("lang");
        Files.createDirectories(emptyLang);

        Messages fromJar = new Messages(emptyData, "en");

        assertEquals("Logged in successfully!", fromJar.get("auth.login.success"));
        try (var entries = Files.list(emptyLang)) {
            assertEquals(0, entries.count(),
                    "An existing empty lang/ directory must stay empty on startup");
        }
    }

    @Test
    void componentForLocale_removedBuiltInFile_servesBundledTranslationWithoutRecreating() throws IOException {
        Path polish = tempDir.resolve("lang").resolve("messages_pl.properties");
        assertTrue(Files.exists(polish));
        Files.delete(polish);
        messages.reload();

        String rendered = PlainTextComponentSerializer.plainText().serialize(
                messages.componentForLocale(Locale.forLanguageTag("pl-PL"),
                        "auth.account_exists", NamedTextColor.WHITE));

        assertEquals("Twoje konto już istnieje! Użyj /login <hasło>", rendered);
        assertFalse(Files.exists(polish),
                "Player locale loading must serve the removed bundled language from the JAR");
    }

    @Test
    void reload_withoutExternalEnglishFile_usesBundledEnglishFallback() throws IOException {
        Path english = tempDir.resolve("lang").resolve("messages_en.properties");
        assertTrue(Files.exists(english));
        Files.delete(english);

        messages.reload();

        assertEquals("Logged in successfully!", messages.get("auth.login.success"));
        assertFalse(Files.exists(english),
                "Bundled English must be served from the JAR without recreating the deleted file");
    }

    @Test
    void constructingAgain_existingLangDir_doesNotRegenerateRemovedBuiltIns() throws IOException {
        Path german = tempDir.resolve("lang").resolve("messages_de.properties");
        assertTrue(Files.exists(german));
        Files.delete(german);

        Messages restarted = new Messages(tempDir, "en");

        assertFalse(Files.exists(german), "Startup must not regenerate a deliberately removed bundled file");
        assertMessageLoaded(restarted.get("auth.login.success"), "English after restart");
    }

    @Test
    void reloadWithLanguage_unknownCode_fallsBackToEnglishAndCreatesNoFile() throws IOException {
        Path bogus = tempDir.resolve("lang").resolve("messages_pll.properties");

        messages.reloadWithLanguage("pll");

        assertEquals("en", messages.getCurrentLanguage());
        assertEquals("Logged in successfully!", messages.get("auth.login.success"));
        assertFalse(Files.exists(bogus), "Unknown reload language must not create a custom file");
    }

    @Test
    void constructingWithUnknownLanguage_fallsBackToEnglishWithoutWriting() throws IOException {
        Path data = tempDir.resolve("unknown-language");
        Path langDir = data.resolve("lang");
        Files.createDirectories(langDir);

        Messages unknown = new Messages(data, "pll");

        assertEquals("en", unknown.getCurrentLanguage());
        assertEquals("Logged in successfully!", unknown.get("auth.login.success"));
        try (var entries = Files.list(langDir)) {
            assertEquals(0, entries.count(),
                    "Unknown configured language must not generate a custom template");
        }
    }

    @Test
    void componentForLocale_missingPlayerKey_prefersConfiguredLanguageThenEnglish() throws IOException {
        Path scenario = tempDir.resolve("scenario");
        Path langDir = scenario.resolve("lang");
        Files.createDirectories(langDir);
        Path serverFile = langDir.resolve("messages_zz.properties");
        Path playerFile = langDir.resolve("messages_yy.properties");
        Files.writeString(serverFile,
                "auth.login.success=Server login\n"
                        + "auth.account_exists=Server account exists\n",
                StandardCharsets.UTF_8);
        String playerContent = "auth.login.success=Player login\n";
        Files.writeString(playerFile, playerContent, StandardCharsets.UTF_8);

        Messages localized = new Messages(scenario, "zz");
        PlainTextComponentSerializer plain = PlainTextComponentSerializer.plainText();
        Locale playerLocale = Locale.forLanguageTag("yy");

        assertEquals("Player login", plain.serialize(localized.componentForLocale(
                        playerLocale, "auth.login.success", NamedTextColor.WHITE)),
                "Requested translation must win when it has the key");
        assertEquals("Server account exists", plain.serialize(localized.componentForLocale(
                        playerLocale, "auth.account_exists", NamedTextColor.WHITE)),
                "Missing player key must prefer the configured server language over English");
        assertEquals("Server account exists",
                localized.getForLocale(playerLocale, "auth.account_exists"),
                "Raw text resolution must use the same server-language fallback");
        assertEquals("Welcome! Use /register <password> <confirm>",
                localized.getForLocale(playerLocale, "auth.first_time"),
                "Raw text resolution must use the same English fallback");
        assertEquals("Welcome! Use /register <password> <confirm>", plain.serialize(
                        localized.componentForLocale(playerLocale, "auth.first_time", NamedTextColor.WHITE)),
                "A key missing from player and server languages must fall back to English");
        assertEquals(playerContent, Files.readString(playerFile),
                "Lazy player bundle loading must not append English keys to the file");
        assertFalse(Files.exists(langDir.resolve("messages_en.properties")),
                "Bundled English fallback must not be written to disk");
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

    @Test
    void setLanguage_unsupportedAfterAnotherLanguage_servesEnglishAndCreatesNoFile() {
        Path bogusFile = tempDir.resolve("lang").resolve("messages_pll.properties");
        messages.setLanguage("pl");

        messages.setLanguage("pll");

        assertEquals("en", messages.getCurrentLanguage());
        assertEquals("Logged in successfully!", messages.get("auth.login.success"),
                "Unsupported language must reload English instead of keeping the previous bundle");
        assertFalse(Files.exists(bogusFile));
    }
}
