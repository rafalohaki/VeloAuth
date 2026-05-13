package net.rafalohaki.veloauth.i18n;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ResourceBundle;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for LanguageFileManager - external language file management.
 */
class LanguageFileManagerTest {

    @TempDir
    Path tempDir;

    private LanguageFileManager languageFileManager;

    @BeforeEach
    void setUp() {
        languageFileManager = new LanguageFileManager(tempDir);
    }

    @AfterEach
    void tearDown() {
        // Cleanup is handled by @TempDir
    }

    @Test
    void testInitializeLanguageFiles_CreatesDirectory() throws IOException {
        // When
        languageFileManager.initializeLanguageFiles();

        // Then
        Path langDir = tempDir.resolve("lang");
        assertTrue(Files.exists(langDir), "Language directory should be created");
        assertTrue(Files.isDirectory(langDir), "Language directory should be a directory");
    }

    @Test
    void testInitializeLanguageFiles_CopiesDefaultFiles() throws IOException {
        // When
        languageFileManager.initializeLanguageFiles();

        // Then
        Path langDir = tempDir.resolve("lang");
        assertTrue(Files.exists(langDir.resolve("messages_en.properties")), 
                "English language file should be copied");
        assertTrue(Files.exists(langDir.resolve("messages_pl.properties")), 
                "Polish language file should be copied");
    }

    @Test
    void testInitializeLanguageFiles_DoesNotOverwriteExisting() throws IOException {
        // Given
        languageFileManager.initializeLanguageFiles();
        Path enFile = tempDir.resolve("lang/messages_en.properties");
        String originalContent = Files.readString(enFile);

        // When - initialize again
        languageFileManager.initializeLanguageFiles();

        // Then
        String newContent = Files.readString(enFile);
        assertEquals(originalContent, newContent, "Existing files should not be overwritten");
    }

    @ParameterizedTest
    @ValueSource(strings = {"en", "pl", "de"})
    void testLoadLanguageBundle_LoadsLanguageOrFallsBack(String language) throws IOException {
        // Given
        languageFileManager.initializeLanguageFiles();

        // When
        ResourceBundle bundle = languageFileManager.loadLanguageBundle(language);

        // Then
        assertNotNull(bundle, "Bundle should not be null for language: " + language);
        assertTrue(bundle.keySet().size() > 0, "Bundle should contain keys for language: " + language);
    }

    @Test
    void testLoadLanguageBundle_ThrowsExceptionWhenNoFiles() {
        // When/Then - no files initialized
        assertThrows(IOException.class, () -> {
            languageFileManager.loadLanguageBundle("en");
        }, "Should throw IOException when no language files exist");
    }

    // ===== fileExists: pure query, does not mutate the filesystem =====

    @Test
    void fileExists_languageWithoutFile_returnsFalseAndDoesNotCreate() throws IOException {
        languageFileManager.initializeLanguageFiles();
        Path langDir = tempDir.resolve("lang");
        Path bogus = langDir.resolve("messages_pll.properties");

        boolean exists = languageFileManager.fileExists("pll");

        assertEquals(false, exists);
        assertEquals(false, Files.exists(bogus),
                "fileExists must be a pure query — no file should be created");
    }

    @Test
    void fileExists_languageWithFile_returnsTrue() throws IOException {
        languageFileManager.initializeLanguageFiles();
        assertTrue(languageFileManager.fileExists("en"));
        assertTrue(languageFileManager.fileExists("pl"));
    }

    @Test
    void fileExists_nullOrBlank_returnsFalse() {
        assertEquals(false, languageFileManager.fileExists(null));
        assertEquals(false, languageFileManager.fileExists(""));
        assertEquals(false, languageFileManager.fileExists("   "));
    }

    @Test
    void fileExists_invalidLanguageCode_returnsFalseWithoutThrowing() throws IOException {
        languageFileManager.initializeLanguageFiles();
        // Path traversal attempts must not pass validateLanguageCode
        assertEquals(false, languageFileManager.fileExists("../etc/passwd"));
        assertEquals(false, languageFileManager.fileExists("en/../pl"));
    }

    // ===== escapePropertyValue / escapePropertyKey =====

    @Test
    void escapePropertyValue_backslashAndControlChars_escapedPerSpec() {
        assertEquals("a\\\\b", LanguageFileManager.escapePropertyValue("a\\b"));
        assertEquals("line1\\nline2", LanguageFileManager.escapePropertyValue("line1\nline2"));
        assertEquals("col\\tval", LanguageFileManager.escapePropertyValue("col\tval"));
        assertEquals("\\r\\n", LanguageFileManager.escapePropertyValue("\r\n"));
    }

    @Test
    void escapePropertyValue_leadingSpace_escaped() {
        // Leading space in a value would be silently swallowed by Properties.load
        assertEquals("\\ leading", LanguageFileManager.escapePropertyValue(" leading"));
        // Internal spaces left untouched
        assertEquals("a b c", LanguageFileManager.escapePropertyValue("a b c"));
    }

    @Test
    void escapePropertyValue_specialCharsInValueAreSafe() {
        // =, :, #, ! in VALUE position are not separators and need no escaping
        assertEquals("a=b:c#d!e", LanguageFileManager.escapePropertyValue("a=b:c#d!e"));
    }

    @Test
    void escapePropertyValue_null_returnsEmpty() {
        assertEquals("", LanguageFileManager.escapePropertyValue(null));
    }

    @Test
    void escapePropertyKey_separatorCharsEscaped() {
        assertEquals("a\\=b", LanguageFileManager.escapePropertyKey("a=b"));
        assertEquals("a\\:b", LanguageFileManager.escapePropertyKey("a:b"));
        assertEquals("\\#hash", LanguageFileManager.escapePropertyKey("#hash"));
        assertEquals("\\!bang", LanguageFileManager.escapePropertyKey("!bang"));
        assertEquals("a\\ b", LanguageFileManager.escapePropertyKey("a b"));
    }

    @Test
    void escapeRoundTrip_writeThenReadThroughProperties() throws IOException {
        String trickyValue = "leading\\ tab\there\nnewline\r=equals#hash!bang";
        String escaped = LanguageFileManager.escapePropertyValue(trickyValue);

        // Round-trip via real Properties.load to prove escape output is spec-compliant
        Path file = tempDir.resolve("roundtrip.properties");
        Files.writeString(file, "k=" + escaped + "\n");

        java.util.Properties props = new java.util.Properties();
        try (var r = Files.newBufferedReader(file)) {
            props.load(r);
        }
        assertEquals(trickyValue, props.getProperty("k"),
                "Escape output must round-trip cleanly through Properties.load");
    }
}
