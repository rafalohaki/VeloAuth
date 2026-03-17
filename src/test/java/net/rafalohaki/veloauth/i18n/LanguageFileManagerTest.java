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
}
