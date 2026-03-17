package net.rafalohaki.veloauth.i18n;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link Messages} covering language selection, fallbacks and formatting.
 */
class MessagesTest {

    private Messages messages;

    @BeforeEach
    void setUp() {
        messages = new Messages();
    }

    @Test
    void setLanguage_nullValue_fallsBackToEnglish() {
        messages.setLanguage(null);

        assertEquals("en", messages.getCurrentLanguage());
    }

    @Test
    void setLanguage_unsupportedLanguage_fallsBackToEnglish() {
        messages.setLanguage("xx");

        assertEquals("en", messages.getCurrentLanguage());
    }

    @Test
    void setLanguage_supportedLanguage_loadsMessages() {
        messages.setLanguage("pl");

        assertEquals("pl", messages.getCurrentLanguage());
        assertEquals("Gracz {} nie istnieje w bazie danych", messages.get("player.not_found"));
    }

    @Test
    void get_missingKey_returnsKeyItself() {
        String key = "non.existing.key";

        String result = messages.get(key);

        assertEquals(key, result);
    }

    @Test
    void get_withArguments_formatsMessage() {
        messages.setLanguage("en");

        String message = messages.get("admin.stats.premium_accounts", 5);

        assertEquals("Premium accounts: 5", message);
    }

    @Test
    void isLanguageSupported_recognizesSupportedLanguages() {
        // Built-in languages from JAR resources (legacy mode)
        assertTrue(messages.isLanguageSupported("en"));
        assertTrue(messages.isLanguageSupported("pl"));
        assertTrue(messages.isLanguageSupported("fr"));
        assertTrue(messages.isLanguageSupported("ja"));
        assertTrue(messages.isLanguageSupported("zh_cn"));
        // Custom languages not available in legacy mode
        assertFalse(messages.isLanguageSupported("xx"));
    }

    @Test
    void getSupportedLanguages_returnsConsistentList() {
        // Only built-in languages - custom languages can still be added by users
        assertArrayEquals(BuiltInLanguages.codes(), messages.getSupportedLanguages());
    }
}
