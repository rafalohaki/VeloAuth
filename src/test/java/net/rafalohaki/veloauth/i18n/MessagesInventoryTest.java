package net.rafalohaki.veloauth.i18n;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Generates the language inventory contract from the canonical English resource.
 * No manually curated Java key list is allowed: source usage is checked separately by
 * {@link MessagesSourceScanTest}, while every bundled locale must exactly match English.
 */
class MessagesInventoryTest {

    private static final Set<String> DEPRECATED_KEYS = Set.of(
            "auth.register.password_too_short",
            "error.connection.generic"
    );

    private static Stream<String> builtInLanguages() {
        return Arrays.stream(BuiltInLanguages.codes());
    }

    @Test
    void canonicalEnglishInventory_IsNonEmptyAndContainsNoBlankValues() throws IOException {
        Properties english = loadProperties(BuiltInLanguages.englishCode());

        assertFalse(english.isEmpty(), "Canonical English message inventory must not be empty");
        assertNoBlankValues(BuiltInLanguages.englishCode(), english);
    }

    @ParameterizedTest
    @MethodSource("builtInLanguages")
    void builtInLocale_ExactlyMatchesCanonicalEnglishInventory(String language) throws IOException {
        Properties english = loadProperties(BuiltInLanguages.englishCode());
        Properties locale = loadProperties(language);

        assertEquals(new LinkedHashSet<>(english.stringPropertyNames()),
                new LinkedHashSet<>(locale.stringPropertyNames()),
                "Language key inventory differs from English for " + language);
        assertNoBlankValues(language, locale);
    }

    @ParameterizedTest
    @MethodSource("builtInLanguages")
    void builtInLocale_ContainsNoDeprecatedAliases(String language) throws IOException {
        Properties locale = loadProperties(language);

        for (String deprecatedKey : DEPRECATED_KEYS) {
            assertFalse(locale.containsKey(deprecatedKey),
                    () -> "Deprecated key " + deprecatedKey + " remains in " + language);
        }
    }

    @ParameterizedTest
    @MethodSource("builtInLanguages")
    void messages_LoadsEveryCanonicalKeyForEachBuiltInLocale(String language) throws IOException {
        Properties english = loadProperties(BuiltInLanguages.englishCode());
        Messages messages = new Messages();
        messages.setLanguage(language);

        for (String key : english.stringPropertyNames()) {
            String value = messages.get(key);
            assertFalse(value.equals(key) || value.startsWith("Missing:"),
                    () -> "Messages could not load " + key + " for " + language);
        }
    }

    private static void assertNoBlankValues(String language, Properties properties) {
        Set<String> blankKeys = new LinkedHashSet<>();
        for (String key : properties.stringPropertyNames()) {
            if (properties.getProperty(key).isBlank()) {
                blankKeys.add(key);
            }
        }
        assertTrue(blankKeys.isEmpty(),
                () -> "Blank translations in " + language + ": " + blankKeys);
    }

    private static Properties loadProperties(String language) throws IOException {
        String resource = "/lang/messages_" + language + ".properties";
        Properties properties = new Properties();
        try (InputStream stream = MessagesInventoryTest.class.getResourceAsStream(resource)) {
            assertNotNull(stream, "Language file not found: " + resource);
            try (InputStreamReader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
                properties.load(reader);
            }
        }
        return properties;
    }
}
