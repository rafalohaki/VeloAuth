package net.rafalohaki.veloauth.i18n;

import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.junit.jupiter.api.Test;

import java.util.Locale;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Client-language detection (issues #50/#52): the player's Minecraft locale picks the
 * message language when a translation exists, with fallback to the configured default
 * language and then to English per missing key. Runs without Mockito (legacy JAR mode).
 */
class MessagesClientLocaleTest {

    private static final PlainTextComponentSerializer PLAIN = PlainTextComponentSerializer.plainText();

    @Test
    void resolvePlayerLanguage_mapsExactVariantsFirst() {
        Messages messages = new Messages();
        messages.setLanguage("en");

        assertEquals("pt_br", messages.resolvePlayerLanguage(Locale.forLanguageTag("pt-BR")));
        assertEquals("zh_cn", messages.resolvePlayerLanguage(Locale.forLanguageTag("zh-CN")));
        assertEquals("zh_hk", messages.resolvePlayerLanguage(Locale.forLanguageTag("zh-HK")));
    }

    @Test
    void resolvePlayerLanguage_fallsBackFromCountryVariantToLanguage() {
        Messages messages = new Messages();
        messages.setLanguage("en");

        assertEquals("pl", messages.resolvePlayerLanguage(Locale.forLanguageTag("pl-PL")));
        assertEquals("de", messages.resolvePlayerLanguage(Locale.forLanguageTag("de-AT")));
    }

    @Test
    void resolvePlayerLanguage_unsupportedOrNullFallsBackToConfiguredDefault() {
        Messages messages = new Messages();
        messages.setLanguage("pl");

        assertEquals("pl", messages.resolvePlayerLanguage(Locale.forLanguageTag("sw-KE")),
                "Unsupported client locale must use the configured default, not hardcoded English");
        assertEquals("pl", messages.resolvePlayerLanguage(null));
    }

    @Test
    void componentForLocale_polishClientGetsPolishMessage() {
        Messages messages = new Messages();
        messages.setLanguage("en");

        String rendered = PLAIN.serialize(messages.componentForLocale(
                Locale.forLanguageTag("pl-PL"), "auth.account_exists", NamedTextColor.GREEN));

        assertEquals("Twoje konto już istnieje! Użyj /login <hasło>", rendered);
    }

    @Test
    void componentForLocale_unsupportedLocaleGetsConfiguredDefault() {
        Messages messages = new Messages();
        messages.setLanguage("en");

        String rendered = PLAIN.serialize(messages.componentForLocale(
                Locale.forLanguageTag("sw-KE"), "auth.account_exists", NamedTextColor.GREEN));

        assertEquals("Your account already exists! Use /login <password>", rendered);
    }

    @Test
    void componentForLocale_nullLocaleMatchesGlobalComponent() {
        Messages messages = new Messages();
        messages.setLanguage("en");

        String global = PLAIN.serialize(messages.component("auth.first_time", NamedTextColor.AQUA));
        String perPlayer = PLAIN.serialize(messages.componentForLocale(
                null, "auth.first_time", NamedTextColor.AQUA));

        assertEquals(global, perPlayer);
    }
}
