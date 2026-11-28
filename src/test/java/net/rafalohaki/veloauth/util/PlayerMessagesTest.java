package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.Test;

import java.util.Locale;

import static net.rafalohaki.veloauth.util.PlayerMessages.playerMessage;
import static net.rafalohaki.veloauth.util.PlayerMessages.playerText;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Contract for the player-facing message helpers: detection enabled follows the client locale,
 * detection disabled ignores it, and unavailable locale falls back to the configured language.
 */
class PlayerMessagesTest {

    private static final PlainTextComponentSerializer PLAIN = PlainTextComponentSerializer.plainText();
    private static final String POLISH_ACCOUNT_EXISTS =
            "Twoje konto już istnieje! Użyj /login <hasło>";

    @Test
    void playerMessage_detectionEnabled_usesClientLocale() {
        Messages messages = new Messages();
        messages.setLanguage("en");
        Settings settings = mock(Settings.class);
        when(settings.isDetectClientLanguage()).thenReturn(true);
        Player player = mock(Player.class);
        when(player.getEffectiveLocale()).thenReturn(Locale.forLanguageTag("pl-PL"));

        String rendered = PLAIN.serialize(playerMessage(
                player, settings, messages, "auth.account_exists", NamedTextColor.GREEN));

        assertEquals(POLISH_ACCOUNT_EXISTS, rendered);
    }

    @Test
    void playerMessage_detectionDisabled_usesConfiguredLanguage() {
        Messages messages = new Messages();
        messages.setLanguage("pl");
        Settings settings = mock(Settings.class);
        when(settings.isDetectClientLanguage()).thenReturn(false);
        Player player = mock(Player.class);
        when(player.getEffectiveLocale()).thenReturn(Locale.ENGLISH);

        String rendered = PLAIN.serialize(playerMessage(
                player, settings, messages, "auth.account_exists", NamedTextColor.GREEN));

        assertEquals(POLISH_ACCOUNT_EXISTS, rendered);
    }

    @Test
    void playerMessage_missingClientLocale_usesConfiguredLanguage() {
        Messages messages = new Messages();
        messages.setLanguage("pl");
        Settings settings = mock(Settings.class);
        when(settings.isDetectClientLanguage()).thenReturn(true);
        Player player = mock(Player.class);
        when(player.getEffectiveLocale()).thenReturn(null);

        String rendered = PLAIN.serialize(playerMessage(
                player, settings, messages, "auth.account_exists", NamedTextColor.GREEN));

        assertEquals(POLISH_ACCOUNT_EXISTS, rendered);
    }

    @Test
    void playerText_usesSameLocaleResolutionAsPlayerMessage() {
        Messages messages = new Messages();
        messages.setLanguage("en");
        Settings settings = mock(Settings.class);
        when(settings.isDetectClientLanguage()).thenReturn(true);
        Player player = mock(Player.class);
        when(player.getEffectiveLocale()).thenReturn(Locale.forLanguageTag("pl-PL"));

        assertEquals(POLISH_ACCOUNT_EXISTS, playerText(
                player, settings, messages, "auth.account_exists"));
    }
}
