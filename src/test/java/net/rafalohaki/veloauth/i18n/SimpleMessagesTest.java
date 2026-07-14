package net.rafalohaki.veloauth.i18n;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextColor;
import net.kyori.adventure.text.format.TextDecoration;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.junit.jupiter.api.Test;

import java.text.MessageFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Unit tests for {@link SimpleMessages} color-code parsing.
 */
class SimpleMessagesTest {

    @Test
    void key_withoutColorCodes_appliesFallbackColor() {
        SimpleMessages simpleMessages = new SimpleMessages(new StubMessages("Plain text"));

        Component component = simpleMessages.key("test.key", NamedTextColor.GREEN);

        assertEquals("Plain text", PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(NamedTextColor.GREEN, component.color());
    }

    @Test
    void key_withLiteralFormattingCharacters_appliesFallbackColor() {
        SimpleMessages simpleMessages = new SimpleMessages(new StubMessages("Terms & conditions § paragraph"));

        Component component = simpleMessages.key("test.key", NamedTextColor.GREEN);

        assertEquals("Terms & conditions § paragraph",
                PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(NamedTextColor.GREEN, component.color());
    }

    @Test
    void key_withSupportedHexSyntaxes_parsesEverySyntax() {
        assertHexColor("<#FF6700>X");
        assertHexColor("&#FF6700X");
        assertHexColor("§#FF6700X");
        assertHexColor("§x§F§F§6§7§0§0X");
    }

    @Test
    void key_withMiniMessageHexColors_parsesHexGradientAndDecorations() {
        SimpleMessages simpleMessages = new SimpleMessages(new StubMessages(
                "<#FF6700>&lS<#FF7312>&le<#FF8024>&lc"));

        Component component = simpleMessages.key("test.key", NamedTextColor.GREEN);

        assertEquals("Sec", PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(TextColor.color(0xFF6700), component.children().get(0).color());
        assertEquals(TextDecoration.State.TRUE, component.children().get(0).decoration(TextDecoration.BOLD));
        assertEquals(TextColor.color(0xFF7312), component.children().get(1).color());
        assertEquals(TextColor.color(0xFF8024), component.children().get(2).color());
    }

    @Test
    void key_withMixedSectionAmpersandAndMiniMessageCodes_preservesFormatting() {
        SimpleMessages simpleMessages = new SimpleMessages(new StubMessages(
                "§a<#FF6700>&lText"));

        Component component = simpleMessages.key("test.key", NamedTextColor.GREEN);

        assertEquals("Text", PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(TextColor.color(0xFF6700), component.color());
        assertEquals(TextDecoration.State.TRUE, component.decoration(TextDecoration.BOLD));
    }

    @Test
    void key_withFormattedOtpUri_preservesLiteralAmpersandsInArgument() {
        String otpUri = "otpauth://totp/VeloAuth:Steve?secret=ABC123&issuer=VeloAuth"
                + "&algorithm=SHA1&digits=6&period=30";
        SimpleMessages simpleMessages = new SimpleMessages(
                new FormattingStubMessages("§eOTP URI: §f{0}"));

        Component component = simpleMessages.key("test.key", NamedTextColor.YELLOW, otpUri);

        assertEquals("OTP URI: " + otpUri,
                PlainTextComponentSerializer.plainText().serialize(component));
    }

    @Test
    void key_withColorLikeFormattedArgument_preservesLiteralValueAndTemplateColor() {
        String literalValue = "R&D &a <#FF0000> §c";
        SimpleMessages simpleMessages = new SimpleMessages(
                new FormattingStubMessages("§fValue: {0}"));

        Component component = simpleMessages.key("test.key", NamedTextColor.YELLOW, literalValue);

        assertEquals("Value: " + literalValue,
                PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(NamedTextColor.WHITE, component.color());
    }

    private static void assertHexColor(String message) {
        SimpleMessages simpleMessages = new SimpleMessages(new StubMessages(message));

        Component component = simpleMessages.key("test.key", NamedTextColor.GREEN);

        assertEquals("X", PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(TextColor.color(0xFF6700), component.color());
    }

    private static final class StubMessages extends Messages {
        private final String value;

        private StubMessages(String value) {
            this.value = value;
        }

        @Override
        public String get(String key, Object... args) {
            return value;
        }
    }

    private static final class FormattingStubMessages extends Messages {
        private final String value;

        private FormattingStubMessages(String value) {
            this.value = value;
        }

        @Override
        public String get(String key, Object... args) {
            return MessageFormat.format(value, args);
        }
    }
}
