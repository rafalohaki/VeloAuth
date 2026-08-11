package net.rafalohaki.veloauth.i18n;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextColor;
import net.kyori.adventure.text.format.TextDecoration;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.junit.jupiter.api.Test;

import java.text.MessageFormat;

import static org.junit.jupiter.api.Assertions.assertEquals;

/** Unit tests for the canonical {@link Messages#component} renderer. */
class MessagesComponentTest {

    @Test
    void component_WithoutColorCodes_AppliesFallbackColor() {
        Messages messages = new StubMessages("Plain text");

        Component component = messages.component("test.key", NamedTextColor.GREEN);

        assertEquals("Plain text", PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(NamedTextColor.GREEN, component.color());
    }

    @Test
    void component_WithLiteralFormattingCharacters_AppliesFallbackColor() {
        Messages messages = new StubMessages("Terms & conditions § paragraph");

        Component component = messages.component("test.key", NamedTextColor.GREEN);

        assertEquals("Terms & conditions § paragraph",
                PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(NamedTextColor.GREEN, component.color());
    }

    @Test
    void component_WithSupportedHexSyntaxes_ParsesEverySyntax() {
        assertHexColor("<#FF6700>X");
        assertHexColor("&#FF6700X");
        assertHexColor("§#FF6700X");
        assertHexColor("§x§F§F§6§7§0§0X");
    }

    @Test
    void component_WithMiniMessageHexColors_ParsesHexGradientAndDecorations() {
        Messages messages = new StubMessages("<#FF6700>&lS<#FF7312>&le<#FF8024>&lc");

        Component component = messages.component("test.key", NamedTextColor.GREEN);

        assertEquals("Sec", PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(TextColor.color(0xFF6700), component.children().get(0).color());
        assertEquals(TextDecoration.State.TRUE,
                component.children().get(0).decoration(TextDecoration.BOLD));
        assertEquals(TextColor.color(0xFF7312), component.children().get(1).color());
        assertEquals(TextColor.color(0xFF8024), component.children().get(2).color());
    }

    @Test
    void component_WithMixedSectionAmpersandAndMiniMessageCodes_PreservesFormatting() {
        Messages messages = new StubMessages("§a<#FF6700>&lText");

        Component component = messages.component("test.key", NamedTextColor.GREEN);

        assertEquals("Text", PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(TextColor.color(0xFF6700), component.color());
        assertEquals(TextDecoration.State.TRUE, component.decoration(TextDecoration.BOLD));
    }

    @Test
    void component_WithFormattedOtpUri_PreservesLiteralAmpersandsInArgument() {
        String otpUri = "otpauth://totp/VeloAuth:Steve?secret=ABC123&issuer=VeloAuth"
                + "&algorithm=SHA1&digits=6&period=30";
        Messages messages = new FormattingStubMessages("§eOTP URI: §f{0}");

        Component component = messages.component("test.key", NamedTextColor.YELLOW, otpUri);

        assertEquals("OTP URI: " + otpUri,
                PlainTextComponentSerializer.plainText().serialize(component));
    }

    @Test
    void component_WithColorLikeFormattedArgument_PreservesLiteralValueAndTemplateColor() {
        String literalValue = "R&D &a <#FF0000> §c";
        Messages messages = new FormattingStubMessages("§fValue: {0}");

        Component component = messages.component("test.key", NamedTextColor.YELLOW, literalValue);

        assertEquals("Value: " + literalValue,
                PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(NamedTextColor.WHITE, component.color());
    }

    private static void assertHexColor(String message) {
        Messages messages = new StubMessages(message);

        Component component = messages.component("test.key", NamedTextColor.GREEN);

        assertEquals("X", PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(TextColor.color(0xFF6700), component.color());
    }

    private static class StubMessages extends Messages {
        private final String value;

        private StubMessages(String value) {
            this.value = value;
        }

        @Override
        public String get(String key, Object... args) {
            return value;
        }
    }

    private static final class FormattingStubMessages extends StubMessages {
        private final String value;

        private FormattingStubMessages(String value) {
            super(value);
            this.value = value;
        }

        @Override
        public String get(String key, Object... args) {
            return MessageFormat.format(value, args);
        }
    }
}
