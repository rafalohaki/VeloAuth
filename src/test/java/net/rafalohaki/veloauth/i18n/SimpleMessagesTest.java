package net.rafalohaki.veloauth.i18n;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextColor;
import net.kyori.adventure.text.format.TextDecoration;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.junit.jupiter.api.Test;

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
        assertEquals(TextColor.color(0xFF6700), component.children().get(0).color());
        assertEquals(TextDecoration.State.TRUE, component.children().get(0).decoration(TextDecoration.BOLD));
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
}
