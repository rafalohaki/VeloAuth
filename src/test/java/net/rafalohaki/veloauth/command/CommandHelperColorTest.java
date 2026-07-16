package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.TextColor;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class CommandHelperColorTest {

    @Test
    void requireValidPassword_coloredValidationMessage_parsesFormatting() {
        Player player = mock(Player.class);
        Settings settings = mock(Settings.class);
        Messages messages = new Messages() {
            @Override
            public String get(String key, Object... args) {
                if ("validation.password.empty".equals(key)) {
                    return "<#FF6700>Password required";
                }
                return super.get(key, args);
            }
        };

        boolean valid = CommandHelper.requireValidPassword(player, "", settings, messages);

        ArgumentCaptor<Component> componentCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player).sendMessage(componentCaptor.capture());
        Component component = componentCaptor.getValue();
        assertFalse(valid);
        assertEquals("Password required",
                PlainTextComponentSerializer.plainText().serialize(component));
        assertEquals(TextColor.color(0xFF6700), component.color());
    }
}
