package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.ConnectionRequestBuilder;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Verifies kick reason rendering produces human-readable log output
 * instead of Adventure's verbose {@code TextComponentImpl{...}} dump.
 */
class KickReasonRendererTest {

    @Test
    void renderPlain_nullComponent_returnsUnknown() {
        assertEquals("unknown", KickReasonRenderer.renderPlain((Component) null));
    }

    @Test
    void renderPlain_nullResult_returnsUnknown() {
        assertEquals("unknown", KickReasonRenderer.renderPlain((ConnectionRequestBuilder.Result) null));
    }

    @Test
    void renderPlain_simpleComponent_returnsContent() {
        Component component = Component.text("You must link your Discord account to play.");
        assertEquals("You must link your Discord account to play.",
                KickReasonRenderer.renderPlain(component));
    }

    @Test
    void renderPlain_styledComponent_stripsStyle() {
        Component component = Component.text("Banned", NamedTextColor.RED);
        String rendered = KickReasonRenderer.renderPlain(component);
        assertEquals("Banned", rendered);
        // Critically: no TextComponentImpl/StyleImpl noise in output
        assertFalse(rendered.contains("StyleImpl"));
        assertFalse(rendered.contains("TextComponentImpl"));
    }

    @Test
    void renderPlain_compositeComponent_concatenatesChildren() {
        Component component = Component.text("You must link your Discord account.")
                .append(Component.text("\n\nAuthorize at "))
                .append(Component.text("https://example.com"));
        String rendered = KickReasonRenderer.renderPlain(component);
        assertEquals("You must link your Discord account.\n\nAuthorize at https://example.com", rendered);
    }

    @Test
    void renderLegacy_styledComponent_keepsColorCodes() {
        Component component = Component.text("Banned", NamedTextColor.RED);
        String rendered = KickReasonRenderer.renderLegacy(component);
        // Legacy serializer emits §c prefix for red
        assertEquals("§cBanned", rendered);
    }

    @Test
    void renderPlain_resultWithReason_returnsReasonText() {
        ConnectionRequestBuilder.Result result = mock(ConnectionRequestBuilder.Result.class);
        when(result.getReasonComponent()).thenReturn(Optional.of(Component.text("Server full")));

        assertEquals("Server full", KickReasonRenderer.renderPlain(result));
    }

    @Test
    void renderPlain_resultWithoutReason_returnsUnknown() {
        ConnectionRequestBuilder.Result result = mock(ConnectionRequestBuilder.Result.class);
        when(result.getReasonComponent()).thenReturn(Optional.empty());

        assertEquals("unknown", KickReasonRenderer.renderPlain(result));
    }
}
