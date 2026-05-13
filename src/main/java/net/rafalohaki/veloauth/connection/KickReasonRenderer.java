package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.ConnectionRequestBuilder;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;

/**
 * Renders Adventure {@link Component} kick reasons into log-friendly strings.
 * <p>
 * The Adventure default {@code Component.toString()} produces verbose dumps of internal
 * state ({@code TextComponentImpl{content=..., style=StyleImpl{...}, children=[...]}})
 * which spam server logs and obscure the actual message. This helper extracts the plain
 * (or legacy color-coded) text payload so logs stay readable.
 * <p>
 * Thread-safe: serializers are immutable singletons.
 */
final class KickReasonRenderer {

    private static final String UNKNOWN_REASON = "unknown";

    private KickReasonRenderer() {}

    /**
     * Renders a kick reason as plain text (no color codes).
     *
     * @param component the kick reason component, may be {@code null}
     * @return readable plain-text reason, never {@code null}
     */
    static String renderPlain(Component component) {
        if (component == null) {
            return UNKNOWN_REASON;
        }
        return PlainTextComponentSerializer.plainText().serialize(component);
    }

    /**
     * Renders a kick reason preserving legacy {@code §}-style color codes.
     *
     * @param component the kick reason component, may be {@code null}
     * @return legacy-serialized reason, never {@code null}
     */
    static String renderLegacy(Component component) {
        if (component == null) {
            return UNKNOWN_REASON;
        }
        return LegacyComponentSerializer.legacySection().serialize(component);
    }

    /**
     * Extracts and renders the reason from a connection request result.
     *
     * @param result the connection result, may be {@code null}
     * @return plain-text reason or {@link #UNKNOWN_REASON} when result/reason missing
     */
    static String renderPlain(ConnectionRequestBuilder.Result result) {
        if (result == null) {
            return UNKNOWN_REASON;
        }
        return result.getReasonComponent().map(KickReasonRenderer::renderPlain).orElse(UNKNOWN_REASON);
    }
}
