package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.proxy.Player;

import java.util.Locale;

/** Reads the Minecraft client locale reported during the settings handshake. */
public final class PlayerLocaleUtils {

    private PlayerLocaleUtils() {
    }

    /**
     * @return the client's locale, or {@code null} when the player or their settings are
     *         unavailable (early login phase, test doubles, broken implementation)
     */
    @javax.annotation.Nullable
    public static Locale clientLocale(@javax.annotation.Nullable Player player) {
        if (player == null) {
            return null;
        }
        try {
            return player.getEffectiveLocale();
        } catch (RuntimeException e) {
            return null;
        }
    }
}
