package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;

/**
 * Player-facing message resolution honoring client-language detection (issues #50/#52):
 * the player's Minecraft locale when enabled and translated, otherwise the configured
 * default language (with per-key English fallback inside {@link Messages}).
 */
public final class PlayerMessages {

    private PlayerMessages() {
    }

    public static Component playerMessage(@javax.annotation.Nullable Player player,
                                          Settings settings, Messages messages,
                                          String key, NamedTextColor color, Object... args) {
        if (settings.isDetectClientLanguage()) {
            return messages.componentForLocale(PlayerLocaleUtils.clientLocale(player), key, color, args);
        }
        return messages.component(key, color, args);
    }
}
