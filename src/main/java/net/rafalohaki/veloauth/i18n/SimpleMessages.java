package net.rafalohaki.veloauth.i18n;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;

/**
 * Wrapper for Messages that provides formatted Adventure Components.
 * Supports color codes in messages:
 * - Legacy codes: §c (red), §a (green), §6 (gold), etc.
 * - Ampersand codes: &c (red), &a (green), &6 (gold), etc.
 */
public final class SimpleMessages {
    private final Messages messages;
    
    // Serializer that supports both § and & color codes
    private static final LegacyComponentSerializer SERIALIZER = LegacyComponentSerializer.builder()
            .character('§')
            .hexColors()
            .build();
    
    private static final LegacyComponentSerializer AMPERSAND_SERIALIZER = LegacyComponentSerializer.builder()
            .character('&')
            .hexColors()
            .build();

    public SimpleMessages(Messages messages) {
        this.messages = messages;
    }

    /**
     * Gets a message as Component with color support.
     * If the message contains color codes (§ or &), they will be parsed.
     * Otherwise, the fallback color is applied.
     * 
     * @param key The message key
     * @param fallbackColor Color to use if message has no color codes
     * @param args Format arguments
     * @return Formatted Component
     */
    public Component key(String key, NamedTextColor fallbackColor, Object... args) {
        String text = messages.get(key, args);
        return parseWithColors(text, fallbackColor);
    }
    
    /**
     * Parses text with color codes. If no color codes found, uses fallback color.
     */
    private Component parseWithColors(String text, NamedTextColor fallbackColor) {
        if (text == null || text.isEmpty()) {
            return Component.empty();
        }
        
        // Check if text contains color codes
        boolean hasLegacyCodes = text.contains("§");
        boolean hasAmpersandCodes = text.contains("&");
        
        if (hasLegacyCodes) {
            return SERIALIZER.deserialize(text);
        } else if (hasAmpersandCodes) {
            return AMPERSAND_SERIALIZER.deserialize(text);
        } else {
            // No color codes, use fallback color
            return Component.text(text, fallbackColor);
        }
    }

    public Component loginSuccess() {
        return key("auth.login.success", NamedTextColor.GREEN);
    }

    public Component loginFailed() {
        return key("auth.login.incorrect_password", NamedTextColor.RED);
    }

    public Component registerSuccess() {
        return key("auth.register.success", NamedTextColor.GREEN);
    }

    public Component alreadyLogged() {
        return key("auth.login.already_logged_in", NamedTextColor.YELLOW);
    }

    public Component alreadyRegistered() {
        return key("auth.register.already_registered", NamedTextColor.RED);
    }

    public Component notRegistered() {
        return key("auth.login.not_registered", NamedTextColor.RED);
    }

    public Component incorrectOldPassword() {
        return key("auth.changepassword.incorrect_old_password", NamedTextColor.RED);
    }

    public Component changePasswordSuccess() {
        return key("auth.changepassword.success", NamedTextColor.GREEN);
    }

    public Component errorDatabase() {
        return key("error.database.query", NamedTextColor.RED);
    }

    public Component errorGeneric() {
        return key("error.unknown_command", NamedTextColor.RED);
    }

    public Component bruteforce(int minutes) {
        return key("security.brute_force.blocked", NamedTextColor.YELLOW, minutes);
    }

    public Component passwordShort(int min) {
        return key("auth.register.password_too_short", NamedTextColor.RED, min);
    }

    public Component passwordMismatch() {
        return key("auth.register.passwords_no_match", NamedTextColor.RED);
    }

    public Component usageLogin() {
        return key("auth.login.usage", NamedTextColor.YELLOW);
    }

    public Component usageRegister() {
        return key("auth.register.usage", NamedTextColor.YELLOW);
    }

    public Component usageChangePassword() {
        return key("auth.changepassword.usage", NamedTextColor.YELLOW);
    }

    public Component nickConflict() {
        return key("player.conflict.header", NamedTextColor.YELLOW);
    }

    public Component nickReserved() {
        return key("player.conflict.description", NamedTextColor.YELLOW);
    }

    public Component invalidUsername() {
        return key("validation.username.invalid", NamedTextColor.RED);
    }


    // System messages
    public Component systemStarting() {
        return key("system.starting", NamedTextColor.RED);
    }

    public Component systemInitError() {
        return key("system.init_error", NamedTextColor.RED);
    }

    public Component systemShuttingDown() {
        return key("system.shutting_down", NamedTextColor.YELLOW);
    }

    public Component systemOverloaded() {
        return key("system.overloaded", NamedTextColor.YELLOW);
    }

    // Connection messages
    public Component connectionErrorGeneric() {
        return key("connection.error.generic", NamedTextColor.RED);
    }

    public Component connectionErrorDatabase() {
        return key("connection.error.database", NamedTextColor.RED);
    }

    public Component connectionErrorUuidMismatch() {
        return key("connection.error.uuid_mismatch", NamedTextColor.RED);
    }

    public Component connectionErrorAuthServer() {
        return key("connection.error.auth_server", NamedTextColor.RED);
    }

    public Component connectionErrorAuthConnect() {
        return key("connection.error.auth_connect", NamedTextColor.RED);
    }

    public Component connectionErrorGameServer() {
        return connectionErrorGameServer(messages.get("error.unknown"));
    }

    public Component connectionErrorGameServer(String reason) {
        return key("connection.error.game_server", NamedTextColor.RED, reason);
    }

    public Component connectionErrorNoServers() {
        return key("connection.error.no_servers", NamedTextColor.RED);
    }

    public Component connectionConnecting() {
        return key("connection.connecting", NamedTextColor.YELLOW);
    }

    // Auth messages
    public Component authHeader() {
        return key("auth.header", NamedTextColor.GOLD);
    }

    public Component authPromptGeneric() {
        return key("auth.prompt.generic", NamedTextColor.YELLOW);
    }

    public Component authAccountExists() {
        return key("auth.account_exists", NamedTextColor.GREEN);
    }

    public Component authFirstTime() {
        return key("auth.first_time", NamedTextColor.AQUA);
    }

    public Component authMustLogin() {
        return key("auth.must_login", NamedTextColor.RED);
    }

    public Component authLoggedOut() {
        return key("auth.logged_out", NamedTextColor.YELLOW);
    }

    // Welcome messages
    public Component welcomeFull() {
        return key("general.welcome.full", NamedTextColor.GREEN);
    }

    // Validation messages
    public Component passwordEmpty() {
        return key("validation.password.empty", NamedTextColor.RED);
    }

    public Component passwordTooShort(int min) {
        return key("validation.password.too_short", NamedTextColor.RED, min);
    }

    public Component passwordTooLong(int max) {
        return key("validation.password.too_long", NamedTextColor.RED, max);
    }

    public Component passwordUtf8TooLong(int bytes) {
        return key("validation.password.utf8_too_long", NamedTextColor.RED, bytes);
    }

    public Component passwordMismatchValidation() {
        return key("validation.password.mismatch", NamedTextColor.RED);
    }

    // Admin messages
    public Component adminPlayerNotFound(String player) {
        return key("admin.player_not_found", NamedTextColor.RED, player);
    }

    public Component adminUuidInvalid() {
        return key("admin.uuid_invalid", NamedTextColor.RED);
    }

    public Component adminAccountDeleted(String player) {
        return key("admin.account_deleted", NamedTextColor.GREEN, player);
    }

    public Component adminCommandsUnregistered() {
        return key("admin.commands_unregistered", NamedTextColor.YELLOW);
    }

    public Component adminHelpHeader() {
        return key("admin.help.header", NamedTextColor.YELLOW);
    }

    public Component adminHelpReload() {
        return key("admin.help.reload", NamedTextColor.YELLOW);
    }

    public Component adminHelpCache() {
        return key("admin.help.cache", NamedTextColor.YELLOW);
    }

    public Component adminHelpStats() {
        return key("admin.help.stats", NamedTextColor.YELLOW);
    }

    public Component adminHelpConflicts() {
        return key("admin.help.conflicts", NamedTextColor.YELLOW);
    }

    // Brute force messages
    public Component bruteForceBlocked() {
        return key("security.brute_force.blocked", NamedTextColor.RED);
    }

    // Admin reload messages
    public Component adminReloadSuccess() {
        return key("admin.reload.success", NamedTextColor.GREEN);
    }

    public Component adminReloadFailed() {
        return key("admin.reload.failed", NamedTextColor.RED);
    }

    // Kick messages
    public Component kickMessage() {
        return key("general.kick.message", NamedTextColor.YELLOW);
    }
}
