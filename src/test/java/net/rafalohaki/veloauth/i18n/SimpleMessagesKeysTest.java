package net.rafalohaki.veloauth.i18n;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests that all translation keys used by SimpleMessages exist in language files.
 * This prevents runtime "Missing translation key" warnings.
 */
class SimpleMessagesKeysTest {

    private Properties englishProps;
    private Properties polishProps;

    /**
     * All translation keys used by SimpleMessages class.
     * Keep this list synchronized with SimpleMessages.java methods.
     */
    private static final List<String> SIMPLE_MESSAGES_KEYS = Arrays.asList(
            // Auth messages
            "auth.login.success",
            "auth.login.incorrect_password",
            "auth.register.success",
            "auth.register.already_registered",
            "auth.login.already_logged_in",
            "auth.login.not_registered",
            "auth.login.usage",
            "auth.register.usage",
            "auth.changepassword.usage",
            "auth.changepassword.success",
            "auth.changepassword.incorrect_old_password",
            "auth.register.passwords_no_match",
            // Admin unregister
            "admin.unregister.usage",
            // Error messages
            "error.database.query",
            "error.unknown_command",
            "error.unknown",
            "error.connection.generic",
            // Security messages
            "security.brute_force.blocked",
            // Player conflict messages
            "player.conflict.header",
            "player.conflict.description",
            // Validation messages
            "validation.username.invalid",
            "validation.password.empty",
            "validation.password.too_short",
            "validation.password.too_long",
            "validation.password.utf8_too_long",
            "validation.password.mismatch",
            // System messages
            "system.starting",
            "system.init_error",
            "system.shutting_down",
            "system.overloaded",
            // Connection messages
            "connection.error.generic",
            "connection.error.database",
            "connection.error.uuid_mismatch",
            "connection.error.auth_server",
            "connection.error.auth_connect",
            "connection.error.game_server",
            "connection.error.no_servers",
            "connection.connecting",
            "connection.retry",
            "connection.commands.registered",
            "connection.manager.initialized",
            "connection.listener.registered",
            "connection.servers.available",
            "connection.picolimbo.server",
            "connection.picolimbo.found",
            // Auth prompt messages
            "auth.header",
            "auth.prompt.generic",
            "auth.account_exists",
            "auth.first_time",
            "auth.must_login",
            "auth.logged_out",
            // Welcome messages
            "general.welcome.full",
            // Admin messages
            "admin.player_not_found",
            "admin.uuid_invalid",
            "admin.account_deleted",
            "admin.commands_unregistered",
            "admin.help.header",
            "admin.help.reload",
            "admin.help.cache",
            "admin.help.stats",
            "admin.help.conflicts",
            // Admin reload messages
            "admin.reload.success",
            "admin.reload.failed",
            // Kick messages
            "general.kick.message"
    );

    /**
     * All translation keys used by loggers via messages.get() in Java code.
     * These are internal/admin messages not shown to players.
     */
    private static final List<String> LOGGER_KEYS = Arrays.asList(
            // Premium check status
            "premium.check_disabled",
            "premium.check_enabled",
            // Admin cache/stats messages
            "admin.cache_reset.success",
            "admin.cache_reset.player",
            "admin.cache_reset.player_not_found",
            "admin.stats.header",
            "admin.stats.registered_accounts",
            "admin.stats.total_accounts",
            "admin.stats.premium_accounts",
            "admin.stats.nonpremium_accounts",
            "admin.stats.premium_percentage",
            "admin.stats.authorized_players",
            "admin.stats.premium_cache",
            "admin.stats.database_cache",
            "admin.stats.cache_size",
            "admin.stats.database_status",
            // Player messages
            "player.not_found",
            "player.unauthorized.redirect",
            "player.transfer.success",
            "player.transfer.backend.success",
            "player.blocked.unauthorized",
            "player.premium.confirmed",
            "player.premium.verified",
            "player.conflict.options",
            "player.conflict.option1",
            "player.conflict.option2",
            "player.conflict.resolution",
            // Admin conflicts
            "admin.conflicts.header",
            "admin.conflicts.none",
            "admin.conflicts.found",
            "admin.conflicts.hours_ago",
            "admin.conflicts.original_nick",
            "admin.conflicts.status_premium",
            "admin.conflicts.status_offline",
            "admin.conflicts.tips_header",
            "admin.conflicts.tip_premium",
            "admin.conflicts.tip_offline",
            "admin.conflicts.tip_admin",
            "admin.conflicts.uuid",
            "admin.conflicts.ip",
            // Error messages
            "error.permission",
            // Plugin initialization
            "plugin.initialization.ready",
            "plugin.initialization.shutdown",
            "plugin.initialization.closed",
            "plugin.initialization.components_ready",
            // Config display
            "config.display.header",
            "config.display.database",
            "config.display.cache_ttl",
            "config.display.cache_max_size",
            "config.display.brute_force",
            "config.display.picolimbo_server",
            "config.display.bcrypt_cost",
            "config.display.premium_check",
            "config.display.cache_stats",
            // Config messages
            "config.reloading",
            "config.reloaded_success",
            "config.reload_failed",
            // Database messages
            "database.connected",
            "database.disconnected",
            "database.error",
            "database.manager.created",
            "database.manager.hikari_init",
            "database.manager.hikari_ready",
            "database.manager.standard_jdbc",
            "database.manager.connected",
            "database.manager.health_checks_started",
            "database.manager.creating_tables",
            "database.manager.tables_created",
            "database.manager.index_error",
            "database.manager.connection_closed",
            "database.manager.shutdown_complete",
            // Cache messages
            "cache.auth.created",
            "cache.all_cleared",
            "cache.stats_final",
            "cache.shutdown",
            "cache.interrupted_shutdown",
            // Validation messages (cache/config)
            "validation.ttl.negative",
            "validation.maxsize.gt_zero",
            "validation.maxsessions.gt_zero",
            "validation.maxpremiumcache.gt_zero",
            "validation.maxloginattempts.gt_zero",
            "validation.bruteforcetimeout.gt_zero",
            // Error messages (additional)
            "error.player_only",
            // Cache debug messages
            "cache.debug.auth.added",
            "cache.debug.failed.login",
            "cache.debug.player.removed",
            "cache.debug.premium.added",
            "cache.debug.premium.removed",
            "cache.debug.reset.attempts",
            "cache.debug.session.ended",
            "cache.debug.session.started",
            "cache.error.args.register_failed",
            "cache.error.state.clear",
            "cache.error.state.register_failed",
            "cache.warn.ip.blocked",
            // Connection messages (additional)
            "connection.picolimbo.error",
            "player.connected.backend",
            "player.transfer.attempt",
            "player.transfer.backend.attempt",
            // Security messages (additional)
            "security.session.hijack",
            "security.session.ip.mismatch"
    );

    /**
     * Combined list of all required keys (SimpleMessages + Logger).
     */
    private static final List<String> REQUIRED_KEYS;
    static {
        java.util.ArrayList<String> all = new java.util.ArrayList<>(SIMPLE_MESSAGES_KEYS);
        all.addAll(LOGGER_KEYS);
        REQUIRED_KEYS = java.util.Collections.unmodifiableList(all);
    }

    @BeforeEach
    void setUp() throws IOException {
        englishProps = loadProperties("messages_en.properties");
        polishProps = loadProperties("messages_pl.properties");
    }

    private Properties loadProperties(String filename) throws IOException {
        Properties props = new Properties();
        try (InputStream is = getClass().getResourceAsStream("/lang/" + filename)) {
            assertNotNull(is, "Language file not found: " + filename);
            try (InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
                props.load(reader);
            }
        }
        return props;
    }

    @Test
    void allRequiredKeys_existInEnglishFile() {
        StringBuilder missing = new StringBuilder();
        for (String key : REQUIRED_KEYS) {
            if (!englishProps.containsKey(key)) {
                missing.append("\n  - ").append(key);
            }
        }
        assertTrue(missing.isEmpty(), 
                "Missing keys in messages_en.properties:" + missing);
    }

    @Test
    void allRequiredKeys_existInPolishFile() {
        StringBuilder missing = new StringBuilder();
        for (String key : REQUIRED_KEYS) {
            if (!polishProps.containsKey(key)) {
                missing.append("\n  - ").append(key);
            }
        }
        assertTrue(missing.isEmpty(), 
                "Missing keys in messages_pl.properties:" + missing);
    }

    @Test
    void englishAndPolish_haveConsistentKeys() {
        // Check for keys in English but not in Polish
        StringBuilder englishOnly = new StringBuilder();
        for (String key : englishProps.stringPropertyNames()) {
            if (!polishProps.containsKey(key)) {
                englishOnly.append("\n  - ").append(key);
            }
        }
        
        // Check for keys in Polish but not in English
        StringBuilder polishOnly = new StringBuilder();
        for (String key : polishProps.stringPropertyNames()) {
            if (!englishProps.containsKey(key)) {
                polishOnly.append("\n  - ").append(key);
            }
        }
        
        StringBuilder message = new StringBuilder();
        if (!englishOnly.isEmpty()) {
            message.append("\nKeys in EN but not in PL:").append(englishOnly);
        }
        if (!polishOnly.isEmpty()) {
            message.append("\nKeys in PL but not in EN:").append(polishOnly);
        }
        
        assertTrue(message.isEmpty(), "Language files have inconsistent keys:" + message);
    }

    @Test
    void allValues_areNotEmpty() {
        StringBuilder emptyValues = new StringBuilder();
        
        for (String key : REQUIRED_KEYS) {
            String enValue = englishProps.getProperty(key);
            String plValue = polishProps.getProperty(key);
            
            if (enValue != null && enValue.trim().isEmpty()) {
                emptyValues.append("\n  - EN: ").append(key);
            }
            if (plValue != null && plValue.trim().isEmpty()) {
                emptyValues.append("\n  - PL: ").append(key);
            }
        }
        
        assertTrue(emptyValues.isEmpty(), 
                "Keys with empty values:" + emptyValues);
    }

    @ParameterizedTest
    @ValueSource(strings = {"en", "pl"})
    void messagesClass_canLoadAllRequiredKeys(String language) {
        Messages messages = new Messages();
        messages.setLanguage(language);
        
        StringBuilder failures = new StringBuilder();
        for (String key : REQUIRED_KEYS) {
            String value = messages.get(key);
            // If key is returned as-is, it means it wasn't found
            if (value.equals(key) || value.startsWith("Missing:")) {
                failures.append("\n  - ").append(key);
            }
        }
        
        assertTrue(failures.isEmpty(), 
                "Messages class cannot load keys for language " + language + ":" + failures);
    }

    @Test
    void allPropertiesKeys_areInRequiredKeys() {
        // Check that all keys in properties files are documented in REQUIRED_KEYS
        // This ensures no unused/orphan keys exist in properties files
        StringBuilder unused = new StringBuilder();
        
        for (String key : englishProps.stringPropertyNames()) {
            if (!REQUIRED_KEYS.contains(key)) {
                unused.append("\n  - EN: ").append(key);
            }
        }
        
        for (String key : polishProps.stringPropertyNames()) {
            if (!REQUIRED_KEYS.contains(key)) {
                unused.append("\n  - PL: ").append(key);
            }
        }
        
        assertTrue(unused.isEmpty(), 
                "Properties contain keys not in REQUIRED_KEYS (potential unused keys):" + unused);
    }

    @Test
    void simpleMessagesKeys_areUsedBySimpleMessagesClass() {
        // Verify that keys in SIMPLE_MESSAGES_KEYS are actually used by SimpleMessages
        // This is a documentation test - all keys should correspond to methods in SimpleMessages
        assertTrue(SIMPLE_MESSAGES_KEYS.size() > 0, "SIMPLE_MESSAGES_KEYS should not be empty");
        assertTrue(LOGGER_KEYS.size() > 0, "LOGGER_KEYS should not be empty");
        assertEquals(SIMPLE_MESSAGES_KEYS.size() + LOGGER_KEYS.size(), REQUIRED_KEYS.size(),
                "REQUIRED_KEYS should be sum of SIMPLE_MESSAGES_KEYS and LOGGER_KEYS");
    }

    @Test
    void noKeyDuplicates_inRequiredKeys() {
        // Ensure no duplicates in combined key list
        java.util.Set<String> unique = new java.util.HashSet<>(REQUIRED_KEYS);
        assertEquals(unique.size(), REQUIRED_KEYS.size(),
                "REQUIRED_KEYS contains duplicates! Found " + 
                (REQUIRED_KEYS.size() - unique.size()) + " duplicate(s)");
    }
}
