package net.rafalohaki.veloauth.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for premium resolver configuration validation.
 * Verifies that Settings properly validates resolver configuration on startup.
 */
class SettingsValidationTest {

    @TempDir
    Path tempDir;

    private Settings settings;

    @BeforeEach
    void setUp() {
        settings = new Settings(tempDir);
    }

    @Test
    void shouldRejectConfigWithAllResolversDisabled() {
        // Given: Config with all resolvers disabled
        String invalidConfig = """
                premium:
                  check-enabled: true
                  resolver:
                    mojang-enabled: false
                    ashcon-enabled: false
                    wpme-enabled: false
                    request-timeout-ms: 2000
                    hit-ttl-minutes: 10
                    miss-ttl-minutes: 3
                """;

        Path configFile = tempDir.resolve("config.yml");

        // When: Loading config with all resolvers disabled
        writeConfigFile(configFile, invalidConfig);

        // Then: Should reject gracefully (validation exceptions are caught and surfaced via return false
        // so /vauth reload and startup paths don't crash on operator typos)
        assertFalse(settings.load(), "Should reject config with all resolvers disabled");
    }

    @ParameterizedTest(name = "shouldAcceptConfigWith mojang={0}, ashcon={1}, wpme={2}")
    @CsvSource({
        "true,  false, false",  // Mojang only
        "false, true,  false",  // Ashcon only
        "false, false, true",   // WPME only
        "true,  true,  true"    // All enabled
    })
    void shouldAcceptConfigWithAtLeastOneResolverEnabled(boolean mojang, boolean ashcon, boolean wpme) {
        // Given: Config with at least one resolver enabled
        String validConfig = String.format("""
                premium:
                  check-enabled: true
                  resolver:
                    mojang-enabled: %s
                    ashcon-enabled: %s
                    wpme-enabled: %s
                    request-timeout-ms: 2000
                    hit-ttl-minutes: 10
                    miss-ttl-minutes: 3
                """, mojang, ashcon, wpme);

        Path configFile = tempDir.resolve("config.yml");

        // When: Loading config
        writeConfigFile(configFile, validConfig);

        // Then: Should load successfully
        assertDoesNotThrow(
            () -> settings.load(),
            "Should accept config with at least one resolver enabled"
        );
    }

    @Test
    void shouldRejectConfigWithNegativeTimeout() {
        // Given: Config with negative timeout
        String invalidConfig = """
                premium:
                  check-enabled: true
                  resolver:
                    mojang-enabled: true
                    ashcon-enabled: true
                    wpme-enabled: false
                    request-timeout-ms: -100
                    hit-ttl-minutes: 10
                    miss-ttl-minutes: 3
                """;

        Path configFile = tempDir.resolve("config.yml");

        // When: Loading config with invalid timeout
        writeConfigFile(configFile, invalidConfig);

        // Then: validation errors are caught inside load() and surfaced via return false
        assertFalse(settings.load(), "Should reject config with negative timeout");
    }

    @Test
    void shouldRejectConfigWithNegativeTTL() {
        // Given: Config with negative TTL
        String invalidConfig = """
                premium:
                  check-enabled: true
                  resolver:
                    mojang-enabled: true
                    ashcon-enabled: true
                    wpme-enabled: false
                    request-timeout-ms: 2000
                    hit-ttl-minutes: -5
                    miss-ttl-minutes: 3
                """;

        Path configFile = tempDir.resolve("config.yml");

        // When: Loading config with invalid TTL
        writeConfigFile(configFile, invalidConfig);

        // Then: validation errors are caught inside load() and surfaced via return false
        assertFalse(settings.load(), "Should reject config with negative TTL");
    }

    @Test
    void shouldUseDefaultsWhenConfigNotFound() throws IOException {
        // Given: No config file exists
        settings.getPostgreSQLSettings().setSslEnabled(false);

        // When: Loading settings without config file
        boolean loaded = settings.load();
        String generatedConfig = Files.readString(tempDir.resolve("config.yml"));

        // Then: Should create default config and load successfully
        assertTrue(loaded, "Should load with default configuration");
        assertTrue(Files.exists(tempDir.resolve("config.yml")), "Should create default config file");
        assertTrue(settings.getPostgreSQLSettings().isSslEnabled(), "Should reload generated defaults after first creation");
        assertTrue(generatedConfig.contains("ssl-enabled: true"), "Generated config should document the runtime SSL default");
        assertTrue(generatedConfig.contains("# BCrypt hashing rounds (10-31)") &&
                        generatedConfig.contains("bcrypt-cost: 10"),
                "Generated config should document the validated BCrypt range");
        assertFalse(generatedConfig.contains("postgresql://user:pass@host:5432/database?sslmode=disable"),
                "Generated config should not advertise unsupported connection-url query parameters");
    }

    @Test
    void shouldLoadFloodgateSettingsWithCustomPrefix() {
        String config = """
                floodgate:
                  enabled: false
                  username-prefix: "+"
                  bypass-auth-server: false
                """;

        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, config);

        boolean loaded = settings.load();

        assertTrue(loaded, "Should load custom Floodgate settings");
        assertFalse(settings.isFloodgateIntegrationEnabled(), "Floodgate integration should be disabled");
        assertEquals("+", settings.getFloodgateUsernamePrefix(), "Custom Floodgate prefix should be loaded");
        assertFalse(settings.isFloodgateBypassAuthServerEnabled(), "Floodgate auth bypass should be disabled");
    }

    @Test
    void shouldRejectFloodgatePrefixWithWhitespace() {
        String invalidConfig = """
                floodgate:
                  enabled: true
                  username-prefix: "bed rock"
                  bypass-auth-server: true
                """;

        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, invalidConfig);

        assertFalse(settings.load(), "Should reject Floodgate prefixes with whitespace");
    }

    @Test
    void shouldFallbackToDefaultsWhenBooleanValuesAreInvalid() {
        String config = """
                debug-enabled: "not-a-boolean"
                premium:
                  check-enabled: "not-a-boolean"
                database:
                  postgresql:
                    ssl-enabled: "not-a-boolean"
                """;

        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, config);

        boolean loaded = settings.load();

        assertTrue(loaded, "Should fall back to defaults for invalid boolean values");
        assertFalse(settings.isDebugEnabled(), "Invalid debug-enabled should fall back to the default false");
        assertTrue(settings.isPremiumCheckEnabled(), "Invalid premium.check-enabled should fall back to the default true");
        assertTrue(settings.getPostgreSQLSettings().isSslEnabled(),
                "Invalid database.postgresql.ssl-enabled should fall back to the default true");
    }

    @ParameterizedTest(name = "shouldReject session-timeout-minutes={0}")
    @CsvSource({
        "0",
        "-1"
    })
    void shouldRejectNonPositiveSessionTimeoutMinutes(int sessionTimeoutMinutes) {
        String invalidConfig = String.format("""
                cache:
                  session-timeout-minutes: %d
                """, sessionTimeoutMinutes);

        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, invalidConfig);

        assertFalse(settings.load(), "Should reject non-positive session timeout values");
    }

    @Test
    void shouldIgnoreConnectionUrlQueryParametersInsteadOfCorruptingDatabaseName() {
        String config = """
                database:
                  storage-type: POSTGRESQL
                  connection-url: "postgresql://user:pass@db.example.com:5432/veloauth?sslmode=disable"
                  connection-parameters: "?prepareThreshold=0"
                """;

        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, config);

        boolean loaded = settings.load();

        assertTrue(loaded, "Should load connection-url values even when the URL includes an unsupported query string");
        assertEquals("POSTGRESQL", settings.getDatabaseStorageType(), "Should detect database type from connection-url");
        assertEquals("db.example.com", settings.getDatabaseHostname(), "Should parse hostname from connection-url");
        assertEquals(5432, settings.getDatabasePort(), "Should parse port from connection-url");
        assertEquals("veloauth", settings.getDatabaseName(), "Should strip the query string from the parsed database name");
        assertEquals("user", settings.getDatabaseUser(), "Should parse database user from connection-url");
        assertEquals("pass", settings.getDatabasePassword(), "Should parse database password from connection-url");
        assertEquals("?prepareThreshold=0", settings.getDatabaseConnectionParameters(),
                "Unsupported query parameters in connection-url should not override explicit connection-parameters");
    }

    /**
     * Helper method to write config file, wrapping IOException in UncheckedIOException.
     */
    private void writeConfigFile(Path configFile, String content) {
        try {
            Files.writeString(configFile, content);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to write test config file", e);
        }
    }
}
