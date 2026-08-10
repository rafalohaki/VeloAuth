package net.rafalohaki.veloauth.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

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
    void shouldUseDefaultPingTimeoutMillisWhenNotConfigured() {
        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, "language: en\n");

        assertTrue(settings.load(), "Should load with default configuration");
        assertEquals(3000, settings.getPingTimeoutMillis(),
                "Default ping-timeout-ms should be 3000 when not specified in config");
    }

    @Test
    void shouldLoadCustomPingTimeoutMillis() {
        String config = """
                connection:
                  ping-timeout-ms: 5000
                """;

        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, config);

        assertTrue(settings.load(), "Should load custom ping-timeout-ms");
        assertEquals(5000, settings.getPingTimeoutMillis(),
                "Custom ping-timeout-ms should be loaded from config");
    }

    @ParameterizedTest(name = "shouldReject ping-timeout-ms={0}")
    @CsvSource({
        "0",
        "-1",
        "30001"
    })
    void shouldRejectInvalidPingTimeoutMillis(int pingTimeoutMs) {
        String invalidConfig = String.format("""
                connection:
                  ping-timeout-ms: %d
                """, pingTimeoutMs);

        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, invalidConfig);

        assertFalse(settings.load(), "Should reject non-positive or over-limit ping-timeout-ms");
    }

    @Test
    void generatedDefaultConfigShouldDocumentPingTimeoutMillis() throws IOException {
        settings.load();
        String generatedConfig = Files.readString(tempDir.resolve("config.yml"));

        assertTrue(generatedConfig.contains("ping-timeout-ms: 3000"),
                "Generated default config should document the ping-timeout-ms default");
    }

    @Test
    void shouldUseDefaultReportEnabledWhenNotConfigured() {
        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, "language: en\n");

        assertTrue(settings.load(), "Should load with default configuration");
        assertTrue(settings.isReportEnabled(),
                "Default report.enabled should be true when not specified in config");
        assertFalse(settings.isReportIncludeLogs(),
                "Logs must be excluded from public reports unless explicitly enabled");
    }

    @Test
    void shouldLoadReportDisabled() {
        String config = """
                report:
                  enabled: false
                """;

        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, config);

        assertTrue(settings.load(), "Should load with report disabled");
        assertFalse(settings.isReportEnabled(),
                "report.enabled should be false when explicitly set to false in config");
    }

    @Test
    void shouldLoadReportIncludeLogsOnlyWhenExplicitlyEnabled() {
        writeConfigFile(tempDir.resolve("config.yml"), """
                report:
                  enabled: true
                  include-logs: true
                """);

        assertTrue(settings.load());
        assertTrue(settings.isReportIncludeLogs());
    }

    @Test
    void securitySensitiveOptIns_removedOnReload_returnToSafeDefaults() {
        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, """
                report:
                  include-logs: true
                two-factor:
                  qr-link-enabled: true
                """);
        assertTrue(settings.load());
        assertTrue(settings.isReportIncludeLogs());
        assertTrue(settings.getTwoFactorSettings().isQrLinkEnabled());

        writeConfigFile(configFile, """
                report:
                  enabled: true
                two-factor:
                  enabled: true
                """);
        assertTrue(settings.load());
        assertFalse(settings.isReportIncludeLogs());
        assertFalse(settings.getTwoFactorSettings().isQrLinkEnabled());
    }

    @Test
    void generatedDefaultConfigShouldDocumentReportEnabled() throws IOException {
        settings.load();
        String generatedConfig = Files.readString(tempDir.resolve("config.yml"));

        assertTrue(generatedConfig.contains("report:"),
                "Generated default config should contain the report section");
        assertTrue(generatedConfig.contains("enabled: true"),
                "Generated default config should document report.enabled: true");
        assertTrue(generatedConfig.contains("include-logs: false"),
                "Generated default config should keep logs private by default");
        assertTrue(generatedConfig.contains("qr-link-enabled: false"),
                "Generated default config should not send TOTP enrollment secrets externally by default");
        assertTrue(generatedConfig.contains("max-lookups-per-ip-per-minute: 30"));
        assertTrue(generatedConfig.contains("max-concurrent-lookups: 32"));
    }

    @ParameterizedTest(name = "shouldReject premium resolver limit {0}={1}")
    @CsvSource({
        "max-lookups-per-ip-per-minute, 0",
        "max-lookups-per-ip-per-minute, -1",
        "max-concurrent-lookups, 0",
        "max-concurrent-lookups, -1"
    })
    void shouldRejectNonPositivePremiumResolverLimits(String key, int value) {
        writeConfigFile(tempDir.resolve("config.yml"), """
                premium:
                  resolver:
                    mojang-enabled: true
                    %s: %d
                """.formatted(key, value));

        assertFalse(settings.load());
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

    @Test
    void connectionUrlPasswordContainingColonShouldBePreservedInFull() {
        // Regression: parseAuthPart used split(":") which tokenized on every colon and
        // kept only element [1], silently truncating "p@ss:word" to "p@ss".
        String config = """
                database:
                  storage-type: POSTGRESQL
                  connection-url: "postgresql://user:p@ss:word@db.example.com:5432/veloauth"
                """;

        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, config);

        boolean loaded = settings.load();
        assertTrue(loaded, "Should load connection-url with a password containing a colon");
        assertEquals("user", settings.getDatabaseUser(), "User is the segment before the first colon");
        assertEquals("p@ss:word", settings.getDatabasePassword(),
                "Password is everything after the first colon — colons inside the password must be preserved");
    }

    @Test
    void connectionUrlWithoutPasswordShouldParseUserOnly() {
        String config = """
                database:
                  storage-type: POSTGRESQL
                  connection-url: "postgresql://solo@db.example.com:5432/veloauth"
                """;

        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, config);

        boolean loaded = settings.load();
        assertTrue(loaded, "Should load connection-url that has only a user (no password)");
        assertEquals("solo", settings.getDatabaseUser(), "User segment with no colon is the user");
        assertEquals("", settings.getDatabasePassword(), "No password segment means empty password");
    }

    @Test
    void connectionUrlWithIpv6BracketedHostShouldParseHostnameAndPort() {
        String config = """
                database:
                  storage-type: POSTGRESQL
                  connection-url: "postgresql://user:pass@[::1]:5432/veloauth"
                """;

        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, config);

        boolean loaded = settings.load();
        assertTrue(loaded, "Should load connection-url with an IPv6 bracketed host");
        assertEquals("::1", settings.getDatabaseHostname(),
                "IPv6 literal inside brackets should be the hostname (brackets stripped)");
        assertEquals(5432, settings.getDatabasePort(), "Port should be parsed from after the bracketed host");
    }

    @Test
    void hotReloadableSettingsFieldsShouldBeMarkedVolatile() throws ReflectiveOperationException {
        // Reload mutates these fields in place from a different thread than the readers.
        // Without volatile a reader thread may observe a stale value indefinitely.
        // If you add a new hot-reloadable scalar, add it here — and if you remove one,
        // drop it. The set is intentionally explicit so this test documents the contract.
        Set<String> hotReloadable = Set.of(
                "ipLimitRegistrations",
                "minPasswordLength",
                "maxPasswordLength",
                "bcryptCost",
                "debugEnabled",
                "reportEnabled",
                "reportIncludeLogs",
                "language");

        for (String fieldName : hotReloadable) {
            Field field = Settings.class.getDeclaredField(fieldName);
            int modifiers = field.getModifiers();
            assertTrue(java.lang.reflect.Modifier.isVolatile(modifiers),
                    "Settings." + fieldName + " must be volatile — it is hot-reloadable");
        }
    }

    @Test
    void conflictModeTtlShouldAcceptZeroAndPositiveValuesAndRejectNegative() {
        // 0 is allowed — it disables the TTL (pre-1.3.3 permanent-conflict behaviour).
        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, """
                security:
                  conflict-mode-ttl-hours: 0
                """);
        assertTrue(settings.load(), "conflict-mode-ttl-hours: 0 should be valid (disables TTL)");
        assertEquals(0, settings.getConflictModeTtlHours());

        writeConfigFile(configFile, """
                security:
                  conflict-mode-ttl-hours: 24
                """);
        assertTrue(settings.load(), "conflict-mode-ttl-hours: 24 should be valid");
        assertEquals(24, settings.getConflictModeTtlHours());

        writeConfigFile(configFile, """
                security:
                  conflict-mode-ttl-hours: -1
                """);
        assertFalse(settings.load(), "conflict-mode-ttl-hours: -1 should fail validation");
        assertEquals(24, settings.getConflictModeTtlHours(),
                "Rejected reload should preserve the previously active TTL");
    }

    @Test
    void failedReloadShouldPreservePreviouslyActiveSettings() {
        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, """
                debug-enabled: true
                security:
                  bcrypt-cost: 12
                  conflict-mode-ttl-hours: 24
                premium:
                  allow-cracked-on-premium-nicks: true
                """);
        assertTrue(settings.load(), "Initial valid configuration should load");

        writeConfigFile(configFile, """
                debug-enabled: false
                security:
                  bcrypt-cost: 11
                  conflict-mode-ttl-hours: -1
                premium:
                  allow-cracked-on-premium-nicks: false
                """);

        assertFalse(settings.load(), "Invalid reload should be rejected");
        assertTrue(settings.isDebugEnabled(), "Rejected reload must preserve the active debug setting");
        assertEquals(12, settings.getBcryptCost(), "Rejected reload must preserve the active BCrypt cost");
        assertEquals(24, settings.getConflictModeTtlHours(),
                "Rejected reload must preserve the active conflict-mode TTL");
        assertTrue(settings.isAllowCrackedOnPremiumNicks(),
                "Rejected reload must preserve the active premium routing policy");
    }

    @Test
    void removingPremiumSecurityOptInShouldRestoreSafeDefaultOnReload() {
        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, """
                premium:
                  allow-cracked-on-premium-nicks: true
                """);
        assertTrue(settings.load(), "Explicit opt-in should load");
        assertTrue(settings.isAllowCrackedOnPremiumNicks());

        writeConfigFile(configFile, "language: en\n");

        assertTrue(settings.load(), "Configuration without the optional premium key should load");
        assertFalse(settings.isAllowCrackedOnPremiumNicks(),
                "Removing a security-sensitive opt-in must restore its safe false default");
    }

    @Test
    void premiumAuthServerBypassShouldBeBackwardCompatibleAndOptIn() {
        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, "language: en\n");

        assertTrue(settings.load(), "Legacy configuration without the new key should load");
        assertFalse(settings.isPremiumBypassAuthServerEnabled(),
                "Existing installations must retain the current auth-server routing by default");

        writeConfigFile(configFile, """
                premium:
                  bypass-auth-server: true
                """);
        assertTrue(settings.load(), "Explicit premium bypass should load");
        assertTrue(settings.isPremiumBypassAuthServerEnabled());

        writeConfigFile(configFile, "language: en\n");
        assertTrue(settings.load(), "Removing the optional key should remain a valid reload");
        assertFalse(settings.isPremiumBypassAuthServerEnabled(),
                "Removing premium bypass must restore the safe false default");
    }

    @Test
    void invalidPremiumAuthServerBypassShouldUseSafeDefault() {
        writeConfigFile(tempDir.resolve("config.yml"), """
                premium:
                  bypass-auth-server: definitely-not-a-boolean
                """);

        assertTrue(settings.load(), "Invalid optional boolean should fall back without breaking upgrades");
        assertFalse(settings.isPremiumBypassAuthServerEnabled());
    }

    @Test
    void generatedConfigShouldDocumentPremiumAuthServerBypassAsDisabled() throws IOException {
        assertTrue(settings.load());

        String generatedConfig = Files.readString(tempDir.resolve("config.yml"));

        assertTrue(generatedConfig.contains("bypass-auth-server: false"),
                "Generated config must expose the conservative premium bypass default");
    }

    @Test
    void previousReleaseConfigWithoutAuthServerModeShouldRemainUnchangedAndExternal() throws IOException {
        Path configFile = tempDir.resolve("config.yml");
        String previousReleaseConfig = """
                language: pl
                auth-server:
                  server-name: legacy-limbo
                  timeout-seconds: 180
                premium:
                  check-enabled: true
                  allow-cracked-on-premium-nicks: false
                floodgate:
                  enabled: false
                  bypass-auth-server: true
                """;
        writeConfigFile(configFile, previousReleaseConfig);

        assertTrue(settings.load(), "Existing auth-server configuration should remain valid");
        assertEquals(Settings.AuthServerMode.EXTERNAL, settings.getAuthServerMode());
        assertEquals("legacy-limbo", settings.getAuthServerName());
        assertEquals(180, settings.getAuthServerTimeoutSeconds());
        assertFalse(settings.isPremiumBypassAuthServerEnabled());
        assertEquals(0, settings.getEmbeddedAuthServerSettings().getPort());
        assertEquals(previousReleaseConfig, Files.readString(configFile),
                "Loading a previous-release config must not rewrite it or inject embedded mode");
    }

    @Test
    void legacyPicolimboSectionShouldRemainExternalAndPreserveRoutingValues() {
        writeConfigFile(tempDir.resolve("config.yml"), """
                picolimbo:
                  server-name: historical-limbo
                  timeout-seconds: 210
                """);

        assertTrue(settings.load(), "Deprecated picolimbo configuration should remain upgradeable");
        assertEquals(Settings.AuthServerMode.EXTERNAL, settings.getAuthServerMode());
        assertEquals("historical-limbo", settings.getAuthServerName());
        assertEquals(210, settings.getAuthServerTimeoutSeconds());
        assertFalse(settings.isPremiumBypassAuthServerEnabled());
    }

    @Test
    void embeddedAuthServerSettingsShouldLoadExplicitValues() {
        writeConfigFile(tempDir.resolve("config.yml"), """
                auth-server:
                  mode: embedded
                  server-name: ignored-for-embedded
                  timeout-seconds: 240
                  embedded:
                    port: 25570
                    max-connections: 750
                    handshake-timeout-seconds: 7
                    login-timeout-seconds: 12
                """);

        assertTrue(settings.load());
        assertEquals(Settings.AuthServerMode.EMBEDDED, settings.getAuthServerMode());
        Settings.EmbeddedAuthServerSettings embedded = settings.getEmbeddedAuthServerSettings();
        assertEquals(25570, embedded.getPort());
        assertEquals(750, embedded.getMaxConnections());
        assertEquals(7, embedded.getHandshakeTimeoutSeconds());
        assertEquals(12, embedded.getLoginTimeoutSeconds());
    }

    @Test
    void embeddedModeShouldNotRequireUnusedExternalServerName() {
        writeConfigFile(tempDir.resolve("config.yml"), """
                auth-server:
                  mode: embedded
                  server-name: ""
                """);

        assertTrue(settings.load(), "Embedded mode must be independent of velocity.toml server entries");
        assertEquals(Settings.AuthServerMode.EMBEDDED, settings.getAuthServerMode());
    }

    @Test
    void malformedAuthServerSectionShouldBeRejectedTransactionally() {
        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, """
                auth-server:
                  server-name: active-limbo
                """);
        assertTrue(settings.load());

        writeConfigFile(configFile, "auth-server: embedded\n");

        assertFalse(settings.load());
        assertEquals(Settings.AuthServerMode.EXTERNAL, settings.getAuthServerMode());
        assertEquals("active-limbo", settings.getAuthServerName());
    }

    @Test
    void malformedEmbeddedAuthServerSectionShouldBeRejectedTransactionally() {
        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, """
                auth-server:
                  server-name: active-limbo
                """);
        assertTrue(settings.load());

        writeConfigFile(configFile, """
                auth-server:
                  mode: embedded
                  embedded: automatic
                """);

        assertFalse(settings.load());
        assertEquals(Settings.AuthServerMode.EXTERNAL, settings.getAuthServerMode());
        assertEquals("active-limbo", settings.getAuthServerName());
    }

    @Test
    void removingEmbeddedOptInOnReloadShouldRestoreExternalDefaults() {
        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, """
                auth-server:
                  mode: embedded
                  embedded:
                    port: 25570
                    max-connections: 750
                    handshake-timeout-seconds: 7
                    login-timeout-seconds: 12
                """);
        assertTrue(settings.load());
        assertEquals(Settings.AuthServerMode.EMBEDDED, settings.getAuthServerMode());

        writeConfigFile(configFile, """
                auth-server:
                  server-name: external-limbo
                """);

        assertTrue(settings.load());
        assertEquals(Settings.AuthServerMode.EXTERNAL, settings.getAuthServerMode());
        assertEquals("external-limbo", settings.getAuthServerName());
        Settings.EmbeddedAuthServerSettings embedded = settings.getEmbeddedAuthServerSettings();
        assertEquals(0, embedded.getPort());
        assertEquals(512, embedded.getMaxConnections());
        assertEquals(10, embedded.getHandshakeTimeoutSeconds());
        assertEquals(15, embedded.getLoginTimeoutSeconds());
    }

    @ParameterizedTest(name = "shouldReject auth-server.mode={0}")
    @CsvSource({"unknown", "EMBEDDED", "''"})
    void invalidAuthServerModeShouldBeRejectedTransactionally(String mode) {
        Path configFile = tempDir.resolve("config.yml");
        writeConfigFile(configFile, """
                auth-server:
                  server-name: active-limbo
                """);
        assertTrue(settings.load());

        writeConfigFile(configFile, """
                auth-server:
                  mode: %s
                  server-name: rejected-limbo
                """.formatted(mode));

        assertFalse(settings.load());
        assertEquals(Settings.AuthServerMode.EXTERNAL, settings.getAuthServerMode());
        assertEquals("active-limbo", settings.getAuthServerName(),
                "Rejected topology must not partially replace the active configuration");
    }

    @ParameterizedTest(name = "shouldReject embedded.port={0}")
    @CsvSource({"65536", "-1"})
    void invalidEmbeddedPortShouldBeRejected(int port) {
        writeConfigFile(tempDir.resolve("config.yml"), """
                auth-server:
                  mode: embedded
                  embedded:
                    port: %d
                """.formatted(port));

        assertFalse(settings.load());
    }

    @Test
    void invalidEmbeddedLimitsShouldBeRejected() {
        writeConfigFile(tempDir.resolve("config.yml"), """
                auth-server:
                  mode: embedded
                  embedded:
                    max-connections: 0
                    handshake-timeout-seconds: 0
                    login-timeout-seconds: 0
                """);

        assertFalse(settings.load());
    }

    @ParameterizedTest(name = "shouldReject embedded.max-connections={0}")
    @CsvSource({"0", "10001", "-1"})
    void invalidEmbeddedConnectionCapacityShouldBeRejected(int maximumConnections) {
        writeConfigFile(tempDir.resolve("config.yml"), """
                auth-server:
                  mode: embedded
                  embedded:
                    max-connections: %d
                """.formatted(maximumConnections));

        assertFalse(settings.load());
    }

    @Test
    void generatedConfigShouldEnableSelfContainedEmbeddedAuthServerForNewInstall() throws IOException {
        assertTrue(settings.load());

        String generatedConfig = Files.readString(tempDir.resolve("config.yml"));

        assertTrue(generatedConfig.contains("mode: embedded"));
        assertTrue(generatedConfig.contains("port: 0"));
        assertTrue(generatedConfig.contains("velocity:player_info"));
        assertTrue(generatedConfig.contains("Existing config.yml files are never rewritten"));
        assertTrue(generatedConfig.contains("plugins/bStats/config.txt"));
        assertFalse(generatedConfig.contains("client-compatibility:"));
        assertFalse(generatedConfig.contains("forwarding-secret-file:"));
    }

    @Test
    void hotReloadablePremiumCoreFieldsShouldBeVolatile() throws ReflectiveOperationException {
        Set<String> hotReloadable = Set.of(
                "checkEnabled", "allowCrackedOnPremiumNicks", "bypassAuthServer");

        for (String fieldName : hotReloadable) {
            Field field = Settings.PremiumSettings.class.getDeclaredField(fieldName);
            assertTrue(java.lang.reflect.Modifier.isVolatile(field.getModifiers()),
                    "Settings.PremiumSettings." + fieldName + " must be volatile — it is read by login events");
        }
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
