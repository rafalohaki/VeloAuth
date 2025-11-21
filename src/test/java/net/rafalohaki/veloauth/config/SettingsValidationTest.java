package net.rafalohaki.veloauth.config;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
        try {
            Files.writeString(configFile, invalidConfig);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Then: Should throw IllegalArgumentException
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> settings.load(),
            "Should reject config with all resolvers disabled"
        );

        assertTrue(
            exception.getMessage().contains("co najmniej jedno źródło") ||
            exception.getMessage().contains("at least one resolver"),
            "Error message should mention resolver requirement"
        );
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
        try {
            Files.writeString(configFile, validConfig);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

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
        try {
            Files.writeString(configFile, invalidConfig);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Then: Should throw IllegalArgumentException
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> settings.load(),
            "Should reject config with negative timeout"
        );

        assertTrue(
            exception.getMessage().contains("timeout") ||
            exception.getMessage().contains("musi być > 0"),
            "Error message should mention timeout validation"
        );
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
        try {
            Files.writeString(configFile, invalidConfig);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Then: Should throw IllegalArgumentException
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> settings.load(),
            "Should reject config with negative TTL"
        );

        assertTrue(
            exception.getMessage().contains("TTL") ||
            exception.getMessage().contains("ujemne"),
            "Error message should mention TTL validation"
        );
    }

    @Test
    void shouldUseDefaultsWhenConfigNotFound() {
        // Given: No config file exists

        // When: Loading settings without config file
        boolean loaded = settings.load();

        // Then: Should create default config and load successfully
        assertTrue(loaded, "Should load with default configuration");
        assertTrue(Files.exists(tempDir.resolve("config.yml")), "Should create default config file");
    }
}
