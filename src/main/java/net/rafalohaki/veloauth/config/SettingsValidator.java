package net.rafalohaki.veloauth.config;

import net.rafalohaki.veloauth.database.DatabaseType;
import net.rafalohaki.veloauth.util.FloodgateDetector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validates Settings configuration values.
 * All methods are static and throw IllegalArgumentException on invalid values.
 */
public final class SettingsValidator {

    private static final Logger logger = LoggerFactory.getLogger(SettingsValidator.class);

    private SettingsValidator() {}

    /**
     * Validates all settings and adjusts values where appropriate.
     *
     * @param settings the settings to validate
     * @throws IllegalArgumentException if any value is invalid
     */
    public static void validate(Settings settings) {
        validateDatabase(settings);
        validateCache(settings);
        validateSecurity(settings);
        validateConnection(settings);
        validatePremium(settings);
        validateFloodgate(settings);
        settings.normalizeLanguage();
        logger.debug("Configuration validation completed successfully");
    }

    static void validateDatabase(Settings settings) {
        if (DatabaseType.fromName(settings.getDatabaseStorageType()) == null) {
            throw new IllegalArgumentException("Unsupported database type: " + settings.getDatabaseStorageType());
        }

        int port = settings.getDatabasePort();
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("Database port must be in range 1-65535");
        }
    }

    static void validateCache(Settings settings) {
        if (settings.getCacheTtlMinutes() < 0) {
            throw new IllegalArgumentException("Cache TTL must not be negative");
        }
        if (settings.getCacheMaxSize() <= 0) {
            throw new IllegalArgumentException("Cache max size must be > 0");
        }
        if (settings.getCacheCleanupIntervalMinutes() <= 0) {
            throw new IllegalArgumentException("Cache cleanup interval must be > 0");
        }
        if (settings.getPremiumTtlHours() <= 0) {
            throw new IllegalArgumentException("Premium TTL hours must be > 0");
        }
        if (settings.getPremiumRefreshThreshold() < 0.0 || settings.getPremiumRefreshThreshold() > 1.0) {
            throw new IllegalArgumentException("Premium refresh threshold must be in range 0.0-1.0");
        }
    }

    static void validateSecurity(Settings settings) {
        validateBcryptCost(settings);
        validateBruteForceSettings(settings);
        validatePasswordLengthSettings(settings);
        adjustMaxPasswordLengthIfNeeded(settings);
        validateIpLimitRegistrations(settings);
    }

    static void validateConnection(Settings settings) {
        if (settings.getConnectionTimeoutSeconds() <= 0) {
            throw new IllegalArgumentException("Connection timeout must be > 0");
        }

        if (settings.getDatabaseConnectionPoolSize() <= 0) {
            throw new IllegalArgumentException("Connection pool size must be > 0");
        }
    }

    static void validatePremium(Settings settings) {
        if (!settings.isPremiumCheckEnabled()) {
            return;
        }

        Settings.PremiumResolverSettings resolver = settings.getPremiumResolverSettings();
        if (resolver == null) {
            return;
        }

        validatePremiumResolverSources(resolver);
        validatePremiumResolverTimeout(resolver);
        validatePremiumResolverTtl(resolver);
    }

    private static final int MIN_BCRYPT_COST = 10;
    private static final int MAX_BCRYPT_COST = 31;

    private static void validateBcryptCost(Settings settings) {
        if (settings.getBcryptCost() < MIN_BCRYPT_COST || settings.getBcryptCost() > MAX_BCRYPT_COST) {
            throw new IllegalArgumentException("BCrypt cost must be in range " + MIN_BCRYPT_COST + "-" + MAX_BCRYPT_COST);
        }
    }

    private static void validateBruteForceSettings(Settings settings) {
        if (settings.getBruteForceMaxAttempts() <= 0) {
            throw new IllegalArgumentException("Brute force max attempts must be > 0");
        }
        if (settings.getBruteForceTimeoutMinutes() <= 0) {
            throw new IllegalArgumentException("Brute force timeout must be > 0");
        }
    }

    private static void validatePasswordLengthSettings(Settings settings) {
        if (settings.getMinPasswordLength() <= 0) {
            throw new IllegalArgumentException("Min password length must be > 0");
        }
        if (settings.getMaxPasswordLength() <= settings.getMinPasswordLength()) {
            throw new IllegalArgumentException("Max password length must be > min password length");
        }
    }

    private static void adjustMaxPasswordLengthIfNeeded(Settings settings) {
        if (settings.getMaxPasswordLength() > 72) {
            logger.warn("BCrypt max password length is 72 bytes — adjusting maxPasswordLength from {} to 72",
                    settings.getMaxPasswordLength());
            settings.adjustMaxPasswordLength();
        }
    }

    private static void validateIpLimitRegistrations(Settings settings) {
        if (settings.getIpLimitRegistrations() <= 0) {
            throw new IllegalArgumentException("IP limit registrations must be > 0");
        }
    }

    private static void validatePremiumResolverSources(Settings.PremiumResolverSettings resolver) {
        if (!resolver.isMojangEnabled() && !resolver.isAshconEnabled() && !resolver.isWpmeEnabled()) {
            throw new IllegalArgumentException("Premium resolver: at least one source (mojang/ashcon/wpme) must be enabled");
        }
    }

    private static void validatePremiumResolverTimeout(Settings.PremiumResolverSettings resolver) {
        if (resolver.getRequestTimeoutMs() <= 0) {
            throw new IllegalArgumentException("Premium resolver: request-timeout-ms must be > 0");
        }
    }

    private static void validatePremiumResolverTtl(Settings.PremiumResolverSettings resolver) {
        if (resolver.getHitTtlMinutes() < 0 || resolver.getMissTtlMinutes() < 0) {
            throw new IllegalArgumentException("Premium resolver: TTL in minutes must not be negative");
        }
    }

    static void validateFloodgate(Settings settings) {
        if (!settings.isFloodgateIntegrationEnabled()) {
            return;
        }

        String prefix = requireFloodgatePrefix(settings);
        validateFloodgatePrefix(prefix);
        warnAboutFloodgateConfiguration(prefix);
    }

    private static String requireFloodgatePrefix(Settings settings) {
        String prefix = settings.getFloodgateUsernamePrefix();
        if (prefix == null) {
            throw new IllegalArgumentException("Floodgate username prefix must not be null");
        }
        return prefix;
    }

    private static void validateFloodgatePrefix(String prefix) {
        if (prefix.length() > 16) {
            throw new IllegalArgumentException("Floodgate username prefix must be at most 16 characters");
        }
        if (prefix.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException("Floodgate username prefix must not contain whitespace");
        }
    }

    private static void warnAboutFloodgateConfiguration(String prefix) {
        if (prefix.isEmpty()) {
            logger.warn("Floodgate integration is enabled with an empty username prefix; ensure Java and Bedrock usernames cannot collide");
        }
        if (isCollisionPronePrefix(prefix)) {
            logger.warn("Floodgate username prefix '{}' is alphanumeric; this increases the risk of username collisions", prefix);
        }
        if (!FloodgateDetector.isFloodgateAvailable()) {
            logger.warn("Floodgate integration is enabled in config but Floodgate plugin is not loaded; Bedrock player detection will not work");
        }
    }

    private static boolean isCollisionPronePrefix(String prefix) {
        return !prefix.isEmpty() && prefix.chars().allMatch(SettingsValidator::isUsernameSafeCharacter);
    }

    private static boolean isUsernameSafeCharacter(int value) {
        return Character.isLetterOrDigit(value) || value == '_';
    }
}
