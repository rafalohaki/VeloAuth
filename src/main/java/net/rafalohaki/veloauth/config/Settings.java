package net.rafalohaki.veloauth.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import net.rafalohaki.veloauth.database.DatabaseType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * VeloAuth configuration with YAML support and validation.
 * Thread-safe immutable configuration object.
 * 
 * <h2>Extracted Components</h2>
 * <ul>
 *   <li>{@link SettingsValidator} - configuration validation</li>
 *   <li>{@link DefaultConfigGenerator} - default config.yml generation</li>
 *   <li>{@link YamlParserUtils} - YAML value parsing utilities</li>
 * </ul>
 */
public class Settings {

    private static final Logger logger = LoggerFactory.getLogger(Settings.class);

    private final Path dataDirectory;
    private final Path configFile;
    private final ObjectMapper yamlMapper;
    private final PostgreSQLSettings postgreSQLSettings = new PostgreSQLSettings();
    private final PremiumSettings premiumSettings = new PremiumSettings();
    private final FloodgateSettings floodgateSettings = new FloodgateSettings();
    private final AlertSettings alertSettings = new AlertSettings();
    private final PasswordPolicy passwordPolicy = new PasswordPolicy();
    private final AuditLogSettings auditLogSettings = new AuditLogSettings();
    private final TwoFactorSettings twoFactorSettings = new TwoFactorSettings();
    @SuppressWarnings("java:S2068")
    private static final String DEFAULT_DATABASE_NAME = "veloauth";
    
    // Database settings
    private String databaseStorageType = DatabaseType.H2.getName();
    private String databaseHostname = "localhost";
    private int databasePort = 3306;
    private String databaseName = DEFAULT_DATABASE_NAME;
    private String databaseUser = DEFAULT_DATABASE_NAME;
    @SuppressWarnings("java:S2068")
    private String databasePassword = "";
    private String databaseConnectionUrl = null;
    private String databaseConnectionParameters = "";
    private int databaseConnectionPoolSize = 20;
    private long databaseMaxLifetimeMillis = 1800000;
    // Cache settings
    private int cacheTtlMinutes = 60;
    private int cacheMaxSize = 10000;
    private int cacheCleanupIntervalMinutes = 5;
    private int sessionTimeoutMinutes = 60;
    private int premiumTtlHours = 24;
    private double premiumRefreshThreshold = 0.8;
    // Auth server settings
    private String authServerName = "limbo";
    private int authServerTimeoutSeconds = 300;
    // Connection settings
    private int connectionTimeoutSeconds = 30;
    // Security settings
    private int bcryptCost = 10;
    private int bruteForceMaxAttempts = 5;
    private int bruteForceTimeoutMinutes = 5;
    private int ipLimitRegistrations = 3;
    private int minPasswordLength = 8;
    private int maxPasswordLength = 72;
    // Debug settings
    private boolean debugEnabled = false;
    // Language settings
    private String language = "en";

    /**
     * Creates a new Settings instance.
     *
     * @param dataDirectory plugin data directory
     */
    public Settings(Path dataDirectory) {
        this.dataDirectory = dataDirectory;
        this.configFile = dataDirectory.resolve("config.yml");
        this.yamlMapper = new ObjectMapper(new YAMLFactory());

        try {
            Files.createDirectories(dataDirectory);
        } catch (IOException e) {
            logger.error("Failed to create data directory: {}", dataDirectory, e);
        }
    }

    /**
     * Loads configuration from YAML file.
     *
     * @return true on success
     */
    public boolean load() {
        try {
            if (!Files.exists(configFile)) {
                logger.debug("Creating default config file: {}", configFile);
                DefaultConfigGenerator.createDefaultConfig(configFile);
            }

            logger.debug("Loading configuration from: {}", configFile);

            applyLoadedState(SettingsLoader.load(this, configFile, yamlMapper, logger));

            try {
                SettingsValidator.validate(this);
            } catch (IllegalArgumentException e) {
                // Validator throws on invalid config values. Convert to a graceful failure so
                // VeloAuth.initializeConfiguration() and /vauth reload can report it without
                // a stack trace propagating to the player or to Velocity's event dispatch.
                // The live Settings instance is left in whatever state the loader applied; on
                // first load the plugin aborts init, and on /vauth reload the caller can surface
                // the validation error to the operator and keep running with the partial state.
                logger.error("Invalid configuration in {}: {}", configFile, e.getMessage());
                if (logger.isDebugEnabled()) {
                    logger.debug("Configuration validation failure details", e);
                }
                return false;
            }

            logger.debug("Configuration loaded successfully");
            return true;

        } catch (JsonProcessingException e) {
            logger.error("YAML parse error in config file: {}", configFile, e);
            return false;
        } catch (IOException e) {
            logger.error("Error reading config file: {}", configFile, e);
            return false;
        }
    }

    private void applyLoadedState(SettingsLoader.LoadedState state) {
        databaseStorageType = state.databaseStorageType;
        databaseHostname = state.databaseHostname;
        databasePort = state.databasePort;
        databaseName = state.databaseName;
        databaseUser = state.databaseUser;
        databasePassword = state.databasePassword;
        databaseConnectionUrl = state.databaseConnectionUrl;
        databaseConnectionParameters = state.databaseConnectionParameters;
        databaseConnectionPoolSize = state.databaseConnectionPoolSize;
        databaseMaxLifetimeMillis = state.databaseMaxLifetimeMillis;
        cacheTtlMinutes = state.cacheTtlMinutes;
        cacheMaxSize = state.cacheMaxSize;
        cacheCleanupIntervalMinutes = state.cacheCleanupIntervalMinutes;
        sessionTimeoutMinutes = state.sessionTimeoutMinutes;
        premiumTtlHours = state.premiumTtlHours;
        premiumRefreshThreshold = state.premiumRefreshThreshold;
        authServerName = state.authServerName;
        authServerTimeoutSeconds = state.authServerTimeoutSeconds;
        connectionTimeoutSeconds = state.connectionTimeoutSeconds;
        bcryptCost = state.bcryptCost;
        bruteForceMaxAttempts = state.bruteForceMaxAttempts;
        bruteForceTimeoutMinutes = state.bruteForceTimeoutMinutes;
        ipLimitRegistrations = state.ipLimitRegistrations;
        minPasswordLength = state.minPasswordLength;
        maxPasswordLength = state.maxPasswordLength;
        debugEnabled = state.debugEnabled;
        language = state.language;
        copyPostgreSqlSettings(state.postgreSQLSettings);
        copyPremiumSettings(state.premiumSettings);
        copyFloodgateSettings(state.floodgateSettings);
        copyAlertSettings(state.alertSettings);
        copyPasswordPolicy(state.passwordPolicy);
        copyAuditLogSettings(state.auditLogSettings);
        copyTwoFactorSettings(state.twoFactorSettings);
    }

    private void copyAuditLogSettings(AuditLogSettings source) {
        auditLogSettings.setEnabled(source.isEnabled());
        auditLogSettings.setRetentionDays(source.getRetentionDays());
    }

    private void copyTwoFactorSettings(TwoFactorSettings source) {
        twoFactorSettings.setEnabled(source.isEnabled());
        twoFactorSettings.setIssuer(source.getIssuer());
        twoFactorSettings.setQrLinkEnabled(source.isQrLinkEnabled());
        twoFactorSettings.setPendingTimeoutSeconds(source.getPendingTimeoutSeconds());
    }

    private void copyPasswordPolicy(PasswordPolicy source) {
        passwordPolicy.setMinDigits(source.getMinDigits());
        passwordPolicy.setMinUppercase(source.getMinUppercase());
        passwordPolicy.setMinLowercase(source.getMinLowercase());
        passwordPolicy.setMinSpecial(source.getMinSpecial());
    }

    private void copyPostgreSqlSettings(PostgreSQLSettings source) {
        postgreSQLSettings.setSslEnabled(source.isSslEnabled());
        postgreSQLSettings.setSslMode(source.getSslMode());
        postgreSQLSettings.setSslCert(source.getSslCert());
        postgreSQLSettings.setSslKey(source.getSslKey());
        postgreSQLSettings.setSslRootCert(source.getSslRootCert());
        postgreSQLSettings.setSslPassword(source.getSslPassword());
    }

    private void copyPremiumSettings(PremiumSettings source) {
        premiumSettings.setCheckEnabled(source.isCheckEnabled());
        premiumSettings.setOnlineModeNeedAuth(source.isOnlineModeNeedAuth());
        premiumSettings.setAllowCrackedOnPremiumNicks(source.isAllowCrackedOnPremiumNicks());
        premiumSettings.getResolver().copyFrom(source.getResolver());
    }

    private void copyFloodgateSettings(FloodgateSettings source) {
        floodgateSettings.setEnabled(source.isEnabled());
        floodgateSettings.setUsernamePrefix(source.getUsernamePrefix());
        floodgateSettings.setBypassAuthServer(source.isBypassAuthServer());
    }

    private void copyAlertSettings(AlertSettings source) {
        alertSettings.setEnabled(source.isEnabled());
        alertSettings.setDiscordEnabled(source.isDiscordEnabled());
        alertSettings.setDiscordWebhookUrl(source.getDiscordWebhookUrl());
        alertSettings.setFailureRateThreshold(source.getFailureRateThreshold());
        alertSettings.setMinRequestsForAlert(source.getMinRequestsForAlert());
        alertSettings.setCheckIntervalMinutes(source.getCheckIntervalMinutes());
        alertSettings.setAlertCooldownMinutes(source.getAlertCooldownMinutes());
    }

    // ===== Package-private mutation methods for validator =====

    void adjustMaxPasswordLength() {
        maxPasswordLength = 72;
    }

    void normalizeLanguage() {
        if (language == null || language.trim().isEmpty()) {
            logger.warn("Language setting is empty, using default 'en'");
            language = "en";
            return;
        }
        language = language.toLowerCase().trim();
        logger.debug("Language setting: {} (will fall back to 'en' if file not found)", language);
    }

    // ===== Getters =====

    public String getDatabaseStorageType() {
        return databaseStorageType != null ? databaseStorageType : DatabaseType.H2.getName();
    }

    public String getDatabaseHostname() {
        return databaseHostname != null ? databaseHostname : "localhost";
    }

    public int getDatabasePort() {
        return databasePort;
    }

    public String getDatabaseName() {
        return databaseName != null ? databaseName : DEFAULT_DATABASE_NAME;
    }

    public String getDatabaseUser() {
        return databaseUser != null ? databaseUser : DEFAULT_DATABASE_NAME;
    }

    public String getDatabasePassword() {
        return databasePassword != null ? databasePassword : "";
    }

    public String getDatabaseConnectionUrl() {
        return databaseConnectionUrl;
    }

    public int getConnectionTimeoutSeconds() {
        return connectionTimeoutSeconds;
    }

    public String getDatabaseConnectionParameters() {
        return databaseConnectionParameters != null ? databaseConnectionParameters : "";
    }

    public int getDatabaseConnectionPoolSize() {
        return databaseConnectionPoolSize;
    }

    public long getDatabaseMaxLifetimeMillis() {
        return databaseMaxLifetimeMillis;
    }

    public PostgreSQLSettings getPostgreSQLSettings() {
        return postgreSQLSettings;
    }

    public int getCacheTtlMinutes() {
        return cacheTtlMinutes;
    }

    public int getCacheMaxSize() {
        return cacheMaxSize;
    }

    public int getCacheCleanupIntervalMinutes() {
        return cacheCleanupIntervalMinutes;
    }

    public int getSessionTimeoutMinutes() {
        return sessionTimeoutMinutes;
    }

    public int getPremiumTtlHours() {
        return premiumTtlHours;
    }

    public double getPremiumRefreshThreshold() {
        return premiumRefreshThreshold;
    }

    public String getAuthServerName() {
        return authServerName != null ? authServerName : "limbo";
    }

    public int getAuthServerTimeoutSeconds() {
        return authServerTimeoutSeconds;
    }

    public int getBcryptCost() {
        return bcryptCost;
    }

    public int getBruteForceMaxAttempts() {
        return bruteForceMaxAttempts;
    }

    public int getBruteForceTimeoutMinutes() {
        return bruteForceTimeoutMinutes;
    }

    public int getIpLimitRegistrations() {
        return ipLimitRegistrations;
    }

    public int getMinPasswordLength() {
        return minPasswordLength;
    }

    public int getMaxPasswordLength() {
        return maxPasswordLength;
    }

    public PasswordPolicy getPasswordPolicy() {
        return passwordPolicy;
    }

    public boolean isPremiumCheckEnabled() {
        return premiumSettings.isCheckEnabled();
    }

    public boolean isOnlineModeNeedAuth() {
        return premiumSettings.isOnlineModeNeedAuth();
    }

    public boolean isAllowCrackedOnPremiumNicks() {
        return premiumSettings.isAllowCrackedOnPremiumNicks();
    }

    public PremiumResolverSettings getPremiumResolverSettings() {
        return premiumSettings.getResolver();
    }

    public PremiumSettings getPremiumSettings() {
        return premiumSettings;
    }

    public boolean isFloodgateIntegrationEnabled() {
        return floodgateSettings.isEnabled();
    }

    public String getFloodgateUsernamePrefix() {
        return floodgateSettings.getUsernamePrefix();
    }

    public boolean isFloodgateBypassAuthServerEnabled() {
        return floodgateSettings.isBypassAuthServer();
    }

    public FloodgateSettings getFloodgateSettings() {
        return floodgateSettings;
    }

    public boolean isDebugEnabled() {
        return debugEnabled;
    }

    public Path getDataDirectory() {
        return dataDirectory;
    }

    public Path getConfigFile() {
        return configFile;
    }

    public String getLanguage() {
        return language;
    }

    public AlertSettings getAlertSettings() {
        return alertSettings;
    }

    public AuditLogSettings getAuditLogSettings() {
        return auditLogSettings;
    }

    public TwoFactorSettings getTwoFactorSettings() {
        return twoFactorSettings;
    }

    // ===== Inner Settings Classes =====

    /**
     * Resolver-specific configuration mapped from premium.resolver.
     */
    public static class PremiumResolverSettings {
        private boolean mojangEnabled = true;
        private boolean ashconEnabled = true;
        private boolean wpmeEnabled = false;
        private int requestTimeoutMs = 2000;
        private int hitTtlMinutes = 10;
        private int missTtlMinutes = 3;
        private boolean caseSensitive = true;
        private int memoryCacheMaxSize = 10_000;

        public boolean isMojangEnabled() { return mojangEnabled; }
        void setMojangEnabled(boolean value) { this.mojangEnabled = value; }
        public boolean isAshconEnabled() { return ashconEnabled; }
        void setAshconEnabled(boolean value) { this.ashconEnabled = value; }
        public boolean isWpmeEnabled() { return wpmeEnabled; }
        void setWpmeEnabled(boolean value) { this.wpmeEnabled = value; }
        public int getRequestTimeoutMs() { return requestTimeoutMs; }
        void setRequestTimeoutMs(int value) { this.requestTimeoutMs = value; }
        public int getHitTtlMinutes() { return hitTtlMinutes; }
        void setHitTtlMinutes(int value) { this.hitTtlMinutes = value; }
        public int getMissTtlMinutes() { return missTtlMinutes; }
        void setMissTtlMinutes(int value) { this.missTtlMinutes = value; }
        public boolean isCaseSensitive() { return caseSensitive; }
        void setCaseSensitive(boolean value) { this.caseSensitive = value; }
        public int getMemoryCacheMaxSize() { return memoryCacheMaxSize; }
        void setMemoryCacheMaxSize(int value) { this.memoryCacheMaxSize = value; }

        void copyFrom(PremiumResolverSettings source) {
            this.mojangEnabled = source.mojangEnabled;
            this.ashconEnabled = source.ashconEnabled;
            this.wpmeEnabled = source.wpmeEnabled;
            this.requestTimeoutMs = source.requestTimeoutMs;
            this.hitTtlMinutes = source.hitTtlMinutes;
            this.missTtlMinutes = source.missTtlMinutes;
            this.caseSensitive = source.caseSensitive;
            this.memoryCacheMaxSize = source.memoryCacheMaxSize;
        }
    }

    /**
     * PostgreSQL-specific database configuration.
     */
    public static class PostgreSQLSettings {
        private boolean sslEnabled = true;
        private String sslMode = "require";
        private String sslCert = "";
        @SuppressWarnings("java:S2068")
        private String sslKey = "";
        private String sslRootCert = "";
        @SuppressWarnings("java:S2068")
        private String sslPassword = "";
        
        public boolean isSslEnabled() { return sslEnabled; }
        void setSslEnabled(boolean value) { this.sslEnabled = value; }
        public String getSslMode() { return sslMode; }
        void setSslMode(String value) { this.sslMode = value; }
        public String getSslCert() { return sslCert; }
        void setSslCert(String value) { this.sslCert = value; }
        public String getSslKey() { return sslKey; }
        void setSslKey(String value) { this.sslKey = value; }
        public String getSslRootCert() { return sslRootCert; }
        void setSslRootCert(String value) { this.sslRootCert = value; }
        public String getSslPassword() { return sslPassword; }
        void setSslPassword(String value) { this.sslPassword = value; }
    }

    /**
     * Premium account detection configuration.
     */
    public static class PremiumSettings {
        private final PremiumResolverSettings resolver = new PremiumResolverSettings();
        private boolean checkEnabled = true;
        private boolean onlineModeNeedAuth = false;
        private boolean allowCrackedOnPremiumNicks = false;

        public boolean isCheckEnabled() { return checkEnabled; }
        void setCheckEnabled(boolean value) { this.checkEnabled = value; }
        public boolean isOnlineModeNeedAuth() { return onlineModeNeedAuth; }
        void setOnlineModeNeedAuth(boolean value) { this.onlineModeNeedAuth = value; }
        public boolean isAllowCrackedOnPremiumNicks() { return allowCrackedOnPremiumNicks; }
        void setAllowCrackedOnPremiumNicks(boolean value) { this.allowCrackedOnPremiumNicks = value; }
        public PremiumResolverSettings getResolver() { return resolver; }
    }

    /**
     * Floodgate integration configuration.
     */
    public static class FloodgateSettings {
        private boolean enabled = false;
        private String usernamePrefix = ".";
        private boolean bypassAuthServer = true;

        public boolean isEnabled() { return enabled; }
        void setEnabled(boolean value) { this.enabled = value; }
        public String getUsernamePrefix() { return usernamePrefix != null ? usernamePrefix : "."; }
        void setUsernamePrefix(String value) { this.usernamePrefix = value != null ? value : "."; }
        public boolean isBypassAuthServer() { return bypassAuthServer; }
        void setBypassAuthServer(boolean value) { this.bypassAuthServer = value; }
    }

    /**
     * Alert system configuration for Discord webhooks.
     */
    public static class AlertSettings {
        private boolean enabled = false;
        private boolean discordEnabled = false;
        private String discordWebhookUrl = "";
        private double failureRateThreshold = 0.5;
        private int minRequestsForAlert = 10;
        private int checkIntervalMinutes = 5;
        private int alertCooldownMinutes = 30;

        public boolean isEnabled() { return enabled; }
        void setEnabled(boolean value) { this.enabled = value; }
        public boolean isDiscordEnabled() { return discordEnabled; }
        void setDiscordEnabled(boolean value) { this.discordEnabled = value; }
        public String getDiscordWebhookUrl() { return discordWebhookUrl; }
        void setDiscordWebhookUrl(String value) { this.discordWebhookUrl = value; }
        public double getFailureRateThreshold() { return failureRateThreshold; }
        void setFailureRateThreshold(double value) { this.failureRateThreshold = value; }
        public int getMinRequestsForAlert() { return minRequestsForAlert; }
        void setMinRequestsForAlert(int value) { this.minRequestsForAlert = value; }
        public int getCheckIntervalMinutes() { return checkIntervalMinutes; }
        void setCheckIntervalMinutes(int value) { this.checkIntervalMinutes = value; }
        public int getAlertCooldownMinutes() { return alertCooldownMinutes; }
        void setAlertCooldownMinutes(int value) { this.alertCooldownMinutes = value; }
    }

    /**
     * Audit log persistence configuration. Default enabled with 90-day retention.
     * Disabling stops both writes and the cleanup scheduler.
     */
    public static class AuditLogSettings {
        private boolean enabled = true;
        private int retentionDays = 90;

        public boolean isEnabled() { return enabled; }
        void setEnabled(boolean value) { this.enabled = value; }
        public int getRetentionDays() { return retentionDays; }
        void setRetentionDays(int value) { this.retentionDays = value; }
    }

    /**
     * 2FA / TOTP configuration. Opt-in per player; {@code enabled=false} disables
     * the entire feature (existing TOTP tokens stop being enforced and {@code /2fa setup}
     * is rejected). Backward-compatible with LimboAuth's {@code TOTPTOKEN} column
     * because we use the same RFC 6238 parameter set as every other authenticator app.
     */
    public static class TwoFactorSettings {
        private boolean enabled = true;
        private String issuer = "VeloAuth";
        private boolean qrLinkEnabled = true;
        private int pendingTimeoutSeconds = 300;

        public boolean isEnabled() { return enabled; }
        void setEnabled(boolean value) { this.enabled = value; }
        public String getIssuer() { return issuer; }
        void setIssuer(String value) { this.issuer = (value == null || value.isBlank()) ? "VeloAuth" : value; }
        public boolean isQrLinkEnabled() { return qrLinkEnabled; }
        void setQrLinkEnabled(boolean value) { this.qrLinkEnabled = value; }
        public int getPendingTimeoutSeconds() { return pendingTimeoutSeconds; }
        void setPendingTimeoutSeconds(int value) { this.pendingTimeoutSeconds = value; }
    }

    /**
     * Password complexity policy. All counters default to 0 (= no constraint),
     * preserving backward compatibility with configs that omit the password-policy section.
     */
    public static class PasswordPolicy {
        private int minDigits;
        private int minUppercase;
        private int minLowercase;
        private int minSpecial;

        public int getMinDigits() { return minDigits; }
        void setMinDigits(int value) { this.minDigits = Math.max(0, value); }
        public int getMinUppercase() { return minUppercase; }
        void setMinUppercase(int value) { this.minUppercase = Math.max(0, value); }
        public int getMinLowercase() { return minLowercase; }
        void setMinLowercase(int value) { this.minLowercase = Math.max(0, value); }
        public int getMinSpecial() { return minSpecial; }
        void setMinSpecial(int value) { this.minSpecial = Math.max(0, value); }

        public boolean isAnyComplexityRequired() {
            return minDigits > 0 || minUppercase > 0 || minLowercase > 0 || minSpecial > 0;
        }

        /**
         * Test-only factory for constructing a fully-specified policy outside this package.
         * Production code loads policy values via {@link SettingsLoader}.
         */
        public static PasswordPolicy forTesting(int minDigits, int minUppercase,
                                                int minLowercase, int minSpecial) {
            PasswordPolicy p = new PasswordPolicy();
            p.setMinDigits(minDigits);
            p.setMinUppercase(minUppercase);
            p.setMinLowercase(minLowercase);
            p.setMinSpecial(minSpecial);
            return p;
        }
    }
}
