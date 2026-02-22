package net.rafalohaki.veloauth.config;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import net.rafalohaki.veloauth.database.DatabaseType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

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
    private final AlertSettings alertSettings = new AlertSettings();
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
    private int connectionTimeoutSeconds = 20;
    // Security settings
    private int bcryptCost = 10;
    private int bruteForceMaxAttempts = 5;
    private int bruteForceTimeoutMinutes = 5;
    private int ipLimitRegistrations = 3;
    private int minPasswordLength = 4;
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
                return true;
            }

            logger.debug("Loading configuration from: {}", configFile);

            @SuppressWarnings("unchecked")
            Map<String, Object> config = yamlMapper.readValue(configFile.toFile(), Map.class);

            loadDatabaseSettings(config);
            loadCacheSettings(config);
            loadAuthServerSettings(config);
            loadConnectionSettings(config);
            loadSecuritySettings(config);
            loadPremiumSettings(config);
            loadAlertSettings(config);
            loadDebugSettings(config);
            loadLanguageSettings(config);

            processDatabaseSettings();
            SettingsValidator.validate(this);

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

    // ===== Loading Methods =====

    @SuppressWarnings("unchecked")
    private void loadDatabaseSettings(Map<String, Object> config) {
        Map<String, Object> database = (Map<String, Object>) config.get("database");
        if (database != null) {
            databaseStorageType = YamlParserUtils.getString(database, "storage-type", databaseStorageType);
            databaseHostname = YamlParserUtils.getString(database, "hostname", databaseHostname);
            databasePort = YamlParserUtils.getInt(database, "port", databasePort);
            databaseName = YamlParserUtils.getString(database, "database", databaseName);
            databaseUser = YamlParserUtils.getString(database, "user", databaseUser);
            databasePassword = YamlParserUtils.getString(database, "password", databasePassword);
            databaseConnectionUrl = YamlParserUtils.getString(database, "connection-url", databaseConnectionUrl);
            databaseConnectionParameters = YamlParserUtils.getString(database, "connection-parameters", databaseConnectionParameters);
            databaseConnectionPoolSize = YamlParserUtils.getInt(database, "connection-pool-size", databaseConnectionPoolSize);
            databaseMaxLifetimeMillis = YamlParserUtils.getLong(database, "max-lifetime-millis", databaseMaxLifetimeMillis);

            loadPostgreSQLSettings(database);
        }
    }

    @SuppressWarnings("unchecked")
    private void loadPostgreSQLSettings(Map<String, Object> database) {
        Object postgreSQLSection = database.get("postgresql");
        if (postgreSQLSection instanceof Map<?, ?>) {
            Map<String, Object> postgreSQL = (Map<String, Object>) postgreSQLSection;
            postgreSQLSettings.setSslEnabled(YamlParserUtils.getBoolean(postgreSQL, "ssl-enabled", postgreSQLSettings.isSslEnabled()));
            postgreSQLSettings.setSslMode(YamlParserUtils.getString(postgreSQL, "ssl-mode", postgreSQLSettings.getSslMode()));
            postgreSQLSettings.setSslCert(YamlParserUtils.getString(postgreSQL, "ssl-cert", postgreSQLSettings.getSslCert()));
            postgreSQLSettings.setSslKey(YamlParserUtils.getString(postgreSQL, "ssl-key", postgreSQLSettings.getSslKey()));
            postgreSQLSettings.setSslRootCert(YamlParserUtils.getString(postgreSQL, "ssl-root-cert", postgreSQLSettings.getSslRootCert()));
            postgreSQLSettings.setSslPassword(YamlParserUtils.getString(postgreSQL, "ssl-password", postgreSQLSettings.getSslPassword()));
        }
    }

    private void loadDebugSettings(Map<String, Object> config) {
        debugEnabled = YamlParserUtils.getBoolean(config, "debug-enabled", debugEnabled);
    }

    private void loadLanguageSettings(Map<String, Object> config) {
        language = YamlParserUtils.getString(config, "language", language);
    }

    @SuppressWarnings("unchecked")
    private void loadCacheSettings(Map<String, Object> config) {
        Map<String, Object> cache = (Map<String, Object>) config.get("cache");
        if (cache != null) {
            cacheTtlMinutes = YamlParserUtils.getInt(cache, "ttl-minutes", cacheTtlMinutes);
            cacheMaxSize = YamlParserUtils.getInt(cache, "max-size", cacheMaxSize);
            cacheCleanupIntervalMinutes = YamlParserUtils.getInt(cache, "cleanup-interval-minutes", cacheCleanupIntervalMinutes);
            sessionTimeoutMinutes = YamlParserUtils.getInt(cache, "session-timeout-minutes", sessionTimeoutMinutes);
            premiumTtlHours = YamlParserUtils.getInt(cache, "premium-ttl-hours", premiumTtlHours);
            premiumRefreshThreshold = YamlParserUtils.getDouble(cache, "premium-refresh-threshold", premiumRefreshThreshold);
        }
    }

    @SuppressWarnings("unchecked")
    private void loadAuthServerSettings(Map<String, Object> config) {
        Map<String, Object> authServer = (Map<String, Object>) config.get("auth-server");
        if (authServer != null) {
            authServerName = YamlParserUtils.getString(authServer, "server-name", authServerName);
            authServerTimeoutSeconds = YamlParserUtils.getInt(authServer, "timeout-seconds", authServerTimeoutSeconds);
            return;
        }
        @SuppressWarnings("unchecked")
        Map<String, Object> picolimbo = (Map<String, Object>) config.get("picolimbo");
        if (picolimbo != null) {
            logger.warn("Config section 'picolimbo:' is deprecated — rename to 'auth-server:' in config.yml");
            authServerName = YamlParserUtils.getString(picolimbo, "server-name", authServerName);
            authServerTimeoutSeconds = YamlParserUtils.getInt(picolimbo, "timeout-seconds", authServerTimeoutSeconds);
        }
    }

    @SuppressWarnings("unchecked")
    private void loadConnectionSettings(Map<String, Object> config) {
        Map<String, Object> connection = (Map<String, Object>) config.get("connection");
        if (connection != null) {
            connectionTimeoutSeconds = YamlParserUtils.getInt(connection, "timeout-seconds", connectionTimeoutSeconds);
        }
    }

    @SuppressWarnings("unchecked")
    private void loadSecuritySettings(Map<String, Object> config) {
        Map<String, Object> security = (Map<String, Object>) config.get("security");
        if (security != null) {
            bcryptCost = YamlParserUtils.getInt(security, "bcrypt-cost", bcryptCost);
            bruteForceMaxAttempts = YamlParserUtils.getInt(security, "bruteforce-max-attempts", bruteForceMaxAttempts);
            bruteForceTimeoutMinutes = YamlParserUtils.getInt(security, "bruteforce-timeout-minutes", bruteForceTimeoutMinutes);
            ipLimitRegistrations = YamlParserUtils.getInt(security, "ip-limit-registrations", ipLimitRegistrations);
            minPasswordLength = YamlParserUtils.getInt(security, "min-password-length", minPasswordLength);
            maxPasswordLength = YamlParserUtils.getInt(security, "max-password-length", maxPasswordLength);
        }
    }

    @SuppressWarnings("java:S3776")
    private void loadPremiumSettings(Map<String, Object> config) {
        Object premiumSection = config.get("premium");
        if (premiumSection instanceof Map<?, ?>) {
            @SuppressWarnings("unchecked")
            Map<String, Object> premium = (Map<String, Object>) premiumSection;
            premiumSettings.setCheckEnabled(YamlParserUtils.getBoolean(premium, "check-enabled", premiumSettings.isCheckEnabled()));
            premiumSettings.setOnlineModeNeedAuth(YamlParserUtils.getBoolean(premium, "online-mode-need-auth", premiumSettings.isOnlineModeNeedAuth()));

            if (premium.containsKey("premium-uuid-resolver")) {
                logger.warn("Detected legacy key premium.premium-uuid-resolver — ignoring. Configure premium.resolver.* instead");
            }

            Object resolverSection = premium.get("resolver");
            if (resolverSection instanceof Map<?, ?>) {
                @SuppressWarnings("unchecked")
                Map<String, Object> resolver = (Map<String, Object>) resolverSection;
                applyResolverSettings(resolver);
            }
        }

        if (config.containsKey("premium-resolver")) {
            logger.warn("Detected legacy section premium-resolver — ignoring. Configure premium.resolver.* instead");
        }
    }

    private void applyResolverSettings(Map<String, Object> resolver) {
        PremiumResolverSettings target = premiumSettings.getResolver();
        target.setMojangEnabled(YamlParserUtils.getBoolean(resolver, "mojang-enabled", target.isMojangEnabled()));
        target.setAshconEnabled(YamlParserUtils.getBoolean(resolver, "ashcon-enabled", target.isAshconEnabled()));
        target.setWpmeEnabled(YamlParserUtils.getBoolean(resolver, "wpme-enabled", target.isWpmeEnabled()));
        target.setRequestTimeoutMs(YamlParserUtils.getInt(resolver, "request-timeout-ms", target.getRequestTimeoutMs()));
        target.setHitTtlMinutes(YamlParserUtils.getInt(resolver, "hit-ttl-minutes", target.getHitTtlMinutes()));
        target.setMissTtlMinutes(YamlParserUtils.getInt(resolver, "miss-ttl-minutes", target.getMissTtlMinutes()));
        target.setCaseSensitive(YamlParserUtils.getBoolean(resolver, "case-sensitive", target.isCaseSensitive()));
    }

    private void loadAlertSettings(Map<String, Object> config) {
        Object alertSection = config.get("alerts");
        if (alertSection instanceof Map<?, ?>) {
            @SuppressWarnings("unchecked")
            Map<String, Object> alerts = (Map<String, Object>) alertSection;
            alertSettings.setEnabled(YamlParserUtils.getBoolean(alerts, "enabled", alertSettings.isEnabled()));
            alertSettings.setFailureRateThreshold(YamlParserUtils.getDouble(alerts, "failure-rate-threshold", alertSettings.getFailureRateThreshold()));
            alertSettings.setMinRequestsForAlert(YamlParserUtils.getInt(alerts, "min-requests-for-alert", alertSettings.getMinRequestsForAlert()));
            alertSettings.setCheckIntervalMinutes(YamlParserUtils.getInt(alerts, "check-interval-minutes", alertSettings.getCheckIntervalMinutes()));
            alertSettings.setAlertCooldownMinutes(YamlParserUtils.getInt(alerts, "alert-cooldown-minutes", alertSettings.getAlertCooldownMinutes()));

            Object discordSection = alerts.get("discord");
            if (discordSection instanceof Map<?, ?>) {
                @SuppressWarnings("unchecked")
                Map<String, Object> discord = (Map<String, Object>) discordSection;
                alertSettings.setDiscordEnabled(YamlParserUtils.getBoolean(discord, "enabled", alertSettings.isDiscordEnabled()));
                alertSettings.setDiscordWebhookUrl(YamlParserUtils.getString(discord, "webhook-url", alertSettings.getDiscordWebhookUrl()));
            }
        }
    }

    // ===== Connection URL Parsing =====

    private void processDatabaseSettings() {
        if (databaseConnectionUrl != null && !databaseConnectionUrl.trim().isEmpty()) {
            parseConnectionUrl(databaseConnectionUrl);
        }
    }

    private void parseConnectionUrl(String connectionUrl) {
        try {
            String url = connectionUrl.trim();

            databaseStorageType = detectDatabaseType(url);
            if (databaseStorageType == null) {
                return;
            }

            String remaining = url.substring(url.indexOf("://") + 3);
            parseConnectionCredentials(remaining);

        } catch (StringIndexOutOfBoundsException e) {
            logger.error("Invalid database connection URL format: {}", connectionUrl, e);
        } catch (IllegalArgumentException e) {
            logger.error("Invalid connection URL parameters: {}", connectionUrl, e);
        }
    }

    private String detectDatabaseType(String url) {
        DatabaseType dbType = DatabaseType.fromUrl(url);
        return dbType != null ? dbType.getName() : null;
    }

    private void parseConnectionCredentials(String remaining) {
        String[] parts = remaining.split("@");
        if (parts.length == 2) {
            String authPart = parts[0];
            String hostPart = parts[1];

            parseAuthPart(authPart);
            parseHostPart(hostPart);

            logger.info("Parsed connection URL: {}@{}:{}/{}",
                    databaseUser, databaseHostname, databasePort, databaseName);
        }
    }

    private void parseAuthPart(String authPart) {
        String[] authSplit = authPart.split(":");
        if (authSplit.length >= 1) {
            databaseUser = URLDecoder.decode(authSplit[0], StandardCharsets.UTF_8);
        }
        if (authSplit.length >= 2) {
            databasePassword = URLDecoder.decode(authSplit[1], StandardCharsets.UTF_8);
        }
    }

    private void parseHostPart(String hostPart) {
        String[] hostSplit = hostPart.split("/");
        String hostAndPort = hostSplit[0];
        if (hostSplit.length >= 2) {
            databaseName = hostSplit[1];
        }

        String[] hpSplit = hostAndPort.split(":");
        if (hpSplit.length >= 1) {
            databaseHostname = hpSplit[0];
        }
        if (hpSplit.length >= 2) {
            try {
                databasePort = Integer.parseInt(hpSplit[1]);
            } catch (NumberFormatException e) {
                logger.warn("Invalid port in connection URL: {}", hpSplit[1]);
            }
        }
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

    /** @deprecated Use {@link #getAuthServerName()} instead. */
    @Deprecated(since = "1.1.0", forRemoval = true)
    public String getPicoLimboServerName() {
        return getAuthServerName();
    }

    /** @deprecated Use {@link #getAuthServerTimeoutSeconds()} instead. */
    @Deprecated(since = "1.1.0", forRemoval = true)
    public int getPicoLimboTimeoutSeconds() {
        return getAuthServerTimeoutSeconds();
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

    public boolean isPremiumCheckEnabled() {
        return premiumSettings.isCheckEnabled();
    }

    public boolean isOnlineModeNeedAuth() {
        return premiumSettings.isOnlineModeNeedAuth();
    }

    public PremiumResolverSettings getPremiumResolverSettings() {
        return premiumSettings.getResolver();
    }

    public PremiumSettings getPremiumSettings() {
        return premiumSettings;
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
    }

    /**
     * PostgreSQL-specific database configuration.
     */
    public static class PostgreSQLSettings {
        private boolean sslEnabled = true;
        private String sslMode = "require";
        private String sslCert = "";
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

        public boolean isCheckEnabled() { return checkEnabled; }
        void setCheckEnabled(boolean value) { this.checkEnabled = value; }
        public boolean isOnlineModeNeedAuth() { return onlineModeNeedAuth; }
        void setOnlineModeNeedAuth(boolean value) { this.onlineModeNeedAuth = value; }
        public PremiumResolverSettings getResolver() { return resolver; }
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
}
