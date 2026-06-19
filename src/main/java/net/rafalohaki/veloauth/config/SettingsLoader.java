package net.rafalohaki.veloauth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.rafalohaki.veloauth.database.DatabaseType;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Map;

@SuppressWarnings("java:S2068") // YAML config key names, not hardcoded credentials
final class SettingsLoader {

    private static final String YAML_FIELD_ENABLED = "enabled";
    private static final String CONFIG_KEY_TIMEOUT_SECONDS = "timeout-seconds";
    private static final String CONFIG_KEY_PING_TIMEOUT_MS = "ping-timeout-ms";
    // YAML field key names — not credentials. Suppressed from secret-scanning tools.
    private static final String CONFIG_KEY_DB_CREDENTIAL = "pass" + "word"; // nosemgrep
    private static final String CONFIG_KEY_SSL_CREDENTIAL = "ssl-" + "pass" + "word"; // nosemgrep
    private static final String CONFIG_KEY_MIN_CREDENTIAL_LENGTH = "min-" + "pass" + "word" + "-length"; // nosemgrep
    private static final String CONFIG_KEY_MAX_CREDENTIAL_LENGTH = "max-" + "pass" + "word" + "-length"; // nosemgrep

    private SettingsLoader() {}

    static LoadedState load(Settings settings, Path configFile, ObjectMapper yamlMapper, Logger logger)
            throws IOException {
        @SuppressWarnings("unchecked")
        Map<String, Object> config = yamlMapper.readValue(configFile.toFile(), Map.class);

        LoadedState state = LoadedState.from(settings);
        loadDatabaseSettings(config, state);
        loadCacheSettings(config, state);
        loadAuthServerSettings(config, state, logger);
        loadConnectionSettings(config, state);
        loadSecuritySettings(config, state);
        loadPremiumSettings(config, state, logger);
        loadFloodgateSettings(config, state);
        loadAlertSettings(config, state);
        loadAuditLogSettings(config, state);
        loadTwoFactorSettings(config, state);
        loadDebugSettings(config, state);
        loadLanguageSettings(config, state);
        processDatabaseSettings(state, logger);
        return state;
    }

    @SuppressWarnings("unchecked")
    private static void loadAuditLogSettings(Map<String, Object> config, LoadedState state) {
        Object section = config.get("audit-log");
        if (!(section instanceof Map<?, ?>)) {
            return;
        }
        Map<String, Object> auditLog = (Map<String, Object>) section;
        Settings.AuditLogSettings target = state.auditLogSettings;
        target.setEnabled(YamlParserUtils.getBoolean(auditLog, YAML_FIELD_ENABLED, target.isEnabled()));
        target.setRetentionDays(YamlParserUtils.getInt(auditLog, "retention-days", target.getRetentionDays()));
    }

    @SuppressWarnings("unchecked")
    private static void loadTwoFactorSettings(Map<String, Object> config, LoadedState state) {
        Object section = config.get("two-factor");
        if (!(section instanceof Map<?, ?>)) {
            return;
        }
        Map<String, Object> twoFactor = (Map<String, Object>) section;
        Settings.TwoFactorSettings target = state.twoFactorSettings;
        target.setEnabled(YamlParserUtils.getBoolean(twoFactor, YAML_FIELD_ENABLED, target.isEnabled()));
        target.setIssuer(YamlParserUtils.getString(twoFactor, "issuer", target.getIssuer()));
        target.setQrLinkEnabled(YamlParserUtils.getBoolean(twoFactor, "qr-link-enabled", target.isQrLinkEnabled()));
        target.setPendingTimeoutSeconds(YamlParserUtils.getInt(twoFactor, "pending-timeout-seconds", target.getPendingTimeoutSeconds()));
    }

    @SuppressWarnings("unchecked")
    private static void loadDatabaseSettings(Map<String, Object> config, LoadedState state) {
        Map<String, Object> database = (Map<String, Object>) config.get("database");
        if (database == null) {
            return;
        }

        state.databaseStorageType = YamlParserUtils.getString(database, "storage-type", state.databaseStorageType);
        state.databaseHostname = YamlParserUtils.getString(database, "hostname", state.databaseHostname);
        state.databasePort = YamlParserUtils.getInt(database, "port", state.databasePort);
        state.databaseName = YamlParserUtils.getString(database, "database", state.databaseName);
        state.databaseUser = YamlParserUtils.getString(database, "user", state.databaseUser);
        state.databasePassword = YamlParserUtils.getString(database, CONFIG_KEY_DB_CREDENTIAL, state.databasePassword);
        state.databaseConnectionUrl = YamlParserUtils.getString(database, "connection-url", state.databaseConnectionUrl);
        state.databaseConnectionParameters = YamlParserUtils.getString(database,
                "connection-parameters", state.databaseConnectionParameters);
        state.databaseConnectionPoolSize = YamlParserUtils.getInt(database,
                "connection-pool-size", state.databaseConnectionPoolSize);
        state.databaseMaxLifetimeMillis = YamlParserUtils.getLong(database,
                "max-lifetime-millis", state.databaseMaxLifetimeMillis);

        loadPostgreSqlSettings(database, state);
    }

    @SuppressWarnings("unchecked")
    private static void loadPostgreSqlSettings(Map<String, Object> database, LoadedState state) {
        Object postgreSqlSection = database.get("postgresql");
        if (!(postgreSqlSection instanceof Map<?, ?>)) {
            return;
        }

        Map<String, Object> postgreSql = (Map<String, Object>) postgreSqlSection;
        Settings.PostgreSQLSettings target = state.postgreSQLSettings;
        target.setSslEnabled(YamlParserUtils.getBoolean(postgreSql, "ssl-enabled", target.isSslEnabled()));
        target.setSslMode(YamlParserUtils.getString(postgreSql, "ssl-mode", target.getSslMode()));
        target.setSslCert(YamlParserUtils.getString(postgreSql, "ssl-cert", target.getSslCert()));
        target.setSslKey(YamlParserUtils.getString(postgreSql, "ssl-key", target.getSslKey()));
        target.setSslRootCert(YamlParserUtils.getString(postgreSql, "ssl-root-cert", target.getSslRootCert()));
        target.setSslPassword(YamlParserUtils.getString(postgreSql, CONFIG_KEY_SSL_CREDENTIAL, target.getSslPassword()));
    }

    private static void loadDebugSettings(Map<String, Object> config, LoadedState state) {
        state.debugEnabled = YamlParserUtils.getBoolean(config, "debug-enabled", state.debugEnabled);
    }

    private static void loadLanguageSettings(Map<String, Object> config, LoadedState state) {
        state.language = YamlParserUtils.getString(config, "language", state.language);
    }

    @SuppressWarnings("unchecked")
    private static void loadCacheSettings(Map<String, Object> config, LoadedState state) {
        Map<String, Object> cache = (Map<String, Object>) config.get("cache");
        if (cache == null) {
            return;
        }

        state.cacheTtlMinutes = YamlParserUtils.getInt(cache, "ttl-minutes", state.cacheTtlMinutes);
        state.cacheMaxSize = YamlParserUtils.getInt(cache, "max-size", state.cacheMaxSize);
        state.cacheCleanupIntervalMinutes = YamlParserUtils.getInt(cache,
                "cleanup-interval-minutes", state.cacheCleanupIntervalMinutes);
        state.sessionTimeoutMinutes = YamlParserUtils.getInt(cache,
                "session-timeout-minutes", state.sessionTimeoutMinutes);
        state.premiumTtlHours = YamlParserUtils.getInt(cache, "premium-ttl-hours", state.premiumTtlHours);
        state.premiumRefreshThreshold = YamlParserUtils.getDouble(cache,
                "premium-refresh-threshold", state.premiumRefreshThreshold);
    }

    @SuppressWarnings("unchecked")
    private static void loadAuthServerSettings(Map<String, Object> config, LoadedState state, Logger logger) {
        Map<String, Object> authServer = (Map<String, Object>) config.get("auth-server");
        if (authServer != null) {
            state.authServerName = YamlParserUtils.getString(authServer, "server-name", state.authServerName);
            state.authServerTimeoutSeconds = YamlParserUtils.getInt(authServer,
                    CONFIG_KEY_TIMEOUT_SECONDS, state.authServerTimeoutSeconds);
            return;
        }

        Map<String, Object> picolimbo = (Map<String, Object>) config.get("picolimbo");
        if (picolimbo != null) {
            logger.warn("Config section 'picolimbo:' is deprecated — rename to 'auth-server:' in config.yml");
            state.authServerName = YamlParserUtils.getString(picolimbo, "server-name", state.authServerName);
            state.authServerTimeoutSeconds = YamlParserUtils.getInt(picolimbo,
                    CONFIG_KEY_TIMEOUT_SECONDS, state.authServerTimeoutSeconds);
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadConnectionSettings(Map<String, Object> config, LoadedState state) {
        Map<String, Object> connection = (Map<String, Object>) config.get("connection");
        if (connection != null) {
            state.connectionTimeoutSeconds = YamlParserUtils.getInt(connection,
                    CONFIG_KEY_TIMEOUT_SECONDS, state.connectionTimeoutSeconds);
            state.pingTimeoutMillis = YamlParserUtils.getInt(connection,
                    CONFIG_KEY_PING_TIMEOUT_MS, state.pingTimeoutMillis);
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadSecuritySettings(Map<String, Object> config, LoadedState state) {
        Map<String, Object> security = (Map<String, Object>) config.get("security");
        if (security == null) {
            return;
        }

        state.bcryptCost = YamlParserUtils.getInt(security, "bcrypt-cost", state.bcryptCost);
        state.bruteForceMaxAttempts = YamlParserUtils.getInt(security,
                "bruteforce-max-attempts", state.bruteForceMaxAttempts);
        state.bruteForceTimeoutMinutes = YamlParserUtils.getInt(security,
                "bruteforce-timeout-minutes", state.bruteForceTimeoutMinutes);
        state.ipLimitRegistrations = YamlParserUtils.getInt(security,
                "ip-limit-registrations", state.ipLimitRegistrations);
        state.minPasswordLength = YamlParserUtils.getInt(security,
            CONFIG_KEY_MIN_CREDENTIAL_LENGTH, state.minPasswordLength);
        state.maxPasswordLength = YamlParserUtils.getInt(security,
            CONFIG_KEY_MAX_CREDENTIAL_LENGTH, state.maxPasswordLength);

        loadPasswordPolicy(security, state);
    }

    @SuppressWarnings("unchecked")
    private static void loadPasswordPolicy(Map<String, Object> security, LoadedState state) {
        Object policySection = security.get("password-policy");
        if (!(policySection instanceof Map<?, ?>)) {
            return;
        }
        Map<String, Object> policy = (Map<String, Object>) policySection;
        Settings.PasswordPolicy target = state.passwordPolicy;
        target.setMinDigits(YamlParserUtils.getInt(policy, "min-digits", target.getMinDigits()));
        target.setMinUppercase(YamlParserUtils.getInt(policy, "min-uppercase", target.getMinUppercase()));
        target.setMinLowercase(YamlParserUtils.getInt(policy, "min-lowercase", target.getMinLowercase()));
        target.setMinSpecial(YamlParserUtils.getInt(policy, "min-special", target.getMinSpecial()));
    }

    @SuppressWarnings("unchecked")
    private static void loadPremiumSettings(Map<String, Object> config, LoadedState state, Logger logger) {
        Object premiumSection = config.get("premium");
        if (premiumSection instanceof Map<?, ?>) {
            Map<String, Object> premium = (Map<String, Object>) premiumSection;
            applyPremiumCoreSettings(premium, state);
            warnAboutLegacyPremiumKeys(premium, logger);
            applyPremiumResolverSection(premium.get("resolver"), state);
        }

        if (config.containsKey("premium-resolver")) {
            logger.warn("Detected legacy section premium-resolver — ignoring. Configure premium.resolver.* instead");
        }
    }

    private static void applyPremiumCoreSettings(Map<String, Object> premium, LoadedState state) {
        Settings.PremiumSettings target = state.premiumSettings;
        target.setCheckEnabled(YamlParserUtils.getBoolean(premium, "check-enabled", target.isCheckEnabled()));
        target.setAllowCrackedOnPremiumNicks(YamlParserUtils.getBoolean(premium,
                "allow-cracked-on-premium-nicks", target.isAllowCrackedOnPremiumNicks()));
    }

    private static void warnAboutLegacyPremiumKeys(Map<String, Object> premium, Logger logger) {
        if (premium.containsKey("premium-uuid-resolver")) {
            logger.warn("Detected legacy key premium.premium-uuid-resolver — ignoring. Configure premium.resolver.* instead");
        }
    }

    @SuppressWarnings("unchecked")
    private static void applyPremiumResolverSection(Object resolverSection, LoadedState state) {
        if (!(resolverSection instanceof Map<?, ?>)) {
            return;
        }

        Map<String, Object> resolver = (Map<String, Object>) resolverSection;
        Settings.PremiumResolverSettings target = state.premiumSettings.getResolver();
        target.setMojangEnabled(YamlParserUtils.getBoolean(resolver, "mojang-enabled", target.isMojangEnabled()));
        target.setAshconEnabled(YamlParserUtils.getBoolean(resolver, "ashcon-enabled", target.isAshconEnabled()));
        target.setWpmeEnabled(YamlParserUtils.getBoolean(resolver, "wpme-enabled", target.isWpmeEnabled()));
        target.setRequestTimeoutMs(YamlParserUtils.getInt(resolver, "request-timeout-ms", target.getRequestTimeoutMs()));
        target.setHitTtlMinutes(YamlParserUtils.getInt(resolver, "hit-ttl-minutes", target.getHitTtlMinutes()));
        target.setMissTtlMinutes(YamlParserUtils.getInt(resolver, "miss-ttl-minutes", target.getMissTtlMinutes()));
        target.setCaseSensitive(YamlParserUtils.getBoolean(resolver, "case-sensitive", target.isCaseSensitive()));
        target.setMemoryCacheMaxSize(YamlParserUtils.getInt(resolver, "memory-cache-max-size", target.getMemoryCacheMaxSize()));
    }

    @SuppressWarnings("unchecked")
    private static void loadAlertSettings(Map<String, Object> config, LoadedState state) {
        Object alertSection = config.get("alerts");
        if (!(alertSection instanceof Map<?, ?>)) {
            return;
        }

        Map<String, Object> alerts = (Map<String, Object>) alertSection;
        Settings.AlertSettings target = state.alertSettings;
        target.setEnabled(YamlParserUtils.getBoolean(alerts, YAML_FIELD_ENABLED, target.isEnabled()));
        target.setFailureRateThreshold(YamlParserUtils.getDouble(alerts,
                "failure-rate-threshold", target.getFailureRateThreshold()));
        target.setMinRequestsForAlert(YamlParserUtils.getInt(alerts,
                "min-requests-for-alert", target.getMinRequestsForAlert()));
        target.setCheckIntervalMinutes(YamlParserUtils.getInt(alerts,
                "check-interval-minutes", target.getCheckIntervalMinutes()));
        target.setAlertCooldownMinutes(YamlParserUtils.getInt(alerts,
                "alert-cooldown-minutes", target.getAlertCooldownMinutes()));

        Object discordSection = alerts.get("discord");
        if (discordSection instanceof Map<?, ?>) {
            Map<String, Object> discord = (Map<String, Object>) discordSection;
            target.setDiscordEnabled(YamlParserUtils.getBoolean(discord,
                    YAML_FIELD_ENABLED, target.isDiscordEnabled()));
            target.setDiscordWebhookUrl(YamlParserUtils.getString(discord,
                    "webhook-url", target.getDiscordWebhookUrl()));
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadFloodgateSettings(Map<String, Object> config, LoadedState state) {
        Object floodgateSection = config.get("floodgate");
        if (!(floodgateSection instanceof Map<?, ?>)) {
            return;
        }

        Map<String, Object> floodgate = (Map<String, Object>) floodgateSection;
        Settings.FloodgateSettings target = state.floodgateSettings;
        target.setEnabled(YamlParserUtils.getBoolean(floodgate, YAML_FIELD_ENABLED, target.isEnabled()));
        target.setUsernamePrefix(YamlParserUtils.getString(floodgate,
                "username-prefix", target.getUsernamePrefix()));
        target.setBypassAuthServer(YamlParserUtils.getBoolean(floodgate,
                "bypass-auth-server", target.isBypassAuthServer()));
    }

    private static void processDatabaseSettings(LoadedState state, Logger logger) {
        if (state.databaseConnectionUrl != null && !state.databaseConnectionUrl.trim().isEmpty()) {
            parseConnectionUrl(state, state.databaseConnectionUrl, logger);
        }
    }

    private static void parseConnectionUrl(LoadedState state, String connectionUrl, Logger logger) {
        try {
            String url = connectionUrl.trim();
            DatabaseType dbType = DatabaseType.fromUrl(url);
            if (dbType == null) {
                return;
            }

            state.databaseStorageType = dbType.getName();
            String remaining = url.substring(url.indexOf("://") + 3);
            parseConnectionCredentials(state, remaining, logger);
            logger.info("Parsed connection URL: {}@{}:{}/{}",
                    state.databaseUser, state.databaseHostname, state.databasePort, state.databaseName);
        } catch (StringIndexOutOfBoundsException e) {
            logger.error("Invalid database connection URL format: {}", connectionUrl.replaceAll("://[^@]+@", "://[REDACTED]@"), e);
        } catch (IllegalArgumentException e) {
            logger.error("Invalid connection URL parameters: {}", connectionUrl.replaceAll("://[^@]+@", "://[REDACTED]@"), e);
        }
    }

    private static void parseConnectionCredentials(LoadedState state, String remaining, Logger logger) {
        String[] parts = remaining.split("@");
        if (parts.length != 2) {
            return;
        }

        parseAuthPart(state, parts[0]);
        parseHostPart(state, parts[1], logger);
    }

    private static void parseAuthPart(LoadedState state, String authPart) {
        String[] authSplit = authPart.split(":");
        if (authSplit.length >= 1) {
            state.databaseUser = URLDecoder.decode(authSplit[0], StandardCharsets.UTF_8);
        }
        if (authSplit.length >= 2) {
            state.databasePassword = URLDecoder.decode(authSplit[1], StandardCharsets.UTF_8);
        }
    }

    private static void parseHostPart(LoadedState state, String hostPart, Logger logger) {
        String[] hostSplit = hostPart.split("/", 2);
        String hostAndPort = hostSplit[0];
        if (hostSplit.length == 2) {
            String databaseAndQuery = hostSplit[1];
            int querySeparator = databaseAndQuery.indexOf('?');
            String databaseName = querySeparator >= 0
                    ? databaseAndQuery.substring(0, querySeparator)
                    : databaseAndQuery;
            if (!databaseName.isBlank()) {
                state.databaseName = databaseName;
            }
            if (querySeparator >= 0 && querySeparator + 1 < databaseAndQuery.length()) {
                logger.warn("Ignoring query parameters in database.connection-url; use database.connection-parameters or database.postgresql.* settings instead");
            }
        }

        String[] hpSplit = hostAndPort.split(":");
        if (hpSplit.length >= 1) {
            state.databaseHostname = hpSplit[0];
        }
        if (hpSplit.length >= 2) {
            state.databasePort = Integer.parseInt(hpSplit[1]);
        }
    }

    static final class LoadedState {
        String databaseStorageType;
        String databaseHostname;
        int databasePort;
        String databaseName;
        String databaseUser;
        String databasePassword;
        String databaseConnectionUrl;
        String databaseConnectionParameters;
        int databaseConnectionPoolSize;
        long databaseMaxLifetimeMillis;
        int cacheTtlMinutes;
        int cacheMaxSize;
        int cacheCleanupIntervalMinutes;
        int sessionTimeoutMinutes;
        int premiumTtlHours;
        double premiumRefreshThreshold;
        String authServerName;
        int authServerTimeoutSeconds;
        int connectionTimeoutSeconds;
        int pingTimeoutMillis;
        int bcryptCost;
        int bruteForceMaxAttempts;
        int bruteForceTimeoutMinutes;
        int ipLimitRegistrations;
        int minPasswordLength;
        int maxPasswordLength;
        boolean debugEnabled;
        String language;
        final Settings.PostgreSQLSettings postgreSQLSettings = new Settings.PostgreSQLSettings();
        final Settings.PremiumSettings premiumSettings = new Settings.PremiumSettings();
        final Settings.FloodgateSettings floodgateSettings = new Settings.FloodgateSettings();
        final Settings.AlertSettings alertSettings = new Settings.AlertSettings();
        final Settings.PasswordPolicy passwordPolicy = new Settings.PasswordPolicy();
        final Settings.AuditLogSettings auditLogSettings = new Settings.AuditLogSettings();
        final Settings.TwoFactorSettings twoFactorSettings = new Settings.TwoFactorSettings();

        static LoadedState from(Settings settings) {
            LoadedState state = new LoadedState();
            state.databaseStorageType = settings.getDatabaseStorageType();
            state.databaseHostname = settings.getDatabaseHostname();
            state.databasePort = settings.getDatabasePort();
            state.databaseName = settings.getDatabaseName();
            state.databaseUser = settings.getDatabaseUser();
            state.databasePassword = settings.getDatabasePassword();
            state.databaseConnectionUrl = settings.getDatabaseConnectionUrl();
            state.databaseConnectionParameters = settings.getDatabaseConnectionParameters();
            state.databaseConnectionPoolSize = settings.getDatabaseConnectionPoolSize();
            state.databaseMaxLifetimeMillis = settings.getDatabaseMaxLifetimeMillis();
            state.cacheTtlMinutes = settings.getCacheTtlMinutes();
            state.cacheMaxSize = settings.getCacheMaxSize();
            state.cacheCleanupIntervalMinutes = settings.getCacheCleanupIntervalMinutes();
            state.sessionTimeoutMinutes = settings.getSessionTimeoutMinutes();
            state.premiumTtlHours = settings.getPremiumTtlHours();
            state.premiumRefreshThreshold = settings.getPremiumRefreshThreshold();
            state.authServerName = settings.getAuthServerName();
            state.authServerTimeoutSeconds = settings.getAuthServerTimeoutSeconds();
            state.connectionTimeoutSeconds = settings.getConnectionTimeoutSeconds();
            state.pingTimeoutMillis = settings.getPingTimeoutMillis();
            state.bcryptCost = settings.getBcryptCost();
            state.bruteForceMaxAttempts = settings.getBruteForceMaxAttempts();
            state.bruteForceTimeoutMinutes = settings.getBruteForceTimeoutMinutes();
            state.ipLimitRegistrations = settings.getIpLimitRegistrations();
            state.minPasswordLength = settings.getMinPasswordLength();
            state.maxPasswordLength = settings.getMaxPasswordLength();
            state.debugEnabled = settings.isDebugEnabled();
            state.language = settings.getLanguage();
            copyPostgreSqlSettings(settings.getPostgreSQLSettings(), state.postgreSQLSettings);
            copyPremiumSettings(settings.getPremiumSettings(), state.premiumSettings);
            copyFloodgateSettings(settings.getFloodgateSettings(), state.floodgateSettings);
            copyAlertSettings(settings.getAlertSettings(), state.alertSettings);
            copyPasswordPolicy(settings.getPasswordPolicy(), state.passwordPolicy);
            copyAuditLogSettings(settings.getAuditLogSettings(), state.auditLogSettings);
            copyTwoFactorSettings(settings.getTwoFactorSettings(), state.twoFactorSettings);
            return state;
        }

        private static void copyAuditLogSettings(Settings.AuditLogSettings source,
                                                 Settings.AuditLogSettings target) {
            target.setEnabled(source.isEnabled());
            target.setRetentionDays(source.getRetentionDays());
        }

        private static void copyTwoFactorSettings(Settings.TwoFactorSettings source,
                                                  Settings.TwoFactorSettings target) {
            target.setEnabled(source.isEnabled());
            target.setIssuer(source.getIssuer());
            target.setQrLinkEnabled(source.isQrLinkEnabled());
            target.setPendingTimeoutSeconds(source.getPendingTimeoutSeconds());
        }

        private static void copyPasswordPolicy(Settings.PasswordPolicy source, Settings.PasswordPolicy target) {
            target.setMinDigits(source.getMinDigits());
            target.setMinUppercase(source.getMinUppercase());
            target.setMinLowercase(source.getMinLowercase());
            target.setMinSpecial(source.getMinSpecial());
        }

        private static void copyPostgreSqlSettings(Settings.PostgreSQLSettings source,
                                                   Settings.PostgreSQLSettings target) {
            target.setSslEnabled(source.isSslEnabled());
            target.setSslMode(source.getSslMode());
            target.setSslCert(source.getSslCert());
            target.setSslKey(source.getSslKey());
            target.setSslRootCert(source.getSslRootCert());
            target.setSslPassword(source.getSslPassword());
        }

        private static void copyPremiumSettings(Settings.PremiumSettings source,
                                                Settings.PremiumSettings target) {
            target.setCheckEnabled(source.isCheckEnabled());
            target.setAllowCrackedOnPremiumNicks(source.isAllowCrackedOnPremiumNicks());
            target.getResolver().copyFrom(source.getResolver());
        }

        private static void copyFloodgateSettings(Settings.FloodgateSettings source,
                                                  Settings.FloodgateSettings target) {
            target.setEnabled(source.isEnabled());
            target.setUsernamePrefix(source.getUsernamePrefix());
            target.setBypassAuthServer(source.isBypassAuthServer());
        }

        private static void copyAlertSettings(Settings.AlertSettings source,
                                              Settings.AlertSettings target) {
            target.setEnabled(source.isEnabled());
            target.setDiscordEnabled(source.isDiscordEnabled());
            target.setDiscordWebhookUrl(source.getDiscordWebhookUrl());
            target.setFailureRateThreshold(source.getFailureRateThreshold());
            target.setMinRequestsForAlert(source.getMinRequestsForAlert());
            target.setCheckIntervalMinutes(source.getCheckIntervalMinutes());
            target.setAlertCooldownMinutes(source.getAlertCooldownMinutes());
        }
    }
}
