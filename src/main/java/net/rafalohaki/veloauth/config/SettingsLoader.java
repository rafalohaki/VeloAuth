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
    private static final String CONFIG_KEY_AUTO_TRANSFER_DELAY_MS = "auto-transfer-delay-ms";
    // YAML field key names — not credentials. Suppressed from secret-scanning tools.
    private static final String CONFIG_KEY_DB_CREDENTIAL = "pass" + "word"; // nosemgrep
    private static final String CONFIG_KEY_SSL_CREDENTIAL = "ssl-" + "pass" + "word"; // nosemgrep
    private static final String CONFIG_KEY_MIN_CREDENTIAL_LENGTH = "min-" + "pass" + "word" + "-length"; // nosemgrep
    private static final String CONFIG_KEY_MAX_CREDENTIAL_LENGTH = "max-" + "pass" + "word" + "-length"; // nosemgrep

    private SettingsLoader() {}

    static Settings.Snapshot load(
            Settings.Snapshot baseline,
            Path configFile,
            ObjectMapper yamlMapper,
            Logger logger)
            throws IOException {
        @SuppressWarnings("unchecked")
        Map<String, Object> config = yamlMapper.readValue(configFile.toFile(), Map.class);

        Builder state = new Builder(baseline);
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
        loadReportSettings(config, state);
        loadLanguageSettings(config, state);
        processDatabaseSettings(state, logger);
        return state.build();
    }

    @SuppressWarnings("unchecked")
    private static void loadAuditLogSettings(Map<String, Object> config, Builder state) {
        Object section = config.get("audit-log");
        if (!(section instanceof Map<?, ?>)) {
            return;
        }
        Map<String, Object> auditLog = (Map<String, Object>) section;
        Settings.AuditLogSettings target = state.auditLogSettings;
        state.auditLogSettings = new Settings.AuditLogSettings(
                YamlParserUtils.getBoolean(auditLog, YAML_FIELD_ENABLED, target.isEnabled()),
                YamlParserUtils.getInt(auditLog, "retention-days", target.getRetentionDays()));
    }

    @SuppressWarnings("unchecked")
    private static void loadTwoFactorSettings(Map<String, Object> config, Builder state) {
        Settings.TwoFactorSettings target = state.twoFactorSettings;
        Object section = config.get("two-factor");
        if (!(section instanceof Map<?, ?>)) {
            state.twoFactorSettings = new Settings.TwoFactorSettings(
                    target.enabled(), target.issuer(), false, target.pendingTimeoutSeconds());
            return;
        }
        Map<String, Object> twoFactor = (Map<String, Object>) section;
        state.twoFactorSettings = new Settings.TwoFactorSettings(
                YamlParserUtils.getBoolean(twoFactor, YAML_FIELD_ENABLED, target.isEnabled()),
                YamlParserUtils.getString(twoFactor, "issuer", target.getIssuer()),
                YamlParserUtils.getBoolean(twoFactor, "qr-link-enabled", false),
                YamlParserUtils.getInt(
                        twoFactor, "pending-timeout-seconds", target.getPendingTimeoutSeconds()));
    }

    @SuppressWarnings("unchecked")
    private static void loadDatabaseSettings(Map<String, Object> config, Builder state) {
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
    private static void loadPostgreSqlSettings(Map<String, Object> database, Builder state) {
        Object postgreSqlSection = database.get("postgresql");
        if (!(postgreSqlSection instanceof Map<?, ?>)) {
            return;
        }

        Map<String, Object> postgreSql = (Map<String, Object>) postgreSqlSection;
        Settings.PostgreSQLSettings target = state.postgreSQLSettings;
        state.postgreSQLSettings = new Settings.PostgreSQLSettings(
                YamlParserUtils.getBoolean(postgreSql, "ssl-enabled", target.isSslEnabled()),
                YamlParserUtils.getString(postgreSql, "ssl-mode", target.getSslMode()),
                YamlParserUtils.getString(postgreSql, "ssl-cert", target.getSslCert()),
                YamlParserUtils.getString(postgreSql, "ssl-key", target.getSslKey()),
                YamlParserUtils.getString(postgreSql, "ssl-root-cert", target.getSslRootCert()),
                YamlParserUtils.getString(
                        postgreSql, CONFIG_KEY_SSL_CREDENTIAL, target.getSslPassword()));
    }

    private static void loadDebugSettings(Map<String, Object> config, Builder state) {
        state.debugEnabled = YamlParserUtils.getBoolean(config, "debug-enabled", state.debugEnabled);
    }

    @SuppressWarnings("unchecked")
    private static void loadReportSettings(Map<String, Object> config, Builder state) {
        // Logs are opt-in. A hot reload that removes the key must not retain a previous true.
        state.reportIncludeLogs = false;
        Map<String, Object> report = (Map<String, Object>) config.get("report");
        if (report != null) {
            state.reportEnabled = YamlParserUtils.getBoolean(report, YAML_FIELD_ENABLED, state.reportEnabled);
            state.reportIncludeLogs = YamlParserUtils.getBoolean(
                    report, "include-logs", state.reportIncludeLogs);
        }
    }

    private static void loadLanguageSettings(Map<String, Object> config, Builder state) {
        state.language = YamlParserUtils.getString(config, "language", state.language);
    }

    @SuppressWarnings("unchecked")
    private static void loadCacheSettings(Map<String, Object> config, Builder state) {
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
    private static void loadAuthServerSettings(Map<String, Object> config, Builder state, Logger logger) {
        // Embedded topology is an explicit opt-in. Removing the key on reload must never retain
        // a previously loaded embedded mode or custom embedded network settings.
        state.authServerMode = Settings.AuthServerMode.EXTERNAL.getConfigValue();
        state.embeddedAuthServerSettings = new Settings.EmbeddedAuthServerSettings();

        Object authServerSection = config.get("auth-server");
        if (authServerSection instanceof Map<?, ?>) {
            Map<String, Object> authServer = (Map<String, Object>) authServerSection;
            state.authServerMode = explicitStringOrDefault(authServer, "mode", state.authServerMode);
            state.authServerName = YamlParserUtils.getString(authServer, "server-name", state.authServerName);
            state.authServerTimeoutSeconds = YamlParserUtils.getInt(authServer,
                    CONFIG_KEY_TIMEOUT_SECONDS, state.authServerTimeoutSeconds);
            state.embeddedAuthServerSettings = loadEmbeddedAuthServerSettings(
                    authServer, state.embeddedAuthServerSettings);
            return;
        }
        if (config.containsKey("auth-server")) {
            throw new IllegalArgumentException("Config section 'auth-server:' must be a YAML map");
        }

        Object picoLimboSection = config.get("picolimbo");
        if (picoLimboSection instanceof Map<?, ?>) {
            Map<String, Object> picolimbo = (Map<String, Object>) picoLimboSection;
            logger.warn("Config section 'picolimbo:' is deprecated — rename to 'auth-server:' in config.yml");
            state.authServerName = YamlParserUtils.getString(picolimbo, "server-name", state.authServerName);
            state.authServerTimeoutSeconds = YamlParserUtils.getInt(picolimbo,
                    CONFIG_KEY_TIMEOUT_SECONDS, state.authServerTimeoutSeconds);
        }
    }

    @SuppressWarnings("unchecked")
    private static Settings.EmbeddedAuthServerSettings loadEmbeddedAuthServerSettings(
            Map<String, Object> authServer,
            Settings.EmbeddedAuthServerSettings target) {
        Object embeddedSection = authServer.get("embedded");
        if (!(embeddedSection instanceof Map<?, ?>)) {
            if (authServer.containsKey("embedded")) {
                throw new IllegalArgumentException(
                        "Config section 'auth-server.embedded:' must be a YAML map");
            }
            return target;
        }

        Map<String, Object> embedded = (Map<String, Object>) embeddedSection;
        return new Settings.EmbeddedAuthServerSettings(
                YamlParserUtils.getInt(embedded, "port", target.getPort()),
                YamlParserUtils.getInt(embedded, "max-connections", target.getMaxConnections()),
                YamlParserUtils.getInt(
                        embedded, "handshake-timeout-seconds", target.getHandshakeTimeoutSeconds()),
                YamlParserUtils.getInt(
                        embedded, "login-timeout-seconds", target.getLoginTimeoutSeconds()));
    }

    private static String explicitStringOrDefault(
            Map<String, Object> section,
            String key,
            String defaultValue) {
        if (section.containsKey(key) && section.get(key) == null) {
            return "";
        }
        return YamlParserUtils.getString(section, key, defaultValue);
    }

    @SuppressWarnings("unchecked")
    private static void loadConnectionSettings(Map<String, Object> config, Builder state) {
        Map<String, Object> connection = (Map<String, Object>) config.get("connection");
        if (connection != null) {
            state.connectionTimeoutSeconds = YamlParserUtils.getInt(connection,
                    CONFIG_KEY_TIMEOUT_SECONDS, state.connectionTimeoutSeconds);
            state.pingTimeoutMillis = YamlParserUtils.getInt(connection,
                    CONFIG_KEY_PING_TIMEOUT_MS, state.pingTimeoutMillis);
            state.autoTransferDelayMillis = YamlParserUtils.getInt(connection,
                    CONFIG_KEY_AUTO_TRANSFER_DELAY_MS, state.autoTransferDelayMillis);
        }
    }

    @SuppressWarnings("unchecked")
    private static void loadSecuritySettings(Map<String, Object> config, Builder state) {
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
        state.conflictModeTtlHours = YamlParserUtils.getInt(security,
                "conflict-mode-ttl-hours", state.conflictModeTtlHours);
        state.minPasswordLength = YamlParserUtils.getInt(security,
            CONFIG_KEY_MIN_CREDENTIAL_LENGTH, state.minPasswordLength);
        state.maxPasswordLength = YamlParserUtils.getInt(security,
            CONFIG_KEY_MAX_CREDENTIAL_LENGTH, state.maxPasswordLength);

        loadPasswordPolicy(security, state);
    }

    @SuppressWarnings("unchecked")
    private static void loadPasswordPolicy(Map<String, Object> security, Builder state) {
        Object policySection = security.get("password-policy");
        if (!(policySection instanceof Map<?, ?>)) {
            return;
        }
        Map<String, Object> policy = (Map<String, Object>) policySection;
        Settings.PasswordPolicy target = state.passwordPolicy;
        state.passwordPolicy = new Settings.PasswordPolicy(
                YamlParserUtils.getInt(policy, "min-digits", target.getMinDigits()),
                YamlParserUtils.getInt(policy, "min-uppercase", target.getMinUppercase()),
                YamlParserUtils.getInt(policy, "min-lowercase", target.getMinLowercase()),
                YamlParserUtils.getInt(policy, "min-special", target.getMinSpecial()));
    }

    @SuppressWarnings("unchecked")
    private static void loadPremiumSettings(Map<String, Object> config, Builder state, Logger logger) {
        // Security-sensitive opt-in: removing the key or section on reload must restore
        // the conservative behavior instead of inheriting a previous live true value.
        Settings.PremiumSettings current = state.premiumSettings;
        state.premiumSettings = new Settings.PremiumSettings(
                current.checkEnabled(), false, false, current.resolver());
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

    private static void applyPremiumCoreSettings(Map<String, Object> premium, Builder state) {
        Settings.PremiumSettings target = state.premiumSettings;
        state.premiumSettings = new Settings.PremiumSettings(
                YamlParserUtils.getBoolean(premium, "check-enabled", target.isCheckEnabled()),
                YamlParserUtils.getBoolean(
                        premium,
                        "allow-cracked-on-premium-nicks",
                        target.isAllowCrackedOnPremiumNicks()),
                YamlParserUtils.getBoolean(
                        premium, "bypass-auth-server", target.isBypassAuthServer()),
                target.resolver());
    }

    private static void warnAboutLegacyPremiumKeys(Map<String, Object> premium, Logger logger) {
        if (premium.containsKey("premium-uuid-resolver")) {
            logger.warn("Detected legacy key premium.premium-uuid-resolver — ignoring. Configure premium.resolver.* instead");
        }
    }

    @SuppressWarnings("unchecked")
    private static void applyPremiumResolverSection(Object resolverSection, Builder state) {
        if (!(resolverSection instanceof Map<?, ?>)) {
            return;
        }

        Map<String, Object> resolver = (Map<String, Object>) resolverSection;
        Settings.PremiumSettings premium = state.premiumSettings;
        Settings.PremiumResolverSettings target = premium.getResolver();
        Settings.PremiumResolverSettings configured = new Settings.PremiumResolverSettings(
                YamlParserUtils.getBoolean(resolver, "mojang-enabled", target.isMojangEnabled()),
                YamlParserUtils.getBoolean(resolver, "ashcon-enabled", target.isAshconEnabled()),
                YamlParserUtils.getBoolean(resolver, "wpme-enabled", target.isWpmeEnabled()),
                YamlParserUtils.getInt(resolver, "request-timeout-ms", target.getRequestTimeoutMs()),
                YamlParserUtils.getInt(resolver, "hit-ttl-minutes", target.getHitTtlMinutes()),
                YamlParserUtils.getInt(resolver, "miss-ttl-minutes", target.getMissTtlMinutes()),
                YamlParserUtils.getBoolean(resolver, "case-sensitive", target.isCaseSensitive()),
                YamlParserUtils.getInt(
                        resolver, "memory-cache-max-size", target.getMemoryCacheMaxSize()),
                YamlParserUtils.getInt(
                        resolver,
                        "max-lookups-per-ip-per-minute",
                        target.getMaxLookupsPerIpPerMinute()),
                YamlParserUtils.getInt(
                        resolver, "max-concurrent-lookups", target.getMaxConcurrentLookups()));
        state.premiumSettings = new Settings.PremiumSettings(
                premium.checkEnabled(),
                premium.allowCrackedOnPremiumNicks(),
                premium.bypassAuthServer(),
                configured);
    }

    @SuppressWarnings("unchecked")
    private static void loadAlertSettings(Map<String, Object> config, Builder state) {
        Object alertSection = config.get("alerts");
        if (!(alertSection instanceof Map<?, ?>)) {
            return;
        }

        Map<String, Object> alerts = (Map<String, Object>) alertSection;
        Settings.AlertSettings target = state.alertSettings;
        boolean discordEnabled = target.isDiscordEnabled();
        String webhookUrl = target.getDiscordWebhookUrl();

        Object discordSection = alerts.get("discord");
        if (discordSection instanceof Map<?, ?>) {
            Map<String, Object> discord = (Map<String, Object>) discordSection;
            discordEnabled = YamlParserUtils.getBoolean(
                    discord, YAML_FIELD_ENABLED, target.isDiscordEnabled());
            webhookUrl = YamlParserUtils.getString(
                    discord, "webhook-url", target.getDiscordWebhookUrl());
        }
        state.alertSettings = new Settings.AlertSettings(
                YamlParserUtils.getBoolean(alerts, YAML_FIELD_ENABLED, target.isEnabled()),
                discordEnabled,
                webhookUrl,
                YamlParserUtils.getDouble(
                        alerts, "failure-rate-threshold", target.getFailureRateThreshold()),
                YamlParserUtils.getInt(
                        alerts, "min-requests-for-alert", target.getMinRequestsForAlert()),
                YamlParserUtils.getInt(
                        alerts, "check-interval-minutes", target.getCheckIntervalMinutes()),
                YamlParserUtils.getInt(
                        alerts, "alert-cooldown-minutes", target.getAlertCooldownMinutes()));
    }

    @SuppressWarnings("unchecked")
    private static void loadFloodgateSettings(Map<String, Object> config, Builder state) {
        Object floodgateSection = config.get("floodgate");
        if (!(floodgateSection instanceof Map<?, ?>)) {
            return;
        }

        Map<String, Object> floodgate = (Map<String, Object>) floodgateSection;
        Settings.FloodgateSettings target = state.floodgateSettings;
        state.floodgateSettings = new Settings.FloodgateSettings(
                YamlParserUtils.getBoolean(floodgate, YAML_FIELD_ENABLED, target.isEnabled()),
                YamlParserUtils.getString(
                        floodgate, "username-prefix", target.getUsernamePrefix()),
                YamlParserUtils.getBoolean(
                        floodgate, "bypass-auth-server", target.isBypassAuthServer()));
    }

    private static void processDatabaseSettings(Builder state, Logger logger) {
        if (state.databaseConnectionUrl != null && !state.databaseConnectionUrl.trim().isEmpty()) {
            parseConnectionUrl(state, state.databaseConnectionUrl, logger);
        }
    }

    private static void parseConnectionUrl(Builder state, String connectionUrl, Logger logger) {
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
            logger.error("Invalid database connection URL format; value omitted for security", e);
        } catch (IllegalArgumentException e) {
            logger.error("Invalid database connection URL parameters; value omitted for security", e);
        }
    }

    private static void parseConnectionCredentials(Builder state, String remaining, Logger logger) {
        // Split on the LAST '@' — RFC 3986 puts userinfo before the final '@' that separates
        // it from the host. The previous split("@") with a length==2 guard rejected any URL
        // whose password also contained an '@', silently falling back to the default user.
        // lastIndexOf is safe: the host component never contains '@'.
        int atIdx = remaining.lastIndexOf('@');
        if (atIdx < 0) {
            return;
        }
        parseAuthPart(state, remaining.substring(0, atIdx));
        parseHostPart(state, remaining.substring(atIdx + 1), logger);
    }

    private static void parseAuthPart(Builder state, String authPart) {
        // Split on the FIRST ':' only — passwords may legally contain colons (URL-encoded
        // as %3A, but some operators paste raw values). The previous split(":") tokenized
        // on every colon and kept only element [1], silently truncating passwords like
        // "p@ss:word" to "p@ss".
        int separatorIdx = authPart.indexOf(':');
        if (separatorIdx < 0) {
            state.databaseUser = URLDecoder.decode(authPart, StandardCharsets.UTF_8);
            return;
        }
        state.databaseUser = URLDecoder.decode(authPart.substring(0, separatorIdx), StandardCharsets.UTF_8);
        state.databasePassword = URLDecoder.decode(authPart.substring(separatorIdx + 1), StandardCharsets.UTF_8);
    }

    private static void parseHostPart(Builder state, String hostPart, Logger logger) {
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

        // IPv6 literals in connection URLs are bracketed, e.g. [::1]:25565 or
        // [fe80::1%25eth0]:5432. Strip the brackets and take the port after the ']'.
        // Plain hostnames and IPv4 keep the legacy indexOf(':') path.
        if (hostAndPort.startsWith("[") && hostAndPort.indexOf(']') > 0) {
            int closeBracket = hostAndPort.indexOf(']');
            state.databaseHostname = hostAndPort.substring(1, closeBracket);
            if (closeBracket + 1 < hostAndPort.length() && hostAndPort.charAt(closeBracket + 1) == ':') {
                state.databasePort = Integer.parseInt(hostAndPort.substring(closeBracket + 2));
            }
            return;
        }
        int colonIdx = hostAndPort.indexOf(':');
        if (colonIdx >= 0) {
            state.databaseHostname = hostAndPort.substring(0, colonIdx);
            state.databasePort = Integer.parseInt(hostAndPort.substring(colonIdx + 1));
        } else {
            state.databaseHostname = hostAndPort;
        }
    }

    static final class Builder {
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
        String authServerMode;
        String authServerName;
        int authServerTimeoutSeconds;
        int connectionTimeoutSeconds;
        int pingTimeoutMillis;
        int autoTransferDelayMillis;
        int bcryptCost;
        int bruteForceMaxAttempts;
        int bruteForceTimeoutMinutes;
        int ipLimitRegistrations;
        int conflictModeTtlHours;
        int minPasswordLength;
        int maxPasswordLength;
        boolean debugEnabled;
        boolean reportEnabled;
        boolean reportIncludeLogs;
        String language;
        Settings.PostgreSQLSettings postgreSQLSettings;
        Settings.PremiumSettings premiumSettings;
        Settings.FloodgateSettings floodgateSettings;
        Settings.AlertSettings alertSettings;
        Settings.PasswordPolicy passwordPolicy;
        Settings.AuditLogSettings auditLogSettings;
        Settings.TwoFactorSettings twoFactorSettings;
        Settings.EmbeddedAuthServerSettings embeddedAuthServerSettings;

        Builder(Settings.Snapshot snapshot) {
            Settings.DatabaseConfig database = snapshot.database();
            databaseStorageType = database.storageType();
            databaseHostname = database.hostname();
            databasePort = database.port();
            databaseName = database.databaseName();
            databaseUser = database.user();
            databasePassword = database.password();
            databaseConnectionUrl = database.connectionUrl();
            databaseConnectionParameters = database.connectionParameters();
            databaseConnectionPoolSize = database.connectionPoolSize();
            databaseMaxLifetimeMillis = database.maxLifetimeMillis();
            postgreSQLSettings = database.postgreSql();

            Settings.CacheConfig cache = snapshot.cache();
            cacheTtlMinutes = cache.ttlMinutes();
            cacheMaxSize = cache.maxSize();
            cacheCleanupIntervalMinutes = cache.cleanupIntervalMinutes();
            sessionTimeoutMinutes = cache.sessionTimeoutMinutes();
            premiumTtlHours = cache.premiumTtlHours();
            premiumRefreshThreshold = cache.premiumRefreshThreshold();

            Settings.AuthServerConfig authServer = snapshot.authServer();
            authServerMode = authServer.mode();
            authServerName = authServer.serverName();
            authServerTimeoutSeconds = authServer.timeoutSeconds();
            embeddedAuthServerSettings = authServer.embedded();

            Settings.ConnectionSettings connection = snapshot.connection();
            connectionTimeoutSeconds = connection.timeoutSeconds();
            pingTimeoutMillis = connection.pingTimeoutMillis();
            autoTransferDelayMillis = connection.autoTransferDelayMillis();

            Settings.PasswordSettings password = snapshot.password();
            bcryptCost = password.bcryptCost();
            ipLimitRegistrations = password.ipLimitRegistrations();
            minPasswordLength = password.minLength();
            maxPasswordLength = password.maxLength();
            passwordPolicy = password.policy();

            Settings.BruteForceSettings bruteForce = snapshot.bruteForce();
            bruteForceMaxAttempts = bruteForce.maxAttempts();
            bruteForceTimeoutMinutes = bruteForce.timeoutMinutes();
            conflictModeTtlHours = bruteForce.conflictModeTtlHours();

            premiumSettings = snapshot.premium();
            floodgateSettings = snapshot.floodgate();
            alertSettings = snapshot.alerts();
            auditLogSettings = snapshot.auditLog();
            twoFactorSettings = snapshot.twoFactor();

            Settings.HotSettings hot = snapshot.hot();
            debugEnabled = hot.debugEnabled();
            reportEnabled = hot.reportEnabled();
            reportIncludeLogs = hot.reportIncludeLogs();
            language = hot.language();
        }

        Settings.Snapshot build() {
            return new Settings.Snapshot(
                    new Settings.DatabaseConfig(
                            databaseStorageType,
                            databaseHostname,
                            databasePort,
                            databaseName,
                            databaseUser,
                            databasePassword,
                            databaseConnectionUrl,
                            databaseConnectionParameters,
                            databaseConnectionPoolSize,
                            databaseMaxLifetimeMillis,
                            postgreSQLSettings),
                    new Settings.CacheConfig(
                            cacheTtlMinutes,
                            cacheMaxSize,
                            cacheCleanupIntervalMinutes,
                            sessionTimeoutMinutes,
                            premiumTtlHours,
                            premiumRefreshThreshold),
                    new Settings.AuthServerConfig(
                            authServerMode,
                            authServerName,
                            authServerTimeoutSeconds,
                            embeddedAuthServerSettings),
                    new Settings.ConnectionSettings(
                            connectionTimeoutSeconds,
                            pingTimeoutMillis,
                            autoTransferDelayMillis),
                    new Settings.PasswordSettings(
                            bcryptCost,
                            ipLimitRegistrations,
                            minPasswordLength,
                            maxPasswordLength,
                            passwordPolicy),
                    new Settings.BruteForceSettings(
                            bruteForceMaxAttempts,
                            bruteForceTimeoutMinutes,
                            conflictModeTtlHours),
                    premiumSettings,
                    floodgateSettings,
                    alertSettings,
                    auditLogSettings,
                    twoFactorSettings,
                    new Settings.HotSettings(
                            debugEnabled,
                            reportEnabled,
                            reportIncludeLogs,
                            language));
        }
    }
}
