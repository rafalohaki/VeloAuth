package net.rafalohaki.veloauth.config;

import net.rafalohaki.veloauth.database.DatabaseType;
import org.spongepowered.configurate.loader.ParsingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.locks.ReentrantLock;

/**
 * VeloAuth configuration with YAML support and validation.
 *
 * <p><b>Concurrency model:</b> a validated immutable generation is published through one
 * volatile {@link Publication} reference. Reload retains restart-only values in the active
 * generation, stores the complete valid candidate as configured state, and reports the differing
 * groups through {@link #getPendingRestartChanges()}.
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
    private final ReentrantLock loadLock = new ReentrantLock();
    private volatile Publication publication = Publication.defaults();
    @SuppressWarnings("java:S2068")
    private static final String DEFAULT_DATABASE_NAME = "veloauth";

    /**
     * Creates a new Settings instance.
     *
     * @param dataDirectory plugin data directory
     */
    public Settings(Path dataDirectory) {
        this.dataDirectory = dataDirectory;
        this.configFile = dataDirectory.resolve("config.yml");
        try {
            Files.createDirectories(dataDirectory);
        } catch (IOException e) {
            logger.error("Failed to create data directory: {}", dataDirectory, e);
        }
    }

    private Settings(Settings source, Snapshot snapshot) {
        this.dataDirectory = source.dataDirectory;
        this.configFile = source.configFile;
        this.publication = Publication.initial(snapshot);
    }

    /**
     * Loads configuration from YAML file.
     *
     * @return true on success
     */
    public boolean load() {
        loadLock.lock();
        try {
            if (!Files.exists(configFile)) {
                logger.debug("Creating default config file: {}", configFile);
                DefaultConfigGenerator.createDefaultConfig(configFile);
            }

            logger.debug("Loading configuration from: {}", configFile);

            Publication current = publication;
            Snapshot loadedSnapshot = SettingsLoader.load(configFile, logger);
            Settings candidate = new Settings(this, loadedSnapshot);
            if (!candidate.validateLoadedConfig()) {
                return false;
            }
            Snapshot configured = candidate.activeSnapshot();
            Snapshot active = current.loaded()
                    ? current.active().withHotValuesFrom(configured)
                    : configured;
            publication = new Publication(
                    active,
                    configured,
                    pendingRestartChanges(active, configured),
                    true);

            logger.debug("Configuration loaded successfully");
            return true;

        } catch (ParsingException e) {
            logger.error("YAML parse error in config file: {}", configFile, e);
            return false;
        } catch (IllegalArgumentException e) {
            logger.error("Invalid configuration in {}: {}", configFile, e.getMessage());
            if (logger.isDebugEnabled()) {
                logger.debug("Configuration loading failure details", e);
            }
            return false;
        } catch (IOException e) {
            logger.error("Error reading config file: {}", configFile, e);
            return false;
        } finally {
            loadLock.unlock();
        }
    }

    // Validator throws on invalid config values. Convert to a graceful failure so
    // VeloAuth.initializeConfiguration() and /vauth reload can report it without
    // a stack trace propagating to the player or to Velocity's event dispatch.
    // Validation runs against an unpublished candidate. On /vauth reload, rejected
    // values therefore cannot partially mutate the live settings used by login events.
    private boolean validateLoadedConfig() {
        try {
            SettingsValidator.validate(this);
            return true;
        } catch (IllegalArgumentException e) {
            logger.error("Invalid configuration in {}: {}", configFile, e.getMessage());
            if (logger.isDebugEnabled()) {
                logger.debug("Configuration validation failure details", e);
            }
            return false;
        }
    }

    // ===== Package-private mutation methods for validator =====

    void adjustMaxPasswordLength() {
        Snapshot adjusted = activeSnapshot().withMaximumPasswordLength(72);
        publication = Publication.initial(adjusted);
    }

    void normalizeLanguage() {
        String language = getLanguage();
        if (language == null || language.trim().isEmpty()) {
            logger.warn("Language setting is empty, using default 'en'");
            publication = Publication.initial(activeSnapshot().withLanguage("en"));
            return;
        }
        String normalized = language.toLowerCase().trim();
        publication = Publication.initial(activeSnapshot().withLanguage(normalized));
        logger.debug("Language setting: {} (will fall back to 'en' if file not found)", normalized);
    }

    // ===== Getters =====

    public String getDatabaseStorageType() {
        return activeSnapshot().database().storageType();
    }

    public String getDatabaseHostname() {
        return activeSnapshot().database().hostname();
    }

    public int getDatabasePort() {
        return activeSnapshot().database().port();
    }

    public String getDatabaseName() {
        return activeSnapshot().database().databaseName();
    }

    public String getDatabaseUser() {
        return activeSnapshot().database().user();
    }

    public String getDatabasePassword() {
        return activeSnapshot().database().password();
    }

    public String getDatabaseConnectionUrl() {
        return activeSnapshot().database().connectionUrl();
    }

    public int getConnectionTimeoutSeconds() {
        return activeSnapshot().connection().timeoutSeconds();
    }

    public int getPingTimeoutMillis() {
        return activeSnapshot().connection().pingTimeoutMillis();
    }

    public int getAutoTransferDelayMillis() {
        return activeSnapshot().connection().autoTransferDelayMillis();
    }

    public String getDatabaseConnectionParameters() {
        return activeSnapshot().database().connectionParameters();
    }

    public int getDatabaseConnectionPoolSize() {
        return activeSnapshot().database().connectionPoolSize();
    }

    public long getDatabaseMaxLifetimeMillis() {
        return activeSnapshot().database().maxLifetimeMillis();
    }

    public PostgreSQLSettings getPostgreSQLSettings() {
        return activeSnapshot().database().postgreSql();
    }

    public int getCacheTtlMinutes() {
        return activeSnapshot().cache().ttlMinutes();
    }

    public int getCacheMaxSize() {
        return activeSnapshot().cache().maxSize();
    }

    public int getCacheCleanupIntervalMinutes() {
        return activeSnapshot().cache().cleanupIntervalMinutes();
    }

    public int getSessionTimeoutMinutes() {
        return activeSnapshot().cache().sessionTimeoutMinutes();
    }

    public int getPremiumTtlHours() {
        return activeSnapshot().cache().premiumTtlHours();
    }

    public double getPremiumRefreshThreshold() {
        return activeSnapshot().cache().premiumRefreshThreshold();
    }

    public String getAuthServerName() {
        return activeSnapshot().authServer().serverName();
    }

    public AuthServerMode getAuthServerMode() {
        return AuthServerMode.parse(activeSnapshot().authServer().mode());
    }

    String getConfiguredAuthServerMode() {
        return activeSnapshot().authServer().mode();
    }

    public EmbeddedAuthServerSettings getEmbeddedAuthServerSettings() {
        return activeSnapshot().authServer().embedded();
    }

    public int getAuthServerTimeoutSeconds() {
        return activeSnapshot().authServer().timeoutSeconds();
    }

    public int getBcryptCost() {
        return activeSnapshot().password().bcryptCost();
    }

    public int getBruteForceMaxAttempts() {
        return activeSnapshot().bruteForce().maxAttempts();
    }

    public int getBruteForceTimeoutMinutes() {
        return activeSnapshot().bruteForce().timeoutMinutes();
    }

    public int getIpLimitRegistrations() {
        return activeSnapshot().password().ipLimitRegistrations();
    }

    public int getMinPasswordLength() {
        return activeSnapshot().password().minLength();
    }

    public int getMaxPasswordLength() {
        return activeSnapshot().password().maxLength();
    }

    /**
     * Returns the CONFLICT_MODE time-to-live in hours. After this window, a stale conflict
     * entry forces full UUID verification again. {@code 0} disables the TTL (permanent
     * conflict — the pre-1.3.3 behaviour) for operators who want it.
     *
     * @return TTL in hours, or {@code 0} to disable TTL-based conflict expiry
     */
    public int getConflictModeTtlHours() {
        return activeSnapshot().bruteForce().conflictModeTtlHours();
    }

    public PasswordPolicy getPasswordPolicy() {
        return activeSnapshot().password().policy();
    }

    public PasswordSettings getPasswordSettings() {
        return activeSnapshot().password();
    }

    public boolean isPremiumCheckEnabled() {
        return activeSnapshot().premium().isCheckEnabled();
    }

    public boolean isAllowCrackedOnPremiumNicks() {
        return activeSnapshot().premium().isAllowCrackedOnPremiumNicks();
    }

    public boolean isPremiumBypassAuthServerEnabled() {
        return activeSnapshot().premium().isBypassAuthServer();
    }

    public PremiumResolverSettings getPremiumResolverSettings() {
        return activeSnapshot().premium().getResolver();
    }

    public PremiumSettings getPremiumSettings() {
        return activeSnapshot().premium();
    }

    public boolean isFloodgateIntegrationEnabled() {
        return activeSnapshot().floodgate().isEnabled();
    }

    public String getFloodgateUsernamePrefix() {
        return activeSnapshot().floodgate().getUsernamePrefix();
    }

    public boolean isFloodgateBypassAuthServerEnabled() {
        return activeSnapshot().floodgate().isBypassAuthServer();
    }

    public FloodgateSettings getFloodgateSettings() {
        return activeSnapshot().floodgate();
    }

    public boolean isDebugEnabled() {
        return activeSnapshot().hot().debugEnabled();
    }

    public boolean isReportEnabled() {
        return activeSnapshot().hot().reportEnabled();
    }

    public boolean isReportIncludeLogs() {
        return activeSnapshot().hot().reportIncludeLogs();
    }

    public Path getDataDirectory() {
        return dataDirectory;
    }

    public Path getConfigFile() {
        return configFile;
    }

    public String getLanguage() {
        return activeSnapshot().hot().language();
    }

    public AlertSettings getAlertSettings() {
        return activeSnapshot().alerts();
    }

    public AuditLogSettings getAuditLogSettings() {
        return activeSnapshot().auditLog();
    }

    public TwoFactorSettings getTwoFactorSettings() {
        return activeSnapshot().twoFactor();
    }

    public Set<String> getPendingRestartChanges() {
        return publication.pendingRestartChanges();
    }

    public boolean hasPendingRestartChanges() {
        return !getPendingRestartChanges().isEmpty();
    }

    /** Captures related command/auth settings and pending status from one publication. */
    public OperationSettings captureOperationSettings() {
        Publication current = publication;
        Snapshot active = current.active();
        HotSettings hot = active.hot();
        return new OperationSettings(
                active.password(),
                active.bruteForce(),
                active.premium(),
                active.floodgate(),
                active.twoFactor(),
                active.connection(),
                new ReportSettings(hot.reportEnabled(), hot.reportIncludeLogs()),
                current.pendingRestartChanges());
    }

    private Snapshot activeSnapshot() {
        return publication.active();
    }

    // ===== Inner Settings Classes =====

    /**
     * Selects who owns the unauthenticated holding server. Both configurations without the key and
     * freshly generated configurations select {@link #EXTERNAL}; embedded mode is explicit opt-in.
     * Changing topology is always restart-required.
     */
    public enum AuthServerMode {
        EXTERNAL("external"),
        EMBEDDED("embedded");

        private final String configValue;

        AuthServerMode(String configValue) {
            this.configValue = configValue;
        }

        public String getConfigValue() {
            return configValue;
        }

        static AuthServerMode parse(String value) {
            return Arrays.stream(values())
                    .filter(candidate -> candidate.configValue.equals(value))
                    .findFirst()
                    .orElseThrow(() -> new IllegalArgumentException(
                            "auth-server.mode must be 'external' or 'embedded' (got '" + value + "')"));
        }
    }

    /**
     * Restart-required embedded auth-server settings. The network address is deliberately not
     * configurable: the implementation always binds to the IP loopback interface.
     */
    public record EmbeddedAuthServerSettings(
            int port,
            int maxConnections,
            int handshakeTimeoutSeconds,
            int loginTimeoutSeconds,
            boolean reviewedRuntimeUpdatesEnabled) {
        static final int DEFAULT_PORT = 0;
        static final int DEFAULT_MAX_CONNECTIONS = 512;
        static final int DEFAULT_HANDSHAKE_TIMEOUT_SECONDS = 10;
        static final int DEFAULT_LOGIN_TIMEOUT_SECONDS = 15;
        static final boolean DEFAULT_REVIEWED_RUNTIME_UPDATES_ENABLED = false;

        public EmbeddedAuthServerSettings() {
            this(DEFAULT_PORT, DEFAULT_MAX_CONNECTIONS,
                    DEFAULT_HANDSHAKE_TIMEOUT_SECONDS, DEFAULT_LOGIN_TIMEOUT_SECONDS,
                    DEFAULT_REVIEWED_RUNTIME_UPDATES_ENABLED);
        }
        public int getPort() { return port; }
        public int getMaxConnections() { return maxConnections; }
        public int getHandshakeTimeoutSeconds() { return handshakeTimeoutSeconds; }
        public int getLoginTimeoutSeconds() { return loginTimeoutSeconds; }
        public boolean isReviewedRuntimeUpdatesEnabled() { return reviewedRuntimeUpdatesEnabled; }
    }

    /**
     * Resolver-specific configuration mapped from premium.resolver.
     */
    public record PremiumResolverSettings(
            boolean mojangEnabled,
            boolean ashconEnabled,
            boolean wpmeEnabled,
            int requestTimeoutMs,
            int hitTtlMinutes,
            int missTtlMinutes,
            boolean caseSensitive,
            int memoryCacheMaxSize,
            int maxLookupsPerIpPerMinute,
            int maxConcurrentLookups) {
        public PremiumResolverSettings() {
            this(true, true, false, 3000, 30, 10, true, 10_000, 30, 32);
        }
        public boolean isMojangEnabled() { return mojangEnabled; }
        public boolean isAshconEnabled() { return ashconEnabled; }
        public boolean isWpmeEnabled() { return wpmeEnabled; }
        public int getRequestTimeoutMs() { return requestTimeoutMs; }
        public int getHitTtlMinutes() { return hitTtlMinutes; }
        public int getMissTtlMinutes() { return missTtlMinutes; }
        public boolean isCaseSensitive() { return caseSensitive; }
        public int getMemoryCacheMaxSize() { return memoryCacheMaxSize; }
        public int getMaxLookupsPerIpPerMinute() { return maxLookupsPerIpPerMinute; }
        public int getMaxConcurrentLookups() { return maxConcurrentLookups; }
    }

    /**
     * PostgreSQL-specific database configuration.
     */
    public record PostgreSQLSettings(
            boolean sslEnabled,
            String sslMode,
            String sslCert,
            String sslKey,
            String sslRootCert,
            String sslPassword) {
        public PostgreSQLSettings() {
            this(true, "require", "", "", "", "");
        }
        public boolean isSslEnabled() { return sslEnabled; }
        public String getSslMode() { return sslMode; }
        public String getSslCert() { return sslCert; }
        public String getSslKey() { return sslKey; }
        public String getSslRootCert() { return sslRootCert; }
        public String getSslPassword() { return sslPassword; }
    }

    /**
     * Premium account detection configuration.
     */
    public record PremiumSettings(
            boolean checkEnabled,
            boolean allowCrackedOnPremiumNicks,
            boolean bypassAuthServer,
            PremiumResolverSettings resolver) {
        public PremiumSettings() {
            this(true, false, false, new PremiumResolverSettings());
        }
        public boolean isCheckEnabled() { return checkEnabled; }
        public boolean isAllowCrackedOnPremiumNicks() { return allowCrackedOnPremiumNicks; }
        public boolean isBypassAuthServer() { return bypassAuthServer; }
        public PremiumResolverSettings getResolver() { return resolver; }

        PremiumSettings withHotValuesFrom(PremiumSettings configured) {
            return new PremiumSettings(
                    configured.checkEnabled,
                    configured.allowCrackedOnPremiumNicks,
                    configured.bypassAuthServer,
                    resolver);
        }
    }

    /**
     * Floodgate integration configuration.
     */
    public record FloodgateSettings(boolean enabled, String usernamePrefix, boolean bypassAuthServer) {
        public FloodgateSettings() {
            this(false, ".", true);
        }

        public FloodgateSettings {
            usernamePrefix = usernamePrefix == null ? "." : usernamePrefix;
        }
        public boolean isEnabled() { return enabled; }
        public String getUsernamePrefix() { return usernamePrefix; }
        public boolean isBypassAuthServer() { return bypassAuthServer; }
    }

    /**
     * Alert system configuration for Discord webhooks.
     */
    public record AlertSettings(
            boolean enabled,
            boolean discordEnabled,
            String discordWebhookUrl,
            double failureRateThreshold,
            int minRequestsForAlert,
            int checkIntervalMinutes,
            int alertCooldownMinutes) {
        public AlertSettings() {
            this(false, false, "", 0.5, 10, 5, 30);
        }
        public boolean isEnabled() { return enabled; }
        public boolean isDiscordEnabled() { return discordEnabled; }
        public String getDiscordWebhookUrl() { return discordWebhookUrl; }
        public double getFailureRateThreshold() { return failureRateThreshold; }
        public int getMinRequestsForAlert() { return minRequestsForAlert; }
        public int getCheckIntervalMinutes() { return checkIntervalMinutes; }
        public int getAlertCooldownMinutes() { return alertCooldownMinutes; }
    }

    /**
     * Audit log persistence configuration. Default enabled with 90-day retention.
     * Disabling stops both writes and the cleanup scheduler.
     */
    public record AuditLogSettings(boolean enabled, int retentionDays) {
        public AuditLogSettings() {
            this(true, 90);
        }
        public boolean isEnabled() { return enabled; }
        public int getRetentionDays() { return retentionDays; }
    }

    /**
     * Restart-only 2FA / TOTP configuration. Opt-in per player; once activated by a restart,
     * {@code enabled=false} disables the entire feature (existing TOTP tokens stop being enforced
     * and {@code /2fa setup} is rejected). Backward-compatible with LimboAuth's {@code TOTPTOKEN} column
     * because we use the same RFC 6238 parameter set as every other authenticator app.
     */
    public record TwoFactorSettings(
            boolean enabled,
            String issuer,
            boolean qrLinkEnabled,
            int pendingTimeoutSeconds) {
        public TwoFactorSettings() {
            this(true, "VeloAuth", false, 300);
        }

        public TwoFactorSettings {
            issuer = issuer == null || issuer.isBlank() ? "VeloAuth" : issuer;
        }
        public boolean isEnabled() { return enabled; }
        public String getIssuer() { return issuer; }
        public boolean isQrLinkEnabled() { return qrLinkEnabled; }
        public int getPendingTimeoutSeconds() { return pendingTimeoutSeconds; }
    }

    /**
     * Password complexity policy. All counters default to 0 (= no constraint),
     * preserving backward compatibility with configs that omit the password-policy section.
     */
    public record PasswordPolicy(int minDigits, int minUppercase, int minLowercase, int minSpecial) {
        public PasswordPolicy() {
            this(0, 0, 0, 0);
        }

        public PasswordPolicy {
            minDigits = Math.max(0, minDigits);
            minUppercase = Math.max(0, minUppercase);
            minLowercase = Math.max(0, minLowercase);
            minSpecial = Math.max(0, minSpecial);
        }
        public int getMinDigits() { return minDigits; }
        public int getMinUppercase() { return minUppercase; }
        public int getMinLowercase() { return minLowercase; }
        public int getMinSpecial() { return minSpecial; }

        public boolean isAnyComplexityRequired() {
            return minDigits > 0 || minUppercase > 0 || minLowercase > 0 || minSpecial > 0;
        }

        /**
         * Test-only factory for constructing a fully-specified policy outside this package.
         * Production code loads policy values via {@link SettingsLoader}.
         */
        public static PasswordPolicy forTesting(int minDigits, int minUppercase,
                                                int minLowercase, int minSpecial) {
            return new PasswordPolicy(minDigits, minUppercase, minLowercase, minSpecial);
        }
    }

    /** Immutable password configuration captured once by a command operation. */
    public record PasswordSettings(
            int bcryptCost,
            int ipLimitRegistrations,
            int minLength,
            int maxLength,
            PasswordPolicy policy) {
    }

    /** Immutable connection tuning captured once by a transfer operation. */
    public record ConnectionSettings(
            int timeoutSeconds,
            int pingTimeoutMillis,
            int autoTransferDelayMillis) {
    }

    public record ReportSettings(boolean enabled, boolean includeLogs) {
    }

    public record BruteForceSettings(int maxAttempts, int timeoutMinutes, int conflictModeTtlHours) {
    }

    public record OperationSettings(
            PasswordSettings password,
            BruteForceSettings bruteForce,
            PremiumSettings premium,
            FloodgateSettings floodgate,
            TwoFactorSettings twoFactor,
            ConnectionSettings connection,
            ReportSettings report,
            Set<String> pendingRestartChanges) {

        public OperationSettings {
            pendingRestartChanges = immutableOrderedSet(pendingRestartChanges);
        }
    }

    record DatabaseConfig(
            String storageType,
            String hostname,
            int port,
            String databaseName,
            String user,
            String password,
            String connectionUrl,
            String connectionParameters,
            int connectionPoolSize,
            long maxLifetimeMillis,
            PostgreSQLSettings postgreSql) {
    }

    record CacheConfig(
            int ttlMinutes,
            int maxSize,
            int cleanupIntervalMinutes,
            int sessionTimeoutMinutes,
            int premiumTtlHours,
            double premiumRefreshThreshold) {
    }

    record AuthServerConfig(
            String mode,
            String serverName,
            int timeoutSeconds,
            EmbeddedAuthServerSettings embedded) {
    }

    record HotSettings(
            boolean debugEnabled,
            boolean reportEnabled,
            boolean reportIncludeLogs,
            String language) {
    }

    record Snapshot(
            DatabaseConfig database,
            CacheConfig cache,
            AuthServerConfig authServer,
            ConnectionSettings connection,
            PasswordSettings password,
            BruteForceSettings bruteForce,
            PremiumSettings premium,
            FloodgateSettings floodgate,
            AlertSettings alerts,
            AuditLogSettings auditLog,
            TwoFactorSettings twoFactor,
            HotSettings hot) {

        static Snapshot defaults() {
            return new Snapshot(
                    new DatabaseConfig(
                            DatabaseType.H2.getName(), "localhost", 3306, DEFAULT_DATABASE_NAME,
                            DEFAULT_DATABASE_NAME, "", null, "", 20, 1_800_000L,
                            new PostgreSQLSettings()),
                    new CacheConfig(60, 10_000, 5, 60, 24, 0.8),
                    new AuthServerConfig(
                            AuthServerMode.EXTERNAL.getConfigValue(), "limbo", 300,
                            new EmbeddedAuthServerSettings()),
                    new ConnectionSettings(30, 3000, 1500),
                    new PasswordSettings(10, 3, 8, 72, new PasswordPolicy()),
                    new BruteForceSettings(5, 5, 168),
                    new PremiumSettings(),
                    new FloodgateSettings(),
                    new AlertSettings(),
                    new AuditLogSettings(),
                    new TwoFactorSettings(),
                    new HotSettings(false, true, false, "en"));
        }

        Snapshot withHotValuesFrom(Snapshot configured) {
            return new Snapshot(
                    database,
                    cache,
                    authServer,
                    connection,
                    password,
                    bruteForce,
                    premium.withHotValuesFrom(configured.premium),
                    floodgate,
                    alerts,
                    auditLog,
                    twoFactor,
                    configured.hot);
        }

        Snapshot withMaximumPasswordLength(int maximum) {
            return new Snapshot(
                    database, cache, authServer, connection,
                    new PasswordSettings(
                            password.bcryptCost,
                            password.ipLimitRegistrations,
                            password.minLength,
                            maximum,
                            password.policy),
                    bruteForce, premium, floodgate, alerts, auditLog, twoFactor, hot);
        }

        Snapshot withLanguage(String language) {
            return new Snapshot(
                    database, cache, authServer, connection, password, bruteForce,
                    premium, floodgate, alerts, auditLog, twoFactor,
                    new HotSettings(
                            hot.debugEnabled,
                            hot.reportEnabled,
                            hot.reportIncludeLogs,
                            language));
        }
    }

    private record Publication(
            Snapshot active,
            Snapshot configured,
            Set<String> pendingRestartChanges,
            boolean loaded) {

        private Publication {
            pendingRestartChanges = immutableOrderedSet(pendingRestartChanges);
        }

        static Publication defaults() {
            Snapshot defaults = Snapshot.defaults();
            return new Publication(defaults, defaults, Set.of(), false);
        }

        static Publication initial(Snapshot snapshot) {
            return new Publication(snapshot, snapshot, Set.of(), true);
        }
    }

    private static Set<String> pendingRestartChanges(Snapshot active, Snapshot configured) {
        Set<String> pending = new LinkedHashSet<>();
        addDifference(pending, "database/pool", active.database, configured.database);
        addDifference(pending, "cache/session", active.cache, configured.cache);
        addDifference(pending, "auth-server", active.authServer, configured.authServer);
        addDifference(pending, "connection", active.connection, configured.connection);
        addDifference(pending, "password/security", active.password, configured.password);
        addDifference(pending, "brute-force", active.bruteForce, configured.bruteForce);
        addDifference(pending, "premium-resolver", active.premium.resolver, configured.premium.resolver);
        addDifference(pending, "floodgate", active.floodgate, configured.floodgate);
        addDifference(pending, "alerts", active.alerts, configured.alerts);
        addDifference(pending, "audit-log", active.auditLog, configured.auditLog);
        addDifference(pending, "two-factor", active.twoFactor, configured.twoFactor);
        return immutableOrderedSet(pending);
    }

    private static Set<String> immutableOrderedSet(Set<String> values) {
        return Collections.unmodifiableSet(new LinkedHashSet<>(values));
    }

    private static void addDifference(Set<String> target, String name, Object active, Object configured) {
        if (!active.equals(configured)) {
            target.add(name);
        }
    }
}
