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
 * Konfiguracja VeloAuth z obsługą YAML i walidacją.
 * Thread-safe immutable configuration object.
 */
public class Settings {

    private static final Logger logger = LoggerFactory.getLogger(Settings.class);

    private final Path dataDirectory;
    private final Path configFile;
    private final ObjectMapper yamlMapper;
    private final PostgreSQLSettings postgreSQLSettings = new PostgreSQLSettings();
    // Premium settings
    private final PremiumSettings premiumSettings = new PremiumSettings();
    private final AlertSettings alertSettings = new AlertSettings();
    private static final String DEFAULT_DATABASE_NAME = "veloauth";
    
    // Database settings
    private String databaseStorageType = DatabaseType.H2.getName();
    private String databaseHostname = "localhost";
    private int databasePort = 3306;
    private String databaseName = DEFAULT_DATABASE_NAME;
    private String databaseUser = DEFAULT_DATABASE_NAME;
    @SuppressWarnings("java:S2068") // Not a hardcoded password - configuration placeholder loaded from config.yml
    private String databasePassword = ""; // NOSONAR - Config placeholder, loaded from config.yml
    private String databaseConnectionUrl = null; // Optional full connection URL
    private String databaseConnectionParameters = ""; // Additional connection params
    private int databaseConnectionPoolSize = 20;
    private long databaseMaxLifetimeMillis = 1800000; // 30 minutes default
    // Cache settings
    private int cacheTtlMinutes = 60;
    private int cacheMaxSize = 10000;
    private int cacheCleanupIntervalMinutes = 5;
    private int sessionTimeoutMinutes = 60;
    private int premiumTtlHours = 24;
    private double premiumRefreshThreshold = 0.8;
    // PicoLimbo settings
    private String picoLimboServerName = "limbo";
    private int picoLimboTimeoutSeconds = 300;
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
    private boolean debugEnabled = false; // Default to false for production
    // Language settings
    private String language = "en"; // Default language: en, pl (users can add custom language files)

    /**
     * Tworzy nowy Settings.
     *
     * @param dataDirectory Katalog danych pluginu
     */
    public Settings(Path dataDirectory) {
        this.dataDirectory = dataDirectory;
        this.configFile = dataDirectory.resolve("config.yml");
        this.yamlMapper = new ObjectMapper(new YAMLFactory());

        // Utwórz katalog danych jeśli nie istnieje
        try {
            Files.createDirectories(dataDirectory);
        } catch (IOException e) {
            logger.error("Nie udało się utworzyć katalogu danych: {}", dataDirectory, e);
        }
    }

    /**
     * Ładuje konfigurację z pliku YAML.
     *
     * @return true jeśli sukces
     */
    public boolean load() {
        try {
            // Utwórz domyślny config jeśli nie istnieje
            if (!Files.exists(configFile)) {
                logger.debug("Tworzenie domyślnego pliku konfiguracji: {}", configFile);
                createDefaultConfig();
                return true;
            }

            // Wczytaj config z pliku
            logger.debug("Ładowanie konfiguracji z: {}", configFile);

            @SuppressWarnings("unchecked")
            Map<String, Object> config = yamlMapper.readValue(configFile.toFile(), Map.class);

            loadDatabaseSettings(config);
            loadCacheSettings(config);
            loadPicoLimboSettings(config);
            loadConnectionSettings(config);
            loadSecuritySettings(config);
            loadPremiumSettings(config);
            loadAlertSettings(config);
            loadDebugSettings(config);
            loadLanguageSettings(config);

            // Post-load database processing (connection URL parsing, etc.)
            processDatabaseSettings();

            // Walidacja konfiguracji
            validateSettings();

            logger.debug("Konfiguracja załadowana pomyślnie");
            return true;

        } catch (JsonProcessingException e) {
            logger.error("Błąd parsowania YAML w pliku konfiguracji: {}", configFile, e);
            return false;
        } catch (IOException e) {
            logger.error("Błąd odczytu pliku konfiguracji: {}", configFile, e);
            return false;
        }
    }

    /**
     * Tworzy domyślny plik konfiguracji.
     */
    @SuppressWarnings("java:S138") // Long method - 83 lines of YAML template string, not refactorable
    private void createDefaultConfig() throws IOException {
        String defaultConfig = """
                # VeloAuth Configuration
                # Complete Velocity Authentication Plugin
                
                # Language configuration (built-in: en, pl; custom languages supported)
                language: en # Plugin language: en = English, pl = Polski
                # To add custom language: create messages_XX.properties in plugins/VeloAuth/lang/
                
                # Debug settings (enable for detailed logging)
                debug-enabled: false # Set to true for development/debugging
                
                # Database storage configuration (supported: H2, MYSQL, POSTGRESQL, SQLITE)
                database:
                  storage-type: H2 # Example: MYSQL, POSTGRESQL, SQLITE
                  hostname: localhost # Database host, e.g. db.example.com
                  port: 3306 # Default ports: MYSQL=3306, POSTGRESQL=5432
                  database: veloauth # Database/schema name
                  user: veloauth # Database user
                  password: "" # Strong password recommended
                  connection-pool-size: 20 # Maximum pooled connections
                  max-lifetime-millis: 1800000 # Connection max lifetime in milliseconds (30 minutes)
                  # Optional: Full database connection URL
                  # If set, will be used instead of individual parameters
                  # Examples:
                  #   postgresql://user:pass@host:5432/database
                  #   postgresql://user:pass@host:5432/database?sslmode=disable
                  #   mysql://user:pass@host:3306/database
                  connection-url: ""
                  # Optional: Additional connection parameters
                  # Example: "?autoReconnect=true&initialTimeout=1&useSSL=false&serverTimezone=UTC"
                  connection-parameters: ""
                
                  # PostgreSQL-specific configuration (used when storage-type is POSTGRESQL)
                  postgresql:
                    # Enable SSL connection to PostgreSQL
                    ssl-enabled: false
                    # SSL mode: disable, allow, prefer, require, verify-ca, verify-full
                    ssl-mode: "prefer"
                    # Path to SSL certificate file (optional)
                    ssl-cert: ""
                    # Path to SSL key file (optional)
                    ssl-key: ""
                    # Path to SSL root certificate file (optional)
                    ssl-root-cert: ""
                    # SSL password for key file (optional)
                    ssl-password: ""
                
                # Authentication cache configuration
                cache:
                  ttl-minutes: 60 # Cache entry lifetime
                  max-size: 10000 # Maximum cached records
                  cleanup-interval-minutes: 5 # Cleanup scheduler interval
                  session-timeout-minutes: 60 # Session inactivity timeout in minutes (default: 60)
                  premium-ttl-hours: 24 # Premium status cache TTL in hours (default: 24)
                  premium-refresh-threshold: 0.8 # Background refresh threshold (0.0-1.0, default: 0.8)
                
                # PicoLimbo integration (fallback server for unauthenticated players)
                picolimbo:
                  server-name: limbo # Registered Velocity server name
                  timeout-seconds: 300 # Kick timeout for PicoLimbo
                
                # Connection settings
                connection:
                  timeout-seconds: 20 # Connection timeout in seconds. Increase if your backend servers are slow.
                
                # Security settings for password hashing and brute-force protection
                security:
                  bcrypt-cost: 10 # BCrypt hashing rounds (4-31)
                  bruteforce-max-attempts: 5 # Attempts before temporary block
                  bruteforce-timeout-minutes: 5 # Block duration in minutes
                  ip-limit-registrations: 3 # Account registrations per IP
                  min-password-length: 4 # Inclusive minimum password length
                  max-password-length: 72 # Inclusive maximum password length
                
                # Premium account detection configuration
                premium:
                  check-enabled: true # Enable premium account verification
                  online-mode-need-auth: false # Force auth for premium players on online-mode proxies
                  resolver:
                    mojang-enabled: true # Query Mojang API
                    ashcon-enabled: true # Query Ashcon API
                    wpme-enabled: false # Query WPME API
                    request-timeout-ms: 2000 # Per-request timeout in milliseconds (2 seconds)
                    hit-ttl-minutes: 10 # Cache TTL for positive hits
                    miss-ttl-minutes: 3 # Cache TTL for misses
                    case-sensitive: true # Preserve username case in resolver cache
                
                # Alert system configuration (optional - Discord webhook notifications)
                alerts:
                  enabled: false # Enable/disable alert system
                  failure-rate-threshold: 0.5 # Alert when failure rate exceeds 50%
                  min-requests-for-alert: 10 # Minimum requests before sending alert
                  check-interval-minutes: 5 # Check metrics every 5 minutes
                  alert-cooldown-minutes: 30 # Cooldown between alerts (prevent spam)
                  
                  # Discord webhook configuration (optional)
                  discord:
                    enabled: false # Enable Discord webhook notifications
                    webhook-url: "" # Discord webhook URL (get from Discord server settings)
                    # Example: "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"
                """;

        Files.writeString(configFile, defaultConfig);
        logger.info("Utworzono domyślny plik konfiguracji");
    }

    /**
     * Ładuje ustawienia bazy danych.
     */
    @SuppressWarnings("unchecked")
    private void loadDatabaseSettings(Map<String, Object> config) {
        Map<String, Object> database = (Map<String, Object>) config.get("database");
        if (database != null) {
            databaseStorageType = getString(database, "storage-type", databaseStorageType);
            databaseHostname = getString(database, "hostname", databaseHostname);
            databasePort = getInt(database, "port", databasePort);
            databaseName = getString(database, "database", databaseName);
            databaseUser = getString(database, "user", databaseUser);
            databasePassword = getString(database, "password", databasePassword);
            databaseConnectionUrl = getString(database, "connection-url", databaseConnectionUrl);
            databaseConnectionParameters = getString(database, "connection-parameters", databaseConnectionParameters);
            databaseConnectionPoolSize = getInt(database, "connection-pool-size", databaseConnectionPoolSize);
            databaseMaxLifetimeMillis = getLong(database, "max-lifetime-millis", databaseMaxLifetimeMillis);

            // Load PostgreSQL-specific settings
            loadPostgreSQLSettings(database);
        }
    }

    /**
     * Loads PostgreSQL-specific settings from database configuration.
     */
    @SuppressWarnings("unchecked")
    private void loadPostgreSQLSettings(Map<String, Object> database) {
        Object postgreSQLSection = database.get("postgresql");
        if (postgreSQLSection instanceof Map<?, ?>) {
            Map<String, Object> postgreSQL = (Map<String, Object>) postgreSQLSection;
            postgreSQLSettings.setSslEnabled(getBoolean(postgreSQL, "ssl-enabled", postgreSQLSettings.isSslEnabled()));
            postgreSQLSettings.setSslMode(getString(postgreSQL, "ssl-mode", postgreSQLSettings.getSslMode()));
            postgreSQLSettings.setSslCert(getString(postgreSQL, "ssl-cert", postgreSQLSettings.getSslCert()));
            postgreSQLSettings.setSslKey(getString(postgreSQL, "ssl-key", postgreSQLSettings.getSslKey()));
            postgreSQLSettings.setSslRootCert(getString(postgreSQL, "ssl-root-cert", postgreSQLSettings.getSslRootCert()));
            postgreSQLSettings.setSslPassword(getString(postgreSQL, "ssl-password", postgreSQLSettings.getSslPassword()));
        }
    }

    /**
     * Ładuje ustawienia debug.
     */
    private void loadDebugSettings(Map<String, Object> config) {
        debugEnabled = getBoolean(config, "debug-enabled", debugEnabled);
    }

    /**
     * Ładuje ustawienia języka.
     */
    private void loadLanguageSettings(Map<String, Object> config) {
        language = getString(config, "language", language);
    }

    /**
     * Processes database settings after loading (connection URL parsing, etc.).
     */
    private void processDatabaseSettings() {
        // If connection URL is provided, parse it to extract connection details
        if (databaseConnectionUrl != null && !databaseConnectionUrl.trim().isEmpty()) {
            parseConnectionUrl(databaseConnectionUrl);
        }

        // Append connection parameters to the URL if provided
        // This is handled in DatabaseConfig based on the storage type
    }

    /**
     * Parses a database connection URL to extract connection details.
     * Supports formats like:
     * - postgresql://user:pass@host:5432/database
     * - mysql://user:pass@host:3306/database
     */
    private void parseConnectionUrl(String connectionUrl) {
        try {
            String url = connectionUrl.trim();

            databaseStorageType = detectDatabaseType(url);
            if (databaseStorageType == null) {
                return; // Warning already logged
            }

            String remaining = url.substring(url.indexOf("://") + 3);
            parseConnectionCredentials(remaining);

        } catch (StringIndexOutOfBoundsException e) {
            logger.error("Nieprawidłowy format URL połączenia z bazą danych: {}", connectionUrl, e);
        } catch (IllegalArgumentException e) {
            logger.error("Nieprawidłowe parametry URL połączenia: {}", connectionUrl, e);
        }
    }

    /**
     * Detects database type from connection URL.
     *
     * @param url Connection URL
     * @return Database type or null if unsupported
     */
    private String detectDatabaseType(String url) {
        DatabaseType dbType = DatabaseType.fromUrl(url);
        return dbType != null ? dbType.getName() : null;
    }

    /**
     * Parses connection credentials and host information from URL.
     *
     * @param remaining URL part after protocol
     */
    private void parseConnectionCredentials(String remaining) {
        // Split by @ to separate auth from host
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

    /**
     * Parses authentication part from connection URL.
     *
     * @param authPart Authentication part (user:password)
     */
    private void parseAuthPart(String authPart) {
        String[] authSplit = authPart.split(":");
        if (authSplit.length >= 1) {
            databaseUser = URLDecoder.decode(authSplit[0], StandardCharsets.UTF_8);
        }
        if (authSplit.length >= 2) {
            databasePassword = URLDecoder.decode(authSplit[1], StandardCharsets.UTF_8);
        }
    }

    /**
     * Parses host part from connection URL.
     *
     * @param hostPart Host part (hostname:port/database)
     */
    private void parseHostPart(String hostPart) {
        // Parse host and database
        String[] hostSplit = hostPart.split("/");
        String hostAndPort = hostSplit[0];
        if (hostSplit.length >= 2) {
            databaseName = hostSplit[1];
        }

        // Parse host and port
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

    /**
     * Ładuje ustawienia cache.
     */
    @SuppressWarnings("unchecked")
    private void loadCacheSettings(Map<String, Object> config) {
        Map<String, Object> cache = (Map<String, Object>) config.get("cache");
        if (cache != null) {
            cacheTtlMinutes = getInt(cache, "ttl-minutes", cacheTtlMinutes);
            cacheMaxSize = getInt(cache, "max-size", cacheMaxSize);
            cacheCleanupIntervalMinutes = getInt(cache, "cleanup-interval-minutes", cacheCleanupIntervalMinutes);
            sessionTimeoutMinutes = getInt(cache, "session-timeout-minutes", sessionTimeoutMinutes);
            premiumTtlHours = getInt(cache, "premium-ttl-hours", premiumTtlHours);
            premiumRefreshThreshold = getDouble(cache, "premium-refresh-threshold", premiumRefreshThreshold);
        }
    }

    /**
     * Ładuje ustawienia PicoLimbo.
     */
    @SuppressWarnings("unchecked")
    private void loadPicoLimboSettings(Map<String, Object> config) {
        Map<String, Object> picolimbo = (Map<String, Object>) config.get("picolimbo");
        if (picolimbo != null) {
            picoLimboServerName = getString(picolimbo, "server-name", picoLimboServerName);
            picoLimboTimeoutSeconds = getInt(picolimbo, "timeout-seconds", picoLimboTimeoutSeconds);
        }
    }

    /**
     * Ładuje ustawienia połączeń.
     */
    @SuppressWarnings("unchecked")
    private void loadConnectionSettings(Map<String, Object> config) {
        Map<String, Object> connection = (Map<String, Object>) config.get("connection");
        if (connection != null) {
            connectionTimeoutSeconds = getInt(connection, "timeout-seconds", connectionTimeoutSeconds);
        }
    }

    /**
     * Ładuje ustawienia bezpieczeństwa.
     */
    @SuppressWarnings("unchecked")
    private void loadSecuritySettings(Map<String, Object> config) {
        Map<String, Object> security = (Map<String, Object>) config.get("security");
        if (security != null) {
            bcryptCost = getInt(security, "bcrypt-cost", bcryptCost);
            bruteForceMaxAttempts = getInt(security, "bruteforce-max-attempts", bruteForceMaxAttempts);
            bruteForceTimeoutMinutes = getInt(security, "bruteforce-timeout-minutes", bruteForceTimeoutMinutes);
            ipLimitRegistrations = getInt(security, "ip-limit-registrations", ipLimitRegistrations);
            minPasswordLength = getInt(security, "min-password-length", minPasswordLength);
            maxPasswordLength = getInt(security, "max-password-length", maxPasswordLength);
        }
    }

    /**
     * Ładuje ustawienia premium.
     */
    @SuppressWarnings("java:S3776") // Configuration loading - complexity 9, acceptable for config parsing
    private void loadPremiumSettings(Map<String, Object> config) {
        Object premiumSection = config.get("premium");
        if (premiumSection instanceof Map<?, ?>) {
            @SuppressWarnings("unchecked")
            Map<String, Object> premium = (Map<String, Object>) premiumSection;
            premiumSettings.setCheckEnabled(getBoolean(premium, "check-enabled", premiumSettings.isCheckEnabled()));
            premiumSettings.setOnlineModeNeedAuth(getBoolean(premium, "online-mode-need-auth", premiumSettings.isOnlineModeNeedAuth()));

            if (premium.containsKey("premium-uuid-resolver")) {
                logger.warn("Wykryto legacy klucz premium.premium-uuid-resolver – ignoruję. Skonfiguruj premium.resolver.*");
            }

            Object resolverSection = premium.get("resolver");
            if (resolverSection instanceof Map<?, ?>) {
                @SuppressWarnings("unchecked")
                Map<String, Object> resolver = (Map<String, Object>) resolverSection;
                applyResolverSettings(resolver);
            }
        }

        if (config.containsKey("premium-resolver")) {
            logger.warn("Wykryto legacy sekcję premium-resolver – ignoruję. Skonfiguruj premium.resolver.*");
        }
    }

    private void applyResolverSettings(Map<String, Object> resolver) {
        PremiumResolverSettings target = premiumSettings.getResolver();
        target.setMojangEnabled(getBoolean(resolver, "mojang-enabled", target.isMojangEnabled()));
        target.setAshconEnabled(getBoolean(resolver, "ashcon-enabled", target.isAshconEnabled()));
        target.setWpmeEnabled(getBoolean(resolver, "wpme-enabled", target.isWpmeEnabled()));
        target.setRequestTimeoutMs(getInt(resolver, "request-timeout-ms", target.getRequestTimeoutMs()));
        target.setHitTtlMinutes(getInt(resolver, "hit-ttl-minutes", target.getHitTtlMinutes()));
        target.setMissTtlMinutes(getInt(resolver, "miss-ttl-minutes", target.getMissTtlMinutes()));
        target.setCaseSensitive(getBoolean(resolver, "case-sensitive", target.isCaseSensitive()));
    }

    /**
     * Ładuje ustawienia alertów (Discord webhooks).
     */
    private void loadAlertSettings(Map<String, Object> config) {
        Object alertSection = config.get("alerts");
        if (alertSection instanceof Map<?, ?>) {
            @SuppressWarnings("unchecked")
            Map<String, Object> alerts = (Map<String, Object>) alertSection;
            alertSettings.setEnabled(getBoolean(alerts, "enabled", alertSettings.isEnabled()));
            alertSettings.setFailureRateThreshold(getDouble(alerts, "failure-rate-threshold", alertSettings.getFailureRateThreshold()));
            alertSettings.setMinRequestsForAlert(getInt(alerts, "min-requests-for-alert", alertSettings.getMinRequestsForAlert()));
            alertSettings.setCheckIntervalMinutes(getInt(alerts, "check-interval-minutes", alertSettings.getCheckIntervalMinutes()));
            alertSettings.setAlertCooldownMinutes(getInt(alerts, "alert-cooldown-minutes", alertSettings.getAlertCooldownMinutes()));

            // Discord webhook settings
            Object discordSection = alerts.get("discord");
            if (discordSection instanceof Map<?, ?>) {
                @SuppressWarnings("unchecked")
                Map<String, Object> discord = (Map<String, Object>) discordSection;
                alertSettings.setDiscordEnabled(getBoolean(discord, "enabled", alertSettings.isDiscordEnabled()));
                alertSettings.setDiscordWebhookUrl(getString(discord, "webhook-url", alertSettings.getDiscordWebhookUrl()));
            }
        }
    }

    /**
     * Waliduje ustawienia konfiguracji.
     */
    private void validateSettings() {
        validateDatabaseType();
        validateConnectionSettings();
        validateTimeoutSettings();
        validateCacheSettings();
        validateSecuritySettings();
        validateConnectionPoolSettings();
        validatePicoLimboSettings();
        validateServerSettings();
        validateLanguageSettings();
        validatePremiumResolverSettings();
    }

    private void validateDatabaseType() {
        DatabaseType dbType = DatabaseType.fromName(databaseStorageType);
        if (dbType == null) {
            throw new IllegalArgumentException("Nieobsługiwany typ bazy danych: " + databaseStorageType);
        }
    }

    private void validateConnectionSettings() {
        if (databasePort <= 0 || databasePort > 65535) {
            throw new IllegalArgumentException("Port bazy danych musi być w zakresie 1-65535");
        }
    }

    private void validateCacheSettings() {
        if (cacheTtlMinutes < 0) {
            throw new IllegalArgumentException("Cache TTL nie może być ujemny");
        }
        if (cacheMaxSize <= 0) {
            throw new IllegalArgumentException("Cache max size musi być > 0");
        }
        if (cacheCleanupIntervalMinutes <= 0) {
            throw new IllegalArgumentException("Cache cleanup interval musi być > 0");
        }
        if (premiumTtlHours <= 0) {
            throw new IllegalArgumentException("Premium TTL hours musi być > 0");
        }
        if (premiumRefreshThreshold < 0.0 || premiumRefreshThreshold > 1.0) {
            throw new IllegalArgumentException("Premium refresh threshold musi być w zakresie 0.0-1.0");
        }
    }

    private void validateSecuritySettings() {
        if (bcryptCost < 4 || bcryptCost > 31) {
            throw new IllegalArgumentException("BCrypt cost musi być w zakresie 4-31");
        }

        if (bruteForceMaxAttempts <= 0) {
            throw new IllegalArgumentException("Brute force max attempts musi być > 0");
        }
        if (bruteForceTimeoutMinutes <= 0) {
            throw new IllegalArgumentException("Brute force timeout musi być > 0");
        }

        if (minPasswordLength <= 0) {
            throw new IllegalArgumentException("Min password length musi być > 0");
        }
        if (maxPasswordLength <= minPasswordLength) {
            throw new IllegalArgumentException("Max password length musi być > min password length");
        }
        if (maxPasswordLength > 72) {
            // BCrypt maksymalna długość to 72 znaki
            logger.warn("Max password length > 72 (BCrypt limit). Ustawianie na 72.");
            adjustMaxPasswordLength();
        }
    }

    private void adjustMaxPasswordLength() {
        maxPasswordLength = 72;
    }

    private void validateTimeoutSettings() {
        if (connectionTimeoutSeconds <= 0) {
            throw new IllegalArgumentException("Connection timeout musi być > 0");
        }
    }

    private void validateConnectionPoolSettings() {
        if (databaseConnectionPoolSize <= 0) {
            throw new IllegalArgumentException("Connection pool size musi być > 0");
        }
    }

    private void validatePicoLimboSettings() {
        if (picoLimboTimeoutSeconds <= 0) {
            throw new IllegalArgumentException("PicoLimbo timeout musi być > 0");
        }
    }

    private void validateServerSettings() {
        validateIpLimitSettings();
        validatePicoLimboServerName();
        validatePremiumResolverSettings();
        
        logger.debug("Walidacja konfiguracji zakończona pomyślnie");
    }
    
    private void validateIpLimitSettings() {
        if (ipLimitRegistrations <= 0) {
            throw new IllegalArgumentException("IP limit registrations musi być > 0");
        }
    }
    
    private void validatePicoLimboServerName() {
        if (picoLimboServerName == null || picoLimboServerName.trim().isEmpty()) {
            throw new IllegalArgumentException("PicoLimbo server name nie może być pusty");
        }
    }
    
    private void validatePremiumResolverSettings() {
        PremiumResolverSettings resolver = premiumSettings.getResolver();
        
        validateResolverSources(resolver);
        validateResolverTimeout(resolver);
        validateResolverTtl(resolver);
    }
    
    private void validateResolverSources(PremiumResolverSettings resolver) {
        if (!resolver.isMojangEnabled() && !resolver.isAshconEnabled() && !resolver.isWpmeEnabled()) {
            throw new IllegalArgumentException("Premium resolver: co najmniej jedno źródło (mojang/ashcon/wpme) musi być włączone");
        }
    }
    
    private void validateResolverTimeout(PremiumResolverSettings resolver) {
        if (resolver.getRequestTimeoutMs() <= 0) {
            throw new IllegalArgumentException("Premium resolver: request-timeout-ms musi być > 0");
        }
    }
    
    private void validateResolverTtl(PremiumResolverSettings resolver) {
        if (resolver.getHitTtlMinutes() < 0 || resolver.getMissTtlMinutes() < 0) {
            throw new IllegalArgumentException("Premium resolver: TTL w minutach nie mogą być ujemne");
        }
    }

    private void validateLanguageSettings() {
        if (language == null || language.trim().isEmpty()) {
            logger.warn("Language setting is empty, using default 'en'");
            language = "en";
            return;
        }

        // Normalize language code (lowercase, trimmed)
        language = language.toLowerCase().trim();
        
        // No strict validation - any language with a messages_XX.properties file will work
        // If the file doesn't exist, the system will fall back to English
        logger.debug("Language setting: {} (will fall back to 'en' if file not found)", language);
    }

    // Utility methods dla parsowania YAML

    private String getString(Map<String, Object> map, String key, String defaultValue) {
        if (map == null || key == null) {
            logger.warn("Null map or key in getString, using default: {}", defaultValue);
            return defaultValue;
        }
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        try {
            return value.toString();
        } catch (Exception e) {
            logger.warn("Error converting value to string for key '{}', using default: {}", key, defaultValue);
            return defaultValue;
        }
    }

    private int getInt(Map<String, Object> map, String key, int defaultValue) {
        if (map == null || key == null) {
            logger.warn("Null map or key in getInt, using default: {}", defaultValue);
            return defaultValue;
        }
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.intValue();
        }
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            logger.warn("Invalid integer value for key '{}': {}, using default: {}", key, value, defaultValue);
            return defaultValue;
        }
    }

    private long getLong(Map<String, Object> map, String key, long defaultValue) {
        if (map == null || key == null) {
            logger.warn("Null map or key in getLong, using default: {}", defaultValue);
            return defaultValue;
        }
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.longValue();
        }
        try {
            return Long.parseLong(value.toString());
        } catch (NumberFormatException e) {
            logger.warn("Invalid long value for key '{}': {}, using default: {}", key, value, defaultValue);
            return defaultValue;
        }
    }

    private boolean getBoolean(Map<String, Object> map, String key, boolean defaultValue) {
        if (map == null || key == null) {
            logger.warn("Null map or key in getBoolean, using default: {}", defaultValue);
            return defaultValue;
        }
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean bool) {
            return bool;
        }
        try {
            return Boolean.parseBoolean(value.toString());
        } catch (Exception e) {
            logger.warn("Invalid boolean value for key '{}': {}, using default: {}", key, value, defaultValue);
            return defaultValue;
        }
    }

    private double getDouble(Map<String, Object> map, String key, double defaultValue) {
        if (map == null || key == null) {
            logger.warn("Null map or key in getDouble, using default: {}", defaultValue);
            return defaultValue;
        }
        Object value = map.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number number) {
            return number.doubleValue();
        }
        try {
            return Double.parseDouble(value.toString());
        } catch (NumberFormatException e) {
            logger.warn("Invalid double value for key '{}': {}, using default: {}", key, value, defaultValue);
            return defaultValue;
        }
    }

    // Gettery dla wszystkich ustawień

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

    public String getPicoLimboServerName() {
        return picoLimboServerName != null ? picoLimboServerName : "limbo";
    }

    public int getPicoLimboTimeoutSeconds() {
        return picoLimboTimeoutSeconds;
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

        public boolean isMojangEnabled() {
            return mojangEnabled;
        }

        void setMojangEnabled(boolean value) {
            this.mojangEnabled = value;
        }

        public boolean isAshconEnabled() {
            return ashconEnabled;
        }

        void setAshconEnabled(boolean value) {
            this.ashconEnabled = value;
        }

        public boolean isWpmeEnabled() {
            return wpmeEnabled;
        }

        void setWpmeEnabled(boolean value) {
            this.wpmeEnabled = value;
        }

        public int getRequestTimeoutMs() {
            return requestTimeoutMs;
        }

        void setRequestTimeoutMs(int value) {
            this.requestTimeoutMs = value;
        }

        public int getHitTtlMinutes() {
            return hitTtlMinutes;
        }

        void setHitTtlMinutes(int value) {
            this.hitTtlMinutes = value;
        }

        public int getMissTtlMinutes() {
            return missTtlMinutes;
        }

        void setMissTtlMinutes(int value) {
            this.missTtlMinutes = value;
        }

        public boolean isCaseSensitive() {
            return caseSensitive;
        }

        void setCaseSensitive(boolean value) {
            this.caseSensitive = value;
        }
    }

    /**
     * PostgreSQL-specific database configuration.
     */
    public static class PostgreSQLSettings {
        private boolean sslEnabled = true; // Default to enabled for security and external services
        private String sslMode = "require"; // Default to require for external services like Supabase
        private String sslCert = "";
        private String sslKey = "";
        private String sslRootCert = "";
        @SuppressWarnings("java:S2068") // Not a hardcoded password - SSL configuration placeholder for runtime value
        private String sslPassword = ""; // NOSONAR - SSL config placeholder
        
        public boolean isSslEnabled() {
            return sslEnabled;
        }

        void setSslEnabled(boolean value) {
            this.sslEnabled = value;
        }

        public String getSslMode() {
            return sslMode;
        }

        void setSslMode(String value) {
            this.sslMode = value;
        }

        public String getSslCert() {
            return sslCert;
        }

        void setSslCert(String value) {
            this.sslCert = value;
        }

        public String getSslKey() {
            return sslKey;
        }

        void setSslKey(String value) {
            this.sslKey = value;
        }

        public String getSslRootCert() {
            return sslRootCert;
        }

        void setSslRootCert(String value) {
            this.sslRootCert = value;
        }

        public String getSslPassword() {
            return sslPassword;
        }

        void setSslPassword(String value) {
            this.sslPassword = value;
        }
    }

    /**
     * Premium account detection configuration.
     */
    public static class PremiumSettings {
        private final PremiumResolverSettings resolver = new PremiumResolverSettings();
        private boolean checkEnabled = true;
        private boolean onlineModeNeedAuth = false; // DEPRECATED - forceOnlineMode() provides full protection

        public boolean isCheckEnabled() {
            return checkEnabled;
        }

        void setCheckEnabled(boolean value) {
            this.checkEnabled = value;
        }

        public boolean isOnlineModeNeedAuth() {
            return onlineModeNeedAuth;
        }

        void setOnlineModeNeedAuth(boolean value) {
            this.onlineModeNeedAuth = value;
        }

        public PremiumResolverSettings getResolver() {
            return resolver;
        }
    }

    /**
     * Alert system configuration for Discord webhooks.
     */
    public static class AlertSettings {
        private boolean enabled = false;
        private boolean discordEnabled = false;
        private String discordWebhookUrl = "";
        private double failureRateThreshold = 0.5; // 50% failure rate
        private int minRequestsForAlert = 10; // Minimum requests before alerting
        private int checkIntervalMinutes = 5; // Check every 5 minutes
        private int alertCooldownMinutes = 30; // Don't spam alerts (30 min cooldown)

        public boolean isEnabled() {
            return enabled;
        }

        void setEnabled(boolean value) {
            this.enabled = value;
        }

        public boolean isDiscordEnabled() {
            return discordEnabled;
        }

        void setDiscordEnabled(boolean value) {
            this.discordEnabled = value;
        }

        public String getDiscordWebhookUrl() {
            return discordWebhookUrl;
        }

        void setDiscordWebhookUrl(String value) {
            this.discordWebhookUrl = value;
        }

        public double getFailureRateThreshold() {
            return failureRateThreshold;
        }

        void setFailureRateThreshold(double value) {
            this.failureRateThreshold = value;
        }

        public int getMinRequestsForAlert() {
            return minRequestsForAlert;
        }

        void setMinRequestsForAlert(int value) {
            this.minRequestsForAlert = value;
        }

        public int getCheckIntervalMinutes() {
            return checkIntervalMinutes;
        }

        void setCheckIntervalMinutes(int value) {
            this.checkIntervalMinutes = value;
        }

        public int getAlertCooldownMinutes() {
            return alertCooldownMinutes;
        }

        void setAlertCooldownMinutes(int value) {
            this.alertCooldownMinutes = value;
        }
    }

    public AlertSettings getAlertSettings() {
        return alertSettings;
    }
}
