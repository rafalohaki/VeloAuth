package net.rafalohaki.veloauth.database;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.util.Objects;

/**
 * Immutable konfiguracja bazy danych.
 * Thread-safe object dla bezpiecznego dostępu wielowątkowego.
 */
public final class DatabaseConfig {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseConfig.class);

    /**
     * Typ bazy danych (MYSQL, POSTGRESQL, H2, SQLITE).
     */
    private final String storageType;

    /**
     * Hostname serwera bazy danych.
     */
    private final String hostname;

    /**
     * Port serwera bazy danych.
     */
    private final int port;

    /**
     * Nazwa bazy danych.
     */
    private final String database;

    /**
     * Użytkownik bazy danych.
     */
    private final String user;

    /**
     * Hasło bazy danych.
     */
    private final String password;

    /**
     * Rozmiar connection pool.
     */
    private final int connectionPoolSize;

    /**
     * HikariCP DataSource dla zaawansowanego connection pooling.
     */
    private final DataSource dataSource;

    /**
     * JDBC URL używany do nawiązywania połączeń.
     */
    private final String jdbcUrl;

    /**
     * Konstruktor podstawowy.
     *
     * @param storageType        Typ bazy danych
     * @param hostname           Hostname
     * @param port               Port
     * @param database           Nazwa bazy danych
     * @param user               Użytkownik
     * @param password           Hasło
     * @param connectionPoolSize Rozmiar connection pool
     */
    public DatabaseConfig(String storageType, String hostname, int port,
                          String database, String user, String password,
                          int connectionPoolSize) {

        validateBasicParameters(storageType, database, connectionPoolSize);
        DatabaseType dbType = validateDatabaseType(storageType);
        validateRemoteDatabaseParameters(dbType, hostname, port, storageType);
        
        // Assign final fields directly in constructor
        this.storageType = dbType.getName();
        this.hostname = hostname;
        this.port = port;
        this.database = database;
        this.user = user;
        this.password = password;
        this.connectionPoolSize = connectionPoolSize;
        this.dataSource = null; // Brak HikariCP w tym konstruktorze
        this.jdbcUrl = buildJdbcUrl(dbType, hostname, port, database, null, null);
    }

    private void validateBasicParameters(String storageType, String database, int connectionPoolSize) {
        if (storageType == null || storageType.isEmpty()) {
            throw new IllegalArgumentException("StorageType nie może być pusty");
        }
        if (database == null || database.isEmpty()) {
            throw new IllegalArgumentException("Database nie może być pusty");
        }
        if (connectionPoolSize <= 0) {
            throw new IllegalArgumentException("ConnectionPoolSize musi być > 0");
        }
    }

    private DatabaseType validateDatabaseType(String storageType) {
        DatabaseType dbType = DatabaseType.fromName(storageType);
        if (dbType == null) {
            throw new IllegalArgumentException("Nieobsługiwany typ bazy danych: " + storageType);
        }
        return dbType;
    }

    private void validateRemoteDatabaseParameters(DatabaseType dbType, String hostname, int port, String storageType) {
        if (dbType.isRemoteDatabase()) {
            if (hostname == null || hostname.isEmpty()) {
                throw new IllegalArgumentException("Hostname nie może być pusty dla " + storageType);
            }
            if (port <= 0 || port > 65535) {
                throw new IllegalArgumentException("Port musi być w zakresie 1-65535");
            }
        }
    }

    /**
     * Konstruktor z HikariCP DataSource.
     *
     * @param storageType        Typ bazy danych
     * @param dataSource         HikariCP DataSource
     * @param connectionPoolSize Rozmiar connection pool
     */
    public DatabaseConfig(String storageType, DataSource dataSource, int connectionPoolSize, String jdbcUrl) {
        if (storageType == null || storageType.isEmpty()) {
            throw new IllegalArgumentException("StorageType nie może być pusty");
        }
        if (dataSource == null) {
            throw new IllegalArgumentException("DataSource nie może być null");
        }
        if (jdbcUrl == null || jdbcUrl.isEmpty()) {
            throw new IllegalArgumentException("jdbcUrl nie może być pusty");
        }

        this.storageType = storageType.toUpperCase();
        this.dataSource = dataSource;
        this.connectionPoolSize = connectionPoolSize;
        this.jdbcUrl = jdbcUrl;

        // Pozostałe pola nie są używane z DataSource
        this.hostname = null;
        this.port = 0;
        this.database = null;
        this.user = null;
        this.password = null;
    }

    /**
     * Tworzy konfigurację dla lokalnych baz danych (H2, SQLite).
     *
     * @param storageType Typ bazy danych (H2 lub SQLITE)
     * @param database    Nazwa bazy danych
     * @return DatabaseConfig
     */
    public static DatabaseConfig forLocalDatabase(String storageType, String database) {
        return new DatabaseConfig(storageType, null, 0, database, null, null, 1);
    }

    /**
     * Tworzy konfigurację dla zdalnych baz danych z HikariCP.
     *
     * @param storageType          Typ bazy danych (MYSQL lub POSTGRESQL)
     * @param hostname             Hostname serwera
     * @param port                 Port serwera
     * @param database             Nazwa bazy danych
     * @param user                 Użytkownik
     * @param password             Hasło
     * @param connectionPoolSize   Rozmiar connection pool
     * @param maxLifetime          Maksymalny czas życia połączenia (ms)
     * @param connectionParameters Dodatkowe parametry połączenia
     * @param postgreSQLSettings   Ustawienia PostgreSQL (może być null)
     * @return DatabaseConfig z HikariCP
     */
    @SuppressWarnings("java:S107")
    // SonarCloud false positive: all 11 parameters required for complete HikariCP configuration
    public static DatabaseConfig forRemoteWithHikari(String storageType, String hostname,
                                                     int port, String database,
                                                     String user, String password,
                                                     int connectionPoolSize, int maxLifetime,
                                                     String connectionParameters,
                                                     net.rafalohaki.veloauth.config.Settings.PostgreSQLSettings postgreSQLSettings,
                                                     boolean debugEnabled) {

        DatabaseType dbType = DatabaseType.fromName(storageType);
        if (dbType == null) {
            throw new IllegalArgumentException("Nieobsługiwany typ bazy danych: " + storageType);
        }

        String jdbcUrl = buildJdbcUrl(dbType, hostname, port, database, connectionParameters, postgreSQLSettings);
        String driverClass = resolveDriverClass(dbType);

        // Debug logging for connection URL (only if debug enabled)
        if (debugEnabled) {
            logger.debug("[VeloAuth DEBUG] JDBC URL: {}", jdbcUrl);
            logger.debug("[VeloAuth DEBUG] Database Type: {}", dbType);
            logger.debug("[VeloAuth DEBUG] Hostname: {}:{}", hostname, port);
            logger.debug("[VeloAuth DEBUG] SSL Settings: {}", (postgreSQLSettings != null ? "enabled" : "using defaults"));
        }

        HikariConfig hikariConfig = new HikariConfig();
        configureBasicHikariSettings(hikariConfig, jdbcUrl, user, password, connectionPoolSize, maxLifetime);
        configureDatabaseOptimizations(hikariConfig, dbType, postgreSQLSettings);

        hikariConfig.setDriverClassName(driverClass);
        try {
            // Safe: Loading trusted JDBC driver from configuration, not user input
            Class.forName(driverClass);
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("Nie znaleziono sterownika JDBC: " + driverClass, e);
        }

        HikariDataSource dataSource = new HikariDataSource(hikariConfig);

        return new DatabaseConfig(storageType, dataSource, connectionPoolSize, jdbcUrl);
    }

    private static void configureBasicHikariSettings(HikariConfig hikariConfig, String jdbcUrl,
                                                     String user, String password,
                                                     int connectionPoolSize, int maxLifetime) {
        hikariConfig.setJdbcUrl(jdbcUrl);
        hikariConfig.setUsername(user);
        hikariConfig.setPassword(password);
        hikariConfig.setMaximumPoolSize(connectionPoolSize);
        hikariConfig.setMinimumIdle(5);
        hikariConfig.setMaxLifetime(maxLifetime);
        hikariConfig.setConnectionTimeout(5000);
        hikariConfig.setIdleTimeout(300000);
        hikariConfig.setAutoCommit(true);
        hikariConfig.setPoolName("VeloAuth-HikariCP");

        // Timeouts for database drivers
        hikariConfig.addDataSourceProperty("loginTimeout", "3");
        hikariConfig.addDataSourceProperty("socketTimeout", "3000");

        // Validation and leak detection
        hikariConfig.setValidationTimeout(5000);
        hikariConfig.setLeakDetectionThreshold(10000);
    }

    private static void configureDatabaseOptimizations(HikariConfig hikariConfig, DatabaseType dbType,
                                                       net.rafalohaki.veloauth.config.Settings.PostgreSQLSettings postgreSQLSettings) {
        if (dbType == DatabaseType.MYSQL) {
            hikariConfig.addDataSourceProperty("cachePrepStmts", "true");
            hikariConfig.addDataSourceProperty("prepStmtCacheSize", "250");
            hikariConfig.addDataSourceProperty("prepStmtCacheSqlLimit", "2048");
            hikariConfig.addDataSourceProperty("useServerPrepStmts", "true");
        } else if (dbType == DatabaseType.POSTGRESQL) {
            hikariConfig.addDataSourceProperty("prepareThreshold", "1");
            hikariConfig.addDataSourceProperty("preparedStatementCacheQueries", "256");
            hikariConfig.addDataSourceProperty("preparedStatementCacheSizeMiB", "5");

            // PostgreSQL SSL settings
            configurePostgreSQLSsl(hikariConfig, postgreSQLSettings);
        }
    }

    private static void configurePostgreSQLSsl(HikariConfig hikariConfig,
                                               net.rafalohaki.veloauth.config.Settings.PostgreSQLSettings postgreSQLSettings) {
        if (postgreSQLSettings != null && postgreSQLSettings.isSslEnabled()) {
            hikariConfig.addDataSourceProperty("ssl", "true");
            hikariConfig.addDataSourceProperty("sslmode", postgreSQLSettings.getSslMode());

            if (postgreSQLSettings.getSslCert() != null && !postgreSQLSettings.getSslCert().isEmpty()) {
                hikariConfig.addDataSourceProperty("sslcert", postgreSQLSettings.getSslCert());
            }
            if (postgreSQLSettings.getSslKey() != null && !postgreSQLSettings.getSslKey().isEmpty()) {
                hikariConfig.addDataSourceProperty("sslkey", postgreSQLSettings.getSslKey());
            }
            if (postgreSQLSettings.getSslRootCert() != null && !postgreSQLSettings.getSslRootCert().isEmpty()) {
                hikariConfig.addDataSourceProperty("sslrootcert", postgreSQLSettings.getSslRootCert());
            }
            if (postgreSQLSettings.getSslPassword() != null && !postgreSQLSettings.getSslPassword().isEmpty()) {
                hikariConfig.addDataSourceProperty("sslpassword", postgreSQLSettings.getSslPassword());
            }
        }
    }

    /**
     * Buduje JDBC URL dla HikariCP.
     * Supports connection parameters and PostgreSQL SSL settings.
     */
    private static String buildJdbcUrl(DatabaseType dbType, String hostname, int port, String database,
                                       String connectionParameters,
                                       net.rafalohaki.veloauth.config.Settings.PostgreSQLSettings postgreSQLSettings) {
        String params = processConnectionParameters(connectionParameters);

        return switch (dbType) {
            case MYSQL -> buildMySqlUrl(hostname, port, database, params);
            case POSTGRESQL -> buildPostgreSqlUrl(hostname, port, database, params, postgreSQLSettings);
            case H2 -> buildH2Url(database);
            case SQLITE -> buildSqliteUrl(database);
            default -> throw new IllegalArgumentException("Invalid storage type: " + dbType);
        };
    }
    
    private static String processConnectionParameters(String connectionParameters) {
        if (connectionParameters == null || connectionParameters.trim().isEmpty()) {
            return "";
        }
        
        // Ensure it starts with ?
        if (!connectionParameters.startsWith("?") && !connectionParameters.startsWith("&")) {
            return "?" + connectionParameters;
        }
        return connectionParameters;
    }
    
    private static String buildMySqlUrl(String hostname, int port, String database, String params) {
        String baseUrl = String.format("jdbc:mysql://%s:%d/%s", hostname, port, database);
        String mysqlParams = addMySqlDefaultParams(params);
        return baseUrl + mysqlParams;
    }
    
    private static String addMySqlDefaultParams(String params) {
        if (params.isEmpty()) {
            return "?useSSL=false&serverTimezone=UTC&cachePrepStmts=true&prepStmtCacheSize=250&prepStmtCacheSqlLimit=2048";
        } else if (!params.contains("useSSL")) {
            return params + "&useSSL=false";
        }
        return params;
    }
    
    private static String buildPostgreSqlUrl(String hostname, int port, String database, String params,
                                            net.rafalohaki.veloauth.config.Settings.PostgreSQLSettings postgreSQLSettings) {
        String baseUrl = String.format("jdbc:postgresql://%s:%d/%s", hostname, port, database);
        String sslParams = buildPostgreSQLSslParams(postgreSQLSettings);
        String mergedParams = mergeSslParams(params, sslParams);
        return baseUrl + mergedParams;
    }
    
    private static String buildH2Url(String database) {
        return String.format("jdbc:h2:file:./data/%s;MODE=MySQL;DATABASE_TO_LOWER=TRUE", database);
    }
    
    private static String buildSqliteUrl(String database) {
        return String.format("jdbc:sqlite:./data/%s.db", database);
    }

    private static String resolveDriverClass(DatabaseType dbType) {
        return dbType.getDriverClass();
    }

    /**
     * Tworzy konfigurację dla zdalnych baz danych (MySQL, PostgreSQL).
     *
     * @param storageType        Typ bazy danych (MYSQL lub POSTGRESQL)
     * @param hostname           Hostname serwera
     * @param port               Port serwera
     * @param database           Nazwa bazy danych
     * @param user               Użytkownik
     * @param password           Hasło
     * @param connectionPoolSize Rozmiar connection pool
     * @return DatabaseConfig
     */
    public static DatabaseConfig forRemoteDatabase(String storageType, String hostname,
                                                   int port, String database,
                                                   String user, String password,
                                                   int connectionPoolSize) {
        return new DatabaseConfig(storageType, hostname, port, database,
                user, password, connectionPoolSize);
    }

    /**
     * Builds PostgreSQL SSL parameters string based on settings.
     * For external services like Supabase, SSL is required by default.
     *
     * @param postgreSQLSettings PostgreSQL SSL settings
     * @return SSL parameters string
     */
    private static String buildPostgreSQLSslParams(net.rafalohaki.veloauth.config.Settings.PostgreSQLSettings postgreSQLSettings) {
        // Default to SSL enabled for security and external services (Supabase requires SSL)
        if (postgreSQLSettings == null) {
            return "ssl=true&sslmode=require";
        }

        // If explicitly disabled, allow it (for local development)
        if (!postgreSQLSettings.isSslEnabled()) {
            return "sslmode=disable";
        }

        return buildEnabledSslParams(postgreSQLSettings);
    }
    
    private static String buildEnabledSslParams(net.rafalohaki.veloauth.config.Settings.PostgreSQLSettings postgreSQLSettings) {
        String sslParams = "ssl=true";
        sslParams = addSslMode(sslParams, postgreSQLSettings.getSslMode());
        sslParams = addSslCert(sslParams, postgreSQLSettings.getSslCert());
        sslParams = addSslKey(sslParams, postgreSQLSettings.getSslKey());
        sslParams = addSslRootCert(sslParams, postgreSQLSettings.getSslRootCert());
        return sslParams;
    }
    
    private static String addSslMode(String sslParams, String sslMode) {
        if (sslMode == null || sslMode.isEmpty()) {
            return sslParams + "&sslmode=require";
        } else {
            return sslParams + "&sslmode=" + sslMode;
        }
    }
    
    private static String addSslCert(String sslParams, String sslCert) {
        if (sslCert != null && !sslCert.isEmpty()) {
            return sslParams + "&sslcert=" + sslCert;
        }
        return sslParams;
    }
    
    private static String addSslKey(String sslParams, String sslKey) {
        if (sslKey != null && !sslKey.isEmpty()) {
            return sslParams + "&sslkey=" + sslKey;
        }
        return sslParams;
    }
    
    private static String addSslRootCert(String sslParams, String sslRootCert) {
        if (sslRootCert != null && !sslRootCert.isEmpty()) {
            return sslParams + "&sslrootcert=" + sslRootCert;
        }
        return sslParams;
    }

    /**
     * Merges SSL parameters with existing connection parameters.
     * Automatically adds prepareThreshold=0 for Supabase poolers.
     * Uses safe parameter replacement to avoid regex vulnerabilities.
     *
     * @param existingParams Existing parameters string
     * @param sslParams      SSL parameters to merge
     * @return Merged parameters string
     */
    private static String mergeSslParams(String existingParams, String sslParams) {
        if (existingParams == null || existingParams.isEmpty()) {
            existingParams = "?" + sslParams;
        } else {
            // Safe parameter replacement - avoid regex vulnerabilities
            String[] paramPairs = existingParams.substring(1).split("&");
            boolean sslReplaced = false;

            for (int i = 0; i < paramPairs.length; i++) {
                String[] pair = paramPairs[i].split("=", 2);
                if (pair.length == 2 && "ssl".equals(pair[0])) {
                    paramPairs[i] = sslParams;
                    sslReplaced = true;
                    break;
                }
            }

            if (sslReplaced) {
                existingParams = "?" + String.join("&", paramPairs);
            } else {
                existingParams += "&" + sslParams;
            }
        }

        // Auto-add prepareThreshold=0 for Supabase poolers (they don't support prepared statements)
        if (!existingParams.contains("prepareThreshold")) {
            existingParams += "&prepareThreshold=0";
        }

        return existingParams;
    }

    /**
     * Zwraca typ bazy danych.
     *
     * @return Typ bazy danych
     */
    public String getStorageType() {
        return storageType;
    }

    /**
     * Zwraca hostname serwera.
     *
     * @return Hostname
     */
    public String getHostname() {
        return hostname;
    }

    /**
     * Zwraca port serwera.
     *
     * @return Port
     */
    public int getPort() {
        return port;
    }

    /**
     * Zwraca nazwę bazy danych.
     *
     * @return Nazwa bazy danych
     */
    public String getDatabase() {
        return database;
    }

    /**
     * Zwraca użytkownika bazy danych.
     *
     * @return Użytkownik
     */
    public String getUser() {
        return user;
    }

    /**
     * Zwraca hasło bazy danych.
     *
     * @return Hasło
     */
    public String getPassword() {
        return password;
    }

    /**
     * Zwraca rozmiar connection pool.
     *
     * @return Rozmiar connection pool
     */
    public int getConnectionPoolSize() {
        return connectionPoolSize;
    }

    /**
     * Zwraca HikariCP DataSource jeśli dostępny.
     *
     * @return DataSource lub null jeśli używa standardowego connection
     */
    public DataSource getDataSource() {
        return dataSource;
    }

    /**
     * Zwraca JDBC URL dla tej konfiguracji.
     *
     * @return JDBC URL
     */
    public String getJdbcUrl() {
        return jdbcUrl;
    }

    /**
     * Sprawdza czy używa HikariCP.
     *
     * @return true jeśli ma skonfigurowany DataSource
     */
    public boolean hasDataSource() {
        return dataSource != null;
    }

    /**
     * Sprawdza czy to lokalna baza danych.
     *
     * @return true jeśli H2 lub SQLite
     */
    public boolean isLocalDatabase() {
        DatabaseType dbType = DatabaseType.fromName(storageType);
        return dbType != null && dbType.isLocalDatabase();
    }

    /**
     * Sprawdza czy to zdalna baza danych.
     *
     * @return true jeśli MySQL lub PostgreSQL
     */
    public boolean isRemoteDatabase() {
        DatabaseType dbType = DatabaseType.fromName(storageType);
        return dbType != null && dbType.isRemoteDatabase();
    }

    /**
     * Zwraca domyślny port dla typu bazy danych.
     *
     * @return Domyślny port
     */
    public int getDefaultPort() {
        DatabaseType dbType = DatabaseType.fromName(storageType);
        return dbType != null ? dbType.getDefaultPort() : 0;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;

        DatabaseConfig that = (DatabaseConfig) obj;
        return port == that.port &&
                connectionPoolSize == that.connectionPoolSize &&
                Objects.equals(storageType, that.storageType) &&
                Objects.equals(hostname, that.hostname) &&
                Objects.equals(database, that.database) &&
                Objects.equals(user, that.user) &&
                Objects.equals(password, that.password) &&
                Objects.equals(jdbcUrl, that.jdbcUrl);
    }

    @Override
    public int hashCode() {
        return Objects.hash(storageType, hostname, port, database,
                user, password, connectionPoolSize, jdbcUrl);
    }

    @Override
    public String toString() {
        return "DatabaseConfig{" +
                "storageType='" + storageType + '\'' +
                ", hostname='" + hostname + '\'' +
                ", port=" + port +
                ", database='" + database + '\'' +
                ", user='" + user + '\'' +
                ", password='***'" + // Nie loguj hasła!
                ", connectionPoolSize=" + connectionPoolSize +
                ", jdbcUrl='" + jdbcUrl + '\'' +
                ", isLocal=" + isLocalDatabase() +
                '}';
    }
}
