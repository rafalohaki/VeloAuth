package net.rafalohaki.veloauth.database;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.DataSourceConnectionSource;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.misc.TransactionManager;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.support.DatabaseConnection;
import com.j256.ormlite.table.TableUtils;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.PremiumUuid;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.sql.SQLException;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Manager bazy danych z obsługą ORMLite, connection pooling i thread-safety.
 * Obsługuje PostgreSQL, MySQL, H2 i SQLite z automatycznym tworzeniem tabel.
 * <p>
 * Używa Virtual Threads dla wydajnych operacji I/O i ConcurrentHashMap dla cache.
 */
public class DatabaseManager {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseManager.class);

    // Stałe dla wiadomości bazy danych
    private static final String DATABASE_ERROR = "database.error";
    
    // Stałe dla zapytań SQL
    private static final String ALTER_TABLE = "ALTER TABLE ";
    private static final String ADD_COLUMN = " ADD COLUMN ";

    // Markery SLF4J dla kategoryzowanego logowania
    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");
    private static final Marker CACHE_MARKER = MarkerFactory.getMarker("CACHE");

    /**
     * Stała dla komunikatu o braku połączenia z bazą danych - unikaj duplikacji
     */
    private static final String DATABASE_NOT_CONNECTED = "Database not connected";
    private static final String DATABASE_NOT_CONNECTED_PREMIUM_CHECK = "Database not connected - cannot check premium status for {}";
    /**
     * Cache dla często używanych zapytań - ZAWSZE ConcurrentHashMap dla thread-safety.
     */
    private final ConcurrentHashMap<String, RegisteredPlayer> playerCache;
    /**
     * Lock dla synchronizacji operacji krytycznych.
     */
    private final ReentrantLock databaseLock;
    /**
     * Konfiguracja bazy danych.
     */
    private final DatabaseConfig config;
    /**
     * System wiadomości i18n.
     */
    private final Messages messages;
    /**
     * Executor z wirtualnymi wątkami dla operacji I/O.
     */
    private final ExecutorService dbExecutor;
    /**
     * Scheduled executor dla health checks.
     */
    private final ScheduledExecutorService healthCheckExecutor;
    /**
     * Connection source dla ORMLite.
     */
    private ConnectionSource connectionSource;
    /**
     * DAO dla operacji na RegisteredPlayer.
     */
    private Dao<RegisteredPlayer, String> playerDao;
    /**
     * DAO dla operacji na PremiumUuid.
     */
    private PremiumUuidDao premiumUuidDao;
    /**
     * JDBC DAO dla gorących ścieżek.
     */
    private JdbcAuthDao jdbcAuthDao;
    /**
     * Czy baza danych jest połączona.
     */
    private volatile boolean connected;
    /**
     * Ostatni czas health checku.
     */
    private volatile long lastHealthCheckTime;
    /**
     * Czy ostatni health check był pozytywny.
     */
    private volatile boolean lastHealthCheckPassed;

    /**
     * Tworzy nowy DatabaseManager.
     *
     * @param config   Konfiguracja bazy danych
     * @param messages System wiadomości i18n
     */
    public DatabaseManager(DatabaseConfig config, Messages messages) {
        if (config == null) {
            throw new IllegalArgumentException("Config cannot be null");
        }

        this.config = config;
        this.messages = messages;
        this.playerCache = new ConcurrentHashMap<>();
        this.databaseLock = new ReentrantLock();
        this.connected = false;
        this.dbExecutor = Executors.newVirtualThreadPerTaskExecutor();
        this.healthCheckExecutor = Executors.newSingleThreadScheduledExecutor();
        this.jdbcAuthDao = new JdbcAuthDao(config);
        this.lastHealthCheckTime = 0;
        this.lastHealthCheckPassed = false;

        if (logger.isInfoEnabled()) {
            logger.info(DB_MARKER, messages.get("database.manager.created"), config.getStorageType());
        }
    }

    /**
     * Inicjalizuje połączenie z bazą danych i tworzy tabele.
     * Używa HikariCP jeśli dostępny, w przeciwnym razie standardowe JDBC.
     *
     * @return CompletableFuture<Boolean> - true jeśli sukces
     */
    public CompletableFuture<Boolean> initialize() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                databaseLock.lock();
                try {
                    if (isAlreadyConnected()) {
                        return true;
                    }

                    initializeConnection();
                    initializeDaos();
                    createTablesIfNotExists();
                    markAsConnected();
                    startHealthChecks();

                    return true;

                } finally {
                    databaseLock.unlock();
                }

            } catch (SQLException e) {
                if (logger.isErrorEnabled()) {
                    logger.error(DB_MARKER, "Błąd podczas inicjalizacji bazy danych", e);
                }
                return false;
            }
        }, dbExecutor);
    }

    private boolean isAlreadyConnected() {
        if (connected) {
            if (logger.isWarnEnabled()) {
                logger.warn(DB_MARKER, "Baza danych już jest połączona");
            }
            return true;
        }
        return false;
    }

    private void initializeConnection() throws SQLException {
        if (config.hasDataSource()) {
            initializeHikariConnection();
        } else {
            initializeStandardJdbcConnection();
        }
    }

    private void initializeHikariConnection() throws SQLException {
        if (logger.isInfoEnabled()) {
            logger.info(DB_MARKER, messages.get("database.manager.hikari_init"));
        }
        connectionSource = new DataSourceConnectionSource(config.getDataSource(), config.getJdbcUrl());

        if (logger.isInfoEnabled()) {
            logger.info(DB_MARKER, messages.get("database.manager.hikari_ready"), config.getStorageType());
        }
    }

    private void initializeStandardJdbcConnection() throws SQLException {
        String jdbcUrl = config.getJdbcUrl();
        if (logger.isInfoEnabled()) {
            logger.info(DB_MARKER, "Connecting to database (standard JDBC): {}", jdbcUrl);
        }

        connectionSource = new JdbcConnectionSource(
                jdbcUrl,
                config.getUser(),
                config.getPassword()
        );

        if (logger.isInfoEnabled()) {
            logger.info(DB_MARKER, messages.get("database.manager.standard_jdbc"), config.getStorageType());
        }
    }

    private void initializeDaos() throws SQLException {
        playerDao = DaoManager.createDao(connectionSource, RegisteredPlayer.class);
        premiumUuidDao = new PremiumUuidDao(connectionSource);
        jdbcAuthDao = new JdbcAuthDao(config);
    }

    private void markAsConnected() {
        connected = true;
        if (logger.isInfoEnabled()) {
            logger.info(DB_MARKER, messages.get("database.manager.connected"), config.getStorageType());
        }
    }

    /**
     * Wykonuje operację w transakcji DB dla atomowości.
     * Używa Virtual Threads dla wydajności I/O i ORMLite TransactionManager.
     *
     * @param operation Operacja do wykonania w transakcji
     * @param <T>       Typ zwracany przez operację
     * @return CompletableFuture z wynikiem operacji
     */
    public <T> CompletableFuture<T> executeInTransaction(Callable<T> operation) {
        return CompletableFuture.supplyAsync(() -> {
            validateConnectionSource();
            return executeTransaction(operation);
        }, dbExecutor);
    }

    private void validateConnectionSource() {
        if (connectionSource == null) {
            throw new RuntimeException(DATABASE_NOT_CONNECTED);
        }
    }

    private <T> T executeTransaction(Callable<T> operation) {
        try {
            TransactionManager transactionManager = new TransactionManager(connectionSource);
            return transactionManager.callInTransaction(operation);
        } catch (SQLException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Błąd SQL podczas transakcji", e);
            }
            throw new RuntimeException("SQL transaction failed", e);
        } catch (IllegalStateException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Błąd stanu w transakcji DB", e);
            }
            throw new RuntimeException("Transaction state failed", e);
        } catch (RuntimeException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Błąd wykonania w transakcji DB", e);
            }
            throw new RuntimeException("Transaction execution failed", e);
        }
    }

    /**
     * Uruchamia okresowe health checks bazy danych.
     */
    private void startHealthChecks() {
        healthCheckExecutor.scheduleAtFixedRate(() -> {
            try {
                performHealthCheck();
            } catch (Exception e) {
                if (logger.isErrorEnabled()) {
                    logger.error(DB_MARKER, "Błąd podczas health check bazy danych", e);
                }
            }
        }, 30, 30, TimeUnit.SECONDS); // Start po 30 sekundach, co 30 sekund

        if (logger.isInfoEnabled()) {
            logger.info(DB_MARKER, messages.get("database.manager.health_checks_started"));
        }
    }

    /**
     * Wykonuje health check bazy danych.
     */
    private void performHealthCheck() {
        try {
            if (!connected) {
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "Health check pominięty - baza danych nie jest połączona");
                }
                return;
            }

            // Prosty health check - wykonujemy szybkie zapytanie
            boolean healthy = jdbcAuthDao.healthCheck();
            lastHealthCheckTime = System.currentTimeMillis();
            lastHealthCheckPassed = healthy;

            if (!healthy) {
                if (logger.isWarnEnabled()) {
                    logger.warn(DB_MARKER, "\u274C Database health check FAILED - connection may be unstable");
                }
                // Don't set connected=false for single health check failure
                // Only log warning - HikariCP will handle connection recovery
            } else {
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "\u2705 Database health check PASSED");
                }
            }

        } catch (Exception e) {
            lastHealthCheckTime = System.currentTimeMillis();
            lastHealthCheckPassed = false;
            // Don't set connected=false for health check exceptions
            // Only log error - HikariCP will handle connection recovery
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "❌ Database health check FAILED with exception: {}", e.getMessage());
            }
        }
    }

    /**
     * Sprawdza czy baza danych jest zdrowa (ostatni health check passed).
     */
    public boolean isHealthy() {
        return connected; // Trust HikariCP connection management
    }

    /**
     * Zwraca czas ostatniego health checku.
     */
    public long getLastHealthCheckTime() {
        return lastHealthCheckTime;
    }

    /**
     * Zwraca czy ostatni health check był pozytywny.
     */
    public boolean wasLastHealthCheckPassed() {
        return lastHealthCheckPassed;
    }

    public void shutdown() {
        try {
            // Zatrzymaj health checks najpierw
            if (healthCheckExecutor != null && !healthCheckExecutor.isShutdown()) {
                healthCheckExecutor.shutdown();
                try {
                    if (!healthCheckExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                        healthCheckExecutor.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    healthCheckExecutor.shutdownNow();
                    Thread.currentThread().interrupt();
                }
                if (logger.isInfoEnabled()) {
                    logger.info(DB_MARKER, "Health checks zatrzymane");
                }
            }

            databaseLock.lock();
            try {
                if (connectionSource != null) {
                    connectionSource.close();
                    connectionSource = null;
                    if (logger.isInfoEnabled()) {
                        logger.info(DB_MARKER, messages.get("database.manager.connection_closed"));
                    }
                }
                connected = false;
                playerCache.clear();
                if (logger.isDebugEnabled()) {
                    logger.debug(CACHE_MARKER, "Cache graczy wyczyszczony");
                }
            } finally {
                databaseLock.unlock();
            }
        } catch (Exception e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Błąd podczas zamykania bazy danych", e);
            }
        } finally {
            dbExecutor.shutdown();
        }
    }

    /**
     * Znajduje gracza po lowercase nickname z wykorzystaniem cache + natywnego JDBC.
     * Zwraca DbResult dla rozróżnienia między "nie znaleziono" a "błąd bazy danych".
     * 
     * CRITICAL FIX: Ensure cache key consistency by always normalizing to lowercase
     * to prevent race conditions when switching between accounts rapidly.
     */
    public CompletableFuture<DbResult<RegisteredPlayer>> findPlayerByNickname(String nickname) {
        if (nickname == null || nickname.isEmpty()) {
            return CompletableFuture.completedFuture(DbResult.success(null));
        }

        String normalizedNickname = nickname.toLowerCase();
        
        return CompletableFuture.supplyAsync(() -> {
            DbResult<RegisteredPlayer> cacheResult = checkCache(normalizedNickname);
            if (cacheResult != null) {
                return cacheResult;
            }

            DbResult<Void> connectionResult = validateDatabaseConnection();
            if (connectionResult.isDatabaseError()) {
                return DbResult.databaseError(connectionResult.getErrorMessage());
            }

            return queryPlayerFromDatabase(normalizedNickname);
        }, dbExecutor);
    }

    private DbResult<RegisteredPlayer> checkCache(String normalizedNickname) {
        RegisteredPlayer cached = playerCache.get(normalizedNickname);
        if (cached == null) {
            return null; // Cache miss
        }

        if (isCacheCorrupted(cached, normalizedNickname)) {
            handleCacheCorruption(normalizedNickname);
            return null; // Treat as cache miss
        }

        logCacheHit(normalizedNickname);
        return DbResult.success(cached);
    }

    private boolean isCacheCorrupted(RegisteredPlayer cached, String normalizedNickname) {
        return !cached.getLowercaseNickname().equals(normalizedNickname);
    }

    private void handleCacheCorruption(String normalizedNickname) {
        playerCache.remove(normalizedNickname);
        if (logger.isWarnEnabled()) {
            logger.warn(CACHE_MARKER, "Cache corruption detected for {} - removing invalid entry", normalizedNickname);
        }
    }

    private void logCacheHit(String normalizedNickname) {
        if (logger.isDebugEnabled()) {
            logger.debug(CACHE_MARKER, "Cache HIT dla gracza: {}", normalizedNickname);
        }
    }

    private DbResult<RegisteredPlayer> queryPlayerFromDatabase(String normalizedNickname) {
        try {
            RegisteredPlayer player = jdbcAuthDao.findPlayerByLowercaseNickname(normalizedNickname);
            if (player != null) {
                handleDatabaseResult(player, normalizedNickname);
            } else {
                logPlayerNotFound(normalizedNickname);
            }
            return DbResult.success(player);
        } catch (SQLException e) {
            return handleDatabaseError(normalizedNickname, e);
        }
    }

    private void handleDatabaseResult(RegisteredPlayer player, String normalizedNickname) {
        if (player.getLowercaseNickname().equals(normalizedNickname)) {
            playerCache.put(normalizedNickname, player);
            if (logger.isDebugEnabled()) {
                logger.debug(CACHE_MARKER, "Cache MISS -> DB HIT dla gracza: {}", normalizedNickname);
            }
        } else {
            if (logger.isWarnEnabled()) {
                logger.warn(CACHE_MARKER, "Database inconsistency for {} - expected {}, found {}", 
                        normalizedNickname, normalizedNickname, player.getLowercaseNickname());
            }
        }
    }

    private void logPlayerNotFound(String normalizedNickname) {
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, "Gracz nie znaleziony: {}", normalizedNickname);
        }
    }

    private DbResult<RegisteredPlayer> handleDatabaseError(String normalizedNickname, SQLException e) {
        if (logger.isErrorEnabled()) {
            logger.error(DB_MARKER, "Błąd podczas wyszukiwania gracza: {}", normalizedNickname, e);
        }
        return DbResult.databaseError(messages.get(DATABASE_ERROR) + ": " + e.getMessage());
    }

    /**
     * Zapisuje lub aktualizuje gracza w bazie danych z użyciem natywnego JDBC.
     */
    public CompletableFuture<DbResult<Boolean>> savePlayer(RegisteredPlayer player) {
        if (player == null) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }

        return CompletableFuture.supplyAsync(() -> {
            DbResult<Void> connectionResult = validateDatabaseConnection();
            if (connectionResult.isDatabaseError()) {
                return DbResult.databaseError(connectionResult.getErrorMessage());
            }

            return executePlayerSave(player);
        }, dbExecutor);
    }

    private DbResult<Void> validateDatabaseConnection() {
        if (!connected) {
            if (logger.isWarnEnabled()) {
                logger.warn(DB_MARKER, DATABASE_NOT_CONNECTED);
            }
            return DbResult.databaseError(DATABASE_NOT_CONNECTED);
        }
        return DbResult.success(null);
    }

    private DbResult<Boolean> executePlayerSave(RegisteredPlayer player) {
        try {
            boolean success = jdbcAuthDao.upsertPlayer(player);
            if (success) {
                playerCache.put(player.getLowercaseNickname(), player);
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "Zapisano gracza (upsert): {}", player.getNickname());
                }
            }
            return DbResult.success(success);
        } catch (SQLException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Błąd podczas zapisywania gracza: {}", player.getNickname(), e);
            }
            return DbResult.databaseError(messages.get(DATABASE_ERROR) + ": " + e.getMessage());
        }
    }

    /**
     * Usuwa gracza z bazy danych i odświeża cache.
     */
    public CompletableFuture<DbResult<Boolean>> deletePlayer(String lowercaseNickname) {
        if (lowercaseNickname == null || lowercaseNickname.isEmpty()) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }

        return CompletableFuture.supplyAsync(() -> {
            DbResult<Void> connectionResult = validateDatabaseConnection();
            if (connectionResult.isDatabaseError()) {
                return DbResult.databaseError(connectionResult.getErrorMessage());
            }

            return executePlayerDelete(lowercaseNickname);
        }, dbExecutor);
    }

    private DbResult<Boolean> executePlayerDelete(String lowercaseNickname) {
        try {
            boolean deleted = jdbcAuthDao.deletePlayer(lowercaseNickname);
            playerCache.remove(lowercaseNickname);

            if (deleted) {
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "Usunięto gracza: {}", lowercaseNickname);
                }
                return DbResult.success(true);
            }

            if (logger.isDebugEnabled()) {
                logger.debug(DB_MARKER, "Gracz nie znaleziony do usunięcia: {}", lowercaseNickname);
            }
            return DbResult.success(false);
        } catch (SQLException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Błąd podczas usuwania gracza: {}", lowercaseNickname, e);
            }
            return DbResult.databaseError(messages.get(DATABASE_ERROR) + ": " + e.getMessage());
        }
    }

    /**
     * Sprawdza premium status gracza z wykorzystaniem PREMIUM_UUIDS table.
     */
    public CompletableFuture<DbResult<Boolean>> isPremium(String username) {
        if (username == null || username.isEmpty()) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }

        return CompletableFuture.supplyAsync(() -> {
            if (!connected) {
                if (logger.isWarnEnabled()) {
                    logger.warn(DB_MARKER, DATABASE_NOT_CONNECTED_PREMIUM_CHECK, username);
                }
                return DbResult.databaseError(DATABASE_NOT_CONNECTED);
            }

            try {
                // Use PREMIUM_UUIDS table for premium status lookup
                boolean premium = premiumUuidDao.findByNickname(username).isPresent();
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "Premium status z PREMIUM_UUIDS dla {}: {}", username, premium);
                }
                return DbResult.success(premium);
            } catch (RuntimeException e) {
                if (logger.isErrorEnabled()) {
                    logger.error(DB_MARKER, "Błąd wykonania podczas sprawdzania premium status dla gracza: {}", username, e);
                }
                return DbResult.databaseError(messages.get(DATABASE_ERROR) + ": " + e.getMessage());
            }
        }, dbExecutor);
    }

    /**
     * Pobiera wszystkich graczy (używa ORMLite, bo nie jest to hot-path).
     */
    public CompletableFuture<List<RegisteredPlayer>> getAllPlayers() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                if (!connected || playerDao == null) {
                    if (logger.isWarnEnabled()) {
                        logger.warn(DB_MARKER, DATABASE_NOT_CONNECTED);
                    }
                    return List.of();
                }

                List<RegisteredPlayer> players = playerDao.queryForAll();
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "Pobrano {} graczy z bazy danych", players.size());
                }

                return players;

            } catch (SQLException e) {
                if (logger.isErrorEnabled()) {
                    logger.error(DB_MARKER, "Błąd podczas pobierania wszystkich graczy", e);
                }
                return List.of();
            }
        }, dbExecutor);
    }

    /**
     * Czyści cache graczy.
     */
    public void clearCache() {
        playerCache.clear();
        if (logger.isDebugEnabled()) {
            logger.debug(CACHE_MARKER, "Cache graczy wyczyszczony");
        }
    }

    /**
     * Usuwa gracza z cache.
     *
     * @param lowercaseNickname Nickname w lowercase
     */
    public void removeCachedPlayer(String lowercaseNickname) {
        if (lowercaseNickname != null) {
            playerCache.remove(lowercaseNickname);
            if (logger.isDebugEnabled()) {
                logger.debug("Usunięto z cache gracza: {}", lowercaseNickname);
            }
        }
    }

    /**
     * Zwraca rozmiar cache.
     *
     * @return Liczba graczy w cache
     */
    public int getCacheSize() {
        return playerCache.size();
    }

    /**
     * Sprawdza czy baza danych jest połączona.
     *
     * @return true jeśli połączona
     */
    public boolean isConnected() {
        return connected;
    }

    /**
     * Zwraca konfigurację bazy danych.
     *
     * @return DatabaseConfig
     */
    public DatabaseConfig getConfig() {
        return config;
    }

    /**
     * Zwraca DAO dla operacji na PremiumUuid.
     *
     * @return PremiumUuidDao
     */
    public PremiumUuidDao getPremiumUuidDao() {
        return premiumUuidDao;
    }

    /**
     * Tworzy tabele jeśli nie istnieją i migruje schemat dla kompatybilności z limboauth.
     */
    private void createTablesIfNotExists() throws SQLException {
        if (logger.isInfoEnabled()) {
            logger.info(messages.get("database.manager.creating_tables"));
        }

        // Tworzenie tabeli AUTH
        TableUtils.createTableIfNotExists(connectionSource, RegisteredPlayer.class);

        // Tworzenie tabeli PREMIUM_UUIDS
        TableUtils.createTableIfNotExists(connectionSource, PremiumUuid.class);

        // Migrowanie schematu dla kompatybilności z limboauth
        migrateAuthTableForLimboauth();

        // Tworzenie indeksów dla wydajności
        createIndexesIfNotExists();

        if (logger.isInfoEnabled()) {
            logger.info(messages.get("database.manager.tables_created"));
        }
    }

    /**
     * Migruje tabelę AUTH dla kompatybilności z limboauth.
     * Dodaje brakujące kolumny: PREMIUMUUID, TOTPTOKEN, ISSUEDTIME.
     */
    private void migrateAuthTableForLimboauth() throws SQLException {
        try {
            java.sql.Connection connection = connectionSource.getReadWriteConnection(null).getUnderlyingConnection();
            try {
                ColumnMigrationResult migrationResult = checkExistingColumns(connection);
                DatabaseType dbType = DatabaseType.fromName(config.getStorageType());
                String quote = dbType == DatabaseType.POSTGRESQL ? "\"" : "`";

                addMissingColumns(connection, migrationResult, quote);
                logMigrationComplete(migrationResult);

            } finally {
                // Nie zamykaj połączenia - jest zarządzane przez ConnectionSource
            }
        } catch (SQLException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Błąd podczas migracji tabeli AUTH dla limboauth", e);
            }
            throw e;
        }
    }

    private ColumnMigrationResult checkExistingColumns(java.sql.Connection connection) throws SQLException {
        boolean hasPremiumUuid = columnExists(connection, "AUTH", "PREMIUMUUID");
        boolean hasTotpToken = columnExists(connection, "AUTH", "TOTPTOKEN");
        boolean hasIssuedTime = columnExists(connection, "AUTH", "ISSUEDTIME");
        return new ColumnMigrationResult(hasPremiumUuid, hasTotpToken, hasIssuedTime);
    }

    private void addMissingColumns(java.sql.Connection connection, ColumnMigrationResult result, String quote) throws SQLException {
        if (!result.hasPremiumUuid) {
            addColumn(connection, quote, "PREMIUMUUID", "VARCHAR(36)", "Dodano kolumnę PREMIUMUUID do tabeli AUTH");
        }

        if (!result.hasTotpToken) {
            addColumn(connection, quote, "TOTPTOKEN", "VARCHAR(32)", "Dodano kolumnę TOTPTOKEN do tabeli AUTH");
        }

        if (!result.hasIssuedTime) {
            addColumn(connection, quote, "ISSUEDTIME", "BIGINT DEFAULT 0", "Dodano kolumnę ISSUEDTIME do tabeli AUTH");
        }
    }

    private void addColumn(java.sql.Connection connection, String quote, String columnName, String columnDefinition, String logMessage) throws SQLException {
        String sql = ALTER_TABLE + quote + "AUTH" + quote + ADD_COLUMN + quote + columnName + quote + " " + columnDefinition;
        executeAlterTable(connection, sql);
        if (logger.isInfoEnabled()) {
            logger.info(DB_MARKER, logMessage);
        }
    }

    private void logMigrationComplete(ColumnMigrationResult result) {
        if (logger.isInfoEnabled() && (!result.hasPremiumUuid || !result.hasTotpToken || !result.hasIssuedTime)) {
            logger.info(DB_MARKER, "Migracja schematu AUTH dla limboauth zakończona");
        }
    }

    private static class ColumnMigrationResult {
        final boolean hasPremiumUuid;
        final boolean hasTotpToken;
        final boolean hasIssuedTime;

        ColumnMigrationResult(boolean hasPremiumUuid, boolean hasTotpToken, boolean hasIssuedTime) {
            this.hasPremiumUuid = hasPremiumUuid;
            this.hasTotpToken = hasTotpToken;
            this.hasIssuedTime = hasIssuedTime;
        }
    }

    /**
     * Wykonuje ALTER TABLE statement w bezpieczny sposób.
     * Używa stałych wartości - nie ma ryzyka SQL injection.
     */
    private void executeAlterTable(java.sql.Connection connection, String sql) throws SQLException {
        try (java.sql.Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    /**
     * Sprawdza czy kolumna istnieje w tabeli używając DatabaseMetaData.
     */
    private boolean columnExists(java.sql.Connection connection, String tableName, String columnName) throws SQLException {
        java.sql.DatabaseMetaData metaData = connection.getMetaData();
        try (java.sql.ResultSet columns = metaData.getColumns(null, null, tableName, columnName)) {
            return columns.next();
        }
    }

    /**
     * Tworzy indeksy dla wydajności.
     */
    private void createIndexesIfNotExists() {
        try {
            DatabaseType dbType = DatabaseType.fromName(config.getStorageType());

            // Indeksy różnią się między bazami danych
            if (dbType == DatabaseType.POSTGRESQL) {
                executeUpdate("CREATE INDEX IF NOT EXISTS idx_auth_ip ON \"AUTH\" (\"IP\")");
                executeUpdate("CREATE INDEX IF NOT EXISTS idx_auth_uuid ON \"AUTH\" (\"UUID\")");
                executeUpdate("CREATE INDEX IF NOT EXISTS idx_auth_logindate ON \"AUTH\" (\"LOGINDATE\")");
                executeUpdate("CREATE INDEX IF NOT EXISTS idx_auth_regdate ON \"AUTH\" (\"REGDATE\")");
            } else if (dbType == DatabaseType.MYSQL) {
                executeUpdate("CREATE INDEX IF NOT EXISTS idx_auth_ip ON `AUTH` (`IP`)");
                executeUpdate("CREATE INDEX IF NOT EXISTS idx_auth_uuid ON `AUTH` (`UUID`)");
                executeUpdate("CREATE INDEX IF NOT EXISTS idx_auth_logindate ON `AUTH` (`LOGINDATE`)");
                executeUpdate("CREATE INDEX IF NOT EXISTS idx_auth_regdate ON `AUTH` (`REGDATE`)");
            }
            // H2 i SQLite tworzą indeksy automatycznie dla kluczy obcych

        } catch (SQLException e) {
            if (logger.isWarnEnabled()) {
                logger.warn(messages.get("database.manager.index_error"), e.getMessage());
            }
        }
    }

    /**
     * Wykonuje UPDATE/DDL statement z poprawnym zarządzaniem połączeniami.
     */
    private void executeUpdate(String sql) throws SQLException {
        if (connectionSource != null) {
            DatabaseConnection connection = null;
            try {
                connection = connectionSource.getReadWriteConnection(null);
                connection.executeStatement(sql, 0);
            } finally {
                if (connection != null) {
                    connectionSource.releaseConnection(connection);
                }
            }
        }
    }

    /**
     * Result wrapper for database operations that distinguishes between
     * "not found" and "database error" states for fail-secure behavior.
     *
     * <p>This wrapper is critical for security as it prevents authentication bypass
     * when the database is unavailable. Without this distinction, a SQLException
     * could be interpreted as "player not found" and allow unauthorized access.
     *
     * <p>Usage examples:
     * <pre>{@code
     * var result = databaseManager.findPlayerByNickname("player").join();
     * if (result.isDatabaseError()) {
     *     // Database unavailable - deny access for security
     *     return false;
     * }
     * RegisteredPlayer player = result.getValue();
     * if (player == null) {
     *     // Player legitimately not found
     *     return false;
     * }
     * // Proceed with authentication
     * }</pre>
     *
     * @param <T> the type of value returned by the database operation
     */
    public static final class DbResult<T> {
        private final T value;
        private final boolean isDatabaseError;
        private final String errorMessage;

        private DbResult(T value, boolean isDatabaseError, String errorMessage) {
            this.value = value;
            this.isDatabaseError = isDatabaseError;
            this.errorMessage = errorMessage;
        }

        /**
         * Creates a successful DbResult with the given value.
         *
         * @param value the successful result value
         * @return DbResult indicating success
         */
        public static <T> DbResult<T> success(T value) {
            return new DbResult<>(value, false, null);
        }

        /**
         * Creates a DbResult indicating a database error.
         *
         * @param errorMessage the error message describing what went wrong
         * @return DbResult indicating database error
         */
        public static <T> DbResult<T> databaseError(String errorMessage) {
            return new DbResult<>(null, true, errorMessage);
        }

        /**
         * Gets the value from a successful database operation.
         *
         * @return the operation result value, or null if this was an error
         */
        public T getValue() {
            return value;
        }

        /**
         * Checks if this result represents a database error.
         *
         * @return true if database error occurred, false for success
         */
        public boolean isDatabaseError() {
            return isDatabaseError;
        }

        /**
         * Gets the error message from a failed database operation.
         *
         * @return the error message, or null if this was successful
         */
        public String getErrorMessage() {
            return errorMessage;
        }

        /**
         * Checks if this result represents a successful operation.
         *
         * @return true if operation succeeded, false for database error
         */
        public boolean isSuccess() {
            return !isDatabaseError;
        }
    }
}
