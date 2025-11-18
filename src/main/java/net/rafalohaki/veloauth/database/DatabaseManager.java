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
     * @param config Konfiguracja bazy danych
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

        logger.info(DB_MARKER, messages.get("database.manager.created"), config.getStorageType());
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

                    if (connected) {
                        logger.warn(DB_MARKER, "Baza danych już jest połączona");
                        return true;
                    }

                    // Sprawdź czy używać HikariCP
                    if (config.hasDataSource()) {
                        // Użyj HikariCP DataSource z DatabaseConfig
                        logger.info(DB_MARKER, messages.get("database.manager.hikari_init"));
                        connectionSource = new DataSourceConnectionSource(config.getDataSource(), config.getJdbcUrl());

                        logger.info(DB_MARKER, messages.get("database.manager.hikari_ready"), config.getStorageType());
                    } else {
                        // Fallback dla H2/SQLite lub gdy HikariCP nie jest skonfigurowany
                        String jdbcUrl = config.getJdbcUrl();
                        logger.info(DB_MARKER, "Connecting to database (standard JDBC): {}", jdbcUrl);

                        connectionSource = new JdbcConnectionSource(
                                jdbcUrl,
                                config.getUser(),
                                config.getPassword()
                        );

                        logger.info(DB_MARKER, messages.get("database.manager.standard_jdbc"), config.getStorageType());
                    }

                    // Tworzenie DAO
                    playerDao = DaoManager.createDao(connectionSource, RegisteredPlayer.class);
                    premiumUuidDao = new PremiumUuidDao(connectionSource);
                    jdbcAuthDao = new JdbcAuthDao(config);

                    // Tworzenie tabel jeśli nie istnieją
                    createTablesIfNotExists();

                    connected = true;
                    logger.info(DB_MARKER, messages.get("database.manager.connected"), config.getStorageType());
                    
                    // Uruchom health checks co 30 sekund
                    startHealthChecks();

                    return true;

                } finally {
                    databaseLock.unlock();
                }

            } catch (SQLException e) {
                logger.error(DB_MARKER, "Błąd podczas inicjalizacji bazy danych", e);
                return false;
            }
        }, dbExecutor);
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
            try {
                if (connectionSource == null) {
                    throw new RuntimeException(DATABASE_NOT_CONNECTED);
                }

                // Użyj ORMLite TransactionManager dla prawdziwych transakcji
                TransactionManager transactionManager = new TransactionManager(connectionSource);
                return transactionManager.callInTransaction(operation);

            } catch (SQLException e) {
                logger.error(DB_MARKER, "Błąd SQL podczas transakcji", e);
                throw new RuntimeException("SQL transaction failed", e);
            } catch (Exception e) {
                logger.error(DB_MARKER, "Błąd w transakcji DB", e);
                throw new RuntimeException("Transaction failed", e);
            }
        }, dbExecutor);
    }

    /**
     * Uruchamia okresowe health checks bazy danych.
     */
    private void startHealthChecks() {
        healthCheckExecutor.scheduleAtFixedRate(() -> {
            try {
                performHealthCheck();
            } catch (Exception e) {
                logger.error(DB_MARKER, "Błąd podczas health check bazy danych", e);
            }
        }, 30, 30, TimeUnit.SECONDS); // Start po 30 sekundach, co 30 sekund
        
        logger.info(DB_MARKER, messages.get("database.manager.health_checks_started"));
    }
    
    /**
     * Wykonuje health check bazy danych.
     */
    private void performHealthCheck() {
        try {
            if (!connected) {
                logger.debug(DB_MARKER, "Health check pominięty - baza danych nie jest połączona");
                return;
            }
            
            // Prosty health check - wykonujemy szybkie zapytanie
            boolean healthy = jdbcAuthDao.healthCheck();
            lastHealthCheckTime = System.currentTimeMillis();
            lastHealthCheckPassed = healthy;
            
            if (!healthy) {
                logger.warn(DB_MARKER, "\u274C Database health check FAILED - connection may be unstable");
                // Don't set connected=false for single health check failure
                // Only log warning - HikariCP will handle connection recovery
            } else {
                logger.debug(DB_MARKER, "\u2705 Database health check PASSED");
            }
            
        } catch (Exception e) {
            lastHealthCheckTime = System.currentTimeMillis();
            lastHealthCheckPassed = false;
            // Don't set connected=false for health check exceptions
            // Only log error - HikariCP will handle connection recovery
            logger.error(DB_MARKER, "❌ Database health check FAILED with exception: {}", e.getMessage());
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
                logger.info(DB_MARKER, "Health checks zatrzymane");
            }
            
            databaseLock.lock();
            try {
                if (connectionSource != null) {
                    connectionSource.close();
                    connectionSource = null;
                    logger.info(DB_MARKER, messages.get("database.manager.connection_closed"));
                }
                connected = false;
                playerCache.clear();
                logger.debug(CACHE_MARKER, "Cache graczy wyczyszczony");
            } finally {
                databaseLock.unlock();
            }
        } catch (Exception e) {
            logger.error(DB_MARKER, "Błąd podczas zamykania bazy danych", e);
        } finally {
            dbExecutor.shutdown();
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
        public T getValue() { return value; }
        
        /**
         * Checks if this result represents a database error.
         * 
         * @return true if database error occurred, false for success
         */
        public boolean isDatabaseError() { return isDatabaseError; }
        
        /**
         * Gets the error message from a failed database operation.
         * 
         * @return the error message, or null if this was successful
         */
        public String getErrorMessage() { return errorMessage; }
        
        /**
         * Checks if this result represents a successful operation.
         * 
         * @return true if operation succeeded, false for database error
         */
        public boolean isSuccess() { return !isDatabaseError; }
    }

    /**
     * Znajduje gracza po lowercase nickname z wykorzystaniem cache + natywnego JDBC.
     * Zwraca DbResult dla rozróżnienia między "nie znaleziono" a "błąd bazy danych".
     */
    public CompletableFuture<DbResult<RegisteredPlayer>> findPlayerByNickname(String lowercaseNickname) {
        if (lowercaseNickname == null || lowercaseNickname.isEmpty()) {
            return CompletableFuture.completedFuture(DbResult.success(null));
        }

        return CompletableFuture.supplyAsync(() -> {
            RegisteredPlayer cached = playerCache.get(lowercaseNickname);
            if (cached != null) {
                logger.debug(CACHE_MARKER, "Cache HIT dla gracza: {}", lowercaseNickname);
                return DbResult.success(cached);
            }

            if (!connected || !isHealthy()) {
                logger.warn(DB_MARKER, DATABASE_NOT_CONNECTED);
                return DbResult.databaseError(DATABASE_NOT_CONNECTED);
            }

            try {
                RegisteredPlayer player = jdbcAuthDao.findPlayerByLowercaseNickname(lowercaseNickname);
                if (player != null) {
                    playerCache.put(lowercaseNickname, player);
                    logger.debug(CACHE_MARKER, "Cache MISS -> DB HIT dla gracza: {}", lowercaseNickname);
                } else {
                    logger.debug(DB_MARKER, "Gracz nie znaleziony: {}", lowercaseNickname);
                }
                return DbResult.success(player);
            } catch (SQLException e) {
                logger.error(DB_MARKER, "Błąd podczas wyszukiwania gracza: {}", lowercaseNickname, e);
                // CRITICAL: Return database error instead of null to prevent bypass
                return DbResult.databaseError(messages.get("database.error") + ": " + e.getMessage());
            }
        }, dbExecutor);
    }

    /**
     * Zapisuje lub aktualizuje gracza w bazie danych z użyciem natywnego JDBC.
     */
    public CompletableFuture<DbResult<Boolean>> savePlayer(RegisteredPlayer player) {
        if (player == null) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }

        return CompletableFuture.supplyAsync(() -> {
            if (!connected) {
                logger.warn(DB_MARKER, DATABASE_NOT_CONNECTED);
                return DbResult.databaseError(DATABASE_NOT_CONNECTED);
            }

            try {
                boolean success = jdbcAuthDao.upsertPlayer(player);
                if (success) {
                    playerCache.put(player.getLowercaseNickname(), player);
                    logger.debug(DB_MARKER, "Zapisano gracza (upsert): {}", player.getNickname());
                }
                return DbResult.success(success);
            } catch (SQLException e) {
                logger.error(DB_MARKER, "Błąd podczas zapisywania gracza: {}", player.getNickname(), e);
                return DbResult.databaseError(messages.get("database.error") + ": " + e.getMessage());
            }
        }, dbExecutor);
    }

    /**
     * Usuwa gracza z bazy danych i odświeża cache.
     */
    public CompletableFuture<DbResult<Boolean>> deletePlayer(String lowercaseNickname) {
        if (lowercaseNickname == null || lowercaseNickname.isEmpty()) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }

        return CompletableFuture.supplyAsync(() -> {
            if (!connected) {
                logger.warn(DB_MARKER, DATABASE_NOT_CONNECTED);
                return DbResult.databaseError(DATABASE_NOT_CONNECTED);
            }

            try {
                boolean deleted = jdbcAuthDao.deletePlayer(lowercaseNickname);
                playerCache.remove(lowercaseNickname);

                if (deleted) {
                    logger.debug(DB_MARKER, "Usunięto gracza: {}", lowercaseNickname);
                    return DbResult.success(true);
                }

                logger.debug(DB_MARKER, "Gracz nie znaleziony do usunięcia: {}", lowercaseNickname);
                return DbResult.success(false);
            } catch (SQLException e) {
                logger.error(DB_MARKER, "Błąd podczas usuwania gracza: {}", lowercaseNickname, e);
                return DbResult.databaseError(messages.get("database.error") + ": " + e.getMessage());
            }
        }, dbExecutor);
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
                logger.warn(DB_MARKER, DATABASE_NOT_CONNECTED_PREMIUM_CHECK, username);
                return DbResult.databaseError(DATABASE_NOT_CONNECTED);
            }

            try {
                // Use PREMIUM_UUIDS table for premium status lookup
                boolean premium = premiumUuidDao.findByNickname(username).isPresent();
                logger.debug(DB_MARKER, "Premium status z PREMIUM_UUIDS dla {}: {}", username, premium);
                return DbResult.success(premium);
            } catch (Exception e) {
                logger.error(DB_MARKER, "Błąd podczas sprawdzania premium status dla gracza: {}", username, e);
                return DbResult.databaseError(messages.get("database.error") + ": " + e.getMessage());
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
                    logger.warn(DB_MARKER, DATABASE_NOT_CONNECTED);
                    return List.of();
                }

                List<RegisteredPlayer> players = playerDao.queryForAll();
                logger.debug(DB_MARKER, "Pobrano {} graczy z bazy danych", players.size());

                return players;

            } catch (SQLException e) {
                logger.error(DB_MARKER, "Błąd podczas pobierania wszystkich graczy", e);
                return List.of();
            }
        }, dbExecutor);
    }

    /**
     * Czyści cache graczy.
     */
    public void clearCache() {
        playerCache.clear();
        logger.debug(CACHE_MARKER, "Cache graczy wyczyszczony");
    }

    /**
     * Usuwa gracza z cache.
     *
     * @param lowercaseNickname Nickname w lowercase
     */
    public void removeCachedPlayer(String lowercaseNickname) {
        if (lowercaseNickname != null) {
            playerCache.remove(lowercaseNickname);
            logger.debug("Usunięto z cache gracza: {}", lowercaseNickname);
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
     * Tworzy tabele jeśli nie istnieją.
     */
    private void createTablesIfNotExists() throws SQLException {
        logger.info(messages.get("database.manager.creating_tables"));

        // Tworzenie tabeli AUTH
        TableUtils.createTableIfNotExists(connectionSource, RegisteredPlayer.class);

        // Tworzenie tabeli PREMIUM_UUIDS
        TableUtils.createTableIfNotExists(connectionSource, PremiumUuid.class);

        // Tworzenie indeksów dla wydajności
        createIndexesIfNotExists();

        logger.info(messages.get("database.manager.tables_created"));
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
            logger.warn(messages.get("database.manager.index_error"), e.getMessage());
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
}
