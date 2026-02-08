package net.rafalohaki.veloauth.database;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.DataSourceConnectionSource;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
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

import java.lang.ref.WeakReference;
import java.sql.SQLException;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Manager bazy danych z obsługą ORMLite, connection pooling i thread-safety.
 * Obsługuje PostgreSQL, MySQL, H2 i SQLite z automatycznym tworzeniem tabel.
 * <p>
 * Używa Virtual Threads dla wydajnych operacji I/O i ConcurrentHashMap dla cache.
 * 
 * <h2>Cache Invalidation Strategy</h2>
 * DatabaseManager coordinates with AuthCache to maintain cache consistency:
 * <ul>
 *   <li><b>DatabaseManager.playerCache</b> - Stores RegisteredPlayer entities by lowercase nickname
 *       for database query reduction. Updated immediately on save/delete operations.</li>
 *   <li><b>AuthCache.authorizedPlayers</b> - Stores active session state by UUID.
 *       Invalidated via {@link #notifyAuthCacheOfUpdate(RegisteredPlayer)} after successful
 *       player data updates to force re-fetch from database on next access.</li>
 * </ul>
 * 
 * <h3>Synchronization Points</h3>
 * <ul>
 *   <li>{@link #savePlayer(RegisteredPlayer)} - Updates playerCache and notifies AuthCache</li>
 *   <li>{@link #deletePlayer(String)} - Removes from playerCache (AuthCache handles via session end)</li>
 *   <li>{@link #clearCache()} - Clears playerCache only (AuthCache managed independently)</li>
 * </ul>
 * 
 * <h3>Weak Reference Design</h3>
 * Uses {@link WeakReference} to AuthCache to avoid circular dependency and allow
 * garbage collection if AuthCache is no longer needed. Cache invalidation is
 * best-effort - if AuthCache is GC'd, operations continue without invalidation.
 */
public class DatabaseManager {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseManager.class);

    // Stałe dla wiadomości bazy danych
    private static final String DATABASE_ERROR = "database.error";

    // Stałe dla zapytań SQL
    private static final String ALTER_TABLE = "ALTER TABLE ";
    private static final String ADD_COLUMN = " ADD COLUMN ";

    // Stałe dla nazw tabel i kolumn - używane w innych metodach
    private static final String AUTH_TABLE = "AUTH";
    private static final String WHERE_CLAUSE = " WHERE ";


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
     * Weak reference to AuthCache for cache invalidation coordination.
     * Uses WeakReference to avoid circular dependency and allow GC if needed.
     */
    private WeakReference<net.rafalohaki.veloauth.cache.AuthCache> authCacheRef;

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

        // Wyłącz verbose ORMLite logging używając SLF4J (Logback jest internal)
        // Zakładamy, że SLF4J jest skonfigurowane w Velocity
        // Jeśli nie mamy dostępu do klas Logback, polegamy na konfiguracji zewnętrznej (logback.xml)
        
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, messages.get("database.manager.created"), config.getStorageType());
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
                    return performDatabaseInitialization();
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

    private boolean performDatabaseInitialization() throws SQLException {
        if (isAlreadyConnected()) {
            return true;
        }

        initializeConnection();
        initializeDaos();
        createTablesIfNotExists();
        markAsConnected();
        startHealthChecks();

        return true;
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
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, messages.get("database.manager.hikari_init"));
        }
        connectionSource = new DataSourceConnectionSource(config.getDataSource(), config.getJdbcUrl());

        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, messages.get("database.manager.hikari_ready"), config.getStorageType());
        }
    }

    private void initializeStandardJdbcConnection() throws SQLException {
        String jdbcUrl = config.getJdbcUrl();
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, "Connecting to database (standard JDBC): {}", jdbcUrl);
        }

        connectionSource = new JdbcConnectionSource(
                jdbcUrl,
                config.getUser(),
                config.getPassword()
        );

        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, messages.get("database.manager.standard_jdbc"), config.getStorageType());
        }
    }

    private void initializeDaos() throws SQLException {
        playerDao = DaoManager.createDao(connectionSource, RegisteredPlayer.class);
        premiumUuidDao = new PremiumUuidDao(connectionSource);
        jdbcAuthDao = new JdbcAuthDao(config);
    }

    private void markAsConnected() {
        connected = true;
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, messages.get("database.manager.connected"), config.getStorageType());
        }
    }

    /**
     * Uruchamia okresowe health checks bazy danych.
     */
    private void startHealthChecks() {
        healthCheckExecutor.scheduleAtFixedRate(() -> {
            try {
                performHealthCheck();
            } catch (RuntimeException e) {
                if (logger.isErrorEnabled()) {
                    logger.error(DB_MARKER, "Błąd podczas health check bazy danych", e);
                }
            }
        }, 30, 30, TimeUnit.SECONDS); // Start po 30 sekundach, co 30 sekund

        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, messages.get("database.manager.health_checks_started"));
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

        } catch (RuntimeException e) {
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
        return connected && wasLastHealthCheckPassed();
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
            stopHealthChecks();

            databaseLock.lock();
            try {
                closeConnectionResources();
            } finally {
                databaseLock.unlock();
            }
        } catch (RuntimeException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Błąd podczas zamykania bazy danych", e);
            }
        } finally {
            dbExecutor.shutdown();
        }
    }

    private void stopHealthChecks() {
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
    }

    private void closeConnectionResources() {
        if (connectionSource != null) {
            try {
                connectionSource.close();
            } catch (Exception e) {
                if (logger.isErrorEnabled()) {
                    logger.error(DB_MARKER, "Error closing database connection", e);
                }
            }
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
    }

    /**
     * Znajduje gracza po lowercase nickname z wykorzystaniem cache + natywnego JDBC.
     * Zwraca DbResult dla rozróżnienia między "nie znaleziono" a "błąd bazy danych".
     * <p>
     * CRITICAL FIX: Ensure cache key consistency by always normalizing to lowercase
     * to prevent race conditions when switching between accounts rapidly.
     */
    public CompletableFuture<DbResult<RegisteredPlayer>> findPlayerByNickname(String nickname) {
        return lookupPlayer(nickname, false);
    }

    /**
     * 🔥 RUNTIME DETECTION: Enhanced player lookup with premium detection.
     * For shared LimboAuth databases - detects premium/offline without migration.
     * 
     * @param nickname Player nickname
     * @return DbResult with RegisteredPlayer and runtime premium detection
     */
    public CompletableFuture<DbResult<RegisteredPlayer>> findPlayerWithRuntimeDetection(String nickname) {
        return lookupPlayer(nickname, true);
    }

    /**
     * Finds a player by nickname first (fast, primary key), then falls back to
     * UUID-based lookup for premium players who changed their Mojang nickname.
     * If found by UUID, auto-updates the nickname in AUTH table.
     *
     * @param nickname     Current player nickname
     * @param premiumUuid  Premium UUID to use as fallback lookup (null for offline)
     * @return DbResult with RegisteredPlayer (found by nick or UUID) or null
     */
    public CompletableFuture<DbResult<RegisteredPlayer>> findPlayerByUuidOrNickname(
            String nickname, UUID premiumUuid) {
        if (nickname == null || nickname.isEmpty()) {
            return CompletableFuture.completedFuture(DbResult.success(null));
        }
        if (dbExecutor.isShutdown()) {
            return CompletableFuture.completedFuture(
                    DbResult.databaseError(messages.get(DATABASE_ERROR) + ": Executor is shutting down"));
        }

        String normalizedNickname = nickname.toLowerCase();

        return CompletableFuture.supplyAsync(() -> {
            // 1. Primary: lookup by nickname (fast, primary key)
            DbResult<RegisteredPlayer> byNick = performPlayerLookup(normalizedNickname, nickname, true);
            if (byNick.isDatabaseError() || byNick.getValue() != null) {
                return byNick;
            }

            // 2. Fallback: lookup by PREMIUMUUID (premium nick change)
            if (premiumUuid == null) {
                return DbResult.success(null);
            }

            DbResult<Void> connectionResult = validateDatabaseConnection();
            if (connectionResult.isDatabaseError()) {
                return DbResult.databaseError(connectionResult.getErrorMessage());
            }

            return findAndMigrateByPremiumUuid(normalizedNickname, nickname, premiumUuid);
        }, dbExecutor);
    }

    private DbResult<RegisteredPlayer> findAndMigrateByPremiumUuid(
            String normalizedNickname, String originalNickname, UUID premiumUuid) {
        try {
            RegisteredPlayer byUuid = playerDao.queryForFirst(
                    playerDao.queryBuilder().where()
                            .eq("PREMIUMUUID", premiumUuid.toString())
                            .prepare());

            if (byUuid == null) {
                return DbResult.success(null);
            }

            String oldNick = byUuid.getNickname();
            logger.info("[NICK CHANGE] Premium player {} changed nickname: {} → {}",
                    premiumUuid, oldNick, originalNickname);

            // Remove old cache entry
            playerCache.remove(byUuid.getLowercaseNickname());

            // Update nickname in AUTH table (setNickname also updates lowercaseNickname)
            byUuid.setNickname(originalNickname);
            playerDao.update(byUuid);

            // Update cache with new key
            playerCache.put(normalizedNickname, byUuid);

            logRuntimeDetection(originalNickname, isPlayerPremiumRuntime(byUuid), byUuid.getHash());
            return DbResult.success(byUuid);
        } catch (SQLException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Error during UUID-based player lookup for {}: {}",
                        premiumUuid, e.getMessage());
            }
            return DbResult.databaseError(messages.get(DATABASE_ERROR) + ": " + e.getMessage());
        }
    }

    /**
     * Unified player lookup logic.
     * 
     * @param nickname Player nickname
     * @param runtimeDetection Whether to log runtime detection details
     * @return CompletableFuture with DbResult
     */
    private CompletableFuture<DbResult<RegisteredPlayer>> lookupPlayer(String nickname, boolean runtimeDetection) {
        if (nickname == null || nickname.isEmpty()) {
            return CompletableFuture.completedFuture(DbResult.success(null));
        }

        if (dbExecutor.isShutdown()) {
            return CompletableFuture.completedFuture(DbResult.databaseError(messages.get(DATABASE_ERROR) + ": Executor is shutting down"));
        }

        String normalizedNickname = nickname.toLowerCase();

        return CompletableFuture.supplyAsync(() -> performPlayerLookup(normalizedNickname, nickname, runtimeDetection), dbExecutor);
    }

    private DbResult<RegisteredPlayer> performPlayerLookup(String normalizedNickname, String originalNickname, boolean runtimeDetection) {
        DbResult<RegisteredPlayer> cacheResult = checkCacheSafe(normalizedNickname);
        
        if (isCacheResultUsable(cacheResult, normalizedNickname, runtimeDetection)) {
            return cacheResult;
        }

        logCacheMiss(normalizedNickname, runtimeDetection);

        DbResult<Void> connectionResult = validateDatabaseConnection();
        if (connectionResult.isDatabaseError()) {
            return DbResult.databaseError(connectionResult.getErrorMessage());
        }

        return queryAndCachePlayer(normalizedNickname, originalNickname, runtimeDetection);
    }

    private boolean isCacheResultUsable(DbResult<RegisteredPlayer> cacheResult, String normalizedNickname, boolean runtimeDetection) {
        if (cacheResult.isDatabaseError() || cacheResult.getValue() != null) {
            if (runtimeDetection && cacheResult.getValue() != null && logger.isDebugEnabled()) {
                logger.debug(CACHE_MARKER, "Runtime detection - cache HIT: {}", normalizedNickname);
            }
            return true;
        }
        return false;
    }

    private void logCacheMiss(String normalizedNickname, boolean runtimeDetection) {
        if (runtimeDetection && logger.isDebugEnabled()) {
            logger.debug(CACHE_MARKER, "Runtime detection - cache MISS: {}", normalizedNickname);
        }
    }

    private DbResult<RegisteredPlayer> queryAndCachePlayer(String normalizedNickname, String originalNickname, boolean runtimeDetection) {
        try {
            RegisteredPlayer player = jdbcAuthDao.findPlayerByLowercaseNickname(normalizedNickname);
            if (player != null) {
                if (player.getLowercaseNickname().equals(normalizedNickname)) {
                    playerCache.put(normalizedNickname, player);
                    if (runtimeDetection) {
                        logRuntimeDetection(originalNickname, isPlayerPremiumRuntime(player), player.getHash());
                    } else if (logger.isDebugEnabled()) {
                        logger.debug(CACHE_MARKER, "Cache MISS -> DB HIT dla gracza: {}", normalizedNickname);
                    }
                } else if (logger.isWarnEnabled()) {
                    logger.warn(CACHE_MARKER, "Database inconsistency for {} - expected {}, found {}",
                            normalizedNickname, normalizedNickname, player.getLowercaseNickname());
                }
            } else {
                logPlayerNotFound(normalizedNickname);
            }
            return DbResult.success(player);
        } catch (SQLException e) {
            return handleDatabaseError(normalizedNickname, e);
        }
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
     * 
     * <p><b>Cache Invalidation Synchronization Point:</b>
     * After successful save, this method:
     * <ol>
     *   <li>Updates DatabaseManager.playerCache with new data</li>
     *   <li>Notifies AuthCache to invalidate cached player data via {@link #notifyAuthCacheOfUpdate(RegisteredPlayer)}</li>
     * </ol>
     * This ensures both caches remain consistent with database state.
     * 
     * @param player RegisteredPlayer to save or update
     * @return CompletableFuture with DbResult indicating success or error
     */
    public CompletableFuture<DbResult<Boolean>> savePlayer(RegisteredPlayer player) {
        if (player == null) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }

        if (dbExecutor.isShutdown()) {
            return CompletableFuture.completedFuture(DbResult.databaseError(messages.get(DATABASE_ERROR) + ": Executor is shutting down"));
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
                
                // Notify AuthCache of player data update for cache invalidation coordination
                notifyAuthCacheOfUpdate(player);
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
     * Notifies AuthCache of player data update for cache invalidation.
     * Uses weak reference to avoid circular dependency.
     * Handles exceptions gracefully to prevent save operation failure.
     * 
     * @param player RegisteredPlayer that was updated
     */
    private void notifyAuthCacheOfUpdate(RegisteredPlayer player) {
        if (authCacheRef == null) {
            return;
        }

        net.rafalohaki.veloauth.cache.AuthCache authCache = authCacheRef.get();
        if (authCache == null) {
            logAuthCacheGarbageCollected();
            return;
        }

        invalidatePlayerInAuthCache(player, authCache);
    }

    private void logAuthCacheGarbageCollected() {
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, "AuthCache reference is null (GC collected) - skipping cache invalidation");
        }
    }

    private void invalidatePlayerInAuthCache(RegisteredPlayer player, net.rafalohaki.veloauth.cache.AuthCache authCache) {
        try {
            UUID playerUuid = UUID.fromString(player.getUuid());
            authCache.invalidatePlayerData(playerUuid);
            logCacheInvalidation(player, playerUuid);
        } catch (IllegalArgumentException e) {
            logInvalidUuidError(player, e);
        } catch (Exception e) {
            logCacheNotificationError(player, e);
        }
    }

    private void logCacheInvalidation(RegisteredPlayer player, UUID playerUuid) {
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, "Notified AuthCache of update for player: {} (UUID: {})",
                    player.getNickname(), playerUuid);
        }
    }

    private void logInvalidUuidError(RegisteredPlayer player, IllegalArgumentException e) {
        if (logger.isWarnEnabled()) {
            logger.warn(DB_MARKER, "Failed to parse UUID for cache invalidation: {} - {}",
                    player.getUuid(), e.getMessage());
        }
    }

    private void logCacheNotificationError(RegisteredPlayer player, Exception e) {
        if (logger.isErrorEnabled()) {
            logger.error(DB_MARKER, "Error notifying AuthCache of player update: {}",
                    player.getNickname(), e);
        }
    }

    /**
     * Usuwa gracza z bazy danych i odświeża cache.
     */
    public CompletableFuture<DbResult<Boolean>> deletePlayer(String nickname) {
        if (nickname == null || nickname.isEmpty()) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }

        String normalizedNickname = nickname.toLowerCase();

        return CompletableFuture.supplyAsync(() -> {
            DbResult<Void> connectionResult = validateDatabaseConnection();
            if (connectionResult.isDatabaseError()) {
                return DbResult.databaseError(connectionResult.getErrorMessage());
            }

            return executePlayerDelete(normalizedNickname);
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
        return isHealthy();
    }

    /**
     * Zwraca liczbę kont non-premium (AUTH z HASH NOT NULL).
     */
    public CompletableFuture<Integer> getTotalNonPremiumAccounts() {
        return CompletableFuture.supplyAsync(() -> {
            if (!connected) {
                return 0;
            }
            try {
                boolean postgres = DatabaseType.POSTGRESQL.getName().equalsIgnoreCase(config.getStorageType());
                String auth = postgres ? "\"AUTH\"" : "AUTH";
                String hash = postgres ? "\"HASH\"" : "HASH";
                String sql = "SELECT COUNT(*) FROM " + auth + WHERE_CLAUSE + hash + " IS NOT NULL";

                return executeCountQuery(sql);
            } catch (SQLException e) {
                if (logger.isErrorEnabled()) {
                    logger.error(DB_MARKER, "Error counting non-premium accounts", e);
                }
                return 0;
            }
        }, dbExecutor);
    }

    @SuppressWarnings("java:S2077") // Safe: predefined templates only
    private int executeCountQuery(String sql) throws SQLException {
        DatabaseConnection dbConnection = connectionSource.getReadWriteConnection(null);
        try {
            java.sql.Connection connection = dbConnection.getUnderlyingConnection();
            // SQL Injection safe: Using constant SQL string, not user input
            try (java.sql.Statement stmt = connection.createStatement();
                 java.sql.ResultSet rs = stmt.executeQuery(sql)) { // NOSONAR - SQL from constants only
                if (rs.next()) {
                    return rs.getInt(1);
                }
                return 0;
            }
        } finally {
            connectionSource.releaseConnection(dbConnection);
        }
    }

    /**
     * Zwraca liczbę wszystkich zarejestrowanych kont.
     * Simple implementation using getAllPlayers() to avoid complex SQL queries.
     */
    public CompletableFuture<Integer> getTotalRegisteredAccounts() {
        return getAllPlayers().thenApply(Collection::size)
                .exceptionally(e -> {
                    if (logger.isErrorEnabled()) {
                        logger.error(DB_MARKER, "Error getting total registered accounts", e);
                    }
                    return 0;
                });
    }

    /**
     * Zwraca liczbę kont premium.
     * Simple implementation using existing data to avoid complex SQL queries.
     */
    public CompletableFuture<Integer> getTotalPremiumAccounts() {
        return getAllPlayers().thenApply(players ->
                (int) players.stream()
                        .filter(player -> player.getPremiumUuid() != null || player.getHash() == null)
                        .count()
        ).exceptionally(e -> {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Error getting total premium accounts", e);
            }
            return 0;
        });
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
     * Sets the AuthCache reference for cache invalidation coordination.
     * Uses WeakReference to avoid circular dependency.
     * 
     * @param authCache AuthCache instance to coordinate with
     */
    public void setAuthCacheReference(net.rafalohaki.veloauth.cache.AuthCache authCache) {
        if (authCache != null) {
            this.authCacheRef = new WeakReference<>(authCache);
            if (logger.isDebugEnabled()) {
                logger.debug(DB_MARKER, "AuthCache reference set for cache invalidation coordination");
            }
        }
    }

    /**
     * Tworzy tabele jeśli nie istnieją i migruje schemat dla kompatybilności z limboauth.
     */
    private void createTablesIfNotExists() throws SQLException {
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("database.manager.creating_tables"));
        }

        // Tworzenie tabeli AUTH
        TableUtils.createTableIfNotExists(connectionSource, RegisteredPlayer.class);

        // Tworzenie tabeli PREMIUM_UUIDS
        TableUtils.createTableIfNotExists(connectionSource, PremiumUuid.class);

        // Migrowanie schematu dla kompatybilności z limboauth
        migrateAuthTableForLimboauth();

        // Tworzenie indeksów dla wydajności
        createIndexesIfNotExists();

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("database.manager.tables_created"));
        }
    }

    /**
     * Migruje tabelę AUTH dla kompatybilności z limboauth.
     * Dodaje brakujące kolumny: PREMIUMUUID, TOTPTOKEN, ISSUEDTIME.
     */
    private void migrateAuthTableForLimboauth() throws SQLException {
        DatabaseConnection dbConnection = connectionSource.getReadWriteConnection(null);
        try {
            performColumnMigration(dbConnection);
        } finally {
            connectionSource.releaseConnection(dbConnection);
        }
    }

    private void performColumnMigration(DatabaseConnection dbConnection) throws SQLException {
        java.sql.Connection connection = dbConnection.getUnderlyingConnection();
        ColumnMigrationResult migrationResult = checkExistingColumns(connection);
        DatabaseType dbType = DatabaseType.fromName(config.getStorageType());
        String quote = dbType == DatabaseType.POSTGRESQL ? "\"" : "`";

        addMissingColumns(connection, migrationResult, quote);
        logMigrationComplete(migrationResult);
    }

    private ColumnMigrationResult checkExistingColumns(java.sql.Connection connection) throws SQLException {
        boolean hasPremiumUuid = columnExists(connection, AUTH_TABLE, "PREMIUMUUID");
        boolean hasTotpToken = columnExists(connection, AUTH_TABLE, "TOTPTOKEN");
        boolean hasIssuedTime = columnExists(connection, AUTH_TABLE, "ISSUEDTIME");
        boolean hasConflictMode = columnExists(connection, AUTH_TABLE, "CONFLICT_MODE");
        boolean hasConflictTimestamp = columnExists(connection, AUTH_TABLE, "CONFLICT_TIMESTAMP");
        boolean hasOriginalNickname = columnExists(connection, AUTH_TABLE, "ORIGINAL_NICKNAME");
        return new ColumnMigrationResult(hasPremiumUuid, hasTotpToken, hasIssuedTime, hasConflictMode, hasConflictTimestamp, hasOriginalNickname);
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

        // Add conflict resolution columns for USE_OFFLINE strategy
        if (!result.hasConflictMode) {
            addColumn(connection, quote, "CONFLICT_MODE", "BOOLEAN DEFAULT FALSE", "Dodano kolumnę CONFLICT_MODE do tabeli AUTH");
        }

        if (!result.hasConflictTimestamp) {
            addColumn(connection, quote, "CONFLICT_TIMESTAMP", "BIGINT DEFAULT 0", "Dodano kolumnę CONFLICT_TIMESTAMP do tabeli AUTH");
        }

        if (!result.hasOriginalNickname) {
            addColumn(connection, quote, "ORIGINAL_NICKNAME", "VARCHAR(16)", "Dodano kolumnę ORIGINAL_NICKNAME do tabeli AUTH");
        }
    }

    private void addColumn(java.sql.Connection connection, String quote, String columnName, String columnDefinition, String logMessage) throws SQLException {
        String sql = ALTER_TABLE + quote + AUTH_TABLE + quote + ADD_COLUMN + quote + columnName + quote + " " + columnDefinition;
        try {
            executeAlterTable(connection, sql);
            if (logger.isInfoEnabled()) {
                logger.info(DB_MARKER, logMessage);
            }
        } catch (SQLException e) {
            // H2 error code 42121 = DUPLICATE_COLUMN_NAME_1
            // Inne bazy mogą mieć różne kody, sprawdzamy też komunikat
            if (e.getErrorCode() == 42121 || e.getMessage().toLowerCase().contains("duplicate column")) {
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "Kolumna {} już istnieje w tabeli {} - pomijam (expected behavior)", 
                              columnName, AUTH_TABLE);
                }
                // Nie rzucaj wyjątku - kolumna już istnieje, kontynuuj
            } else {
                // Inny błąd SQL - przekaż dalej
                throw e;
            }
        }
    }

    private void logMigrationComplete(ColumnMigrationResult result) {
        if (logger.isDebugEnabled() && (!result.hasPremiumUuid || !result.hasTotpToken || !result.hasIssuedTime)) {
            logger.debug(DB_MARKER, "Migracja schematu AUTH dla limboauth zakończona");
        }
    }

    /**
     * Wykonuje ALTER TABLE statement w bezpieczny sposób.
     * Używa stałych wartości - nie ma ryzyka SQL injection.
     */
    @SuppressWarnings("java:S2077") // SQL Injection safe - internal migration constants only
    private void executeAlterTable(java.sql.Connection connection, String sql) throws SQLException {
        // SQL Injection safe: Using constant SQL string, not user input
        try (java.sql.Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
        }
    }

    /**
     * Sprawdza czy kolumna istnieje w tabeli używając DatabaseMetaData.
     * Obsługuje H2 z DATABASE_TO_LOWER=TRUE poprzez case-insensitive porównywanie.
     */
    private boolean columnExists(java.sql.Connection connection, String tableName, String columnName) throws SQLException {
        java.sql.DatabaseMetaData metaData = connection.getMetaData();
        
        // Sprawdź zarówno uppercase jak i lowercase nazwy
        // H2 z DATABASE_TO_LOWER=TRUE zwraca lowercase, inne bazy mogą zwracać uppercase
        try (java.sql.ResultSet columns = metaData.getColumns(null, null, tableName, null)) {
            while (columns.next()) {
                String existingColumn = columns.getString("COLUMN_NAME");
                if (existingColumn != null && existingColumn.equalsIgnoreCase(columnName)) {
                    if (logger.isDebugEnabled()) {
                        logger.debug(DB_MARKER, "Kolumna {} istnieje w tabeli {} (znaleziona jako: {})", 
                                   columnName, tableName, existingColumn);
                    }
                    return true;
                }
            }
        }
        
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, "Kolumna {} nie istnieje w tabeli {}", columnName, tableName);
        }
        return false;
    }

    /**
     * Tworzy indeksy dla wydajności.
     */
    private void createIndexesIfNotExists() {
        DatabaseType dbType = DatabaseType.fromName(config.getStorageType());

        // Indeksy różnią się między bazami danych
        if (dbType == DatabaseType.POSTGRESQL) {
            createPostgreSqlIndexes();
        } else if (dbType == DatabaseType.MYSQL) {
            createMySqlIndexes();
        }
        // H2 i SQLite tworzą indeksy automatycznie dla kluczy obcych
    }

    /**
     * Tworzy indeksy dla PostgreSQL.
     */
    private void createPostgreSqlIndexes() {
        createIndexSafely("CREATE INDEX IF NOT EXISTS idx_auth_ip ON \"AUTH\" (\"IP\")");
        createIndexSafely("CREATE INDEX IF NOT EXISTS idx_auth_uuid ON \"AUTH\" (\"UUID\")");
        createIndexSafely("CREATE INDEX IF NOT EXISTS idx_auth_logindate ON \"AUTH\" (\"LOGINDATE\")");
        createIndexSafely("CREATE INDEX IF NOT EXISTS idx_auth_regdate ON \"AUTH\" (\"REGDATE\")");
    }

    /**
     * Tworzy indeksy dla MySQL.
     */
    private void createMySqlIndexes() {
        createIndexSafely("CREATE INDEX IF NOT EXISTS idx_auth_ip ON `AUTH` (`IP`)");
        createIndexSafely("CREATE INDEX IF NOT EXISTS idx_auth_uuid ON `AUTH` (`UUID`)");
        createIndexSafely("CREATE INDEX IF NOT EXISTS idx_auth_logindate ON `AUTH` (`LOGINDATE`)");
        createIndexSafely("CREATE INDEX IF NOT EXISTS idx_auth_regdate ON `AUTH` (`REGDATE`)");
    }

    /**
     * Bezpiecznie tworzy indeks z obsługą błędów.
     */
    private void createIndexSafely(String sql) {
        try {
            executeUpdate(sql);
        } catch (SQLException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Index creation failed (may already exist): {}", e.getMessage());
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
     * 🔥 RUNTIME DETECTION: Detects if a player is premium based on HASHEDPASSWORD.
     * Used for shared LimboAuth databases without migration.
     * 
     * @param player RegisteredPlayer from database
     * @return true if player is premium (empty/null hash), false if offline (has password)
     */
    public boolean isPlayerPremiumRuntime(RegisteredPlayer player) {
        if (player == null) {
            return false;
        }
        
        String hash = player.getHash();
        // Premium accounts have empty/null HASHEDPASSWORD in LimboAuth
        return hash == null || hash.isEmpty() || hash.isBlank();
    }


    /**
     * Null-safe cache check that ALWAYS returns DbResult.
     * Never returns null - returns DbResult.success(null) for cache miss.
     */
    private DbResult<RegisteredPlayer> checkCacheSafe(String normalizedNickname) {
        RegisteredPlayer cached = playerCache.get(normalizedNickname);
        
        // Cache miss
        if (cached == null) {
            return DbResult.success(null);
        }
        
        // Cache corruption check
        if (isCacheCorrupted(cached, normalizedNickname)) {
            handleCacheCorruption(normalizedNickname);
            return DbResult.success(null); // Treat corruption as cache miss
        }
        
        // Cache hit
        logCacheHit(normalizedNickname);
        return DbResult.success(cached);
    }


    /**
     * Logs runtime detection results for debugging.
     */
    private void logRuntimeDetection(String nickname, boolean isPremium, String hash) {
        if (logger.isDebugEnabled()) {
            logger.debug("[RUNTIME DETECTION] {} -> {} (hash empty: {})", 
                       nickname, isPremium ? "PREMIUM" : "OFFLINE", 
                       hash == null || hash.isEmpty());
        }
    }

    /**
     * 🔥 ADMIN COMMAND: Finds all players currently in conflict mode.
     * Used by /vauth conflicts command to list nickname conflicts.
     * 
     * @return List of players with conflict mode enabled
     */
    public CompletableFuture<List<RegisteredPlayer>> findPlayersInConflictMode() {
        return CompletableFuture.supplyAsync(() -> {
            try {
                return jdbcAuthDao.findAllPlayersInConflictMode();
            } catch (SQLException e) {
                logger.error("Database error while finding players in conflict mode", e);
                return List.of();
            }
        }, dbExecutor);
    }

    private record ColumnMigrationResult(boolean hasPremiumUuid, boolean hasTotpToken, boolean hasIssuedTime, boolean hasConflictMode, boolean hasConflictTimestamp, boolean hasOriginalNickname) {
    }

    /**
     * Result wrapper for database operations that distinguishes between
     * "not found" and "database error" states for fail-secure behavior.
     *
     * <p>This wrapper is critical for security as it prevents authentication bypass
     * when the database is unavailable. Without this distinction, a SQLException
     * could be interpreted as "player not found" and allow unauthorized access.
     *
     * <p><b>IMPORTANT: Always check {@link #isSuccess()} or {@link #isDatabaseError()} 
     * before calling {@link #getValue()}.</b> Calling getValue() on a database error 
     * will return null, which could be misinterpreted as "not found".
     *
     * <p>Usage examples:
     * <pre>{@code
     * // CORRECT: Check for database error first
     * var result = databaseManager.findPlayerByNickname("player").join();
     * if (result.isDatabaseError()) {
     *     // Database unavailable - deny access for security
     *     logger.error("Database error: {}", result.getErrorMessage());
     *     return false;
     * }
     * RegisteredPlayer player = result.getValue();
     * if (player == null) {
     *     // Player legitimately not found
     *     return false;
     * }
     * // Proceed with authentication
     * 
     * // ALTERNATIVE: Use isSuccess() pattern
     * if (!result.isSuccess()) {
     *     logger.error("Database error: {}", result.getErrorMessage());
     *     return false;
     * }
     * RegisteredPlayer player = result.getValue();
     * 
     * // WRONG: Don't call getValue() without checking first
     * RegisteredPlayer player = result.getValue(); // Could be null due to error OR not found!
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
         * @param value the successful result value (may be null if not found)
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
         * <p>
         * <b>WARNING:</b> Always check {@link #isSuccess()} or {@link #isDatabaseError()} 
         * before calling this method. This method returns null for both database errors 
         * and legitimate "not found" cases.
         *
         * @return the operation result value, or null if this was an error or not found
         */
        @javax.annotation.Nullable
        public T getValue() {
            return value;
        }

        /**
         * Gets the value from a successful database operation using Optional pattern.
         * Returns empty Optional for both database errors and not found cases.
         * <p>
         * <b>NOTE:</b> This method does not distinguish between database errors and 
         * not found. Use {@link #isDatabaseError()} first if you need to handle 
         * errors differently.
         *
         * @return Optional containing the value if present, empty otherwise
         */
        @javax.annotation.Nonnull
        public java.util.Optional<T> getValueOptional() {
            return java.util.Objects.requireNonNull(java.util.Optional.ofNullable(value), "Optional cannot be null");
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
        @javax.annotation.Nullable
        public String getErrorMessage() {
            return errorMessage;
        }

        /**
         * Checks if this result represents a successful operation.
         * <p>
         * <b>NOTE:</b> Success means no database error occurred. The value may still 
         * be null if the requested entity was not found.
         *
         * @return true if operation succeeded, false for database error
         */
        public boolean isSuccess() {
            return !isDatabaseError;
        }
    }
}
