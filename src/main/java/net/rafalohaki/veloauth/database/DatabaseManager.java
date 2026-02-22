package net.rafalohaki.veloauth.database;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.DataSourceConnectionSource;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.support.DatabaseConnection;
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
import java.util.concurrent.locks.ReentrantLock;

/**
 * Manager bazy danych z obsługą ORMLite, connection pooling i thread-safety.
 * Obsługuje PostgreSQL, MySQL, H2 i SQLite z automatycznym tworzeniem tabel.
 * <p>
 * Używa Virtual Threads dla wydajnych operacji I/O i ConcurrentHashMap dla cache.
 * 
 * <h2>Extracted Components</h2>
 * <ul>
 *   <li>{@link DatabaseHealthCheck} - periodic health check monitoring</li>
 *   <li>{@link DatabaseMigrationService} - schema creation and migration</li>
 * </ul>
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
 * <h3>Weak Reference Design</h3>
 * Uses {@link WeakReference} to AuthCache to avoid circular dependency and allow
 * garbage collection if AuthCache is no longer needed.
 */
public class DatabaseManager {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseManager.class);

    private static final String DATABASE_ERROR = "database.error";
    private static final String WHERE_CLAUSE = " WHERE ";

    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");
    private static final Marker CACHE_MARKER = MarkerFactory.getMarker("CACHE");

    private static final String DATABASE_NOT_CONNECTED = "Database not connected";
    private static final String DATABASE_NOT_CONNECTED_PREMIUM_CHECK = "Database not connected - cannot check premium status for {}";

    private final ConcurrentHashMap<String, RegisteredPlayer> playerCache;
    private final ReentrantLock databaseLock;
    private final DatabaseConfig config;
    private final Messages messages;
    private final ExecutorService dbExecutor;
    private final DatabaseHealthCheck healthCheck;
    private final DatabaseMigrationService migrationService;

    private ConnectionSource connectionSource;
    private Dao<RegisteredPlayer, String> playerDao;
    private PremiumUuidDao premiumUuidDao;
    private JdbcAuthDao jdbcAuthDao;
    private volatile boolean connected;
    
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
        this.jdbcAuthDao = new JdbcAuthDao(config);
        this.healthCheck = new DatabaseHealthCheck(jdbcAuthDao, messages);
        this.migrationService = new DatabaseMigrationService(config);

        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, messages.get("database.manager.created"), config.getStorageType());
        }
    }

    /**
     * Inicjalizuje połączenie z bazą danych i tworzy tabele.
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
                    logger.error(DB_MARKER, "Error during database initialization", e);
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
        migrationService.createTablesAndMigrate(connectionSource,
                messages.get("database.manager.creating_tables"),
                messages.get("database.manager.tables_created"));
        markAsConnected();
        healthCheck.start();

        return true;
    }

    private boolean isAlreadyConnected() {
        if (connected) {
            if (logger.isWarnEnabled()) {
                logger.warn(DB_MARKER, "Database already connected");
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

    // ===== Health Check delegation =====

    public boolean isHealthy() {
        return connected && healthCheck.wasLastHealthCheckPassed();
    }

    public long getLastHealthCheckTime() {
        return healthCheck.getLastHealthCheckTime();
    }

    public boolean wasLastHealthCheckPassed() {
        return healthCheck.wasLastHealthCheckPassed();
    }

    // ===== Shutdown =====

    public void shutdown() {
        try {
            healthCheck.stop();

            databaseLock.lock();
            try {
                closeConnectionResources();
            } finally {
                databaseLock.unlock();
            }
        } catch (RuntimeException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Error during database shutdown", e);
            }
        } finally {
            dbExecutor.shutdown();
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
            logger.debug(CACHE_MARKER, "Player cache cleared");
        }
    }

    // ===== Player CRUD Operations =====

    /**
     * Znajduje gracza po lowercase nickname z wykorzystaniem cache + natywnego JDBC.
     */
    public CompletableFuture<DbResult<RegisteredPlayer>> findPlayerByNickname(String nickname) {
        return lookupPlayer(nickname, false);
    }

    /**
     * Enhanced player lookup with premium detection.
     */
    public CompletableFuture<DbResult<RegisteredPlayer>> findPlayerWithRuntimeDetection(String nickname) {
        return lookupPlayer(nickname, true);
    }

    /**
     * Finds a player by nickname first, then falls back to UUID-based lookup.
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
            DbResult<RegisteredPlayer> byNick = performPlayerLookup(normalizedNickname, nickname, true);
            if (byNick.isDatabaseError() || byNick.getValue() != null) {
                return byNick;
            }

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

            playerCache.remove(byUuid.getLowercaseNickname());
            byUuid.setNickname(originalNickname);
            playerDao.update(byUuid);
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
            logger.debug(DB_MARKER, "Player not found: {}", normalizedNickname);
        }
    }

    private DbResult<RegisteredPlayer> handleDatabaseError(String normalizedNickname, SQLException e) {
        if (logger.isErrorEnabled()) {
            logger.error(DB_MARKER, "Error searching for player: {}", normalizedNickname, e);
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
                    logger.debug(DB_MARKER, "Saved player (upsert): {}", player.getNickname());
                }
                
                notifyAuthCacheOfUpdate(player);
            }
            return DbResult.success(success);
        } catch (SQLException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Error saving player: {}", player.getNickname(), e);
            }
            return DbResult.databaseError(messages.get(DATABASE_ERROR) + ": " + e.getMessage());
        }
    }
    
    private void notifyAuthCacheOfUpdate(RegisteredPlayer player) {
        if (authCacheRef == null) {
            return;
        }

        net.rafalohaki.veloauth.cache.AuthCache authCache = authCacheRef.get();
        if (authCache == null) {
            if (logger.isDebugEnabled()) {
                logger.debug(DB_MARKER, "AuthCache reference is null (GC collected) - skipping cache invalidation");
            }
            return;
        }

        try {
            UUID playerUuid = UUID.fromString(player.getUuid());
            authCache.invalidatePlayerData(playerUuid);
            if (logger.isDebugEnabled()) {
                logger.debug(DB_MARKER, "Notified AuthCache of update for player: {} (UUID: {})",
                        player.getNickname(), playerUuid);
            }
        } catch (IllegalArgumentException e) {
            if (logger.isWarnEnabled()) {
                logger.warn(DB_MARKER, "Failed to parse UUID for cache invalidation: {} - {}",
                        player.getUuid(), e.getMessage());
            }
        } catch (Exception e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Error notifying AuthCache of player update: {}",
                        player.getNickname(), e);
            }
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
                    logger.debug(DB_MARKER, "Deleted player: {}", lowercaseNickname);
                }
                return DbResult.success(true);
            }

            if (logger.isDebugEnabled()) {
                logger.debug(DB_MARKER, "Player not found for deletion: {}", lowercaseNickname);
            }
            return DbResult.success(false);
        } catch (SQLException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Error deleting player: {}", lowercaseNickname, e);
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
                boolean premium = premiumUuidDao.findByNickname(username).isPresent();
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "Premium status from PREMIUM_UUIDS for {}: {}", username, premium);
                }
                return DbResult.success(premium);
            } catch (RuntimeException e) {
                if (logger.isErrorEnabled()) {
                    logger.error(DB_MARKER, "Runtime error checking premium status for player: {}", username, e);
                }
                return DbResult.databaseError(messages.get(DATABASE_ERROR) + ": " + e.getMessage());
            }
        }, dbExecutor);
    }

    /**
     * Pobiera wszystkich graczy.
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
                    logger.error(DB_MARKER, "Error fetching all players", e);
                }
                return List.of();
            }
        }, dbExecutor);
    }

    // ===== Cache Operations =====

    public void clearCache() {
        playerCache.clear();
        if (logger.isDebugEnabled()) {
            logger.debug(CACHE_MARKER, "Cache graczy wyczyszczony");
        }
    }

    public void removeCachedPlayer(String lowercaseNickname) {
        if (lowercaseNickname != null) {
            playerCache.remove(lowercaseNickname);
            if (logger.isDebugEnabled()) {
                logger.debug("Removed player from cache: {}", lowercaseNickname);
            }
        }
    }

    public int getCacheSize() {
        return playerCache.size();
    }

    private DbResult<RegisteredPlayer> checkCacheSafe(String normalizedNickname) {
        RegisteredPlayer cached = playerCache.get(normalizedNickname);
        
        if (cached == null) {
            return DbResult.success(null);
        }
        
        if (isCacheCorrupted(cached, normalizedNickname)) {
            handleCacheCorruption(normalizedNickname);
            return DbResult.success(null);
        }
        
        logCacheHit(normalizedNickname);
        return DbResult.success(cached);
    }

    // ===== Accessors =====

    public boolean isConnected() {
        return isHealthy();
    }

    public DatabaseConfig getConfig() {
        return config;
    }

    public PremiumUuidDao getPremiumUuidDao() {
        return premiumUuidDao;
    }
    
    public void setAuthCacheReference(net.rafalohaki.veloauth.cache.AuthCache authCache) {
        if (authCache != null) {
            this.authCacheRef = new WeakReference<>(authCache);
            if (logger.isDebugEnabled()) {
                logger.debug(DB_MARKER, "AuthCache reference set for cache invalidation coordination");
            }
        }
    }

    // ===== Statistics Queries =====

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

    @SuppressWarnings("java:S2077")
    private int executeCountQuery(String sql) throws SQLException {
        DatabaseConnection dbConnection = connectionSource.getReadWriteConnection(null);
        try {
            java.sql.Connection connection = dbConnection.getUnderlyingConnection();
            try (java.sql.Statement stmt = connection.createStatement();
                 java.sql.ResultSet rs = stmt.executeQuery(sql)) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
                return 0;
            }
        } finally {
            connectionSource.releaseConnection(dbConnection);
        }
    }

    public CompletableFuture<Integer> getTotalRegisteredAccounts() {
        return getAllPlayers().thenApply(Collection::size)
                .exceptionally(e -> {
                    if (logger.isErrorEnabled()) {
                        logger.error(DB_MARKER, "Error getting total registered accounts", e);
                    }
                    return 0;
                });
    }

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

    // ===== Runtime Detection =====

    public boolean isPlayerPremiumRuntime(RegisteredPlayer player) {
        if (player == null) {
            return false;
        }
        
        String hash = player.getHash();
        return hash == null || hash.isEmpty() || hash.isBlank();
    }

    private void logRuntimeDetection(String nickname, boolean isPremium, String hash) {
        if (logger.isDebugEnabled()) {
            logger.debug("[RUNTIME DETECTION] {} -> {} (hash empty: {})", 
                       nickname, isPremium ? "PREMIUM" : "OFFLINE", 
                       hash == null || hash.isEmpty());
        }
    }

    // ===== Conflict Mode =====

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

    /**
     * Result wrapper for database operations that distinguishes between
     * "not found" and "database error" states for fail-secure behavior.
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

        public static <T> DbResult<T> success(T value) {
            return new DbResult<>(value, false, null);
        }

        public static <T> DbResult<T> databaseError(String errorMessage) {
            return new DbResult<>(null, true, errorMessage);
        }

        @javax.annotation.Nullable
        public T getValue() {
            return value;
        }

        @javax.annotation.Nonnull
        public java.util.Optional<T> getValueOptional() {
            return java.util.Objects.requireNonNull(java.util.Optional.ofNullable(value), "Optional cannot be null");
        }

        public boolean isDatabaseError() {
            return isDatabaseError;
        }

        @javax.annotation.Nullable
        public String getErrorMessage() {
            return errorMessage;
        }

        public boolean isSuccess() {
            return !isDatabaseError;
        }
    }
}
