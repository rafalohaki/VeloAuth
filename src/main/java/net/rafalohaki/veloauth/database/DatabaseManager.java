package net.rafalohaki.veloauth.database;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.DataSourceConnectionSource;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.misc.TransactionManager;
import com.j256.ormlite.support.ConnectionSource;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.sql.SQLException;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

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
 * <h3>AuthCache Reference</h3>
 * Holds a strong reference to AuthCache. AuthCache does not retain a reference
 * back to DatabaseManager, so there is no cycle — the previous WeakReference
 * scheme was protecting against a non-existent leak and made cache invalidation
 * silently no-op once AuthCache was GC'd. The lifecycle owner ({@code VeloAuth})
 * keeps both references alive for the same duration.
 */
public class DatabaseManager {

    private static final Logger logger = LoggerFactory.getLogger(DatabaseManager.class);

    private static final String DATABASE_ERROR = "database.error";

    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");
    private static final Marker CACHE_MARKER = MarkerFactory.getMarker("CACHE");

    private static final String DATABASE_NOT_CONNECTED = "Database not connected";
    private static final String EXECUTOR_SHUTTING_DOWN = ": Executor is shutting down";
    private static final long FAIL_SECURE_IP_REGISTRATION_COUNT = Long.MAX_VALUE;


    private final ConcurrentHashMap<String, RegisteredPlayer> playerCache;
    /** Idempotency guard for {@link #initialize()} — prevents two concurrent init paths from
     *  both running {@code performDatabaseInitialization()}. */
    private final AtomicBoolean initializing = new AtomicBoolean(false);
    /** Mutual exclusion between {@link #initialize()} and {@link #shutdown()}: without this,
     *  a shutdown firing while init is still assigning {@code connectionSource} could null the
     *  field mid-{@code initializeDaos()} and cause an NPE inside ORMLite's {@code DaoManager}.
     *  Held only for the duration of those two methods — neither is on a hot path. */
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private final DatabaseConfig config;
    private final Messages messages;
    private final ExecutorService dbExecutor;
    private final DatabaseHealthCheck healthCheck;
    private final DatabaseMigrationService migrationService;
    private final DatabaseStatisticsQueryService statisticsQueryService;

    private ConnectionSource connectionSource;
    private Dao<RegisteredPlayer, String> playerDao;
    private PremiumUuidDao premiumUuidDao;
    private AuditLogDao auditLogDao;
    private SchemaVersionDao schemaVersionDao;
    private JdbcAuthDao jdbcAuthDao;
    private volatile boolean connected;
    
    private volatile net.rafalohaki.veloauth.cache.AuthCache authCache;

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
        this.connected = false;
        this.dbExecutor = VirtualThreadExecutorProvider.getVirtualExecutor();
        this.jdbcAuthDao = new JdbcAuthDao(config);
        this.healthCheck = new DatabaseHealthCheck(jdbcAuthDao, messages);
        this.migrationService = new DatabaseMigrationService(config);
        this.statisticsQueryService = new DatabaseStatisticsQueryService(
            config,
            () -> connectionSource,
            () -> connected,
            dbExecutor,
            logger,
            DB_MARKER
        );

        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, messages.get("database.manager.created"), config.getStorageType());
        }
    }

    void setConnectedForTesting(boolean connected) {
        this.connected = connected;
    }

    void setJdbcAuthDaoForTesting(JdbcAuthDao jdbcAuthDao) {
        this.jdbcAuthDao = jdbcAuthDao;
    }

    void setPremiumUuidDaoForTesting(PremiumUuidDao premiumUuidDao) {
        this.premiumUuidDao = premiumUuidDao;
    }

    /**
     * Inicjalizuje połączenie z bazą danych i tworzy tabele.
     *
     * @return CompletableFuture<Boolean> - true jeśli sukces
     */
    public CompletableFuture<Boolean> initialize() {
        return CompletableFuture.supplyAsync(() -> {
            if (!initializing.compareAndSet(false, true)) {
                if (logger.isWarnEnabled()) {
                    logger.warn(DB_MARKER, "initialize() called concurrently — refusing duplicate call");
                }
                return connected;
            }
            lifecycleLock.lock();
            try {
                return performDatabaseInitialization();
            } catch (SQLException e) {
                if (logger.isErrorEnabled()) {
                    logger.error(DB_MARKER, "Error during database initialization", e);
                }
                return false;
            } finally {
                lifecycleLock.unlock();
                initializing.set(false);
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
        recordSchemaBaseline();
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
        schemaVersionDao = new SchemaVersionDao(connectionSource);
        auditLogDao = new AuditLogDao(connectionSource);
        jdbcAuthDao = new JdbcAuthDao(config);
    }

    private void recordSchemaBaseline() {
        if (schemaVersionDao == null) {
            return;
        }
        if (schemaVersionDao.getCurrentVersion().isPresent()) {
            return;
        }
        schemaVersionDao.recordVersion(1, "baseline v1.2.0 schema");
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
            connected = false;
            // Wait for any in-flight initialize() to finish its connectionSource assignment
            // before we tear down resources; otherwise we could null connectionSource while
            // initializeDaos() is mid-call.
            lifecycleLock.lock();
            try {
                closeConnectionResources();
            } finally {
                lifecycleLock.unlock();
            }
        } catch (RuntimeException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Error during database shutdown", e);
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
        }
        try {
            config.closeDataSource();
        } catch (RuntimeException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Error closing database data source", e);
            }
        }
        if (logger.isInfoEnabled()) {
            logger.info(DB_MARKER, messages.get("database.manager.connection_closed"));
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
        String normalizedNickname = normalizeNickname(nickname);
        if (normalizedNickname == null) {
            return CompletableFuture.completedFuture(DbResult.success(null));
        }
        return lookupPlayer(nickname, true).thenApplyAsync(byNick -> {
            if (byNick.isDatabaseError() || byNick.getValue() != null || premiumUuid == null) {
                return byNick;
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
            String oldLowercaseNickname = byUuid.getLowercaseNickname();
            logger.info(DB_MARKER, "[NICK CHANGE] Premium player {} changed nickname: {} → {}",
                    premiumUuid, oldNick, originalNickname);

            TransactionManager.callInTransaction(connectionSource, () -> {
                // updateId() must be called BEFORE setNickname() — lowercaseNickname is the @id field,
                // and update() cannot change the id (it uses id in WHERE). See ORMLite Dao.updateId().
                playerDao.updateId(byUuid, normalizedNickname);
                byUuid.setNickname(originalNickname);
                playerDao.update(byUuid);
                return null;
            });

            // Cache mutations happen only after a successful commit so we never reflect
            // partial state from a rolled-back transaction.
            playerCache.remove(oldLowercaseNickname);
            playerCache.put(normalizedNickname, byUuid);

            logRuntimeDetection(originalNickname, isPlayerPremiumRuntime(byUuid), byUuid.getHash());
            return DbResult.success(byUuid);
        } catch (SQLException e) {
            if (logger.isErrorEnabled()) {
                logger.error(DB_MARKER, "Error during UUID-based player lookup for {}",
                        premiumUuid, e);
            }
            return genericDatabaseErrorResult();
        }
    }

    private CompletableFuture<DbResult<RegisteredPlayer>> lookupPlayer(String nickname, boolean runtimeDetection) {
        String normalizedNickname = normalizeNickname(nickname);
        CompletableFuture<DbResult<RegisteredPlayer>> earlyExit = validateLookupPreconditions(normalizedNickname);
        if (earlyExit != null) {
            return earlyExit;
        }

        return CompletableFuture.supplyAsync(() -> performPlayerLookup(normalizedNickname, nickname, runtimeDetection), dbExecutor);
    }

    private <T> CompletableFuture<DbResult<T>> validateLookupPreconditions(String normalizedNickname) {
        if (normalizedNickname == null) {
            return CompletableFuture.completedFuture(DbResult.success(null));
        }
        DbResult<T> executorState = checkExecutorState();
        if (executorState != null) {
            return CompletableFuture.completedFuture(executorState);
        }
        return null;
    }

    private String normalizeNickname(String nickname) {
        if (nickname == null || nickname.isBlank()) {
            return null;
        }
        return nickname.toLowerCase(Locale.ROOT);
    }

    private <T> DbResult<T> checkExecutorState() {
        if (dbExecutor.isShutdown()) {
            return DbResult.databaseError(messages.get(DATABASE_ERROR) + EXECUTOR_SHUTTING_DOWN);
        }
        return null;
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
            if (player == null) {
                logPlayerNotFound(normalizedNickname);
                return DbResult.success(null);
            }
            cacheAndLogLookup(normalizedNickname, originalNickname, runtimeDetection, player);
            return DbResult.success(player);
        } catch (SQLException e) {
            return handleDatabaseError(normalizedNickname, e);
        }
    }

    private void cacheAndLogLookup(String normalizedNickname, String originalNickname,
                                    boolean runtimeDetection, RegisteredPlayer player) {
        if (!player.getLowercaseNickname().equals(normalizedNickname)) {
            if (logger.isWarnEnabled()) {
                logger.warn(CACHE_MARKER, "Database inconsistency for {} - expected {}, found {}",
                        normalizedNickname, normalizedNickname, player.getLowercaseNickname());
            }
            return;
        }
        playerCache.put(normalizedNickname, player);
        if (runtimeDetection) {
            logRuntimeDetection(originalNickname, isPlayerPremiumRuntime(player), player.getHash());
        } else if (logger.isDebugEnabled()) {
            logger.debug(CACHE_MARKER, "Cache MISS -> DB HIT dla gracza: {}", normalizedNickname);
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
        logDatabaseOperationFailure("player lookup", normalizedNickname, e);
        return genericDatabaseErrorResult();
    }

    private String genericDatabaseErrorMessage() {
        return messages.get(DATABASE_ERROR);
    }

    private <T> DbResult<T> genericDatabaseErrorResult() {
        return DbResult.databaseError(genericDatabaseErrorMessage());
    }

    private void logDatabaseOperationFailure(String operation, String identifier, Throwable throwable) {
        if (logger.isErrorEnabled()) {
            logger.error(DB_MARKER, "Database operation '{}' failed for {}", operation, identifier);
        }
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, "Database operation '{}' failure details for {}", operation, identifier, throwable);
        }
    }

    /**
     * Zapisuje lub aktualizuje gracza w bazie danych z użyciem natywnego JDBC.
     */
    public CompletableFuture<DbResult<Boolean>> savePlayer(RegisteredPlayer player) {
        if (player == null) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }

        return submitConnectedTask(() -> executePlayerSave(player));
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
            logDatabaseOperationFailure("player save", player.getNickname(), e);
            return genericDatabaseErrorResult();
        }
    }
    
    private void notifyAuthCacheOfUpdate(RegisteredPlayer player) {
        net.rafalohaki.veloauth.cache.AuthCache cache = resolveAuthCacheForUpdate();
        if (cache == null) {
            return;
        }

        invalidateAuthCachePlayerData(cache, player);
    }

    private net.rafalohaki.veloauth.cache.AuthCache resolveAuthCacheForUpdate() {
        return authCache;
    }

    private void invalidateAuthCachePlayerData(net.rafalohaki.veloauth.cache.AuthCache authCache,
                                               RegisteredPlayer player) {
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
        String normalizedNickname = normalizeNickname(nickname);
        if (normalizedNickname == null) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }

        return submitConnectedTask(() -> executePlayerDelete(normalizedNickname));
    }

    /**
     * Counts registrations from a specific IP address.
     */
    public CompletableFuture<Long> countRegistrationsByIp(String ip) {
        return countRegistrationsByIpResult(ip).thenApply(result -> {
            if (result.isDatabaseError()) {
                if (logger.isWarnEnabled()) {
                    logger.warn(DB_MARKER, "Fail-secure IP registration count fallback for {}", ip);
                }
                return FAIL_SECURE_IP_REGISTRATION_COUNT;
            }
            Long value = result.getValue();
            return value == null ? 0L : value;
        });
    }

    public CompletableFuture<DbResult<Long>> countRegistrationsByIpResult(String ip) {
        if (ip == null || ip.isBlank()) {
            return CompletableFuture.completedFuture(DbResult.success(0L));
        }
        return submitConnectedTask(() -> executeRegistrationCount(ip));
    }

    private DbResult<Long> executeRegistrationCount(String ip) {
        try {
            return DbResult.success(jdbcAuthDao.countRegistrationsByIp(ip));
        } catch (SQLException e) {
            logDatabaseOperationFailure("count registrations by IP", ip, e);
            return genericDatabaseErrorResult();
        }
    }

    private <T> CompletableFuture<DbResult<T>> submitConnectedTask(Supplier<DbResult<T>> task) {
        DbResult<T> executorState = checkExecutorState();
        if (executorState != null) {
            return CompletableFuture.completedFuture(executorState);
        }

        return CompletableFuture.supplyAsync(() -> {
            DbResult<Void> connectionResult = validateDatabaseConnection();
            if (connectionResult.isDatabaseError()) {
                return DbResult.databaseError(connectionResult.getErrorMessage());
            }

            return task.get();
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
            logDatabaseOperationFailure("player delete", lowercaseNickname, e);
            return genericDatabaseErrorResult();
        }
    }

    /**
     * Sprawdza premium status gracza z wykorzystaniem PREMIUM_UUIDS table.
     */
    public CompletableFuture<DbResult<Boolean>> isPremium(String username) {
        if (username == null || username.isBlank()) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }

        return submitConnectedTask(() -> {
            try {
                boolean premium = premiumUuidDao.findByNicknameStrict(username).isPresent();
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "Premium status from PREMIUM_UUIDS for {}: {}", username, premium);
                }
                return DbResult.success(premium);
            } catch (SQLException | RuntimeException e) {
                logDatabaseOperationFailure("premium status check", username, e);
                return genericDatabaseErrorResult();
            }
        });
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
                logger.debug(DB_MARKER, "Removed player from cache: {}", lowercaseNickname);
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

    /**
     * Indicates whether the database pool is initialized and the manager has not been shut down.
     * <p>
     * Distinct from {@link #isHealthy()}: a manager that just finished initialization is
     * {@code connected} immediately, but {@code healthy} only after the first health check
     * completes successfully. Admin commands gate on this method so they do not falsely
     * report "database not connected" during the 30s window before the first scheduled check.
     */
    public boolean isConnected() {
        return connected;
    }

    public DatabaseConfig getConfig() {
        return config;
    }

    public PremiumUuidDao getPremiumUuidDao() {
        return premiumUuidDao;
    }

    public AuditLogDao getAuditLogDao() {
        return auditLogDao;
    }

    public SchemaVersionDao getSchemaVersionDao() {
        return schemaVersionDao;
    }

    /**
     * Saves or updates a premium UUID entry in the PREMIUM_UUIDS table.
     * Keeps PREMIUM_UUIDS in sync with AUTH.PREMIUMUUID field.
     *
     * @param username    player nickname
     * @param premiumUuid player's premium UUID
     * @return future resolving to true if saved successfully
     */
    public CompletableFuture<DbResult<Boolean>> savePremiumUuid(String username, UUID premiumUuid) {
        if (username == null || username.isBlank() || premiumUuid == null) {
            return CompletableFuture.completedFuture(DbResult.success(false));
        }

        return submitConnectedTask(() -> {
            try {
                boolean success = premiumUuidDao.saveOrUpdateStrict(premiumUuid, username);
                if (logger.isDebugEnabled()) {
                    logger.debug(DB_MARKER, "Synced PREMIUM_UUIDS for {}: {} (success={})",
                            username, premiumUuid, success);
                }
                return DbResult.success(success);
            } catch (SQLException | RuntimeException e) {
                logDatabaseOperationFailure("premium UUID sync", username, e);
                return genericDatabaseErrorResult();
            }
        });
    }
    
    public void setAuthCacheReference(net.rafalohaki.veloauth.cache.AuthCache authCache) {
        if (authCache != null) {
            this.authCache = authCache;
            if (logger.isDebugEnabled()) {
                logger.debug(DB_MARKER, "AuthCache reference set for cache invalidation coordination");
            }
        }
    }

    // ===== Statistics Queries =====

    public CompletableFuture<Integer> getTotalNonPremiumAccounts() {
        return statisticsQueryService.getTotalNonPremiumAccounts();
    }

    public CompletableFuture<Integer> getTotalRegisteredAccounts() {
        return statisticsQueryService.getTotalRegisteredAccounts();
    }

    public CompletableFuture<Integer> getTotalPremiumAccounts() {
        return statisticsQueryService.getTotalPremiumAccounts();
    }

    // ===== Runtime Detection =====

    public boolean isPlayerPremiumRuntime(RegisteredPlayer player) {
        if (player == null) {
            return false;
        }

        // Primary: premiumUuid is the authoritative premium marker (set by PostAuthFlow)
        String premiumUuid = player.getPremiumUuid();
        if (premiumUuid != null && !premiumUuid.isEmpty()) {
            return true;
        }

        // Fallback: LimboAuth compatibility — premium players have null/empty hash.
        // Keeps isPlayerPremiumRuntime consistent with getTotalPremiumAccounts() SQL:
        //   PREMIUMUUID IS NOT NULL OR HASH IS NULL OR HASH = ''
        String hash = player.getHash();
        return hash == null || hash.isEmpty();
    }

    private void logRuntimeDetection(String nickname, boolean isPremium, String hash) {
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, "[RUNTIME DETECTION] {} -> {} (hash empty: {})", 
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
                logger.error(DB_MARKER, "Database error while finding players in conflict mode", e);
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
