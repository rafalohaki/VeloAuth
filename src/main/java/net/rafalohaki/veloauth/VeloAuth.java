package net.rafalohaki.veloauth;

import jakarta.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.Dependency;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.command.CommandHandler;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.database.DatabaseConfig;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseType;
import net.rafalohaki.veloauth.database.HikariConfigParams;
import net.rafalohaki.veloauth.exception.VeloAuthException;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.listener.AuthListener;
import net.rafalohaki.veloauth.listener.EarlyLoginBlocker;
import net.rafalohaki.veloauth.listener.PreLoginHandler;
import net.rafalohaki.veloauth.listener.PostLoginHandler;
import net.rafalohaki.veloauth.premium.PremiumResolverService;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
import org.bstats.velocity.Metrics;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;

/**
 * Velocity proxy authentication plugin.
 * Manages player auth flows between Velocity, a configurable auth server, and backend servers.
 */
@Plugin(
        id = "veloauth",
        name = "VeloAuth",
        version = BuildConstants.VERSION,
        description = "Complete Velocity Authentication Plugin with BCrypt, Virtual Threads and multi-database support",
    authors = {"Rafal"},
    dependencies = {
        @Dependency(id = "floodgate", optional = true)
    }
)
public class VeloAuth {

    private static final int BSTATS_PLUGIN_ID = 28142;

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;
    private final Metrics.Factory metricsFactory;

    // Główne komponenty pluginu
    private Settings settings;
    private Messages messages;
    private DatabaseManager databaseManager;
    private AuthCache authCache;
    private CommandHandler commandHandler;
    private ConnectionManager connectionManager;
    private AuthListener authListener;
    private PremiumResolverService premiumResolverService;

    // Status pluginu
    // CRITICAL: This flag protects against early connections during initialization
    // - Starts as FALSE to block connections
    // - Set to TRUE only after ALL components successfully initialize
    // - Remains FALSE if initialization fails (prevents connections to broken plugin)
    // - Set to FALSE during shutdown to reject new operations
    private volatile boolean initialized = false;

    // Startup queue: connections arriving during init wait on this future instead of getting kicked
    private final CompletableFuture<Void> initializationFuture = new CompletableFuture<>();

    /**
     * Konstruktor VeloAuth.
     *
     * @param server        ProxyServer instance
     * @param logger        Logger instance
     * @param dataDirectory Path do data folder
     */
    @Inject
    public VeloAuth(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory, Metrics.Factory metricsFactory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        this.metricsFactory = metricsFactory;
        
        logger.info("VeloAuth instance created.");
                
        if (logger.isDebugEnabled()) {
            logger.debug("VeloAuth konstruktor - Java {}, Velocity API {}",
                    System.getProperty("java.version"),
                    server.getVersion().getVersion());
        }
    }

    
    private boolean reloadLanguageFiles() {
        try {
            // Get new language from reloaded config
            String newLanguage = settings.getLanguage();
            
            // Reload with potentially new language setting
            messages.reloadWithLanguage(newLanguage);
            logger.info("Language files reloaded successfully (language: {})", newLanguage);
            return true;
        } catch (IOException e) {
            logger.error("Failed to reload language files", e);
            return false;
        }
    }

    /**
     * Inicjalizacja pluginu przy starcie proxy.
     */
    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        logVersion();
        logEnvironment();

        if (!registerEarlyLoginBlocker()) {
            return;
        }

        // Inicjalizacja asynchroniczna z Virtual Threads
        // skipcq: JAVA-W1087 - Future is properly handled with whenComplete
        long initializationStartTime = System.currentTimeMillis();
        
        CompletableFuture.runAsync(this::initializePlugin, VirtualThreadExecutorProvider.getVirtualExecutor())
                .whenComplete((result, throwable) -> handleInitializationResult(throwable, initializationStartTime));
    }

    private void logVersion() {
        try {
            logger.info("Loading VeloAuth v{}...", getVersion());
        } catch (Exception e) {
            logger.error("Failed to retrieve version from BuildConstants", e);
            logger.info("Loading VeloAuth (version unknown)...");
        }
    }

    private void logEnvironment() {
        if (logger.isDebugEnabled()) {
            logger.debug("Java: {}, Virtual Threads: {}",
                    System.getProperty("java.version"),
                    Thread.currentThread().isVirtual() ? "Available" : "Unavailable");
        }
    }

    private boolean registerEarlyLoginBlocker() {
        // CRITICAL: Register early PreLogin blocker BEFORE starting async initialization
        // This prevents players from connecting before authentication handlers are ready
        if (logger.isDebugEnabled()) {
            logger.debug("Registering early PreLogin blocker for initialization protection...");
        }
        try {
            EarlyLoginBlocker earlyBlocker = new EarlyLoginBlocker(this);
            server.getEventManager().register(this, earlyBlocker);
            if (logger.isDebugEnabled()) {
                logger.debug("✅ EarlyLoginBlocker registered BEFORE initialization - PreLogin protection active");
            }
            return true;
        } catch (Exception e) {
            logger.error("Failed to register early PreLogin blocker", e);
            return false;
        }
    }

    private void handleInitializationResult(Throwable throwable, long startTime) {
        long initializationDuration = System.currentTimeMillis() - startTime;
        
        if (throwable != null) {
            logger.error("❌ VeloAuth initialization FAILED after {} ms", initializationDuration, throwable);
            // CRITICAL: Keep initialized flag as FALSE to prevent connections to broken plugin
            logger.warn("⚠️ Initialization flag remains FALSE - all player connections will be blocked");
            initializationFuture.completeExceptionally(throwable);
            shutdown();
        } else {
            finalizeInitialization(initializationDuration);
        }
    }

    private void finalizeInitialization(long initializationDuration) {
        // Clear any stale cache entries from previous server runs
        if (databaseManager != null) {
            databaseManager.clearCache();
        }
        if (authCache != null) {
            authCache.clearAll();
        }

        // Initialize bStats metrics
        metricsFactory.make(this, BSTATS_PLUGIN_ID);

        // CRITICAL: Complete future first so EarlyLoginBlocker queue can drain,
        // then set flag. Order matters: future.complete() unblocks waiting connections,
        // but they still go through AuthListener which checks isInitialized().
        initializationFuture.complete(null);
        initialized = true;
        
        logStartupInfo(initializationDuration);
    }

    /**
     * Zamknięcie pluginu przy wyłączaniu proxy.
     */
    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        if (messages != null && logger.isInfoEnabled()) {
            logger.info(messages.get("plugin.initialization.shutdown"));
        } else if (logger.isInfoEnabled()) {
            logger.info("VeloAuth - Shutdown");
        }
        
        shutdown();
        
        if (messages != null && logger.isInfoEnabled()) {
            logger.info(messages.get("plugin.initialization.closed"));
        } else if (logger.isInfoEnabled()) {
            logger.info("VeloAuth - Closed");
        }
    }

    /**
     * Helper method to reduce cognitive complexity in error handling.
     * Logs error if enabled and throws the specified exception.
     */
    private void logErrorAndRethrow(String message, Exception cause, RuntimeException toThrow) {
        if (logger.isErrorEnabled()) {
            logger.error(message, cause);
        }
        throw toThrow;
    }

    /**
     * Inicjalizuje wszystkie komponenty pluginu.
     */
    private void initializePlugin() {
        try {
            initializeConfiguration();
            initializeMessages();
            initializeDatabase();
            initializeCache();
            initializeCommands();
            initializeConnectionManager();
            initializePremiumResolver();
            initializeListeners();
            debugServers();

            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("plugin.initialization.components_ready"));
            }

        } catch (VeloAuthException e) {
            logErrorAndRethrow("VeloAuth error during initialization", e, e);
        } catch (IllegalStateException | IllegalArgumentException e) {
            logErrorAndRethrow("Critical error during VeloAuth initialization", e, 
                VeloAuthException.configuration("plugin initialization", e));
        } catch (Exception e) {
            logErrorAndRethrow("Unexpected error during VeloAuth initialization", e, 
                VeloAuthException.configuration("unexpected error", e));
        }
    }

    private void initializeConfiguration() {
        if (logger.isDebugEnabled()) {
            logger.debug("📋 [1/8] Loading configuration...");
        }
        long startTime = System.currentTimeMillis();
        
        settings = new Settings(dataDirectory);
        if (!settings.load()) {
            throw VeloAuthException.configuration("settings loading", null);
        }
        
        if (logger.isDebugEnabled()) {
            logger.debug("✅ Configuration loaded in {} ms", System.currentTimeMillis() - startTime);
        }
    }

    private void initializeMessages() {
        if (logger.isDebugEnabled()) {
            logger.debug("💬 [2/8] Initializing message system...");
        }
        long startTime = System.currentTimeMillis();
        
        String language = settings.getLanguage();
        
        try {
            messages = new Messages(dataDirectory, language);
            if (logger.isDebugEnabled()) {
                logger.debug("✅ Message system initialized in {} ms (Language: {}, External files: enabled)", 
                        System.currentTimeMillis() - startTime, language);
            }
        } catch (IOException e) {
            logger.error("Failed to initialize external language files, falling back to JAR-embedded files", e);
            messages = new Messages();
            messages.setLanguage(language);
            if (logger.isDebugEnabled()) {
                logger.debug("✅ Message system initialized in {} ms (Language: {}, External files: disabled)", 
                        System.currentTimeMillis() - startTime, language);
            }
        }
    }

    private void initializeDatabase() {
        if (logger.isDebugEnabled()) {
            logger.debug("🗄️ [3/8] Initializing database connection...");
        }
        long startTime = System.currentTimeMillis();
        
        DatabaseConfig dbConfig = createDatabaseConfig();
        databaseManager = new DatabaseManager(dbConfig, messages);

        boolean dbInitialized = databaseManager.initialize().join();
        if (!dbInitialized) {
            throw VeloAuthException.database("initialization", null);
        }
        
        if (logger.isDebugEnabled()) {
            logger.debug("✅ Database initialized in {} ms (Type: {})", 
                    System.currentTimeMillis() - startTime, settings.getDatabaseStorageType());
        }
    }

    private void initializeCache() {
        if (logger.isDebugEnabled()) {
            logger.debug("💾 [4/8] Initializing authentication cache...");
        }
        long startTime = System.currentTimeMillis();
        
        authCache = new AuthCache(
                new AuthCache.AuthCacheConfig(
                    settings.getCacheTtlMinutes(),
                    settings.getCacheMaxSize(),
                    settings.getCacheMaxSize(), // maxSessions - użyj tej samej wartości co maxSize
                    10000, // maxPremiumCache - set to 10000 as per requirement 6.5
                    settings.getBruteForceMaxAttempts(),
                    settings.getBruteForceTimeoutMinutes(),
                    settings.getCacheCleanupIntervalMinutes(),
                    settings.getSessionTimeoutMinutes()
                ),
                settings,
                messages
        );
        
        // Set AuthCache reference in DatabaseManager for cache invalidation coordination
        if (databaseManager != null) {
            databaseManager.setAuthCacheReference(authCache);
            logger.debug("AuthCache reference set in DatabaseManager");
        }
        
        logger.debug("✅ Cache initialized in {} ms (TTL: {} min, Max size: {}, Premium cache: 10000)", 
                System.currentTimeMillis() - startTime, 
                settings.getCacheTtlMinutes(), 
                settings.getCacheMaxSize());
    }

    private void initializeCommands() {
        if (logger.isDebugEnabled()) {
            logger.debug("⌨️ [5/8] Registering commands...");
        }
        long startTime = System.currentTimeMillis();
        
        commandHandler = new CommandHandler(this, databaseManager, authCache, settings, messages);
        commandHandler.registerCommands();
        
        logger.debug("✅ Commands registered in {} ms", System.currentTimeMillis() - startTime);
    }

    private void initializeConnectionManager() {
        if (logger.isDebugEnabled()) {
            logger.debug("🔌 [6/8] Initializing connection manager...");
        }
        long startTime = System.currentTimeMillis();
        
        connectionManager = new ConnectionManager(this, authCache, settings, messages);
        
        logger.debug("✅ Connection manager initialized in {} ms", System.currentTimeMillis() - startTime);
    }

    private void initializePremiumResolver() {
        if (logger.isDebugEnabled()) {
            logger.debug("👑 [7/8] Initializing premium resolver service...");
        }
        long startTime = System.currentTimeMillis();
        
        premiumResolverService = new PremiumResolverService(logger, settings, databaseManager.getPremiumUuidDao());
        
        logger.debug("✅ Premium resolver initialized in {} ms (Enabled: {})", 
                System.currentTimeMillis() - startTime, 
                settings.isPremiumCheckEnabled());
    }

    private void initializeListeners() {
        if (logger.isDebugEnabled()) {
            logger.debug("🎧 [8/8] Registering event listeners...");
        }
        long startTime = System.currentTimeMillis();
        
        // CRITICAL: Create handlers BEFORE AuthListener
        PreLoginHandler preLoginHandler = new PreLoginHandler(
            authCache, premiumResolverService, settings, databaseManager,
            messages, logger);
        logger.debug("PreLoginHandler created successfully");
        
        PostLoginHandler postLoginHandler = new PostLoginHandler(
            authCache, databaseManager,
            messages, logger);
        logger.debug("PostLoginHandler created successfully");
        
        // Create AuthListener with initialized handlers and ConnectionManager
        authListener = new AuthListener(
            this, authCache, settings,
            preLoginHandler, postLoginHandler, connectionManager, databaseManager, messages);
        
        server.getEventManager().register(this, authListener);
        logger.debug("✅ Event listeners registered in {} ms (PreLoginHandler + PostLoginHandler + AuthListener)", 
                System.currentTimeMillis() - startTime);
    }

    private void debugServers() {
        connectionManager.debugServers();
    }

    /**
     * Simple pending operations cleanup.
     * Components handle their own graceful shutdown internally.
     */
    private void waitForPendingOperations() {
        if (logger.isDebugEnabled()) {
            logger.debug("Component shutdown in progress - pending operations handled internally");
        }
    }

    /**
     * Creates database configuration from settings.
     * Uses HikariCP for remote databases (MySQL, PostgreSQL).
     */
    private DatabaseConfig createDatabaseConfig() {
        String storageType = settings.getDatabaseStorageType();
        DatabaseType dbType = DatabaseType.fromName(storageType);

        if (dbType != null && dbType.isLocalDatabase()) {
            // Local databases - standard JDBC
            return DatabaseConfig.forLocalDatabase(storageType, settings.getDatabaseName());
        } else {
            // Remote databases - use HikariCP for better performance
            return DatabaseConfig.forRemoteWithHikari(
                    HikariConfigParams.builder()
                            .storageType(storageType)
                            .hostname(settings.getDatabaseHostname())
                            .port(settings.getDatabasePort())
                            .database(settings.getDatabaseName())
                            .user(settings.getDatabaseUser())
                            .password(settings.getDatabasePassword())
                            .connectionPoolSize(settings.getDatabaseConnectionPoolSize())
                            .maxLifetime((int) settings.getDatabaseMaxLifetimeMillis())
                            .connectionParameters(settings.getDatabaseConnectionParameters())
                            .postgreSQLSettings(settings.getPostgreSQLSettings())
                            .debugEnabled(settings.isDebugEnabled())
                            .build()
            );
        }
    }

    /**
     * Zamyka wszystkie komponenty pluginu z graceful shutdown.
     */
    private void shutdown() {
        // CRITICAL: Set initialized flag to FALSE immediately to reject new operations
        initialized = false;
        // Complete future exceptionally if still pending (shutdown during init)
        initializationFuture.completeExceptionally(new IllegalStateException("Plugin shutting down"));
        logger.info("🔴 Initialization flag set to FALSE - blocking all new player connections");

        try {
            logger.info("Inicjowanie graceful shutdown VeloAuth...");

            // 1. Zamknij event listeners
            if (authListener != null) {
                server.getEventManager().unregisterListener(this, authListener);
                logger.debug("AuthListener wyrejestrowany");
            }

            // 2. Zamknij command handlers
            if (commandHandler != null) {
                commandHandler.unregisterCommands();
                logger.debug("Komendy wyrejestrowane");
            }

            // 3. Czekaj na pending operacje (timeout 2 sekundy)
            waitForPendingOperations();

            // 4. Zamknij komponenty w odwrotnej kolejności
            if (connectionManager != null) {
                connectionManager.shutdown();
                logger.debug("ConnectionManager zamknięty");
            }

            if (authCache != null) {
                authCache.shutdown();
                logger.debug("AuthCache zamknięty");
            }

            // 5. Zamknij DB connection jako ostatni
            if (databaseManager != null) {
                databaseManager.shutdown();
                logger.debug("DatabaseManager zamknięty");
            }

            // 6. Zamknij Virtual Thread executor
            VirtualThreadExecutorProvider.shutdown();
            logger.debug("VirtualThreadExecutorProvider zamknięty");

            logger.info("VeloAuth shutdown completed successfully");

        } catch (IllegalStateException e) {
            logger.error("Błąd stanu podczas graceful shutdown", e);
        }
    }

    private void logStartupInfo(long initializationDuration) {
        if (logger.isInfoEnabled()) {
            logger.info("Auth server '{}' configured", settings.getAuthServerName());
            logger.info("Floodgate support: {} (prefix='{}', auth bypass={})",
                    settings.isFloodgateIntegrationEnabled() ? "enabled" : "disabled",
                    settings.getFloodgateUsernamePrefix(),
                    settings.isFloodgateBypassAuthServerEnabled());
            
            String dbType = settings.getDatabaseStorageType();
            String language = settings.getLanguage();
            
            logger.info("Initialized in {} ms ({} database, {} language, bStats enabled)", 
                    initializationDuration, dbType, language);
            logger.info("Ready - player connections allowed");
        }
    }

    /**
     * Przeładowuje konfigurację pluginu i pliki językowe.
     *
     * @return true jeśli sukces
     */
    public boolean reloadConfig() {
        try {
            if (logger.isInfoEnabled()) {
                logger.info(messages.get("config.reloading"));
            }

            // Reload configuration
            boolean configReloaded = settings.load();
            
            // Reload language files
            boolean languageReloaded = reloadLanguageFiles();

            if (configReloaded) {
                if (logger.isInfoEnabled()) {
                    logger.info(messages.get("config.reloaded_success"));
                }
                logStartupInfo(0); // Pass 0 as duration for reload
                return languageReloaded; // Return true only if both succeeded
            } else {
                if (logger.isErrorEnabled()) {
                    logger.error(messages.get("config.reload_failed"));
                }
                return false;
            }

        } catch (IllegalStateException e) {
            if (logger.isErrorEnabled()) {
                logger.error("Błąd stanu podczas przeładowywania konfiguracji", e);
            }
            return false;
        }
    }

    // Gettery dla komponentów (dla innych klas)

    /**
     * Zwraca ProxyServer instance.
     *
     * @return ProxyServer
     */
    public ProxyServer getServer() {
        return server;
    }

    /**
     * Zwraca Logger instance.
     *
     * @return Logger
     */
    public Logger getLogger() {
        return logger;
    }

    /**
     * Zwraca katalog danych pluginu.
     *
     * @return Path do katalogu danych
     */
    public Path getDataDirectory() {
        return dataDirectory;
    }

    /**
     * Zwraca ustawienia pluginu.
     *
     * @return Settings
     */
    public Settings getSettings() {
        return settings;
    }

    /**
     * Zwraca system wiadomości (i18n).
     *
     * @return Messages
     */
    public Messages getMessages() {
        return messages;
    }

    /**
     * Zwraca manager bazy danych.
     *
     * @return DatabaseManager
     */
    public DatabaseManager getDatabaseManager() {
        return databaseManager;
    }

    /**
     * Zwraca cache autoryzacji.
     *
     * @return AuthCache
     */
    public AuthCache getAuthCache() {
        return authCache;
    }

    /**
     * Zwraca connection manager.
     *
     * @return ConnectionManager
     */
    public ConnectionManager getConnectionManager() {
        return connectionManager;
    }

    /**
     * Sprawdza czy plugin jest zainicjalizowany.
     *
     * @return true jeśli zainicjalizowany
     */
    public boolean isInitialized() {
        return initialized;
    }

    /**
     * Returns a future that completes when the plugin is fully initialized.
     * Used by EarlyLoginBlocker to queue connections during startup.
     *
     * @return CompletableFuture that completes on successful initialization
     */
    public CompletableFuture<Void> getInitializationFuture() {
        return initializationFuture.copy();
    }

    /**
     * Zwraca wersję pluginu.
     *
     * @return Wersja pluginu
     */
    public String getVersion() {
        return BuildConstants.VERSION;
    }
}
