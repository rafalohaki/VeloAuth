package net.rafalohaki.veloauth;

import com.google.inject.Inject;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
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

import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;

/**
 * VeloAuth - Complete Velocity Authentication Plugin.
 * <p>
 * Manager autoryzacji na proxy Velocity, który zarządza przepuszczaniem graczy
 * między Velocity, PicoLimbo (mini serwer lobby) i serwerami backend.
 * <p>
 * Kluczowe cechy:
 * - Zarządzanie cache autoryzacji - zalogowani gracze omijają logowanie
 * - Transfer graczy via Velocity - Velocity steruje przepuszczaniem między serwerami
 * - Wszystkie operacje na proxy - /login, /register, /changepassword obsługiwane przez VeloAuth
 * - BCrypt hashing - bezpieczne przechowywanie haseł
 * - Wspólna baza danych - kompatybilna z LimboAuth
 * - Obsługa graczy premium i cracked
 * - Virtual Threads (Project Loom) - wydajne I/O
 * - Backend API - integracja z innymi pluginami
 * - Java 21 - najnowsze optymalizacje
 */
@Plugin(
        id = "veloauth",
        name = "VeloAuth",
        version = "1.0.1",
        description = "Complete Velocity Authentication Plugin with BCrypt, Virtual Threads and multi-database support",
        authors = {"Rafal"}
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
        } catch (Exception e) {
            logger.error("Failed to reload language files", e);
            return false;
        }
    }

    /**
     * Inicjalizacja pluginu przy starcie proxy.
     */
    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        logger.info("=== VeloAuth v{} - Initialization ===", getVersion());

        // Conditional logging to avoid unnecessary string concatenation
        if (logger.isDebugEnabled()) {
            logger.debug("Java: {}, Virtual Threads: {}",
                    System.getProperty("java.version"),
                    Thread.currentThread().isVirtual() ? "Available" : "Unavailable");
        }

        // CRITICAL: Register early PreLogin blocker BEFORE starting async initialization
        // This prevents players from connecting before authentication handlers are ready
        logger.info("Registering early PreLogin blocker for initialization protection...");
        try {
            EarlyLoginBlocker earlyBlocker = new EarlyLoginBlocker(this);
            server.getEventManager().register(this, earlyBlocker);
            logger.info("✅ EarlyLoginBlocker registered BEFORE initialization - PreLogin protection active");
        } catch (Exception e) {
            logger.error("Failed to register early PreLogin blocker", e);
            return;
        }

        // Inicjalizacja asynchroniczna z Virtual Threads
        // skipcq: JAVA-W1087 - Future is properly handled with whenComplete
        long initializationStartTime = System.currentTimeMillis();
        logger.info("🚀 Starting VeloAuth initialization at {} (initialized flag: {})", 
                new java.util.Date(initializationStartTime), initialized);
        
        CompletableFuture.runAsync(this::initializePlugin, VirtualThreadExecutorProvider.getVirtualExecutor())
                .whenComplete((result, throwable) -> {
                    long initializationDuration = System.currentTimeMillis() - initializationStartTime;
                    
                    if (throwable != null) {
                        logger.error("❌ VeloAuth initialization FAILED after {} ms", initializationDuration, throwable);
                        // CRITICAL: Keep initialized flag as FALSE to prevent connections to broken plugin
                        logger.warn("⚠️ Initialization flag remains FALSE - all player connections will be blocked");
                        shutdown();
                    } else {
                        // Clear any stale cache entries from previous server runs
                        if (databaseManager != null) {
                            databaseManager.clearCache();
                            logger.debug("Cleared stale database cache entries");
                        }
                        if (authCache != null) {
                            authCache.clearAll();
                            logger.debug("Cleared stale authentication cache entries");
                        }

                        // Initialize bStats metrics
                        metricsFactory.make(this, BSTATS_PLUGIN_ID);
                        logger.info("📊 bStats metrics initialized (Plugin ID: {})", BSTATS_PLUGIN_ID);

                        // CRITICAL: Set initialized flag to TRUE only after ALL components are ready
                        initialized = true;
                        logger.info("✅ VeloAuth initialization completed successfully in {} ms", initializationDuration);
                        logger.info("🟢 Initialization flag set to TRUE - player connections now allowed");
                        logger.info(messages.get("plugin.initialization.ready"));
                        logStartupInfo();
                    }
                });
    }

    /**
     * Zamknięcie pluginu przy wyłączaniu proxy.
     */
    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        if (logger.isInfoEnabled()) {
            logger.info(messages.get("plugin.initialization.shutdown"));
        }
        shutdown();
        if (logger.isInfoEnabled()) {
            logger.info(messages.get("plugin.initialization.closed"));
        }
    }

    /**
     * Inicjalizuje wszystkie komponenty pluginu.
     */
    @SuppressWarnings({"java:S2139", "java:S3776"}) // Exception handling + initialization complexity 10
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

        } catch (IllegalStateException e) {
            if (logger.isErrorEnabled()) {
                logger.error("Critical state error during VeloAuth initialization", e);
            }
            throw VeloAuthException.configuration("plugin initialization", e);
        } catch (IllegalArgumentException e) {
            if (logger.isErrorEnabled()) {
                logger.error("Critical argument error during VeloAuth initialization", e);
            }
            throw VeloAuthException.configuration("invalid arguments", e);
        } catch (VeloAuthException e) {
            if (logger.isErrorEnabled()) {
                logger.error("VeloAuth error during initialization", e);
            }
            throw e; // Re-throw our custom exceptions
        } catch (Exception e) {
            if (logger.isErrorEnabled()) {
                logger.error("Unexpected error during VeloAuth initialization", e);
            }
            throw VeloAuthException.configuration("unexpected error", e);
        }
    }

    private void initializeConfiguration() {
        logger.info("📋 [1/8] Loading configuration...");
        long startTime = System.currentTimeMillis();
        
        settings = new Settings(dataDirectory);
        if (!settings.load()) {
            throw VeloAuthException.configuration("settings loading", null);
        }
        
        logger.info("✅ Configuration loaded in {} ms", System.currentTimeMillis() - startTime);
    }

    private void initializeMessages() {
        logger.info("💬 [2/8] Initializing message system...");
        long startTime = System.currentTimeMillis();
        
        String language = settings.getLanguage();
        
        try {
            messages = new Messages(dataDirectory, language);
            logger.info("✅ Message system initialized in {} ms (Language: {}, External files: enabled)", 
                    System.currentTimeMillis() - startTime, language);
        } catch (Exception e) {
            logger.error("Failed to initialize external language files, falling back to JAR-embedded files", e);
            messages = new Messages();
            messages.setLanguage(language);
            logger.info("✅ Message system initialized in {} ms (Language: {}, External files: disabled)", 
                    System.currentTimeMillis() - startTime, language);
        }
    }

    private void initializeDatabase() {
        logger.info("🗄️ [3/8] Initializing database connection...");
        long startTime = System.currentTimeMillis();
        
        DatabaseConfig dbConfig = createDatabaseConfig();
        databaseManager = new DatabaseManager(dbConfig, messages);

        boolean dbInitialized = databaseManager.initialize().join();
        if (!dbInitialized) {
            throw VeloAuthException.database("initialization", null);
        }
        
        logger.info("✅ Database initialized in {} ms (Type: {})", 
                System.currentTimeMillis() - startTime, settings.getDatabaseStorageType());
    }

    private void initializeCache() {
        logger.info("💾 [4/8] Initializing authentication cache...");
        long startTime = System.currentTimeMillis();
        
        authCache = new AuthCache(
                settings.getCacheTtlMinutes(),
                settings.getCacheMaxSize(),
                settings.getCacheMaxSize(), // maxSessions - użyj tej samej wartości co maxSize
                10000, // maxPremiumCache - set to 10000 as per requirement 6.5
                settings.getBruteForceMaxAttempts(),
                settings.getBruteForceTimeoutMinutes(),
                settings.getCacheCleanupIntervalMinutes(),
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
        logger.info("⌨️ [5/8] Registering commands...");
        long startTime = System.currentTimeMillis();
        
        commandHandler = new CommandHandler(this, databaseManager, authCache, settings, messages);
        commandHandler.registerCommands();
        
        logger.debug("✅ Commands registered in {} ms", System.currentTimeMillis() - startTime);
    }

    private void initializeConnectionManager() {
        logger.info("🔌 [6/8] Initializing connection manager...");
        long startTime = System.currentTimeMillis();
        
        connectionManager = new ConnectionManager(this, databaseManager, authCache, settings, messages);
        
        logger.debug("✅ Connection manager initialized in {} ms", System.currentTimeMillis() - startTime);
    }

    private void initializePremiumResolver() {
        logger.info("👑 [7/8] Initializing premium resolver service...");
        long startTime = System.currentTimeMillis();
        
        premiumResolverService = new PremiumResolverService(logger, settings, databaseManager.getPremiumUuidDao());
        
        logger.debug("✅ Premium resolver initialized in {} ms (Enabled: {})", 
                System.currentTimeMillis() - startTime, 
                settings.isPremiumCheckEnabled());
    }

    private void initializeListeners() {
        logger.info("🎧 [8/8] Registering event listeners...");
        long startTime = System.currentTimeMillis();
        
        // CRITICAL: Create handlers BEFORE AuthListener
        PreLoginHandler preLoginHandler = new PreLoginHandler(
            authCache, premiumResolverService, databaseManager,
            messages, logger);
        logger.debug("PreLoginHandler created successfully");
        
        PostLoginHandler postLoginHandler = new PostLoginHandler(
            this, authCache, connectionManager, databaseManager,
            messages, logger);
        logger.debug("PostLoginHandler created successfully");
        
        // Create AuthListener with initialized handlers
        authListener = new AuthListener(
            this, authCache, settings,
            preLoginHandler, postLoginHandler, databaseManager, messages);
        
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

    /**
     * Loguje informacje o starcie pluginu.
     */
    private void logStartupInfo() {
        if (logger.isInfoEnabled()) {
            logger.info(messages.get("config.display.header"));
            
            String dbStatus = databaseManager.isConnected() ? messages.get("database.connected") : messages.get("database.disconnected");
            String premiumStatus = settings.isPremiumCheckEnabled() ? messages.get("premium.check_enabled") : messages.get("premium.check_disabled");
            var stats = authCache.getStats();
            
            logger.info(messages.get("config.display.database"),
                    settings.getDatabaseStorageType(),
                    dbStatus);
            logger.info(messages.get("config.display.cache_ttl"), settings.getCacheTtlMinutes());
            logger.info(messages.get("config.display.cache_max_size"), settings.getCacheMaxSize());
            logger.info(messages.get("config.display.brute_force"),
                    settings.getBruteForceMaxAttempts(),
                    settings.getBruteForceTimeoutMinutes());
            logger.info(messages.get("config.display.picolimbo_server"), settings.getPicoLimboServerName());
            logger.info(messages.get("config.display.bcrypt_cost"), settings.getBcryptCost());
            logger.info(messages.get("config.display.premium_check"), premiumStatus);
            
            logger.info(messages.get("config.display.cache_stats"),
                    stats.authorizedPlayersCount(),
                    stats.bruteForceEntriesCount(),
                    stats.premiumCacheCount());
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
                logStartupInfo();
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
     * Zwraca wersję pluginu.
     *
     * @return Wersja pluginu
     */
    public String getVersion() {
        return "1.0.1";
    }
}
