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
import net.rafalohaki.veloauth.exception.VeloAuthException;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.listener.AuthListener;
import net.rafalohaki.veloauth.listener.EarlyLoginBlocker;
import net.rafalohaki.veloauth.premium.PremiumResolverService;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
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
        version = "1.0.0",
        description = "Complete Velocity Authentication Plugin with BCrypt, Virtual Threads and multi-database support",
        authors = {"Rafal"}
)
public class VeloAuth {

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDirectory;

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
    private volatile boolean initialized = false;

    /**
     * Konstruktor z dependency injection Velocity.
     *
     * @param server        ProxyServer instance
     * @param logger        Logger instance
     * @param dataDirectory Katalog danych pluginu
     */
    @Inject
    public VeloAuth(ProxyServer server, Logger logger, @DataDirectory Path dataDirectory) {
        this.server = server;
        this.logger = logger;
        this.dataDirectory = dataDirectory;

        if (logger.isDebugEnabled()) {
            logger.debug("VeloAuth konstruktor - Java {}, Velocity API {}",
                    System.getProperty("java.version"),
                    server.getVersion().getVersion());
        }
    }

    /**
     * Inicjalizacja pluginu przy starcie proxy.
     */
    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        logger.info("=== VeloAuth v1.0.0 - Initialization ===");

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
        CompletableFuture.runAsync(this::initializePlugin, VirtualThreadExecutorProvider.getVirtualExecutor())
                .whenComplete((result, throwable) -> {
                    if (throwable != null) {
                        logger.error("Error during VeloAuth initialization", throwable);
                        shutdown();
                    } else {
                        // Clear any stale cache entries from previous server runs
                        if (databaseManager != null) {
                            databaseManager.clearCache();
                            logger.info("Cleared stale database cache entries");
                        }
                        if (authCache != null) {
                            authCache.clearAll();
                            logger.info("Cleared stale authentication cache entries");
                        }
                        
                        initialized = true;
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
    @SuppressWarnings("java:S2139") // SonarCloud false positive: we log AND rethrow with cause
    private void initializePlugin() {
        try {
            // 1. Ładowanie konfiguracji
            logger.info("Loading configuration...");
            settings = new Settings(dataDirectory);
            if (!settings.load()) {
                throw VeloAuthException.configuration("settings loading", null);
            }

            // 2. Inicjalizacja systemu wiadomości (i18n)
            if (logger.isInfoEnabled()) {
                logger.info("Initializing message system...");
            }
            messages = new Messages();
            messages.setLanguage(settings.getLanguage());

            // Now we can use localized messages
            if (logger.isInfoEnabled()) {
                logger.info(messages.get("plugin.initialization.loading_config"));
                logger.info(messages.get("plugin.initialization.init_messages"));
            }

            // 3. Inicjalizacja bazy danych
            if (logger.isInfoEnabled()) {
                logger.info(messages.get("plugin.initialization.init_database"));
            }
            DatabaseConfig dbConfig = createDatabaseConfig();
            databaseManager = new DatabaseManager(dbConfig, messages);

            boolean dbInitialized = databaseManager.initialize().join();
            if (!dbInitialized) {
                throw VeloAuthException.database("initialization", null);
            }

            // 4. Inicjalizacja cache
            if (logger.isInfoEnabled()) {
                logger.info(messages.get("plugin.initialization.init_cache"));
            }
            authCache = new AuthCache(
                    settings.getCacheTtlMinutes(),
                    settings.getCacheMaxSize(),
                    settings.getCacheMaxSize(), // maxSessions - użyj tej samej wartości co maxSize
                    settings.getCacheMaxSize(), // maxPremiumCache - użyj tej samej wartości co maxSize
                    settings.getBruteForceMaxAttempts(),
                    settings.getBruteForceTimeoutMinutes(),
                    settings.getCacheCleanupIntervalMinutes(),
                    settings,
                    messages
            );

            // 5. Inicjalizacja command handler
            if (logger.isInfoEnabled()) {
                logger.info(messages.get("plugin.initialization.registering_commands"));
            }
            commandHandler = new CommandHandler(this, databaseManager, authCache, settings, messages);
            commandHandler.registerCommands();

            // 6. Inicjalizacja connection manager
            if (logger.isInfoEnabled()) {
                logger.info(messages.get("plugin.initialization.init_connection_manager"));
            }
            connectionManager = new ConnectionManager(this, databaseManager, authCache, settings, messages);

            // 7. Premium resolver service
            if (logger.isInfoEnabled()) {
                logger.info(messages.get("plugin.initialization.init_premium_resolver"));
            }
            premiumResolverService = new PremiumResolverService(logger, settings, databaseManager.getPremiumUuidDao());

            // 8. Rejestracja pełnego AuthListener z wszystkimi zależnościami
            if (logger.isInfoEnabled()) {
                logger.info(messages.get("plugin.initialization.registering_listeners"));
            }
            authListener = new AuthListener(this, connectionManager, authCache, settings, premiumResolverService, databaseManager, messages);
            server.getEventManager().register(this, authListener);
            if (logger.isInfoEnabled()) {
                logger.info("✅ Full AuthListener registered after initialization");
            }

            // 9. Debug serwerów (zgodnie z notes.txt)
            connectionManager.debugServers();

            if (logger.isInfoEnabled()) {
                logger.info(messages.get("plugin.initialization.components_ready"));
            }

        } catch (IllegalStateException e) {
            logger.error("Critical state error during VeloAuth initialization", e);
            throw VeloAuthException.configuration("plugin initialization", e);
        } catch (IllegalArgumentException e) {
            logger.error("Critical argument error during VeloAuth initialization", e);
            throw VeloAuthException.configuration("invalid arguments", e);
        } catch (VeloAuthException e) {
            logger.error("VeloAuth error during initialization", e);
            throw e; // Re-throw our custom exceptions
        } catch (Exception e) {
            logger.error("Unexpected error during VeloAuth initialization", e);
            throw VeloAuthException.configuration("unexpected error", e);
        }
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
                    storageType,
                    settings.getDatabaseHostname(),
                    settings.getDatabasePort(),
                    settings.getDatabaseName(),
                    settings.getDatabaseUser(),
                    settings.getDatabasePassword(),
                    settings.getDatabaseConnectionPoolSize(),
                    (int) settings.getDatabaseMaxLifetimeMillis(), // Cast long to int for HikariCP
                    settings.getDatabaseConnectionParameters(),
                    settings.getPostgreSQLSettings(),
                    settings.isDebugEnabled()
            );
        }
    }

    /**
     * Zamyka wszystkie komponenty pluginu z graceful shutdown.
     */
    private void shutdown() {
        initialized = false;

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
        logger.info(messages.get("config.display.header"));
        logger.info(messages.get("config.display.database"),
                settings.getDatabaseStorageType(),
                databaseManager.isConnected() ? messages.get("database.connected") : messages.get("database.disconnected"));
        logger.info(messages.get("config.display.cache_ttl"), settings.getCacheTtlMinutes());
        logger.info(messages.get("config.display.cache_max_size"), settings.getCacheMaxSize());
        logger.info(messages.get("config.display.brute_force"),
                settings.getBruteForceMaxAttempts(),
                settings.getBruteForceTimeoutMinutes());
        logger.info(messages.get("config.display.picolimbo_server"), settings.getPicoLimboServerName());
        logger.info(messages.get("config.display.bcrypt_cost"), settings.getBcryptCost());
        logger.info(messages.get("config.display.premium_check"),
                settings.isPremiumCheckEnabled() ? messages.get("premium.check_enabled") : messages.get("premium.check_disabled"));

        // Statystyki cache
        var stats = authCache.getStats();
        logger.info(messages.get("config.display.cache_stats"),
                stats.authorizedPlayersCount(),
                stats.bruteForceEntriesCount(),
                stats.premiumCacheCount());
    }

    /**
     * Przeładowuje konfigurację pluginu.
     *
     * @return true jeśli sukces
     */
    public boolean reloadConfig() {
        try {
            logger.info(messages.get("config.reloading"));

            if (settings.load()) {
                logger.info(messages.get("config.reloaded_success"));
                logStartupInfo();
                return true;
            } else {
                logger.error(messages.get("config.reload_failed"));
                return false;
            }

        } catch (IllegalStateException e) {
            logger.error("Błąd stanu podczas przeładowywania konfiguracji", e);
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
        return "1.0.0";
    }
}
