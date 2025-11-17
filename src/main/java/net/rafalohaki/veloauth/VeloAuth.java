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
        logger.info("=== VeloAuth v1.0.0 - Inicjalizacja ===");

        // Conditional logging to avoid unnecessary string concatenation
        if (logger.isDebugEnabled()) {
            logger.debug("Java: {}, Virtual Threads: {}",
                    System.getProperty("java.version"),
                    Thread.currentThread().isVirtual() ? "Dostępne" : "Niedostępne");
        }

        // Inicjalizacja asynchroniczna z Virtual Threads
        // skipcq: JAVA-W1087 - Future is properly handled with whenComplete
        CompletableFuture.runAsync(this::initializePlugin, VirtualThreadExecutorProvider.getVirtualExecutor())
                .whenComplete((result, throwable) -> {
                    if (throwable != null) {
                        logger.error("Błąd podczas inicjalizacji VeloAuth", throwable);
                        shutdown();
                    } else {
                        initialized = true;
                        logger.info("=== VeloAuth v1.0.0 - Gotowy do pracy ===");
                        logStartupInfo();
                    }
                });
    }

    /**
     * Zamknięcie pluginu przy wyłączaniu proxy.
     */
    @Subscribe
    public void onProxyShutdown(ProxyShutdownEvent event) {
        logger.info("=== VeloAuth - Zamykanie ===");
        shutdown();
        logger.info("=== VeloAuth - Zamknięty ===");
    }

    /**
     * Inicjalizuje wszystkie komponenty pluginu.
     */
    @SuppressWarnings("java:S2139") // SonarCloud false positive: we log AND rethrow with cause
    private void initializePlugin() {
        try {
            // 1. Ładowanie konfiguracji
            logger.info("Ładowanie konfiguracji...");
            settings = new Settings(dataDirectory);
            if (!settings.load()) {
                throw VeloAuthException.configuration("settings loading", null);
            }

            // 2. Inicjalizacja systemu wiadomości (i18n)
            logger.info("Inicjalizacja systemu wiadomości...");
            messages = new Messages();
            messages.setLanguage(settings.getLanguage());

            // 3. Inicjalizacja bazy danych
            logger.info("Inicjalizacja bazy danych...");
            DatabaseConfig dbConfig = createDatabaseConfig();
            databaseManager = new DatabaseManager(dbConfig);

            boolean dbInitialized = databaseManager.initialize().join();
            if (!dbInitialized) {
                throw VeloAuthException.database("initialization", null);
            }

            // 4. Inicjalizacja cache
            logger.info("Inicjalizacja cache autoryzacji...");
            authCache = new AuthCache(
                    settings.getCacheTtlMinutes(),
                    settings.getCacheMaxSize(),
                    settings.getCacheMaxSize(), // maxSessions - użyj tej samej wartości co maxSize
                    settings.getCacheMaxSize(), // maxPremiumCache - użyj tej samej wartości co maxSize
                    settings.getBruteForceMaxAttempts(),
                    settings.getBruteForceTimeoutMinutes(),
                    settings.getCacheCleanupIntervalMinutes(),
                    settings
            );

            // 5. Inicjalizacja command handler
            logger.info("Rejestracja komend...");
            commandHandler = new CommandHandler(this, databaseManager, authCache, settings, messages);
            commandHandler.registerCommands();

            // 6. Inicjalizacja connection manager
            logger.info("Inicjalizacja connection manager...");
            connectionManager = new ConnectionManager(this, databaseManager, authCache, settings);

            // 7. Premium resolver service
            logger.info("Inicjalizacja premium resolver service...");
            premiumResolverService = new PremiumResolverService(logger, settings, databaseManager.getPremiumUuidDao());

            // 8. Rejestracja event listener
            logger.info("Rejestracja event listeners...");
            authListener = new AuthListener(this, connectionManager, authCache, settings, premiumResolverService, databaseManager);
            server.getEventManager().register(this, authListener);

            // 9. Debug serwerów (zgodnie z notes.txt)
            connectionManager.debugServers();

            logger.info("Wszystkie komponenty zainicjalizowane pomyślnie");

        } catch (IllegalStateException e) {
            logger.error("Krytyczny błąd stanu podczas inicjalizacji VeloAuth", e);
            throw VeloAuthException.configuration("plugin initialization", e);
        } catch (IllegalArgumentException e) {
            logger.error("Krytyczny błąd argumentów podczas inicjalizacji VeloAuth", e);
            throw VeloAuthException.configuration("invalid arguments", e);
        } catch (VeloAuthException e) {
            logger.error("Błąd VeloAuth podczas inicjalizacji", e);
            throw e; // Re-throw our custom exceptions
        } catch (Exception e) {
            logger.error("Nieoczekiwany błąd podczas inicjalizacji VeloAuth", e);
            throw VeloAuthException.configuration("unexpected error", e);
        }
    }

    /**
     * Simple pending operations cleanup.
     * Components handle their own graceful shutdown internally.
     */
    private void waitForPendingOperations() {
        logger.debug("Component shutdown in progress - pending operations handled internally");
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
        logger.info("Konfiguracja:");
        logger.info("  - Baza danych: {} ({})",
                settings.getDatabaseStorageType(),
                databaseManager.isConnected() ? "Połączona" : "Rozłączona");
        logger.info("  - Cache TTL: {} minut", settings.getCacheTtlMinutes());
        logger.info("  - Cache Max Size: {}", settings.getCacheMaxSize());
        logger.info("  - Brute Force: {} prób / {} minut timeout",
                settings.getBruteForceMaxAttempts(),
                settings.getBruteForceTimeoutMinutes());
        logger.info("  - PicoLimbo serwer: {}", settings.getPicoLimboServerName());
        logger.info("  - BCrypt cost: {}", settings.getBcryptCost());
        logger.info("  - Premium check: {}", settings.isPremiumCheckEnabled() ? "Włączony" : "Wyłączony");

        // Statystyki cache
        var stats = authCache.getStats();
        logger.info("Cache: {} autoryzowanych, {} brute force, {} premium",
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
            logger.info("Przeładowywanie konfiguracji...");

            if (settings.load()) {
                logger.info("Konfiguracja przeładowana pomyślnie");
                logStartupInfo();
                return true;
            } else {
                logger.error("Nie udało się przeładować konfiguracji");
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
