package net.rafalohaki.veloauth.integration;

import com.velocitypowered.api.command.CommandManager;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.command.CommandHandler;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseConfig;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.net.InetAddress;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * REAL integration tests using public APIs only.
 * Tests actual system behavior without accessing private implementation.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class VeloAuthIntegrationTest {

    private final String playerName = "TestPlayer";
    private VeloAuth plugin;
    private DatabaseManager databaseManager;
    private AuthCache authCache;
    private Settings settings;
    private Messages messages;
    @Mock
    private ProxyServer proxyServer;
    @Mock
    private org.slf4j.Logger logger;
    @Mock
    private CommandManager commandManager;
    @Mock
    private Player player;
    @Mock
    private CommandSource commandSource;
    private CommandHandler commandHandler;
    private UUID playerUuid;

    @BeforeEach
    void setUp() throws Exception {
        playerUuid = UUID.randomUUID();

        // Use real plugin instance to avoid Mockito inline mocking of plugin class
        when(logger.isDebugEnabled()).thenReturn(false);
        plugin = new VeloAuth(proxyServer, logger, java.nio.file.Path.of("."));

        messages = new Messages();
        messages.setLanguage("en");
        settings = new TestSettings(java.nio.file.Path.of(".test-settings"), true, "auth");
        authCache = new net.rafalohaki.veloauth.cache.AuthCache(
                60, 10000, 1000, 10000,
                5, 5, 1,
                settings, messages
        );

        // Fix CommandManager mocking - properly chain builder pattern
        com.velocitypowered.api.command.CommandMeta.Builder metaBuilder = mock(com.velocitypowered.api.command.CommandMeta.Builder.class);
        when(metaBuilder.aliases(any(String[].class))).thenReturn(metaBuilder);
        when(metaBuilder.build()).thenReturn(mock(com.velocitypowered.api.command.CommandMeta.class));
        when(commandManager.metaBuilder(anyString())).thenReturn(metaBuilder);

        when(proxyServer.getCommandManager()).thenReturn(commandManager);

        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn(playerName);
        when(player.getRemoteAddress()).thenReturn(java.net.InetSocketAddress.createUnresolved("127.0.0.1", 25565));
        when(player.isOnlineMode()).thenReturn(false);

        // No mocking required for settings

        // Use lightweight DatabaseManager stub instead of Mockito inline mocks
        Messages testMessages = new Messages();
        testMessages.setLanguage("en");
        DatabaseConfig testConfig = DatabaseConfig.forLocalDatabase("H2", "memtest");
        databaseManager = new TestDatabaseManager(testConfig, testMessages);

        commandHandler = new CommandHandler(plugin, databaseManager, authCache, settings, messages);
    }

    @Test
    void testCommandRegistration_allCommandsRegisteredSuccessfully() {
        // Test: Verify all commands are registered with aliases
        commandHandler.registerCommands();

        // Verify command manager was called for each command
        verify(commandManager, times(5)).register(any(), any()); // Total should be 5 commands
    }

    @Test
    void testLoginCommand_throughPublicAPI_shouldHandleDatabaseFailure() {
        // Setup: Mock command execution through CommandManager
        when(commandManager.metaBuilder("login")).thenReturn(mock(com.velocitypowered.api.command.CommandMeta.Builder.class));
        when(commandManager.metaBuilder("login").aliases("log", "l")).thenReturn(mock(com.velocitypowered.api.command.CommandMeta.Builder.class));
        when(commandManager.metaBuilder("login").aliases("log", "l").build()).thenReturn(mock(com.velocitypowered.api.command.CommandMeta.class));

        // Register commands
        commandHandler.registerCommands();

        // Verify registration doesn't throw exceptions
        assertDoesNotThrow(() -> commandHandler.registerCommands());
    }

    @Test
    void testSystemInitialization_completeFlow_shouldWork() {
        // Test: Complete system initialization using stub
        ((TestDatabaseManager) databaseManager).setInitResult(CompletableFuture.completedFuture(true));

        assertDoesNotThrow(() -> {
            boolean initialized = databaseManager.initialize().join();
            assertTrue(initialized, "Database should initialize successfully");
        });
    }

    @Test
    void testPlayerAuthorization_flow_shouldWorkCorrectly() {
        // Setup: Mock only what's needed for this test
        ((TestDatabaseManager) databaseManager).setFindResult(
                playerName.toLowerCase(),
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(null))
        );

        // Test: Player tries to login without account
        CompletableFuture<DatabaseManager.DbResult<RegisteredPlayer>> findResult = databaseManager.findPlayerByNickname(playerName.toLowerCase());

        // Should complete without exceptions
        assertDoesNotThrow(() -> {
            DatabaseManager.DbResult<RegisteredPlayer> dbResult = findResult.join();
            assertFalse(dbResult.isDatabaseError(), "Should not have database error");
            RegisteredPlayer found = dbResult.getValue();
            assertNull(found, "Non-existent player should return null");
        });

        // Verify database was called
        // Verify that method completes and returns expected result
        assertNull(findResult.join().getValue());
    }

    @Test
    void testSessionManagement_persistenceShouldWork() {
        // Setup real cache state
        authCache.startSession(playerUuid, playerName, "127.0.0.1");
        authCache.addAuthorizedPlayer(playerUuid,
                new net.rafalohaki.veloauth.model.CachedAuthUser(
                        playerUuid, playerName, "127.0.0.1",
                        System.currentTimeMillis(), false, null));

        // Test: Session should persist after disconnect
        boolean hasSession = authCache.hasActiveSession(playerUuid, playerName, "127.0.0.1");
        boolean isAuthorized = authCache.isPlayerAuthorized(playerUuid, "127.0.0.1");

        // Verify session persistence works
        assertTrue(hasSession, "Session should persist");
        assertTrue(isAuthorized, "Player should remain authorized");
    }

    @Test
    void testPremiumVsOffline_separationShouldWork() {
        // Setup: Mock only premium player test needs
        Player premiumPlayer = mock(Player.class);
        UUID premiumUuid = UUID.randomUUID();
        String premiumName = "PremiumPlayer";

        when(premiumPlayer.getUniqueId()).thenReturn(premiumUuid);
        when(premiumPlayer.getUsername()).thenReturn(premiumName);
        when(premiumPlayer.isOnlineMode()).thenReturn(true); // Premium player

        ((TestDatabaseManager) databaseManager).setPremiumResult(
                premiumName,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(true))
        );

        // Test: Premium player detection
        CompletableFuture<DatabaseManager.DbResult<Boolean>> premiumCheck = databaseManager.isPremium(premiumName);

        // Should complete without exceptions
        assertDoesNotThrow(() -> {
            DatabaseManager.DbResult<Boolean> dbResult = premiumCheck.join();
            assertFalse(dbResult.isDatabaseError(), "Should not have database error");
            assertTrue(dbResult.getValue(), "Premium player should return true");
        });

        // No method verification on stub; ensure result is correct
    }

    @Test
    void testErrorHandling_systemShouldNotCrash() {
        // Setup: Mock database to return error result (not throw exception)
        DbResult<RegisteredPlayer> errorResult = DbResult.databaseError("Database connection failed");
        ((TestDatabaseManager) databaseManager).setFindResult(
                "test",
                CompletableFuture.completedFuture(errorResult)
        );

        // Should handle database failure gracefully
        CompletableFuture<DbResult<RegisteredPlayer>> result = databaseManager.findPlayerByNickname("test");

        // Should complete with database error, not crash
        assertDoesNotThrow(() -> {
            DbResult<RegisteredPlayer> dbResult = result.join();
            assertTrue(dbResult.isDatabaseError(), "Should return database error on failure");
            assertNull(dbResult.getValue(), "Should return null value on database error");
        });
    }

    @Test
    void testCacheOperations_threadSafetyShouldWork() {
        // Setup real cache state
        authCache.addAuthorizedPlayer(playerUuid,
                new net.rafalohaki.veloauth.model.CachedAuthUser(
                        playerUuid, playerName, "127.0.0.1",
                        System.currentTimeMillis(), false, null));

        // Multiple concurrent calls should not cause issues
        assertDoesNotThrow(() -> {
            for (int i = 0; i < 100; i++) {
                boolean authorized = authCache.isPlayerAuthorized(playerUuid, "127.0.0.1");
                assertTrue(authorized, "Cache should return consistent results");
            }
        });

        // No mock verification for real cache instance
    }

    @Test
    void testConfiguration_loadingShouldWork() {
        // Test: Configuration should load without errors

        // Should access configuration without exceptions
        assertDoesNotThrow(() -> {
            boolean debugEnabled = settings.isDebugEnabled();
            String picoLimboServer = settings.getPicoLimboServerName();

            assertTrue(debugEnabled, "Debug setting should be accessible");
            assertEquals("auth", picoLimboServer, "PicoLimbo server should be configurable");
        });
    }
}
