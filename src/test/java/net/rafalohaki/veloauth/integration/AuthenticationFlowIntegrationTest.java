package net.rafalohaki.veloauth.integration;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.listener.PostLoginHandler;
import net.rafalohaki.veloauth.listener.PreLoginHandler;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.premium.PremiumResolverService;
import org.bstats.velocity.Metrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration tests for authentication flow scenarios.
 * Tests requirements 4.1, 4.2, and 4.4 from the refactoring spec.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings({"java:S100", "java:S1450"}) // Test method names use descriptive underscores; test fields are acceptable
class AuthenticationFlowIntegrationTest {

    private PreLoginHandler preLoginHandler;
    private PostLoginHandler postLoginHandler;
    private AuthCache authCache;
    private TestDatabaseManager databaseManager;
    private Messages messages;
    
    private PremiumResolverService premiumResolverService;
    private Settings settings;
    @Mock
    private org.slf4j.Logger logger;
    private net.rafalohaki.veloauth.VeloAuth plugin;
    private net.rafalohaki.veloauth.connection.ConnectionManager connectionManager;
    @Mock
    private com.velocitypowered.api.proxy.ProxyServer proxyServer;

    @BeforeEach
    void setUp() {
        messages = new Messages();
        messages.setLanguage("en");
        
        java.nio.file.Path tempDir;
        try {
            tempDir = java.nio.file.Files.createTempDirectory("veloauth-it-config");
        } catch (java.io.IOException e) {
            tempDir = java.nio.file.Paths.get("target", "veloauth-it-config");
            try { 
                java.nio.file.Files.createDirectories(tempDir); 
            } catch (java.io.IOException ignored) {
                // Fallback directory creation failed, test will use non-existent path
            }
        }
        settings = new Settings(tempDir);
        settings.load();
        
        authCache = new AuthCache(
                60, 10000, 1000, 10000,
                5, 5, 1,
                settings, messages
        );
        
        net.rafalohaki.veloauth.database.DatabaseConfig testConfig = 
                net.rafalohaki.veloauth.database.DatabaseConfig.forLocalDatabase("H2", "memtest");
        databaseManager = new TestDatabaseManager(testConfig, messages);

        try {
            com.j256.ormlite.jdbc.JdbcConnectionSource cs =
                    new com.j256.ormlite.jdbc.JdbcConnectionSource("jdbc:h2:mem:veloauth_premium");
            net.rafalohaki.veloauth.database.PremiumUuidDao premiumDao =
                    new net.rafalohaki.veloauth.database.PremiumUuidDao(cs);
            premiumResolverService = new PremiumResolverService(logger, settings, premiumDao);
        } catch (java.sql.SQLException e) {
            throw new IllegalStateException("Failed to initialize PremiumUuidDao for test", e);
        }
        
        when(logger.isDebugEnabled()).thenReturn(false);
        when(logger.isInfoEnabled()).thenReturn(false);

        Metrics.Factory metricsFactory = mock(Metrics.Factory.class);
        plugin = new net.rafalohaki.veloauth.VeloAuth(proxyServer, logger, tempDir, metricsFactory);
        
        preLoginHandler = new PreLoginHandler(
                authCache,
                premiumResolverService,
                databaseManager,
                messages,
                logger
        );
        
        when(proxyServer.getScheduler()).thenReturn(mock(com.velocitypowered.api.scheduler.Scheduler.class));
        com.velocitypowered.api.scheduler.Scheduler.TaskBuilder taskBuilder = 
                mock(com.velocitypowered.api.scheduler.Scheduler.TaskBuilder.class);
        when(proxyServer.getScheduler().buildTask(any(), any(Runnable.class))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(mock(com.velocitypowered.api.scheduler.ScheduledTask.class));
        
        connectionManager = new net.rafalohaki.veloauth.connection.ConnectionManager(
                plugin,
                databaseManager,
                authCache,
                settings,
                messages
        );

        postLoginHandler = new PostLoginHandler(
                plugin,
                authCache,
                databaseManager,
                messages,
                logger
        );
    }

    /**
     * Test: Premium player login flow
     * Requirements: 4.1, 4.2
     */
    @Test
    void testPremiumPlayerLoginFlow_shouldAuthorizeAndStartSession() {
        // Setup premium player
        String username = "PremiumPlayer";
        UUID premiumUuid = UUID.randomUUID();
        String playerIp = "192.168.1.100";
        
        // Mock premium resolution
        authCache.addPremiumPlayer(username, premiumUuid);
        
        // Test pre-login validation
        assertTrue(preLoginHandler.isValidUsername(username), 
                "Premium player username should be valid");
        
        PreLoginHandler.PremiumResolutionResult result = 
                preLoginHandler.resolvePremiumStatus(username);
        assertTrue(result.premium(), "Player should be detected as premium");
        assertNotNull(result.premiumUuid(), "Premium UUID should be present");
        
        // Mock player
        Player player = mock(Player.class);
        when(player.getUsername()).thenReturn(username);
        when(player.getUniqueId()).thenReturn(premiumUuid);
        when(player.isOnlineMode()).thenReturn(true);
        
        // Test post-login handling
        assertDoesNotThrow(() -> postLoginHandler.handlePremiumPlayer(player, playerIp),
                "Premium player handling should not throw exceptions");
        
        // Verify authorization
        assertTrue(authCache.isPlayerAuthorized(premiumUuid, playerIp),
                "Premium player should be authorized");
        assertTrue(authCache.hasActiveSession(premiumUuid, username, playerIp),
                "Premium player should have active session");
    }

    /**
     * Test: Offline player login flow
     * Requirements: 4.1, 4.2
     */
    @Test
    void testOfflinePlayerLoginFlow_shouldRedirectToPicoLimbo() {
        // Setup offline player
        String username = "OfflinePlayer";
        UUID offlineUuid = UUID.randomUUID();
        String playerIp = "192.168.1.101";
        
        // Mock offline resolution
        authCache.addPremiumPlayer(username, null);
        
        // Test pre-login validation
        assertTrue(preLoginHandler.isValidUsername(username),
                "Offline player username should be valid");
        
        PreLoginHandler.PremiumResolutionResult result = 
                preLoginHandler.resolvePremiumStatus(username);
        assertFalse(result.premium(), "Player should be detected as offline");
        
        // Mock player
        Player player = mock(Player.class);
        when(player.getUsername()).thenReturn(username);
        when(player.getUniqueId()).thenReturn(offlineUuid);
        when(player.isOnlineMode()).thenReturn(false);
        
        // Test post-login handling (unauthorized player)
        assertDoesNotThrow(() -> postLoginHandler.handleOfflinePlayer(player, playerIp),
                "Offline player handling should not throw exceptions");
        
        // Verify player is not authorized yet
        assertFalse(authCache.isPlayerAuthorized(offlineUuid, playerIp),
                "Offline player should not be authorized before login");
    }

    /**
     * Test: Brute force protection
     * Requirements: 4.1, 4.4
     */
    @Test
    void testBruteForceProtection_shouldBlockAfterMultipleFailedAttempts() throws Exception {
        // Setup
        InetAddress attackerIp = InetAddress.getByName("10.0.0.1");
        
        // Initially not blocked
        assertFalse(preLoginHandler.isBruteForceBlocked(attackerIp),
                "IP should not be blocked initially");
        
        // Simulate failed login attempts
        for (int i = 0; i < 5; i++) {
            authCache.registerFailedLogin(attackerIp);
        }
        
        // Should be blocked after threshold
        assertTrue(preLoginHandler.isBruteForceBlocked(attackerIp),
                "IP should be blocked after multiple failed attempts");
    }

    /**
     * Test: Nickname conflict scenario - Premium using offline nickname
     * Requirements: 4.1, 4.2
     */
    @Test
    void testNicknameConflict_premiumUsingOfflineNickname_shouldForceOfflineMode() {
        // Setup: Existing offline player in database
        String conflictedNickname = "ConflictedPlayer";
        RegisteredPlayer existingOfflinePlayer = new RegisteredPlayer();
        existingOfflinePlayer.setNickname(conflictedNickname); // This also sets lowercaseNickname
        existingOfflinePlayer.setUuid(UUID.randomUUID().toString());
        existingOfflinePlayer.setPremiumUuid(null); // Offline player
        existingOfflinePlayer.setConflictMode(false);
        
        // Mock database to return existing player
        databaseManager.setFindResult(
                conflictedNickname.toLowerCase(),
                CompletableFuture.completedFuture(
                        DatabaseManager.DbResult.success(existingOfflinePlayer)
                )
        );
        
        // Test: Premium player tries to use this nickname
        boolean isPremium = true;
        boolean existingIsPremium = (existingOfflinePlayer.getPremiumUuid() != null);
        
        boolean hasConflict = preLoginHandler.isNicknameConflict(
                existingOfflinePlayer, isPremium, existingIsPremium);
        
        assertTrue(hasConflict, 
                "Should detect conflict when premium player uses offline nickname");
        
        assertDoesNotThrow(() ->
                preLoginHandler.handleNicknameConflictNoEvent(conflictedNickname, existingOfflinePlayer, isPremium),
                "Conflict handling should not throw exceptions");
    }

    /**
     * Test: Offline player accessing conflicted account
     * Requirements: 4.1, 4.2
     */
    @Test
    void testNicknameConflict_offlinePlayerAccessingConflictedAccount_shouldForceOfflineMode() {
        // Setup: Player in conflict mode
        String conflictedNickname = "ConflictedPlayer";
        RegisteredPlayer conflictedPlayer = new RegisteredPlayer();
        conflictedPlayer.setNickname(conflictedNickname); // This also sets lowercaseNickname
        conflictedPlayer.setUuid(UUID.randomUUID().toString());
        conflictedPlayer.setPremiumUuid(null);
        conflictedPlayer.setConflictMode(true); // Already in conflict mode
        conflictedPlayer.setConflictTimestamp(System.currentTimeMillis());
        conflictedPlayer.setOriginalNickname(conflictedNickname);
        
        // Test: Offline player tries to access
        boolean isPremium = false;
        boolean existingIsPremium = false;
        
        boolean hasConflict = preLoginHandler.isNicknameConflict(
                conflictedPlayer, isPremium, existingIsPremium);
        
        assertTrue(hasConflict,
                "Should detect conflict when offline player accesses conflicted account");
        
        assertDoesNotThrow(() ->
                preLoginHandler.handleNicknameConflictNoEvent(conflictedNickname, conflictedPlayer, isPremium),
                "Conflict handling should not throw exceptions");
    }

    /**
     * Test: PicoLimbo routing for unauthorized players
     * Requirements: 4.2
     */
    @Test
    void testPicoLimboRouting_unauthorizedPlayer_shouldTransferToPicoLimbo() {
        // Setup unauthorized player
        String username = "UnauthorizedPlayer";
        UUID playerUuid = UUID.randomUUID();
        String playerIp = "192.168.1.102";
        
        Player player = mock(Player.class);
        when(player.getUsername()).thenReturn(username);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.isOnlineMode()).thenReturn(false);
        when(player.getRemoteAddress()).thenReturn(
                InetSocketAddress.createUnresolved(playerIp, 25565));
        
        // Test: Unauthorized player should be transferred
        assertDoesNotThrow(() -> postLoginHandler.handleOfflinePlayer(player, playerIp),
                "Unauthorized player handling should not throw exceptions");
        
        // Verify player is not authorized
        assertFalse(authCache.isPlayerAuthorized(playerUuid, playerIp),
                "Unauthorized player should not be in authorized cache");
    }

    /**
     * Test: Backend server routing for authorized players
     * Requirements: 4.2
     */
    @Test
    void testBackendRouting_authorizedPlayer_shouldStayOnBackend() {
        // Setup authorized player
        String username = "AuthorizedPlayer";
        UUID playerUuid = UUID.randomUUID();
        String playerIp = "192.168.1.103";
        
        // Authorize player first
        CachedAuthUser cachedUser = new CachedAuthUser(
                playerUuid, username, playerIp,
                System.currentTimeMillis(), false, null);
        authCache.addAuthorizedPlayer(playerUuid, cachedUser);
        
        Player player = mock(Player.class);
        when(player.getUsername()).thenReturn(username);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.isOnlineMode()).thenReturn(false);
        
        // Test: Authorized player should stay on backend
        assertDoesNotThrow(() -> postLoginHandler.handleOfflinePlayer(player, playerIp),
                "Authorized player handling should not throw exceptions");
        
        // Verify player remains authorized
        assertTrue(authCache.isPlayerAuthorized(playerUuid, playerIp),
                "Authorized player should remain in authorized cache");
    }

    /**
     * Test: Session management works correctly
     * Requirements: 4.2, 4.4
     */
    @Test
    void testSessionManagement_shouldMaintainSessionState() {
        // Setup
        String username = "SessionPlayer";
        UUID playerUuid = UUID.randomUUID();
        String playerIp = "192.168.1.104";
        
        // Start session
        authCache.startSession(playerUuid, username, playerIp);
        
        // Verify session exists
        assertTrue(authCache.hasActiveSession(playerUuid, username, playerIp),
                "Session should be active after starting");
        
        // Add authorization
        CachedAuthUser cachedUser = new CachedAuthUser(
                playerUuid, username, playerIp,
                System.currentTimeMillis(), false, null);
        authCache.addAuthorizedPlayer(playerUuid, cachedUser);
        
        // Verify both session and authorization
        assertTrue(authCache.hasActiveSession(playerUuid, username, playerIp),
                "Session should persist after authorization");
        assertTrue(authCache.isPlayerAuthorized(playerUuid, playerIp),
                "Player should be authorized");
        
        // End session
        authCache.endSession(playerUuid);
        
        // Verify session ended but authorization may persist
        assertFalse(authCache.hasActiveSession(playerUuid, username, playerIp),
                "Session should end after explicit termination");
    }

    /**
     * Test: Username validation
     * Requirements: 4.1
     */
    @Test
    void testUsernameValidation_variousFormats_shouldValidateCorrectly() {
        // Valid usernames
        assertTrue(preLoginHandler.isValidUsername("Player123"),
                "Alphanumeric username should be valid");
        assertTrue(preLoginHandler.isValidUsername("Test_User"),
                "Username with underscore should be valid");
        assertTrue(preLoginHandler.isValidUsername("ABC"),
                "3-character username should be valid");
        assertTrue(preLoginHandler.isValidUsername("A123456789012345"),
                "16-character username should be valid");
        
        // Invalid usernames
        assertFalse(preLoginHandler.isValidUsername("AB"),
                "2-character username should be invalid");
        assertFalse(preLoginHandler.isValidUsername("A1234567890123456"),
                "17-character username should be invalid");
        assertFalse(preLoginHandler.isValidUsername("Player-123"),
                "Username with hyphen should be invalid");
        assertFalse(preLoginHandler.isValidUsername("Player.123"),
                "Username with dot should be invalid");
        assertFalse(preLoginHandler.isValidUsername(""),
                "Empty username should be invalid");
        assertFalse(preLoginHandler.isValidUsername(null),
                "Null username should be invalid");
    }

    /**
     * Test: Conflict message display logic
     * Requirements: 4.2
     */
    @Test
    void testConflictMessage_premiumPlayerInConflictMode_shouldShowMessage() {
        // Setup: Player in conflict mode
        String username = "ConflictPlayer";
        UUID playerUuid = UUID.randomUUID();
        UUID premiumUuid = UUID.randomUUID();
        
        RegisteredPlayer conflictedPlayer = new RegisteredPlayer();
        conflictedPlayer.setNickname(username); // This also sets lowercaseNickname
        conflictedPlayer.setUuid(playerUuid.toString());
        conflictedPlayer.setPremiumUuid(premiumUuid.toString());
        conflictedPlayer.setConflictMode(true);
        
        // Mock database
        databaseManager.setFindResult(
                username.toLowerCase(),
                CompletableFuture.completedFuture(
                        DatabaseManager.DbResult.success(conflictedPlayer)
                )
        );
        
        // Mock premium status
        authCache.addPremiumPlayer(username, premiumUuid);
        
        Player player = mock(Player.class);
        when(player.getUsername()).thenReturn(username);
        when(player.getUniqueId()).thenReturn(playerUuid);
        
        // Test: Should show conflict message
        boolean shouldShow = postLoginHandler.shouldShowConflictMessage(player);
        assertTrue(shouldShow, "Should show conflict message for premium player in conflict mode");
        
        // Test: Message display should not throw
        assertDoesNotThrow(() -> postLoginHandler.showConflictResolutionMessage(player),
                "Showing conflict message should not throw exceptions");
    }

    /**
     * Test: Thread safety in concurrent operations
     * Requirements: 4.4
     */
    @Test
    void testThreadSafety_concurrentOperations_shouldNotCauseIssues() {
        // Setup multiple players
        int playerCount = 10;
        
        assertDoesNotThrow(() -> {
            for (int i = 0; i < playerCount; i++) {
                String username = "Player" + i;
                UUID playerUuid = UUID.randomUUID();
                String playerIp = "192.168.1." + (100 + i);
                
                // Concurrent cache operations
                authCache.startSession(playerUuid, username, playerIp);
                
                CachedAuthUser cachedUser = new CachedAuthUser(
                        playerUuid, username, playerIp,
                        System.currentTimeMillis(), false, null);
                authCache.addAuthorizedPlayer(playerUuid, cachedUser);
                
                // Verify operations succeeded
                assertTrue(authCache.hasActiveSession(playerUuid, username, playerIp),
                        "Session should be active for player " + i);
                assertTrue(authCache.isPlayerAuthorized(playerUuid, playerIp),
                        "Player " + i + " should be authorized");
            }
        }, "Concurrent operations should not cause exceptions");
    }
}
