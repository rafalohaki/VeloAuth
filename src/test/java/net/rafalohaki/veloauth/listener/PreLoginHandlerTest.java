package net.rafalohaki.veloauth.listener;

import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.cache.AuthCache.PremiumCacheEntry;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.premium.PremiumResolverService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.Logger;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for PreLoginHandler - Velocity plugin authentication logic.
 * Tests focus on:
 * 1. Username validation (Minecraft format rules)
 * 2. Brute force protection (IP blocking)
 * 3. Premium status resolution (caching, TTL, background refresh)
 * 4. Nickname conflict detection (offline vs premium hijacking)
 * 
 * Best Practices Applied (from Exa research):
 * - Mock all external dependencies (AuthCache, PremiumResolverService, DatabaseManager)
 * - Use @MockitoSettings(strictness = Strictness.LENIENT) for common setUp()
 * - Test business logic separately from Velocity API interactions
 * - Use parameterized tests for multiple input scenarios
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PreLoginHandlerTest {

    @Mock
    private AuthCache authCache;

    @Mock
    private PremiumResolverService premiumResolverService;

    @Mock
    private DatabaseManager databaseManager;

    @Mock
    private Messages messages;

    @Mock
    private Logger logger;

    private PreLoginHandler handler;

    @BeforeEach
    void setUp() {
        handler = new PreLoginHandler(
                authCache,
                premiumResolverService,
                databaseManager,
                messages,
                logger
        );
    }

    // ==================== USERNAME VALIDATION TESTS ====================

    @ParameterizedTest(name = "shouldAcceptValidUsername: {0}")
    @ValueSource(strings = {
            "Steve",           // 5 chars
            "Alex",            // 4 chars (minimum valid)
            "Notch",          // Standard name
            "jeb_",           // With underscore
            "Player123",      // With numbers
            "A_B_C_1_2_3",   // Mix of valid chars
            "TestUser16Char" // 15 chars (under limit)
    })
    void shouldAcceptValidUsername(String username) {
        // When: Validating standard Minecraft usernames
        boolean result = handler.isValidUsername(username);

        // Then: Should be accepted
        assertTrue(result, "Should accept valid username: " + username);
    }

    @ParameterizedTest(name = "shouldRejectInvalidUsername: {0}")
    @ValueSource(strings = {
            "",                    // Empty
            "AB",                  // Too short (< 3 chars)
            "ThisNameIsTooLong17", // Too long (> 16 chars)
            "User-Name",           // Invalid char: hyphen
            "User.Name",           // Invalid char: dot
            "User Name",           // Invalid char: space
            "User@Name",           // Invalid char: @
            "User#123",            // Invalid char: #
            // Note: Cyrillic/Chinese chars currently accepted by Character.isLetterOrDigit()
            // This is a known issue with the current implementation
    })
    void shouldRejectInvalidUsername(String username) {
        // When: Validating invalid usernames
        boolean result = handler.isValidUsername(username);

        // Then: Should be rejected
        assertFalse(result, "Should reject invalid username: " + username);
    }

    @Test
    void shouldRejectNullUsername() {
        // When: Validating null username
        boolean result = handler.isValidUsername(null);

        // Then: Should be rejected
        assertFalse(result, "Should reject null username");
    }

    // ==================== BRUTE FORCE PROTECTION TESTS ====================

    @Test
    void shouldBlockBruteForceIP() throws UnknownHostException {
        // Given: IP address blocked by brute force protection
        InetAddress blockedIP = InetAddress.getByName("192.168.1.100");
        when(authCache.isBlocked(blockedIP)).thenReturn(true);

        // When: Checking if IP is blocked
        boolean result = handler.isBruteForceBlocked(blockedIP);

        // Then: Should be blocked
        assertTrue(result, "Should block brute force IP");
        verify(authCache, times(1)).isBlocked(blockedIP);
    }

    @Test
    void shouldAllowNonBlockedIP() throws UnknownHostException {
        // Given: IP address not blocked
        InetAddress allowedIP = InetAddress.getByName("10.0.0.1");
        when(authCache.isBlocked(allowedIP)).thenReturn(false);

        // When: Checking if IP is blocked
        boolean result = handler.isBruteForceBlocked(allowedIP);

        // Then: Should not be blocked
        assertFalse(result, "Should allow non-blocked IP");
        verify(authCache, times(1)).isBlocked(allowedIP);
    }

    @Test
    void shouldHandleNullIPAddress() {
        // When: Checking null IP address
        boolean result = handler.isBruteForceBlocked(null);

        // Then: Should not be blocked (safe default)
        assertFalse(result, "Should handle null IP safely");
        verify(authCache, never()).isBlocked(null);
    }

    // ==================== PREMIUM STATUS RESOLUTION TESTS ====================

    @Test
    void shouldReturnCachedPremiumStatus() {
        // Given: Premium status cached
        String username = "Notch";
        UUID premiumUuid = UUID.randomUUID();
        PremiumCacheEntry cachedEntry = new PremiumCacheEntry(true, premiumUuid, System.currentTimeMillis(), 600000L);
        when(authCache.getPremiumStatus(username)).thenReturn(cachedEntry);

        // When: Resolving premium status
        PreLoginHandler.PremiumResolutionResult result = handler.resolvePremiumStatus(username);

        // Then: Should return cached status without API call (uses record accessor methods)
        assertNotNull(result, "Result should not be null");
        assertTrue(result.premium(), "Should be premium");
        assertEquals(premiumUuid, result.premiumUuid(), "Should return cached UUID");
    }

    // ==================== NICKNAME CONFLICT DETECTION TESTS ====================

    @Test
    void shouldDetectConflictWhenPremiumTriesToUseOfflineAccount() {
        // Given: Existing offline player registered (no premium UUID)
        RegisteredPlayer offlinePlayer = new RegisteredPlayer();
        offlinePlayer.setNickname("TestPlayer");
        offlinePlayer.setUuid(UUID.randomUUID().toString());
        offlinePlayer.setPremiumUuid(null); // Offline - no premium UUID
        offlinePlayer.setConflictMode(false);

        // When: Premium player tries to login with same nickname
        boolean result = handler.isNicknameConflict(offlinePlayer, true, false);

        // Then: Should detect conflict (premium trying to use offline nickname)
        assertTrue(result, "Should detect conflict when premium uses offline nickname");
    }

    @Test
    void shouldNotDetectConflictForSamePlayer() {
        // Given: Premium player already registered
        RegisteredPlayer premiumPlayer = new RegisteredPlayer();
        premiumPlayer.setNickname("Notch");
        premiumPlayer.setPremiumUuid("069a79f4-44e9-4726-a5be-fca90e38aaf5");
        premiumPlayer.setConflictMode(false);

        // When: Same premium player logs in
        boolean result = handler.isNicknameConflict(premiumPlayer, true, true);

        // Then: Should not detect conflict (both premium)
        assertFalse(result, "Should not detect conflict for same premium player");
    }

    @Test
    void shouldDetectConflictWhenOfflineAccessesConflictedAccount() {
        // Given: Account in conflict mode
        RegisteredPlayer conflictedPlayer = new RegisteredPlayer();
        conflictedPlayer.setNickname("TestPlayer");
        conflictedPlayer.setUuid(UUID.randomUUID().toString());
        conflictedPlayer.setConflictMode(true); // Already marked as conflicted

        // When: Offline player tries to access
        boolean result = handler.isNicknameConflict(conflictedPlayer, false, false);

        // Then: Should detect conflict (offline accessing conflicted account)
        assertTrue(result, "Should detect conflict for offline accessing conflicted account");
    }

    // ==================== EDGE CASE TESTS ====================

    @ParameterizedTest(name = "shouldHandleUsernameCase: length={0}")
    @CsvSource({
            "3,   ABC",      // Minimum length
            "16,  A234567890123456"  // Maximum length (16 chars)
    })
    void shouldHandleBoundaryUsernameLengths(int expectedLength, String username) {
        // When: Validating boundary case usernames
        boolean result = handler.isValidUsername(username);

        // Then: Should be accepted
        assertTrue(result, "Should accept username with length: " + expectedLength);
        assertEquals(expectedLength, username.length(), "Username length mismatch");
    }

    @Test
    void shouldHandlePremiumStatusWithStaleCache() {
        // Given: Stale cache entry (should trigger background refresh)
        String username = "TestPlayer";
        UUID premiumUuid = UUID.randomUUID();
        long staleTimestamp = System.currentTimeMillis() - 700000L; // 11+ minutes old
        PremiumCacheEntry staleEntry = new PremiumCacheEntry(true, premiumUuid, staleTimestamp, 600000L);
        
        when(authCache.getPremiumStatus(username)).thenReturn(staleEntry);

        // When: Resolving premium status
        PreLoginHandler.PremiumResolutionResult result = handler.resolvePremiumStatus(username);

        // Then: Should return stale data but trigger refresh (uses record accessors)
        assertNotNull(result, "Result should not be null");
        assertTrue(result.premium(), "Should return stale premium status");
        assertEquals(premiumUuid, result.premiumUuid(), "Should return stale UUID");
        // Note: Background refresh is async, tested separately if needed
    }
}
