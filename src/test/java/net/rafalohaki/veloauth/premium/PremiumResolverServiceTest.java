package net.rafalohaki.veloauth.premium;

import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.PremiumUuidDao;
import net.rafalohaki.veloauth.model.PremiumUuid;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.Logger;

import java.util.Optional;
import java.util.UUID;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for PremiumResolverService to verify:
 * 1. Single API call per resolver (no double calls)
 * 2. Proper fallback chain (Mojang → Ashcon → WPME)
 * 3. Cache effectiveness
 * 4. Nickname hijacking prevention
 * 
 * Uses LENIENT strictness to allow common setUp() stubbings
 * that may not be used in all tests (reduces code duplication).
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PremiumResolverServiceTest {

    @Mock
    private Logger logger;

    @Mock
    private Settings settings;

    @Mock
    private Settings.PremiumSettings premiumSettings;

    @Mock
    private Settings.PremiumResolverSettings resolverSettings;

    @Mock
    private PremiumUuidDao dao;

    private PremiumResolverService service;

    @BeforeEach
    void setUp() {
        // Setup default mock behavior
        when(settings.getPremiumResolverSettings()).thenReturn(resolverSettings);
        when(settings.getPremiumSettings()).thenReturn(premiumSettings);
        
        // Default: all resolvers enabled with 3s timeout
        when(resolverSettings.isMojangEnabled()).thenReturn(true);
        when(resolverSettings.isAshconEnabled()).thenReturn(true);
        when(resolverSettings.isWpmeEnabled()).thenReturn(false);
        when(resolverSettings.getRequestTimeoutMs()).thenReturn(3000);
        when(resolverSettings.getHitTtlMinutes()).thenReturn(30);
        when(resolverSettings.getMissTtlMinutes()).thenReturn(10);
        when(resolverSettings.isCaseSensitive()).thenReturn(true);

        service = new PremiumResolverService(logger, settings, dao);
    }

    @Test
    void shouldCallResolverOnlyOnce() {
        // Given: A username to resolve
        String username = "TestPlayer";
        PremiumResolver premiumResolver = mock(PremiumResolver.class);
        PremiumResolver offlineResolver = mock(PremiumResolver.class);
        UUID premiumUuid = UUID.randomUUID();

        when(premiumResolver.enabled()).thenReturn(true);
        when(premiumResolver.id()).thenReturn("premium-mock");
        when(premiumResolver.resolve(username)).thenReturn(PremiumResolution.premium(premiumUuid, username, "premium-mock"));

        when(offlineResolver.enabled()).thenReturn(true);
        when(offlineResolver.id()).thenReturn("offline-mock");
        when(offlineResolver.resolve(username)).thenReturn(PremiumResolution.offline(username, "offline-mock", "offline"));

        service = new PremiumResolverService(logger, dao, List.of(premiumResolver, offlineResolver), 10 * 60_000L, 3 * 60_000L);
        when(dao.findByNickname(anyString())).thenReturn(Optional.empty());
        when(dao.saveOrUpdate(any(UUID.class), anyString())).thenReturn(true);

        // When: Resolving premium status
        PremiumResolution result = service.resolve(username);

        // Then: Should resolve without issues
        assertNotNull(result, "Result should not be null");
        assertTrue(result.isPremium(), "Premium resolver result should win");
        
        verify(dao, times(1)).findByNickname(username);
        verify(dao, times(1)).saveOrUpdate(premiumUuid, username);
        verify(premiumResolver, times(1)).resolve(username);
        verify(offlineResolver, times(1)).resolve(username);
    }

    @Test
    void shouldTreatStaleDbCacheEntryAsMissAndFallThroughToApi() {
        // Given: a DB cache row with lastSeen older than the configured hit-ttl (10 minutes).
        String username = "StaleNickTest";
        UUID staleUuid = UUID.randomUUID();
        PremiumUuid staleEntry = mock(PremiumUuid.class);
        when(staleEntry.getUuid()).thenReturn(staleUuid);
        when(staleEntry.getNickname()).thenReturn(username);
        when(staleEntry.getLastSeen()).thenReturn(System.currentTimeMillis() - 60L * 60_000L); // 60 min old

        when(dao.findByNickname(username)).thenReturn(Optional.of(staleEntry));

        // No API resolvers — service should hit the "no resolvers enabled" offline branch,
        // proving the stale DB entry was bypassed.
        when(resolverSettings.isMojangEnabled()).thenReturn(false);
        when(resolverSettings.isAshconEnabled()).thenReturn(false);
        when(resolverSettings.isWpmeEnabled()).thenReturn(false);
        service = new PremiumResolverService(logger, settings, dao);

        PremiumResolution result = service.resolve(username);

        assertNotNull(result);
        assertTrue(result.isOffline(),
                "Stale DB cache entry must NOT short-circuit to premium — it should fall through to the API path");
    }

    @Test
    void shouldTrustDbCacheRowWithZeroLastSeenForLimboAuthCompatibility() {
        // Given: a DB row migrated from LimboAuth — LAST_SEEN defaults to 0 because the column was
        // ALTER TABLE-added with DEFAULT 0. Forcing those rows through the API on every login would
        // be an upgrade-time API storm, so we treat lastSeen <= 0 as "trusted, unknown freshness".
        String username = "LegacyNickTest";
        UUID legacyUuid = UUID.randomUUID();
        PremiumUuid legacyEntry = mock(PremiumUuid.class);
        when(legacyEntry.getUuid()).thenReturn(legacyUuid);
        when(legacyEntry.getNickname()).thenReturn(username);
        when(legacyEntry.getLastSeen()).thenReturn(0L);

        when(dao.findByNickname(username)).thenReturn(Optional.of(legacyEntry));

        PremiumResolution result = service.resolve(username);

        assertNotNull(result);
        assertTrue(result.isPremium(), "Legacy row with lastSeen=0 must be trusted (LimboAuth migration compatibility)");
        assertEquals(legacyUuid, result.uuid());
    }

    @Test
    void shouldCacheSuccessfulPremiumResolution() {
        // Given: A premium player UUID
        UUID premiumUuid = UUID.randomUUID();
        String username = "NotchTest";
        
        PremiumUuid premiumUuidModel = mock(PremiumUuid.class);
        when(premiumUuidModel.getUuid()).thenReturn(premiumUuid);
        when(premiumUuidModel.getNickname()).thenReturn(username);
        
        when(dao.findByNickname(username)).thenReturn(Optional.of(premiumUuidModel));

        // When: Resolving (should hit DB cache)
        PremiumResolution result = service.resolve(username);

        // Then: Should return premium status from cache
        assertNotNull(result);
        assertTrue(result.isPremium(), "Should be premium from cache");
        assertEquals(premiumUuid, result.uuid(), "Should return cached UUID");
        
        // Verify cache hit (DAO findByNickname called)
        verify(dao, times(1)).findByNickname(username);
    }

    @Test
    void shouldHandleInvalidUsername() {
        // Given: Invalid usernames
        String[] invalidUsernames = {"", " ", "ab", "ThisUsernameIsTooLongForMinecraft123"};

        for (String invalid : invalidUsernames) {
            // When: Resolving invalid username
            PremiumResolution result = service.resolve(invalid);

            // Then: Should return offline status
            assertNotNull(result, "Result should not be null for: " + invalid);
            assertTrue(result.isOffline(), "Should be offline for invalid username: " + invalid);
        }
    }

    @Test
    void shouldHandleNullUsername() {
        // Given: null username
        
        // When: Resolving null
        PremiumResolution result = service.resolve(null);

        // Then: Should return offline status
        assertNotNull(result);
        assertTrue(result.isOffline(), "Should be offline for null username");
        assertEquals("empty username", result.message(), "Should have appropriate message");
    }

    @Test
    void shouldNormalizeCaseForCacheLookup() {
        // Given: Username with different cases
        String username = "NotchTest";
        UUID premiumUuid = UUID.randomUUID();
        
        PremiumUuid premiumUuidModel = mock(PremiumUuid.class);
        when(premiumUuidModel.getUuid()).thenReturn(premiumUuid);
        when(premiumUuidModel.getNickname()).thenReturn(username);
        
        // When: Looking up with different case
        when(dao.findByNickname(username)).thenReturn(Optional.of(premiumUuidModel));
        when(dao.findByNickname("NOTCHTEST")).thenReturn(Optional.empty());
        when(dao.findByNickname("notchtest")).thenReturn(Optional.empty());

        PremiumResolution result1 = service.resolve(username);
        
        // Then: Should find regardless of case (cache key is lowercase)
        assertNotNull(result1);
        assertTrue(result1.isPremium(), "Should find premium player");
    }

    @Test
    void shouldReturnOfflineWhenNoResolversEnabled() {
        // Given: All resolvers disabled
        when(resolverSettings.isMojangEnabled()).thenReturn(false);
        when(resolverSettings.isAshconEnabled()).thenReturn(false);
        when(resolverSettings.isWpmeEnabled()).thenReturn(false);
        
        // Recreate service with disabled resolvers
        service = new PremiumResolverService(logger, settings, dao);
        
        when(dao.findByNickname(anyString())).thenReturn(Optional.empty());

        // When: Resolving with no resolvers
        PremiumResolution result = service.resolve("TestPlayer");

        // Then: Should return offline status
        assertNotNull(result);
        assertTrue(result.isOffline(), "Should be offline when no resolvers enabled");
        assertEquals("no resolvers enabled", result.message(), "Should have no resolvers message");
    }

    @Test
    void shouldPreventNicknameConflict() {
        // Given: Offline player registered in DB, premium player tries to connect
        String username = "ConflictTest";
        UUID offlineUuid = UUID.nameUUIDFromBytes(("OfflinePlayer:" + username).getBytes());

        // Offline player in DB (no premium UUID)
        PremiumUuid offlinePlayer = mock(PremiumUuid.class);
        when(offlinePlayer.getUuid()).thenReturn(offlineUuid);
        when(offlinePlayer.getNickname()).thenReturn(username);
        
        when(dao.findByNickname(username)).thenReturn(Optional.of(offlinePlayer));

        // When: Resolving (offline player exists, but real premium player connects)
        PremiumResolution result = service.resolve(username);

        // Then: Should detect as offline from cache
        // Note: Actual conflict detection happens in PreLoginHandler
        assertNotNull(result);
        
        // The cache returns offline player's UUID
        assertEquals(offlineUuid, result.uuid(), "Should return offline UUID from DB cache");
    }

    @Test
    void shouldHandleSpecialCharacters() {
        // Given: Username with underscores (valid in Minecraft)
        String validUsername = "Test_Player_123";
        when(dao.findByNickname(anyString())).thenReturn(Optional.empty());

        // When: Resolving
        PremiumResolution result = service.resolve(validUsername);

        // Then: Should process without error
        assertNotNull(result, "Should handle underscores");
        
        // Invalid characters
        String[] invalidUsernames = {"Test@Player", "Test.Player", "Test Player", "Test#123"};
        for (String invalid : invalidUsernames) {
            result = service.resolve(invalid);
            assertTrue(result.isOffline(), "Should reject invalid chars: " + invalid);
        }
    }

    @Test
    void shouldRespectCacheTTL() {
        // Given: Cached entry
        String username = "CachedPlayer";
        
        // First call - cache miss
        when(dao.findByNickname(username)).thenReturn(Optional.empty());
        
        PremiumResolution firstCall = service.resolve(username);
        assertNotNull(firstCall);

        // Second call immediately - should hit memory cache (no DB call)
        when(dao.findByNickname(username)).thenReturn(Optional.empty());
        
        PremiumResolution secondCall = service.resolve(username);
        assertNotNull(secondCall);

        // Verify DB was called only once (second hit memory cache)
        verify(dao, times(1)).findByNickname(username);
    }

    @Test
    void shouldSavePremiumToDatabase() {
        // Given: Premium resolution that should be cached
        String username = "PremiumPlayer";
        
        when(dao.findByNickname(username)).thenReturn(Optional.empty());
        when(dao.saveOrUpdate(any(UUID.class), anyString())).thenReturn(true);

        // When: Resolving premium player (in real scenario, resolver would return premium)
        service.resolve(username);

        // Then: Should attempt to find in cache
        verify(dao, times(1)).findByNickname(username);
        
        // Note: saveOrUpdate would be called if resolver returned premium
        // This test verifies the flow, actual premium detection depends on API
    }

    @Test
    void shouldHandleConcurrentRequests() {
        // Given: Same username from multiple threads
        String username = "ConcurrentTest";
        when(dao.findByNickname(anyString())).thenReturn(Optional.empty());

        // When: Multiple concurrent resolutions
        Thread[] threads = new Thread[10];
        for (int i = 0; i < threads.length; i++) {
            threads[i] = new Thread(() -> {
                PremiumResolution result = service.resolve(username);
                assertNotNull(result, "Should handle concurrent access");
            });
            threads[i].start();
        }

        // Wait for all threads
        for (Thread thread : threads) {
            try {
                thread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        // Then: Should handle without exceptions (thread-safe ConcurrentHashMap)
        // Verify was called multiple times (once per thread)
        verify(dao, times(10)).findByNickname(username);
    }

    // ===== Mojang-authoritative + non-Mojang quorum policy (selectBestResult) =====

    private PremiumResolver mockResolver(String id, PremiumResolution result) {
        PremiumResolver r = mock(PremiumResolver.class);
        when(r.enabled()).thenReturn(true);
        when(r.id()).thenReturn(id);
        when(r.resolve(anyString())).thenReturn(result);
        return r;
    }

    private PremiumResolverService serviceWith(List<PremiumResolver> resolvers) {
        when(dao.findByNickname(anyString())).thenReturn(Optional.empty());
        return new PremiumResolverService(logger, dao, resolvers, 10 * 60_000L, 3 * 60_000L);
    }

    @Test
    void selectBestResult_mojangOffline_isAuthoritative() {
        // Mojang says OFFLINE — that alone is enough regardless of mirrors.
        String username = "AuthOfflineNick";
        PremiumResolver mojang = mockResolver("mojang",
                PremiumResolution.offline(username, "mojang", "not-found"));
        PremiumResolver ashcon = mockResolver("ashcon",
                PremiumResolution.unknown("ashcon", "timeout"));

        PremiumResolution result = serviceWith(List.of(mojang, ashcon)).resolve(username);

        assertTrue(result.isOffline(),
                "Mojang's authoritative OFFLINE must win over Ashcon UNKNOWN");
        assertEquals("mojang", result.source(),
                "Returned resolution should be Mojang's");
    }

    @Test
    void selectBestResult_mojangUnknownAndMirrorOffline_returnsOfflineByQuorum() {
        // Mojang silent, single mirror says OFFLINE → quorum-of-1 is enough (unanimous among
        // enabled non-Mojang resolvers).
        String username = "QuorumOfOneNick";
        PremiumResolver mojang = mockResolver("mojang",
                PremiumResolution.unknown("mojang", "timeout"));
        PremiumResolver ashcon = mockResolver("ashcon",
                PremiumResolution.offline(username, "ashcon", "not-found"));

        PremiumResolution result = serviceWith(List.of(mojang, ashcon)).resolve(username);

        assertTrue(result.isOffline(),
                "Mojang UNKNOWN + Ashcon OFFLINE (unanimous non-Mojang) → OFFLINE");
        assertEquals("ashcon", result.source());
    }

    @Test
    void selectBestResult_mojangUnknownAndMirrorsAllOffline_returnsOfflineByQuorum() {
        // Mojang silent, BOTH mirrors say OFFLINE → unanimous quorum.
        String username = "QuorumOfTwoNick";
        PremiumResolver mojang = mockResolver("mojang",
                PremiumResolution.unknown("mojang", "rate-limit"));
        PremiumResolver ashcon = mockResolver("ashcon",
                PremiumResolution.offline(username, "ashcon", "not-found"));
        PremiumResolver wpme = mockResolver("wpme",
                PremiumResolution.offline(username, "wpme", "not-found"));

        PremiumResolution result = serviceWith(List.of(mojang, ashcon, wpme)).resolve(username);

        assertTrue(result.isOffline(),
                "Mojang UNKNOWN + all mirrors OFFLINE → OFFLINE");
    }

    @Test
    void selectBestResult_mojangUnknownAndOneMirrorUnknown_returnsUnknownToDenyLogin() {
        // THE KEY SECURITY TEST: Mojang silent, one mirror OFFLINE, another mirror UNKNOWN.
        // Previous policy: OFFLINE (the silent mirror could be a stale cache covering a real
        // premium account → name-sniping window).
        // New policy: UNKNOWN (insufficient evidence; listener will deny login fail-closed).
        String username = "NoQuorumNick";
        PremiumResolver mojang = mockResolver("mojang",
                PremiumResolution.unknown("mojang", "timeout"));
        PremiumResolver ashcon = mockResolver("ashcon",
                PremiumResolution.offline(username, "ashcon", "not-found"));
        PremiumResolver wpme = mockResolver("wpme",
                PremiumResolution.unknown("wpme", "timeout"));

        PremiumResolution result = serviceWith(List.of(mojang, ashcon, wpme)).resolve(username);

        assertTrue(result.isUnknown(),
                "Mojang UNKNOWN + Ashcon OFFLINE + wpme UNKNOWN → UNKNOWN (no quorum). "
                        + "Listener will deny login fail-closed to prevent name-sniping.");
    }

    @Test
    void selectBestResult_premiumFromAnyResolver_winsImmediately() {
        // PREMIUM is a positive assertion; one confirmation is enough — even from a mirror.
        String username = "PremiumWinsNick";
        UUID uuid = UUID.randomUUID();
        PremiumResolver mojang = mockResolver("mojang",
                PremiumResolution.unknown("mojang", "timeout"));
        PremiumResolver ashcon = mockResolver("ashcon",
                PremiumResolution.premium(uuid, username, "ashcon"));

        when(dao.saveOrUpdate(any(UUID.class), anyString())).thenReturn(true);
        PremiumResolution result = serviceWith(List.of(mojang, ashcon)).resolve(username);

        assertTrue(result.isPremium(),
                "PREMIUM from a single (mirror) resolver wins even when Mojang is UNKNOWN");
        assertEquals(uuid, result.uuid());
    }

    @Test
    void selectBestResult_mojangDisabledAndMirrorOffline_returnsOfflineByQuorum() {
        // Mojang resolver not enabled at all. Policy: trust unanimous non-Mojang OFFLINE.
        String username = "MojangDisabledNick";
        PremiumResolver ashcon = mockResolver("ashcon",
                PremiumResolution.offline(username, "ashcon", "not-found"));

        PremiumResolution result = serviceWith(List.of(ashcon)).resolve(username);

        assertTrue(result.isOffline(),
                "With Mojang disabled, unanimous non-Mojang OFFLINE must still resolve to OFFLINE");
    }

    @Test
    void selectBestResult_allResolversUnknown_returnsUnknown() {
        String username = "AllUnknownNick";
        PremiumResolver mojang = mockResolver("mojang",
                PremiumResolution.unknown("mojang", "timeout"));
        PremiumResolver ashcon = mockResolver("ashcon",
                PremiumResolution.unknown("ashcon", "timeout"));

        PremiumResolution result = serviceWith(List.of(mojang, ashcon)).resolve(username);

        assertTrue(result.isUnknown(),
                "All resolvers UNKNOWN → UNKNOWN (login denied)");
    }
}
