package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.auth.ConflictModeService;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UuidVerificationHandler} — security-critical UUID verification
 * for cracked (offline-mode) players against the AUTH table.
 *
 * <p>Security invariants under test:
 * <ul>
 *   <li>Premium (online-mode) players skip verification entirely — no DB round-trip</li>
 *   <li>Database error is fail-secure: verification fails AND the session is invalidated
 *       (distinct from "player not found", which fails without an error path)</li>
 *   <li>UUID mismatch denies access, invalidates cache/session and emits an audit event</li>
 *   <li>CONFLICT_MODE allows access despite a UUID mismatch (conflict resolution window)</li>
 *   <li>Any unexpected exception resolves to {@code false} (fail-secure), never propagates</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UuidVerificationHandlerTest {

    private static final String USERNAME = "CrackedSteve";
    private static final String PLAYER_IP = "192.0.2.77";

    @Mock
    private DatabaseManager databaseManager;

    @Mock
    private AuthCache authCache;

    @Mock
    private Logger logger;

    @Mock
    private AuditLogService auditLogService;

    @Mock
    private Player player;

    private UuidVerificationHandler handler;

    private UUID playerUuid;

    /** Conflict TTL in hours used by the handler under test. Non-zero so the TTL-expiry
     *  path is exercised; matches the production default of 168h (7 days). */
    private static final int CONFLICT_TTL_HOURS = 168;

    @BeforeEach
    void setUp() {
        playerUuid = UUID.randomUUID();
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn(USERNAME);
        when(player.isOnlineMode()).thenReturn(false);
        when(player.getRemoteAddress()).thenReturn(new InetSocketAddress(PLAYER_IP, 25565));

        handler = new UuidVerificationHandler(databaseManager, authCache, logger, () -> auditLogService,
                new ConflictModeService(databaseManager, CONFLICT_TTL_HOURS));
    }

    // ==================== PREMIUM (ONLINE MODE) PATH ====================

    @Test
    void testVerifyPlayerUuid_OnlineModePremiumPlayer_SkipsDatabaseAndReturnsTrue() {
        // Arrange
        when(player.isOnlineMode()).thenReturn(true);

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertTrue(result, "Premium players are Mojang-verified - verification must pass");
        verify(databaseManager, never()).findPlayerByNickname(anyString());
        verify(authCache, never()).removeAuthorizedPlayer(any(UUID.class));
    }

    // ==================== DATABASE ERROR — FAIL-SECURE ====================

    @Test
    void testVerifyPlayerUuid_DatabaseError_FailSecureReturnsFalseAndInvalidatesSession() {
        // Arrange
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.databaseError("connection refused")));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertFalse(result, "DB error must never be treated as a successful verification");
        verify(authCache).removeAuthorizedPlayer(playerUuid);
        verify(authCache).endSession(playerUuid);
    }

    @Test
    void testVerifyPlayerUuid_PlayerNotRegistered_ReturnsFalseWithoutErrorHandling() {
        // Arrange — DbResult.success(null) means "not found", distinct from a DB error
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.success(null)));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertFalse(result, "Unregistered cracked player must not pass UUID verification");
        verify(authCache, never()).removeAuthorizedPlayer(any(UUID.class));
        verify(authCache, never()).endSession(any(UUID.class));
    }

    // ==================== UUID MATCH PATHS ====================

    @Test
    void testVerifyPlayerUuid_UuidMatchesStoredUuid_ReturnsTrue() {
        // Arrange
        RegisteredPlayer dbPlayer = registeredPlayer(playerUuid.toString(), null, false);
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertTrue(result, "Connection UUID matching the stored UUID must pass");
        verify(authCache, never()).removeAuthorizedPlayer(any(UUID.class));
    }

    @Test
    void testVerifyPlayerUuid_UuidMatchesStoredPremiumUuid_ReturnsTrue() {
        // Arrange — stored UUID differs, but PREMIUMUUID matches the connection UUID
        RegisteredPlayer dbPlayer =
                registeredPlayer(UUID.randomUUID().toString(), playerUuid.toString(), false);
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertTrue(result, "Connection UUID matching PREMIUMUUID must pass");
        verify(authCache, never()).removeAuthorizedPlayer(any(UUID.class));
    }

    // ==================== UUID MISMATCH — DENY + AUDIT ====================

    @Test
    void testVerifyPlayerUuid_UuidMismatch_ReturnsFalseInvalidatesCacheAndAudits() {
        // Arrange — neither stored UUID nor PREMIUMUUID match the connection UUID
        RegisteredPlayer dbPlayer =
                registeredPlayer(UUID.randomUUID().toString(), UUID.randomUUID().toString(), false);
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertFalse(result, "UUID mismatch on a cracked connection must be denied");
        verify(authCache).removeAuthorizedPlayer(playerUuid);
        verify(authCache).endSession(playerUuid);
        verify(auditLogService).save(
                eq(AuditEventType.UUID_MISMATCH), eq(USERNAME), eq(PLAYER_IP), anyString());
    }

    @Test
    void testVerifyPlayerUuid_UuidMismatchWithLegacyConstructor_NoAuditServiceStillDenies() {
        // Arrange — legacy ctor supplies a null audit service; mismatch must not NPE
        handler = new UuidVerificationHandler(databaseManager, authCache, logger);
        RegisteredPlayer dbPlayer =
                registeredPlayer(UUID.randomUUID().toString(), UUID.randomUUID().toString(), false);
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertFalse(result, "Missing audit service must not weaken the deny decision");
        verify(authCache).removeAuthorizedPlayer(playerUuid);
        verify(authCache).endSession(playerUuid);
    }

    @Test
    void testVerifyPlayerUuid_NullAuditSupplier_DefaultsToNoAuditAndStillDenies() {
        // Arrange — explicit null supplier must be normalized internally
        handler = new UuidVerificationHandler(databaseManager, authCache, logger, null);
        RegisteredPlayer dbPlayer =
                registeredPlayer(UUID.randomUUID().toString(), UUID.randomUUID().toString(), false);
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertFalse(result, "Null audit supplier must not break fail-secure mismatch handling");
        verify(authCache).removeAuthorizedPlayer(playerUuid);
    }

    // ==================== CONFLICT_MODE ====================

    @Test
    void testVerifyPlayerUuid_ConflictModeWithUuidMismatch_AllowsAccess() {
        // Arrange — CONFLICT_MODE permits a mismatch during the conflict resolution window.
        // Timestamp is "now" so it falls inside the default TTL configured in setUp().
        RegisteredPlayer dbPlayer =
                registeredPlayer(UUID.randomUUID().toString(), UUID.randomUUID().toString(), true);
        dbPlayer.setConflictTimestamp(System.currentTimeMillis());
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertTrue(result, "CONFLICT_MODE must allow access despite UUID mismatch within TTL");
        verify(authCache, never()).removeAuthorizedPlayer(any(UUID.class));
        verify(authCache, never()).endSession(any(UUID.class));
    }

    @Test
    void testVerifyPlayerUuid_ConflictModeWithMatchingUuid_AllowsAccess() {
        // Arrange
        RegisteredPlayer dbPlayer = registeredPlayer(playerUuid.toString(), null, true);
        dbPlayer.setConflictTimestamp(System.currentTimeMillis());
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertTrue(result, "CONFLICT_MODE with a matching UUID must allow access");
    }

    @Test
    void testVerifyPlayerUuid_ConflictModeExpired_PerformsFullUuidVerificationAndDenies() {
        // Arrange — conflict mark is older than the TTL: the relaxed-verification window
        // has closed, so the handler must fall through to full UUID verification. A mismatch
        // must now be denied and the cache invalidated (regression for the pre-1.3.3 hole
        // where a single conflict mark disabled UUID verification forever).
        RegisteredPlayer dbPlayer =
                registeredPlayer(UUID.randomUUID().toString(), UUID.randomUUID().toString(), true);
        long expiredMillis = System.currentTimeMillis()
                - (CONFLICT_TTL_HOURS * 60L * 60L * 1000L) - 60_000L; // TTL + 1 minute ago
        dbPlayer.setConflictTimestamp(expiredMillis);
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertFalse(result,
                "An expired CONFLICT_MODE entry must NOT relax UUID verification — full check applies");
        verify(authCache).removeAuthorizedPlayer(playerUuid);
        verify(authCache).endSession(playerUuid);
        verify(auditLogService).save(
                eq(AuditEventType.UUID_MISMATCH), eq(USERNAME), eq(PLAYER_IP), anyString());
    }

    @Test
    void testVerifyPlayerUuid_ConflictModeExpiredButUuidMatches_AllowsAccess() {
        // Arrange — expired conflict, but the connection UUID legitimately matches the
        // stored one. Full verification must still pass (the conflict flag must not cause
        // a spurious deny once the window has closed).
        RegisteredPlayer dbPlayer = registeredPlayer(playerUuid.toString(), null, true);
        long expiredMillis = System.currentTimeMillis()
                - (CONFLICT_TTL_HOURS * 60L * 60L * 1000L) - 60_000L;
        dbPlayer.setConflictTimestamp(expiredMillis);
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertTrue(result,
                "Expired CONFLICT_MODE with a matching UUID must pass full verification");
        verify(authCache, never()).removeAuthorizedPlayer(any(UUID.class));
    }

    @Test
    void testVerifyPlayerUuid_ConflictModePermanent_TtlDisabledAllowsDespiteMismatch() {
        // Arrange — TTL disabled (0h): pre-1.3.3 permanent-conflict behaviour. Operators
        // who rely on the legacy semantics set conflict-mode-ttl-hours: 0 in config.
        handler = new UuidVerificationHandler(databaseManager, authCache, logger, () -> auditLogService,
                new ConflictModeService(databaseManager, 0));
        RegisteredPlayer dbPlayer =
                registeredPlayer(UUID.randomUUID().toString(), UUID.randomUUID().toString(), true);
        // No timestamp set (or very old) — irrelevant when TTL is disabled.
        dbPlayer.setConflictTimestamp(0L);
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertTrue(result,
                "With conflict-mode-ttl-hours=0 (disabled), conflict mode must be permanent (legacy)");
        verify(authCache, never()).removeAuthorizedPlayer(any(UUID.class));
    }

    // ==================== EXCEPTION PATHS — FAIL-SECURE ====================

    @Test
    void testVerifyPlayerUuid_DbFutureCompletesExceptionally_FailSecureReturnsFalse() {
        // Arrange
        when(databaseManager.findPlayerByNickname(USERNAME)).thenReturn(
                CompletableFuture.failedFuture(new IllegalStateException("pool exhausted")));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertFalse(result, "An async DB failure must resolve to false, never propagate");
        verify(authCache).removeAuthorizedPlayer(playerUuid);
        verify(authCache).endSession(playerUuid);
    }

    @Test
    void testVerifyPlayerUuid_OnlineModeCheckThrows_FailSecureReturnsFalse() {
        // Arrange
        when(player.isOnlineMode()).thenThrow(new IllegalStateException("connection closed"));

        // Act
        boolean result = handler.verifyPlayerUuid(player).join();

        // Assert
        assertFalse(result, "A synchronous RuntimeException must resolve to false");
        verify(authCache).removeAuthorizedPlayer(playerUuid);
        verify(authCache).endSession(playerUuid);
    }

    // ==================== performUuidVerification EDGE CASES ====================

    @Test
    void testPerformUuidVerification_NullDbPlayer_ReturnsFalse() {
        // Arrange — null dbPlayer means "not registered"

        // Act
        boolean result = handler.performUuidVerification(player, null);

        // Assert
        assertFalse(result, "Null DB record must fail verification");
        verify(authCache, never()).removeAuthorizedPlayer(any(UUID.class));
    }

    @Test
    void testPerformUuidVerification_MalformedStoredUuids_TreatedAsMismatchReturnsFalse() {
        // Arrange — unparseable UUID strings (e.g. legacy rows written by external tools)
        // cannot be created via RegisteredPlayer setters (they validate), so mock the model
        RegisteredPlayer dbPlayer = org.mockito.Mockito.mock(RegisteredPlayer.class);
        when(dbPlayer.getUuid()).thenReturn("not-a-uuid");
        when(dbPlayer.getPremiumUuid()).thenReturn("also-not-a-uuid");
        when(dbPlayer.getConflictMode()).thenReturn(false);

        // Act
        boolean result = handler.performUuidVerification(player, dbPlayer);

        // Assert
        assertFalse(result, "Malformed stored UUIDs must be treated as a mismatch (fail-secure)");
        verify(authCache).removeAuthorizedPlayer(playerUuid);
        verify(authCache).endSession(playerUuid);
    }

    @Test
    void testPerformUuidVerification_NullStoredUuidsWithoutConflictMode_ReturnsFalse() {
        // Arrange — record exists but carries no UUID data at all
        RegisteredPlayer dbPlayer = registeredPlayer(null, null, false);

        // Act
        boolean result = handler.performUuidVerification(player, dbPlayer);

        // Assert
        assertFalse(result, "A record without any stored UUID must not match any connection");
    }

    // ==================== HELPERS ====================

    private static RegisteredPlayer registeredPlayer(String uuid, String premiumUuid, boolean conflictMode) {
        RegisteredPlayer dbPlayer = new RegisteredPlayer();
        dbPlayer.setNickname(USERNAME);
        if (uuid != null) {
            // setUuid validates - a null stored UUID is modeled by leaving the field unset
            dbPlayer.setUuid(uuid);
        }
        dbPlayer.setPremiumUuid(premiumUuid);
        dbPlayer.setConflictMode(conflictMode);
        return dbPlayer;
    }
}
