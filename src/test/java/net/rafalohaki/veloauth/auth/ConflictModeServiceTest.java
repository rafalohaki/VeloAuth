package net.rafalohaki.veloauth.auth;

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

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ConflictModeService} — TTL-based expiry and auto-clear of the
 * nickname-conflict flag.
 *
 * <p>Invariants under test:
 * <ul>
 *   <li>isActive() respects the TTL window and the {@code 0 = disabled} escape hatch</li>
 *   <li>clearIfPresent() mutates the player, persists fire-and-forget, and is a no-op when
 *       the player is null or not in conflict mode</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ConflictModeServiceTest {

    private static final String USERNAME = "ConflictVictim";
    private static final int TTL_HOURS = 24;

    @Mock
    private DatabaseManager databaseManager;

    private ConflictModeService service;

    @BeforeEach
    void setUp() {
        service = new ConflictModeService(databaseManager, TTL_HOURS);
        when(databaseManager.savePlayer(any(RegisteredPlayer.class)))
                .thenReturn(CompletableFuture.completedFuture(DbResult.success(true)));
    }

    // ==================== isActive() ====================

    @Test
    void isActive_NullDbPlayer_ReturnsFalse() {
        assertFalse(service.isActive(null), "null dbPlayer must not be considered in conflict");
    }

    @Test
    void isActive_NotInConflictMode_ReturnsFalse() {
        RegisteredPlayer player = inConflict(false, System.currentTimeMillis());
        assertFalse(service.isActive(player), "Player without conflict flag must not be active");
    }

    @Test
    void isActive_ConflictSetTimestampNow_ReturnsTrue() {
        RegisteredPlayer player = inConflict(true, System.currentTimeMillis());
        assertTrue(service.isActive(player),
                "Fresh conflict timestamp must be within the TTL window");
    }

    @Test
    void isActive_ConflictTimestampOlderThanTtl_ReturnsFalse() {
        long expired = System.currentTimeMillis() - (TTL_HOURS * 60L * 60L * 1000L) - 1L;
        RegisteredPlayer player = inConflict(true, expired);
        assertFalse(service.isActive(player),
                "Conflict timestamp older than TTL must be expired");
    }

    @Test
    void isActive_ConflictTimestampZeroTtlEnabled_ReturnsFalse() {
        // Legacy row written before CONFLICT_TIMESTAMP existed. Safer to treat as expired
        // (forces a full verification) than to allow forever.
        RegisteredPlayer player = inConflict(true, 0L);
        assertFalse(service.isActive(player),
                "Missing timestamp (0) with TTL enabled must be treated as expired");
    }

    @Test
    void isActive_TtlDisabled_ConflictAlwaysActiveRegardlessOfTimestamp() {
        // conflict-mode-ttl-hours = 0 restores the pre-1.3.3 permanent-conflict behaviour.
        ConflictModeService permanent = new ConflictModeService(databaseManager, 0);
        RegisteredPlayer ancient = inConflict(true, 0L);
        assertTrue(permanent.isActive(ancient),
                "TTL disabled (0) must make conflict permanent regardless of timestamp");
        assertEquals(0, permanent.getConflictTtlHours(),
                "getConflictTtlHours() must echo the configured value");
    }

    // ==================== clearIfPresent() ====================

    @Test
    void clearIfPresent_ConflictSet_ClearsFieldsAndPersists() {
        RegisteredPlayer player = inConflict(true, System.currentTimeMillis());

        service.clearIfPresent(player, "login");

        assertFalse(player.getConflictMode(), "Conflict flag must be cleared in memory");
        assertEquals(0L, player.getConflictTimestamp(), "Conflict timestamp must be reset");
        verify(databaseManager).savePlayer(player);
    }

    @Test
    void clearIfPresent_NotInConflictMode_NoOpNoSave() {
        RegisteredPlayer player = inConflict(false, 0L);

        service.clearIfPresent(player, "login");

        verify(databaseManager, never()).savePlayer(any(RegisteredPlayer.class));
    }

    @Test
    void clearIfPresent_NullPlayer_NoOpNoSave() {
        service.clearIfPresent(null, "login");

        verify(databaseManager, never()).savePlayer(any(RegisteredPlayer.class));
    }

    @Test
    void clearIfPresent_SaveFails_LoggedButInMemoryStateStaysCleared() {
        // Fire-and-forget save failure must not roll back the in-memory clear: the player
        // object is already mutated, and the next savePlayer call (e.g. login date update)
        // will retry the persistence. The exception is swallowed by .exceptionally().
        RegisteredPlayer player = inConflict(true, System.currentTimeMillis());
        when(databaseManager.savePlayer(any(RegisteredPlayer.class)))
                .thenReturn(CompletableFuture.failedFuture(new RuntimeException("connection lost")));

        service.clearIfPresent(player, "login");

        assertFalse(player.getConflictMode(),
                "In-memory clear must persist even if the save future fails");
        verify(databaseManager).savePlayer(player);
    }

    // ==================== helpers ====================

    private static RegisteredPlayer inConflict(boolean conflict, long timestamp) {
        RegisteredPlayer player = new RegisteredPlayer();
        player.setNickname(USERNAME);
        player.setUuid(UUID.randomUUID().toString());
        player.setConflictMode(conflict);
        player.setConflictTimestamp(timestamp);
        return player;
    }
}
