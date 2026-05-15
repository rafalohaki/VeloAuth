package net.rafalohaki.veloauth.auth.totp;

import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.time.Duration;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class PendingTotpStoreTest {

    @Test
    void put_then_get_returnsState() {
        PendingTotpStore store = new PendingTotpStore(Duration.ofMinutes(5), null);
        UUID uuid = UUID.randomUUID();
        RegisteredPlayer dbPlayer = Mockito.mock(RegisteredPlayer.class);
        Mockito.when(dbPlayer.getNickname()).thenReturn("Steve");

        store.put(PendingTotpState.forLogin(uuid, dbPlayer, "1.2.3.4"));

        assertTrue(store.get(uuid).isPresent());
        assertEquals(PendingTotpState.Kind.LOGIN, store.get(uuid).get().kind());
        assertEquals(dbPlayer, store.get(uuid).get().dbPlayer());
        assertEquals("1.2.3.4", store.get(uuid).get().ip());
    }

    @Test
    void invalidate_removesEntry() {
        PendingTotpStore store = new PendingTotpStore(Duration.ofMinutes(5), null);
        UUID uuid = UUID.randomUUID();
        store.put(PendingTotpState.forSetup(uuid, "ABCDEFGH", "127.0.0.1"));

        store.invalidate(uuid);
        assertTrue(store.get(uuid).isEmpty(), "invalidate must drop the entry");
    }

    @Test
    void get_nullUuid_returnsEmpty() {
        PendingTotpStore store = new PendingTotpStore(Duration.ofMinutes(5), null);
        assertTrue(store.get(null).isEmpty());
    }

    @Test
    void invalidate_nullUuid_isNoOp() {
        PendingTotpStore store = new PendingTotpStore(Duration.ofMinutes(5), null);
        assertDoesNotThrow(() -> store.invalidate(null));
    }

    @Test
    void constructor_rejectsZeroOrNegativeTtl() {
        assertThrows(IllegalArgumentException.class,
                () -> new PendingTotpStore(Duration.ZERO, null));
        assertThrows(IllegalArgumentException.class,
                () -> new PendingTotpStore(Duration.ofSeconds(-1), null));
        assertThrows(IllegalArgumentException.class,
                () -> new PendingTotpStore(null, null));
    }

    @Test
    void pendingTotpState_loginKindRequiresDbPlayer() {
        UUID uuid = UUID.randomUUID();
        assertThrows(IllegalArgumentException.class,
                () -> new PendingTotpState(uuid, PendingTotpState.Kind.LOGIN, null, null, "ip", 0L));
    }

    @Test
    void pendingTotpState_setupKindRequiresSecret() {
        UUID uuid = UUID.randomUUID();
        assertThrows(IllegalArgumentException.class,
                () -> new PendingTotpState(uuid, PendingTotpState.Kind.SETUP, null, null, "ip", 0L));
        assertThrows(IllegalArgumentException.class,
                () -> new PendingTotpState(uuid, PendingTotpState.Kind.SETUP, null, "", "ip", 0L));
    }
}
