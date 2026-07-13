package net.rafalohaki.veloauth.model;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RegisteredPlayerTest {

    @Test
    void constructor_invalidUuidShouldThrowIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new RegisteredPlayer("Alice", "hash", "127.0.0.1", "invalid-uuid"));
    }

    @Test
    void setPremiumUuid_blankValueShouldClearPremiumUuid() {
        RegisteredPlayer player = new RegisteredPlayer(
                "Alice",
                "hash",
                "127.0.0.1",
                UUID.randomUUID().toString()
        );

        player.setPremiumUuid(UUID.randomUUID().toString());
        player.setPremiumUuid("   ");

        assertNull(player.getPremiumUuid());
    }

    @Test
    void conflictMetadataAndBlankHashShouldRoundTripThroughAccessors() {
        RegisteredPlayer player = new RegisteredPlayer(
                "Alice",
                "hash",
                "127.0.0.1",
                UUID.randomUUID().toString()
        );

        player.setConflictMode(true);
        player.setConflictTimestamp(12_345L);
        player.setOriginalNickname("OriginalAlice");
        player.setHash("   ");

        assertTrue(player.getConflictMode());
        assertEquals(12_345L, player.getConflictTimestamp());
        assertEquals("OriginalAlice", player.getOriginalNickname());
        assertNull(player.getHash());
        assertFalse(player.isPreserveUuid());

        player.setPreserveUuid(true);
        assertTrue(player.isPreserveUuid());
    }

    @Test
    void toString_shouldRedactSensitiveFields() {
        RegisteredPlayer player = new RegisteredPlayer(
                "Alice",
                "secret-hash",
                "192.168.0.10",
                UUID.randomUUID().toString()
        );
        player.setLoginIp("10.0.0.5");
        player.setPremiumUuid(UUID.randomUUID().toString());

        String description = player.toString();

        assertTrue(description.contains("[REDACTED]"));
        assertFalse(description.contains("192.168.0.10"));
        assertFalse(description.contains("10.0.0.5"));
        assertFalse(description.contains("secret-hash"));
        assertFalse(description.contains(player.getUuid()));
        assertFalse(description.contains(player.getPremiumUuid()));
    }
}
