package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UuidVerificationHandlerTest {

    @Mock
    private DatabaseManager databaseManager;

    @Mock
    private AuthCache authCache;

    @Mock
    private Logger logger;

    @Mock
    private Player player;

    private UuidVerificationHandler handler;

    @BeforeEach
    void setUp() {
        handler = new UuidVerificationHandler(databaseManager, authCache, logger);
    }

    @Test
    void shouldReturnTrueForPremiumPlayer() {
        // Given
        when(player.isOnlineMode()).thenReturn(true);

        // When
        boolean result = handler.verifyPlayerUuid(player).join();

        // Then
        assertTrue(result);
        verify(databaseManager, never()).findPlayerByNickname(anyString());
    }

    @Test
    void shouldReturnTrueWhenUuidMatches() {
        // Given
        String username = "testplayer";
        UUID uuid = UUID.randomUUID();
        when(player.isOnlineMode()).thenReturn(false);
        when(player.getUsername()).thenReturn(username);
        when(player.getUniqueId()).thenReturn(uuid);

        RegisteredPlayer dbPlayer = new RegisteredPlayer();
        dbPlayer.setNickname(username);
        dbPlayer.setUuid(uuid.toString());

        when(databaseManager.findPlayerByNickname(username))
                .thenReturn(CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // When
        boolean result = handler.verifyPlayerUuid(player).join();

        // Then
        assertTrue(result);
    }

    @Test
    void shouldReturnFalseOnDatabaseError() {
        // Given
        String username = "testplayer";
        when(player.isOnlineMode()).thenReturn(false);
        when(player.getUsername()).thenReturn(username);

        when(databaseManager.findPlayerByNickname(username))
                .thenReturn(CompletableFuture.completedFuture(DbResult.databaseError("DB error")));

        // When
        boolean result = handler.verifyPlayerUuid(player).join();

        // Then
        assertFalse(result);
    }

    @Test
    void shouldReturnTrueInConflictMode() {
        // Given
        String username = "testplayer";
        when(player.isOnlineMode()).thenReturn(false);
        when(player.getUsername()).thenReturn(username);

        RegisteredPlayer dbPlayer = new RegisteredPlayer();
        dbPlayer.setNickname(username);
        dbPlayer.setUuid(UUID.randomUUID().toString()); // Different UUID
        dbPlayer.setConflictMode(true);

        when(databaseManager.findPlayerByNickname(username))
                .thenReturn(CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // When
        boolean result = handler.verifyPlayerUuid(player).join();

        // Then
        assertTrue(result);
    }

    @Test
    void shouldReturnFalseOnUuidMismatch() {
        // Given
        String username = "testplayer";
        UUID playerUuid = UUID.randomUUID();
        UUID dbUuid = UUID.randomUUID();
        when(player.isOnlineMode()).thenReturn(false);
        when(player.getUsername()).thenReturn(username);
        when(player.getUniqueId()).thenReturn(playerUuid);

        RegisteredPlayer dbPlayer = new RegisteredPlayer();
        dbPlayer.setNickname(username);
        dbPlayer.setUuid(dbUuid.toString());
        dbPlayer.setConflictMode(false);

        when(databaseManager.findPlayerByNickname(username))
                .thenReturn(CompletableFuture.completedFuture(DbResult.success(dbPlayer)));

        // When
        boolean result = handler.verifyPlayerUuid(player).join();

        // Then
        assertFalse(result);
    }
}
