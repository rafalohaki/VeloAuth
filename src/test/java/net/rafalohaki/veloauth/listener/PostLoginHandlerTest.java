package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.Logger;

import java.util.UUID;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PostLoginHandler#handleOfflinePlayer} — specifically the
 * session-expiry boundary. Authorization and active sessions are separate state;
 * an authorization cache hit must never renew an expired session.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class PostLoginHandlerTest {

    private static final String USERNAME = "OfflineSteve";
    private static final String PLAYER_IP = "192.0.2.42";

    @Mock private AuthCache authCache;
    @Mock private DatabaseManager databaseManager;
    @Mock private Messages messages;
    @Mock private Logger logger;
    @Mock private Player player;

    private PostLoginHandler handler;
    private UUID playerUuid;

    @BeforeEach
    void setUp() {
        playerUuid = UUID.randomUUID();
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn(USERNAME);

        handler = new PostLoginHandler(authCache, databaseManager, messages, logger);
    }

    @Test
    void handleOfflinePlayer_NotAuthorized_NeverTouchesSession() {
        when(authCache.isPlayerAuthorized(playerUuid, PLAYER_IP)).thenReturn(false);

        handler.handleOfflinePlayer(player, PLAYER_IP);

        verify(authCache, never()).startSession(
                org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
    }

    @Test
    void handleOfflinePlayer_AuthorizedWithActiveSession_DoesNotRestartSession() {
        when(authCache.isPlayerAuthorized(playerUuid, PLAYER_IP)).thenReturn(true);
        when(authCache.hasActiveSession(playerUuid, USERNAME, PLAYER_IP)).thenReturn(true);

        handler.handleOfflinePlayer(player, PLAYER_IP);

        verify(authCache, never()).startSession(playerUuid, USERNAME, PLAYER_IP);
    }

    @Test
    void handleOfflinePlayer_AuthorizedButSessionExpired_DoesNotBypassPasswordLogin() {
        when(authCache.isPlayerAuthorized(playerUuid, PLAYER_IP)).thenReturn(true);
        when(authCache.hasActiveSession(playerUuid, USERNAME, PLAYER_IP)).thenReturn(false);

        handler.handleOfflinePlayer(player, PLAYER_IP);

        verify(authCache, never()).startSession(playerUuid, USERNAME, PLAYER_IP);
    }
}
