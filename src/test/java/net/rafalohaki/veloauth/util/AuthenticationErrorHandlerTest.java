package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.Logger;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link AuthenticationErrorHandler}.
 * Confirms that every failure path invalidates cache + ends session
 * — the security-critical postcondition.
 */
@ExtendWith(MockitoExtension.class)
class AuthenticationErrorHandlerTest {

    @Mock
    private Player player;

    @Mock
    private AuthCache authCache;

    @Mock
    private Logger logger;

    @Mock
    private RegisteredPlayer dbPlayer;

    private static final UUID PLAYER_UUID = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID STORED_UUID = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final UUID PREMIUM_UUID = UUID.fromString("33333333-3333-3333-3333-333333333333");

    @Test
    void handleVerificationFailure_invalidatesCacheAndSession() {
        when(logger.isErrorEnabled()).thenReturn(true);
        when(player.getUsername()).thenReturn("alice");

        AuthenticationErrorHandler.handleVerificationFailure(player, PLAYER_UUID, authCache, logger);

        verify(authCache).removeAuthorizedPlayer(PLAYER_UUID);
        verify(authCache).endSession(PLAYER_UUID);
    }

    @Test
    void handleUuidMismatch_invalidatesCacheAndSession() throws UnknownHostException {
        when(player.getUsername()).thenReturn("alice");
        when(player.getRemoteAddress()).thenReturn(
                new InetSocketAddress(InetAddress.getByName("203.0.113.10"), 25565));

        AuthenticationErrorHandler.handleUuidMismatch(
                player, PLAYER_UUID, STORED_UUID, PREMIUM_UUID, dbPlayer, authCache, logger);

        verify(authCache).removeAuthorizedPlayer(PLAYER_UUID);
        verify(authCache).endSession(PLAYER_UUID);
    }

    @Test
    void handleUuidMismatch_nullStoredUuids_stillInvalidates() throws UnknownHostException {
        when(player.getUsername()).thenReturn("alice");
        when(player.getRemoteAddress()).thenReturn(
                new InetSocketAddress(InetAddress.getByName("203.0.113.10"), 25565));

        AuthenticationErrorHandler.handleUuidMismatch(
                player, PLAYER_UUID, null, null, null, authCache, logger);

        verify(authCache).removeAuthorizedPlayer(PLAYER_UUID);
        verify(authCache).endSession(PLAYER_UUID);
    }

    @Test
    void handleVerificationError_invalidatesCacheAndReturnsFalse() {
        when(logger.isErrorEnabled()).thenReturn(true);
        when(player.getUsername()).thenReturn("alice");
        when(player.getUniqueId()).thenReturn(PLAYER_UUID);

        boolean result = AuthenticationErrorHandler.handleVerificationError(
                player, new RuntimeException("boom"), authCache, logger);

        assertFalse(result);
        verify(authCache).removeAuthorizedPlayer(PLAYER_UUID);
        verify(authCache).endSession(PLAYER_UUID);
    }
}
