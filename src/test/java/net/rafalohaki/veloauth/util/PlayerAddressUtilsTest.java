package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.proxy.InboundConnection;
import com.velocitypowered.api.proxy.Player;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PlayerAddressUtilsTest {

    @Mock
    private Player player;

    @Mock
    private PreLoginEvent preLoginEvent;

    @Mock
    private InboundConnection inboundConnection;

    @Test
    void getPlayerIp_nullPlayer_returnsUnknown() {
        assertEquals("unknown", PlayerAddressUtils.getPlayerIp(null));
    }

    @Test
    void getPlayerIp_validAddress_returnsHostAddress() throws UnknownHostException {
        InetSocketAddress addr = new InetSocketAddress(InetAddress.getByName("198.51.100.10"), 25565);
        when(player.getRemoteAddress()).thenReturn(addr);
        when(player.getUsername()).thenReturn("alice");

        assertEquals("198.51.100.10", PlayerAddressUtils.getPlayerIp(player));
    }

    @Test
    void getPlayerIp_nullRemoteAddress_returnsUnknown() {
        when(player.getRemoteAddress()).thenReturn(null);
        when(player.getUsername()).thenReturn("alice");

        assertEquals("unknown", PlayerAddressUtils.getPlayerIp(player));
    }

    @Test
    void getPlayerAddress_nullPlayer_returnsNull() {
        assertNull(PlayerAddressUtils.getPlayerAddress(null));
    }

    @Test
    void getPlayerAddress_validPlayer_returnsInetAddress() throws UnknownHostException {
        InetSocketAddress addr = new InetSocketAddress(InetAddress.getByName("203.0.113.5"), 25565);
        when(player.getRemoteAddress()).thenReturn(addr);
        when(player.getUsername()).thenReturn("alice");

        InetAddress result = PlayerAddressUtils.getPlayerAddress(player);

        assertNotNull(result);
        assertEquals("203.0.113.5", result.getHostAddress());
    }

    @Test
    void getAddressFromPreLogin_nullEvent_returnsNull() {
        assertNull(PlayerAddressUtils.getAddressFromPreLogin(null));
    }

    @Test
    void getAddressFromPreLogin_validInetSocket_returnsAddress() throws UnknownHostException {
        InetSocketAddress addr = new InetSocketAddress(InetAddress.getByName("192.0.2.1"), 25565);
        when(preLoginEvent.getConnection()).thenReturn(inboundConnection);
        when(inboundConnection.getRemoteAddress()).thenReturn(addr);
        when(preLoginEvent.getUsername()).thenReturn("bob");

        InetAddress result = PlayerAddressUtils.getAddressFromPreLogin(preLoginEvent);

        assertNotNull(result);
        assertEquals("192.0.2.1", result.getHostAddress());
    }

    @Test
    void getAddressFromPreLogin_nullConnection_returnsNull() {
        when(preLoginEvent.getConnection()).thenReturn(null);

        assertNull(PlayerAddressUtils.getAddressFromPreLogin(preLoginEvent));
    }

    @Test
    void hasValidAddress_nullPlayer_returnsFalse() {
        assertFalse(PlayerAddressUtils.hasValidAddress(null));
    }

    @Test
    void hasValidAddress_nullRemoteAddress_returnsFalse() {
        when(player.getRemoteAddress()).thenReturn(null);

        assertFalse(PlayerAddressUtils.hasValidAddress(player));
    }

    @Test
    void hasValidAddress_validAddress_returnsTrue() throws UnknownHostException {
        InetSocketAddress addr = new InetSocketAddress(InetAddress.getByName("10.0.0.1"), 25565);
        when(player.getRemoteAddress()).thenReturn(addr);

        assertTrue(PlayerAddressUtils.hasValidAddress(player));
    }
}
