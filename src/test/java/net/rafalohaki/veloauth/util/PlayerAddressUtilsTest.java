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
import java.net.SocketAddress;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PlayerAddressUtilsTest {

    @Mock
    private PreLoginEvent preLoginEvent;

    @Mock
    private InboundConnection inboundConnection;

    @Mock
    private Player player;

    @Test
    void getAddressFromPreLogin_NullEvent_ReturnsNull() {
        assertNull(PlayerAddressUtils.getAddressFromPreLogin(null));
    }

    @Test
    void getAddressFromPreLogin_NullConnection_ReturnsNull() {
        when(preLoginEvent.getConnection()).thenReturn(null);
        assertNull(PlayerAddressUtils.getAddressFromPreLogin(preLoginEvent));
    }

    @Test
    void getAddressFromPreLogin_NullRemoteAddress_ReturnsNull() {
        when(preLoginEvent.getConnection()).thenReturn(inboundConnection);
        when(inboundConnection.getRemoteAddress()).thenReturn(null);

        assertNull(PlayerAddressUtils.getAddressFromPreLogin(preLoginEvent));
    }

    @Test
    void getAddressFromPreLogin_NonInetSocketAddress_ReturnsNull() {
        when(preLoginEvent.getConnection()).thenReturn(inboundConnection);
        SocketAddress otherSocketAddress = mock(SocketAddress.class);
        when(inboundConnection.getRemoteAddress()).thenReturn(otherSocketAddress);

        assertNull(PlayerAddressUtils.getAddressFromPreLogin(preLoginEvent));
    }

    @Test
    void getAddressFromPreLogin_ValidAddress_ReturnsInetAddress() throws Exception {
        InetAddress expectedAddress = InetAddress.getByName("127.0.0.1");
        InetSocketAddress socketAddress = new InetSocketAddress(expectedAddress, 12345);

        when(preLoginEvent.getConnection()).thenReturn(inboundConnection);
        when(inboundConnection.getRemoteAddress()).thenReturn(socketAddress);
        when(preLoginEvent.getUsername()).thenReturn("testuser");

        InetAddress result = PlayerAddressUtils.getAddressFromPreLogin(preLoginEvent);
        assertEquals(expectedAddress, result);
    }

    @Test
    void getAddressFromPreLogin_Exception_ReturnsNull() {
        when(preLoginEvent.getConnection()).thenThrow(new RuntimeException("Unexpected error"));

        assertNull(PlayerAddressUtils.getAddressFromPreLogin(preLoginEvent));
    }

    @Test
    void getPlayerIp_NullPlayer_ReturnsUnknown() {
        // UNKNOWN is from StringConstants.UNKNOWN
        assertEquals("unknown", PlayerAddressUtils.getPlayerIp(null));
    }

    @Test
    void getPlayerIp_NullAddress_ReturnsUnknown() {
        when(player.getRemoteAddress()).thenReturn(null);
        when(player.getUsername()).thenReturn("testuser");

        assertEquals("unknown", PlayerAddressUtils.getPlayerIp(player));
    }

    @Test
    void getPlayerIp_ValidAddress_ReturnsHostAddress() throws Exception {
        InetAddress address = InetAddress.getByName("192.168.1.1");
        InetSocketAddress socketAddress = new InetSocketAddress(address, 12345);

        when(player.getRemoteAddress()).thenReturn(socketAddress);

        assertEquals("192.168.1.1", PlayerAddressUtils.getPlayerIp(player));
    }

    @Test
    void getPlayerAddress_NullPlayer_ReturnsNull() {
        assertNull(PlayerAddressUtils.getPlayerAddress(null));
    }

    @Test
    void getPlayerAddress_ValidPlayer_ReturnsAddress() throws Exception {
        InetAddress expectedAddress = InetAddress.getByName("8.8.8.8");
        InetSocketAddress socketAddress = new InetSocketAddress(expectedAddress, 53);

        when(player.getRemoteAddress()).thenReturn(socketAddress);

        assertEquals(expectedAddress, PlayerAddressUtils.getPlayerAddress(player));
    }

    @Test
    void hasValidAddress_NullPlayer_ReturnsFalse() {
        assertFalse(PlayerAddressUtils.hasValidAddress(null));
    }

    @Test
    void hasValidAddress_NullAddress_ReturnsFalse() {
        when(player.getRemoteAddress()).thenReturn(null);
        assertFalse(PlayerAddressUtils.hasValidAddress(player));
    }

    @Test
    void hasValidAddress_ValidAddress_ReturnsTrue() {
        InetSocketAddress socketAddress = new InetSocketAddress("127.0.0.1", 12345);
        when(player.getRemoteAddress()).thenReturn(socketAddress);
        assertTrue(PlayerAddressUtils.hasValidAddress(player));
    }
}
