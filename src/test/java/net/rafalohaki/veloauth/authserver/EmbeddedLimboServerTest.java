package net.rafalohaki.veloauth.authserver;

import io.netty.channel.Channel;
import net.kyori.adventure.text.Component;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.UUID;

import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.connect;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.readFrame;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.readString;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.sendHandshake;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.sendLogin;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.writeDeclaredFrameLength;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.writeFrame;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.packet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

class EmbeddedLimboServerTest {

    private EmbeddedLimboServer server;

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.close();
        }
    }

    @Test
    void login_WithExpectedRedirect_ShouldReachGameUsingMinecraft18WireProtocol() throws Exception {
        UUID playerId = UUID.randomUUID();
        server = newServer(0);
        server.start();
        server.expectPlayer(playerId, "PlayerOne");

        try (Socket socket = connect(server.port())) {
            sendLogin(socket, LegacyProtocolCodec.PROTOCOL_VERSION, "PlayerOne");

            MinecraftWireTestSupport.Frame loginSuccess = readFrame(socket);
            assertEquals(0x02, loginSuccess.packetId());
            assertEquals(playerId.toString(), readString(loginSuccess.payload()));
            assertEquals("PlayerOne", readString(loginSuccess.payload()));

            MinecraftWireTestSupport.Frame joinGame = readFrame(socket);
            assertEquals(0x01, joinGame.packetId());

            MinecraftWireTestSupport.Frame position = readFrame(socket);
            assertEquals(0x08, position.packetId());
            position.payload().readDouble();
            assertEquals(64.0, position.payload().readDouble(),
                    "Minecraft 1.8 should retain its legacy in-world spawn height");
            assertEquals(1, server.playersInGame());
            assertEquals(0, server.invalidRedirects());
        }
    }

    @Test
    void login_WithoutExpectedRedirect_ShouldFailClosedAndBurnAttempt() throws Exception {
        server = newServer(0);
        server.start();

        try (Socket socket = connect(server.port())) {
            sendLogin(socket, LegacyProtocolCodec.PROTOCOL_VERSION, "Unexpected");
            MinecraftWireTestSupport.Frame disconnect = readFrame(socket);

            assertEquals(0x00, disconnect.packetId());
            assertTrue(readString(disconnect.payload()).contains("invalid redirect"));
        }
        assertEquals(1, server.invalidRedirects());
        assertEquals(0, server.playersInGame());
    }

    @Test
    void statusPing_ShouldAdvertiseCompleteRangeWithoutExpectedRedirect() throws Exception {
        server = newServer(0);
        server.start();

        try (Socket socket = connect(server.port())) {
            sendHandshake(socket, LegacyProtocolCodec.PROTOCOL_VERSION, 1);
            writeFrame(socket, packet(0x00));
            MinecraftWireTestSupport.Frame response = readFrame(socket);
            String json = readString(response.payload());

            assertEquals(0x00, response.packetId());
            assertTrue(json.contains("VeloAuth 1.8-26.2"));
            assertTrue(json.contains("\"protocol\":47"));
            assertEquals(0, server.playersInGame());
        }
    }

    @Test
    void login_WrongBaseProtocolWithoutTranslator_ShouldDisconnectBeforeLogin() throws Exception {
        server = newServer(0);
        server.start();

        try (Socket socket = connect(server.port())) {
            sendLogin(socket, 769, "PlayerOne");
            assertThrows(EOFException.class, () -> readFrame(socket));
        }
        assertEquals(0, server.playersInGame());
    }

    @Test
    void lifecycle_PortCollisionAndRepeatedClose_ShouldReleasePortForNewInstance() throws Exception {
        int port = availablePort();
        server = newServer(port);
        server.start();

        EmbeddedLimboServer collision = newServer(port);
        assertThrows(IllegalStateException.class, collision::start);
        collision.close();

        server.close();
        server.close();

        EmbeddedLimboServer replacement = newServer(port);
        try {
            replacement.start();
            assertTrue(replacement.isListening());
        } finally {
            replacement.close();
        }
    }

    @Test
    void framing_DeclaredOversizedInboundFrame_ShouldDisconnectBeforeBufferingPayload() throws Exception {
        server = newServer(0);
        server.start();

        try (Socket socket = connect(server.port())) {
            writeDeclaredFrameLength(socket, EmbeddedLimboServer.MAX_FRAME_BYTES + 1);

            assertThrows(IOException.class, () -> readFrame(socket));
        }
        assertEquals(0, server.playersInGame());
    }

    private static EmbeddedLimboServer newServer(int port) {
        EmbeddedLimboServer.Config config = new EmbeddedLimboServer.Config(
                port, 16, Duration.ofSeconds(2), Duration.ofSeconds(4));
        EmbeddedLimboServer.PlayerMessages messages = new EmbeddedLimboServer.PlayerMessages(
                Component.text("VeloAuth test"),
                Component.text("invalid redirect"),
                Component.text("overloaded"),
                Component.text("timeout"));
        return new EmbeddedLimboServer(config, new NoopProtocolRuntime(), messages, mock(Logger.class));
    }

    private static int availablePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }

    private static final class NoopProtocolRuntime implements ProtocolRuntime {
        @Override
        public boolean supportsProtocol(int protocol) {
            return protocol == LegacyProtocolCodec.PROTOCOL_VERSION;
        }

        @Override
        public int minimumProtocol() {
            return LegacyProtocolCodec.PROTOCOL_VERSION;
        }

        @Override
        public int maximumProtocol() {
            return LegacyProtocolCodec.PROTOCOL_VERSION;
        }

        @Override
        public String minimumVersionName() {
            return "1.8";
        }

        @Override
        public String maximumVersionName() {
            return "26.2";
        }

        @Override
        public String runtimeVersion() {
            return "test";
        }

        @Override
        public void inject(Channel channel) {
            // The base-protocol test intentionally exercises MCProtocolLib without translation.
        }

        @Override
        public int clientProtocol(Channel channel) {
            return LegacyProtocolCodec.PROTOCOL_VERSION;
        }

        @Override
        public void close() {
            // Test-owned no-op.
        }
    }

}
