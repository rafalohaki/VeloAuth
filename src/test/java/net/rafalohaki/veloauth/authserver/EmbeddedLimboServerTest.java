package net.rafalohaki.veloauth.authserver;

import io.netty.channel.Channel;
import net.kyori.adventure.text.Component;
import org.geysermc.mcprotocollib.network.NetworkConstants;
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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.connect;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.readFrame;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.readString;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.sendHandshake;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.sendLogin;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.writeDeclaredFrameLength;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.writeFrame;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.packet;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
            joinGame.payload().readInt();
            assertEquals(3, joinGame.payload().readUnsignedByte(),
                    "Minecraft 1.8 should remain suspended in spectator mode");
            assertEquals(1, joinGame.payload().readByte(),
                    "Minecraft 1.8 should enter the End dimension");

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
    void login_AfterEnteringGame_ShouldReplaceReadTimeoutWithProtocolKeepAlive() throws Exception {
        UUID playerId = UUID.randomUUID();
        NoopProtocolRuntime runtime = new NoopProtocolRuntime();
        server = newServer(0, runtime);
        server.start();
        server.expectPlayer(playerId, "IdlePlayer");

        try (Socket socket = connect(server.port())) {
            assertTrue(hasReadTimeout(runtime),
                    "Pre-login connections still need MCProtocolLib's read timeout");
            sendLogin(socket, LegacyProtocolCodec.PROTOCOL_VERSION, "IdlePlayer");
            readFrame(socket);
            readFrame(socket);
            readFrame(socket);

            assertFalse(hasReadTimeout(runtime),
                    "GAME sessions should use VeloAuth's keepalive instead of a duplicate Netty timer");
        }
    }

    @Test
    void keepAlive_WithoutClientResponse_ShouldDisconnectIdleGameSession() throws Exception {
        UUID playerId = UUID.randomUUID();
        server = newServer(0, new NoopProtocolRuntime(), Duration.ofMillis(100));
        server.start();
        server.expectPlayer(playerId, "SilentPlayer");

        try (Socket socket = connect(server.port())) {
            sendLogin(socket, LegacyProtocolCodec.PROTOCOL_VERSION, "SilentPlayer");
            readFrame(socket);
            readFrame(socket);
            readFrame(socket);
            MinecraftWireTestSupport.Frame keepAlive = readFrame(socket);
            assertEquals(0x00, keepAlive.packetId());

            assertThrows(EOFException.class, () -> readFrame(socket));
        }
        assertEquals(1, server.timedOutConnections());
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
        IllegalStateException collisionFailure =
                assertThrows(IllegalStateException.class, collision::start);
        assertTrue(collisionFailure.getMessage().contains("Failed to start embedded limbo"));
        assertTrue(collisionFailure.getCause().getMessage().contains("MCProtocolLib did not bind"));
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
        return newServer(port, new NoopProtocolRuntime());
    }

    private static EmbeddedLimboServer newServer(int port, ProtocolRuntime runtime) {
        return newServer(port, runtime, Duration.ofSeconds(15));
    }

    private static EmbeddedLimboServer newServer(
            int port, ProtocolRuntime runtime, Duration keepAliveInterval) {
        EmbeddedLimboServer.Config config = new EmbeddedLimboServer.Config(
                port, 16, Duration.ofSeconds(2), Duration.ofSeconds(4), keepAliveInterval);
        EmbeddedLimboServer.PlayerMessages messages = new EmbeddedLimboServer.PlayerMessages(
                Component.text("VeloAuth test"),
                Component.text("invalid redirect"),
                Component.text("overloaded"),
                Component.text("timeout"));
        return new EmbeddedLimboServer(config, runtime, messages, mock(Logger.class));
    }

    private static boolean hasReadTimeout(NoopProtocolRuntime runtime) throws Exception {
        Channel channel = runtime.channel();
        CompletableFuture<Boolean> result = new CompletableFuture<>();
        channel.eventLoop().execute(() -> result.complete(
                channel.pipeline().get(NetworkConstants.READ_TIMEOUT_NAME) != null));
        return result.get(2, TimeUnit.SECONDS);
    }

    private static int availablePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }

    private static final class NoopProtocolRuntime implements ProtocolRuntime {
        private final CompletableFuture<Channel> channel = new CompletableFuture<>();

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
            this.channel.complete(channel);
        }

        private Channel channel() throws Exception {
            return channel.get(2, TimeUnit.SECONDS);
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
