package net.rafalohaki.veloauth.authserver;

import com.viaversion.viaversion.ViaManagerImpl;
import net.kyori.adventure.text.Component;
import org.geysermc.mcprotocollib.auth.GameProfile;
import org.geysermc.mcprotocollib.network.ClientSession;
import org.geysermc.mcprotocollib.network.Session;
import org.geysermc.mcprotocollib.network.event.session.SessionAdapter;
import org.geysermc.mcprotocollib.network.factory.ClientNetworkSessionFactory;
import org.geysermc.mcprotocollib.network.packet.Packet;
import org.geysermc.mcprotocollib.protocol.MinecraftProtocol;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.ClientboundLoginPacket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.net.Socket;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.connect;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.packet;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.readFrame;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.readString;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.sendHandshake;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.writeFrame;
import static org.mockito.Mockito.mock;

class EmbeddedLimboProtocolMatrixTest {

    @TempDir
    private Path temporaryDirectory;

    private EmbeddedLimboServer server;
    private ManagedProtocolRuntime runtime;
    private ClientSession client;

    @AfterEach
    void tearDown() {
        if (client != null && client.isConnected()) {
            client.disconnect("test complete");
        }
        if (server != null) {
            server.close();
        }
        if (runtime != null) {
            runtime.close();
        }
    }

    @Test
    void login_Minecraft262Client_ShouldTranslateTo18BaseAndEnterGame() throws Exception {
        startServer();

        UUID playerId = UUID.randomUUID();
        String username = "LatestClient";
        server.expectPlayer(playerId, username);
        CountDownLatch joined = new CountDownLatch(1);
        MinecraftProtocol protocol = new MinecraftProtocol(new GameProfile(playerId, username), null);
        assertEquals(runtime.maximumProtocol(), protocol.getCodec().getProtocolVersion());
        client = ClientNetworkSessionFactory.factory()
                .setAddress("127.0.0.1", server.port())
                .setProtocol(protocol)
                .setPacketHandlerExecutor(Runnable::run)
                .create();
        client.addListener(new SessionAdapter() {
            @Override
            public void packetReceived(Session session, Packet packet) {
                if (packet instanceof ClientboundLoginPacket) {
                    joined.countDown();
                }
            }
        });

        client.connect(true);

        assertTrue(joined.await(10, TimeUnit.SECONDS),
                "Minecraft 26.2 client should receive its translated Join Game packet");
        assertEquals(1, server.playersInGame());
        assertEquals(0, server.invalidRedirects());
    }

    @Test
    void statusPing_RepresentativeHistoricClients_ShouldTranslateAcrossSupportedMatrix() throws Exception {
        startServer();
        List<ProtocolAnchor> anchors = List.of(
                new ProtocolAnchor(47, "1.8"),
                new ProtocolAnchor(340, "1.12.2"),
                new ProtocolAnchor(754, "1.16.5"),
                new ProtocolAnchor(763, "1.20.1"),
                new ProtocolAnchor(769, "1.21.4"));

        for (ProtocolAnchor anchor : anchors) {
            assertTrue(runtime.supportsProtocol(anchor.protocol()),
                    () -> "Pinned ViaVersion must retain Minecraft " + anchor.version());
            try (Socket socket = connect(server.port())) {
                sendHandshake(socket, anchor.protocol(), 1);
                writeFrame(socket, packet(0x00));

                MinecraftWireTestSupport.Frame response = readFrame(socket);
                assertEquals(0x00, response.packetId(),
                        () -> "Status response packet missing for Minecraft " + anchor.version());
                assertTrue(readString(response.payload()).contains("VeloAuth 1.8-"),
                        () -> "Status response was not translated for Minecraft " + anchor.version());
            }
        }
        assertEquals(0, server.playersInGame());
        assertEquals(0, server.invalidRedirects());
    }

    private void startServer() throws Exception {
        Path artifact = Path.of(ViaManagerImpl.class.getProtectionDomain()
                .getCodeSource().getLocation().toURI());
        runtime = ManagedProtocolRuntime.open(
                artifact, temporaryDirectory.resolve("via"), mock(Logger.class), "test");
        server = new EmbeddedLimboServer(
                new EmbeddedLimboServer.Config(
                        0, 16, Duration.ofSeconds(3), Duration.ofSeconds(8)),
                runtime,
                new EmbeddedLimboServer.PlayerMessages(
                        Component.text("VeloAuth test"),
                        Component.text("invalid redirect"),
                        Component.text("overloaded"),
                        Component.text("timeout")),
                mock(Logger.class));
        server.start();
    }

    private record ProtocolAnchor(int protocol, String version) {
    }
}
