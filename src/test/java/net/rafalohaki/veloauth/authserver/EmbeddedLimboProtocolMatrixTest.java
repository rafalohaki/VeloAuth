package net.rafalohaki.veloauth.authserver;

import com.viaversion.viaversion.ViaManagerImpl;
import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;
import org.geysermc.mcprotocollib.auth.GameProfile;
import org.geysermc.mcprotocollib.network.ClientSession;
import org.geysermc.mcprotocollib.network.Session;
import org.geysermc.mcprotocollib.network.event.session.SessionAdapter;
import org.geysermc.mcprotocollib.network.factory.ClientNetworkSessionFactory;
import org.geysermc.mcprotocollib.network.packet.Packet;
import org.geysermc.mcprotocollib.protocol.MinecraftProtocol;
import org.geysermc.mcprotocollib.protocol.data.game.entity.player.GameMode;
import org.geysermc.mcprotocollib.protocol.data.game.level.notify.GameEvent;
import org.geysermc.mcprotocollib.protocol.packet.configuration.clientbound.ClientboundRegistryDataPacket;
import org.geysermc.mcprotocollib.protocol.packet.common.clientbound.ClientboundKeepAlivePacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.ClientboundLoginPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.entity.player.ClientboundPlayerPositionPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.level.ClientboundGameEventPacket;
import org.geysermc.mcprotocollib.protocol.packet.login.clientbound.ClientboundCustomQueryPacket;
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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
    void login_Minecraft262Client_ShouldRequestVelocityForwardingAndEnterGame() throws Exception {
        startServer();

        UUID playerId = UUID.randomUUID();
        String username = "LatestClient";
        server.expectPlayer(playerId, username);
        CountDownLatch forwardingRequested = new CountDownLatch(1);
        CountDownLatch joined = new CountDownLatch(1);
        CountDownLatch terrainLoadingStarted = new CountDownLatch(1);
        CountDownLatch positionedOutsideVoidWorld = new CountDownLatch(1);
        CountDownLatch keptAlive = new CountDownLatch(1);
        AtomicReference<byte[]> forwardingRequestData = new AtomicReference<>();
        AtomicReference<ClientboundLoginPacket> loginPacket = new AtomicReference<>();
        AtomicReference<ClientboundPlayerPositionPacket> positionPacket = new AtomicReference<>();
        AtomicInteger endDimensionId = new AtomicInteger(-1);
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
                if (packet instanceof ClientboundCustomQueryPacket query
                        && Key.key("velocity", "player_info").equals(query.getChannel())) {
                    forwardingRequestData.set(query.getData());
                    forwardingRequested.countDown();
                } else if (packet instanceof ClientboundRegistryDataPacket registryData
                        && Key.key("minecraft", "dimension_type").equals(registryData.getRegistry())) {
                    for (int index = 0; index < registryData.getEntries().size(); index++) {
                        if (Key.key("minecraft", "the_end")
                                .equals(registryData.getEntries().get(index).getId())) {
                            endDimensionId.set(index);
                            break;
                        }
                    }
                } else if (packet instanceof ClientboundLoginPacket login) {
                    loginPacket.set(login);
                    joined.countDown();
                } else if (packet instanceof ClientboundGameEventPacket event
                        && event.getNotification() == GameEvent.LEVEL_CHUNKS_LOAD_START) {
                    terrainLoadingStarted.countDown();
                } else if (packet instanceof ClientboundPlayerPositionPacket position) {
                    positionPacket.set(position);
                    positionedOutsideVoidWorld.countDown();
                } else if (packet instanceof ClientboundKeepAlivePacket) {
                    keptAlive.countDown();
                }
            }
        });

        client.connect(true);

        assertTrue(forwardingRequested.await(10, TimeUnit.SECONDS),
                "Minecraft 1.13+ clients should receive the standard Velocity forwarding request");
        assertArrayEquals(new byte[0], forwardingRequestData.get(),
                "An empty request asks Velocity to use its compatible default forwarding version");
        assertTrue(joined.await(10, TimeUnit.SECONDS),
                "Minecraft 26.2 client should receive its translated Join Game packet");
        assertTrue(endDimensionId.get() >= 0,
                "Minecraft 26.2 should receive the End dimension registry entry");
        assertEquals(endDimensionId.get(), loginPacket.get().getCommonPlayerSpawnInfo().getDimension(),
                "Translated Join Game must reference the End dimension type");
        assertEquals(Key.key("minecraft", "the_end"),
                loginPacket.get().getCommonPlayerSpawnInfo().getWorldName(),
                "Translated Join Game must use the End world identifier");
        assertEquals(GameMode.SPECTATOR,
                loginPacket.get().getCommonPlayerSpawnInfo().getGameMode(),
                "Translated clients should remain suspended instead of falling through the void");
        assertTrue(loginPacket.get().isEnforcesSecureChat(),
                "Embedded limbo should not trigger the modern client's insecure-chat warning toast");
        assertTrue(terrainLoadingStarted.await(10, TimeUnit.SECONDS),
                "Minecraft 26.2 should receive the translated start-loading-chunks event");
        assertTrue(positionedOutsideVoidWorld.await(10, TimeUnit.SECONDS),
                "Minecraft 26.2 should receive the translated initial player position");
        assertEquals(400.0, positionPacket.get().getPosition().getY(),
                "Modern clients must spawn above the unloaded void world to leave Loading terrain");
        assertTrue(keptAlive.await(20, TimeUnit.SECONDS),
                "A cracked client must remain connected through embedded limbo's first keepalive");
        assertTrue(client.isConnected(),
                "The translated keepalive response must not disconnect the client");
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
