package net.rafalohaki.veloauth.authserver;

import org.geysermc.mcprotocollib.auth.GameProfile;
import org.geysermc.mcprotocollib.network.ClientSession;
import org.geysermc.mcprotocollib.network.Session;
import org.geysermc.mcprotocollib.network.event.session.SessionAdapter;
import org.geysermc.mcprotocollib.network.factory.ClientNetworkSessionFactory;
import org.geysermc.mcprotocollib.network.packet.Packet;
import org.geysermc.mcprotocollib.protocol.MinecraftProtocol;
import org.geysermc.mcprotocollib.protocol.packet.common.clientbound.ClientboundKeepAlivePacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.ClientboundLoginPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.ClientboundSystemChatPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.serverbound.ServerboundChatCommandPacket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertTrue;

/** Opt-in real-proxy smoke; scripts/test-velocity-embedded.sh owns the Velocity process. */
class VelocityEmbeddedProxyIT {

    private ClientSession client;

    @AfterEach
    void disconnectClient() {
        if (client != null && client.isConnected()) {
            client.disconnect("embedded proxy smoke complete");
        }
    }

    @Test
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    void loginLatestClientThroughVelocityShouldEnterEmbeddedLimbo() throws Exception {
        String host = System.getProperty("veloauth.smoke.host");
        Assumptions.assumeTrue(host != null && !host.isBlank(),
                "Run through scripts/test-velocity-embedded.sh");
        int port = Integer.getInteger("veloauth.smoke.port", 25565);
        CountDownLatch joined = new CountDownLatch(1);
        CountDownLatch keptAlive = new CountDownLatch(1);
        CountDownLatch commandResponse = new CountDownLatch(1);
        AtomicBoolean commandSent = new AtomicBoolean();
        AtomicReference<ClientboundLoginPacket> loginPacket = new AtomicReference<>();
        MinecraftProtocol protocol = new MinecraftProtocol(
                new GameProfile(UUID.randomUUID(), "VAuthSmoke"), null);
        client = ClientNetworkSessionFactory.factory()
                .setAddress(host, port)
                .setProtocol(protocol)
                .setPacketHandlerExecutor(Runnable::run)
                .create();
        client.addListener(new SessionAdapter() {
            @Override
            public void packetReceived(Session session, Packet packet) {
                if (packet instanceof ClientboundLoginPacket login) {
                    loginPacket.set(login);
                    joined.countDown();
                } else if (packet instanceof ClientboundKeepAlivePacket) {
                    keptAlive.countDown();
                } else if (packet instanceof ClientboundSystemChatPacket && commandSent.get()) {
                    commandResponse.countDown();
                }
            }
        });

        client.connect(true);

        assertTrue(joined.await(20, TimeUnit.SECONDS),
                "Minecraft 26.2 client should reach VeloAuth embedded limbo through Velocity");
        assertTrue(loginPacket.get().isEnforcesSecureChat(),
                "Velocity should preserve embedded limbo's secure-chat marker");
        assertTrue(keptAlive.await(20, TimeUnit.SECONDS),
                "A cracked client should survive embedded limbo's first keepalive through Velocity");
        assertTrue(client.isConnected(),
                "The proxy must keep the cracked client connected in embedded limbo");
        commandSent.set(true);
        client.send(new ServerboundChatCommandPacket("login embedded-smoke-placeholder"));
        assertTrue(commandResponse.await(10, TimeUnit.SECONDS),
                "Velocity-owned authentication commands must remain usable after the keepalive");
        assertTrue(client.isConnected(),
                "An unauthenticated cracked client must remain in limbo after a rejected login");
    }
}
