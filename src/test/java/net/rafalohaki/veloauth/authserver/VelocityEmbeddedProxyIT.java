package net.rafalohaki.veloauth.authserver;

import org.geysermc.mcprotocollib.auth.GameProfile;
import org.geysermc.mcprotocollib.network.ClientSession;
import org.geysermc.mcprotocollib.network.Session;
import org.geysermc.mcprotocollib.network.event.session.SessionAdapter;
import org.geysermc.mcprotocollib.network.factory.ClientNetworkSessionFactory;
import org.geysermc.mcprotocollib.network.packet.Packet;
import org.geysermc.mcprotocollib.protocol.MinecraftProtocol;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.ClientboundLoginPacket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

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
    void loginLatestClientThroughVelocityShouldEnterEmbeddedLimbo() throws Exception {
        String host = System.getProperty("veloauth.smoke.host");
        Assumptions.assumeTrue(host != null && !host.isBlank(),
                "Run through scripts/test-velocity-embedded.sh");
        int port = Integer.getInteger("veloauth.smoke.port", 25565);
        CountDownLatch joined = new CountDownLatch(1);
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
                if (packet instanceof ClientboundLoginPacket) {
                    joined.countDown();
                }
            }
        });

        client.connect(true);

        assertTrue(joined.await(20, TimeUnit.SECONDS),
                "Minecraft 26.2 client should reach VeloAuth embedded limbo through Velocity");
    }
}
