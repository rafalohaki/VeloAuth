package net.rafalohaki.veloauth.authserver;

import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.geysermc.mcprotocollib.auth.GameProfile;
import org.geysermc.mcprotocollib.network.ClientSession;
import org.geysermc.mcprotocollib.network.Session;
import org.geysermc.mcprotocollib.network.event.session.SessionAdapter;
import org.geysermc.mcprotocollib.network.factory.ClientNetworkSessionFactory;
import org.geysermc.mcprotocollib.network.packet.Packet;
import org.geysermc.mcprotocollib.protocol.MinecraftProtocol;
import org.geysermc.mcprotocollib.protocol.data.game.entity.player.GameMode;
import org.geysermc.mcprotocollib.protocol.data.game.entity.player.HandPreference;
import org.geysermc.mcprotocollib.protocol.data.game.level.notify.GameEvent;
import org.geysermc.mcprotocollib.protocol.data.game.setting.ChatVisibility;
import org.geysermc.mcprotocollib.protocol.data.game.setting.ParticleStatus;
import org.geysermc.mcprotocollib.protocol.packet.configuration.clientbound.ClientboundRegistryDataPacket;
import org.geysermc.mcprotocollib.protocol.packet.common.clientbound.ClientboundKeepAlivePacket;
import org.geysermc.mcprotocollib.protocol.packet.common.serverbound.ServerboundClientInformationPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.ClientboundLoginPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.ClientboundSystemChatPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.entity.player.ClientboundPlayerPositionPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.level.ClientboundGameEventPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.serverbound.ServerboundChatCommandPacket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
        CountDownLatch terrainLoadingStarted = new CountDownLatch(1);
        CountDownLatch positionedOutsideVoidWorld = new CountDownLatch(1);
        CountDownLatch keptAlive = new CountDownLatch(1);
        CountDownLatch commandResponse = new CountDownLatch(1);
        AtomicInteger endDimensionId = new AtomicInteger(-1);
        AtomicReference<ClientboundLoginPacket> loginPacket = new AtomicReference<>();
        AtomicReference<ClientboundPlayerPositionPacket> positionPacket = new AtomicReference<>();
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
                if (packet instanceof ClientboundRegistryDataPacket registryData
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
                } else if (packet instanceof ClientboundSystemChatPacket chat
                        && PlainTextComponentSerializer.plainText().serialize(chat.getContent())
                                .contains("Użycie: /login <hasło>")) {
                    commandResponse.countDown();
                }
            }
        });

        client.connect(true);

        assertTrue(joined.await(20, TimeUnit.SECONDS),
                "The latest client should reach VeloAuth embedded limbo through Velocity");
        assertTrue(endDimensionId.get() >= 0,
                "Velocity should deliver the End dimension registry entry");
        assertEquals(endDimensionId.get(), loginPacket.get().getCommonPlayerSpawnInfo().getDimension(),
                "Velocity should preserve embedded limbo's End dimension type");
        assertEquals(Key.key("minecraft", "the_end"),
                loginPacket.get().getCommonPlayerSpawnInfo().getWorldName(),
                "Velocity should preserve embedded limbo's End world identifier");
        assertEquals(GameMode.SPECTATOR,
                loginPacket.get().getCommonPlayerSpawnInfo().getGameMode(),
                "Velocity should preserve embedded limbo's suspended spectator state");
        assertTrue(loginPacket.get().isEnforcesSecureChat(),
                "Velocity should preserve embedded limbo's secure-chat marker");
        assertTrue(terrainLoadingStarted.await(10, TimeUnit.SECONDS),
                "Velocity should preserve ViaVersion's start-loading-chunks event");
        assertTrue(positionedOutsideVoidWorld.await(10, TimeUnit.SECONDS),
                "Velocity should deliver the embedded limbo position to the latest client");
        assertTrue(positionPacket.get().getPosition().getY() >= 320.0,
                "Latest clients must spawn above the unloaded void world to leave Loading terrain");
        assertTrue(keptAlive.await(20, TimeUnit.SECONDS),
                "A cracked client should survive embedded limbo's first keepalive through Velocity");
        assertTrue(client.isConnected(),
                "The proxy must keep the cracked client connected in embedded limbo");
        client.send(new ServerboundClientInformationPacket("pl_pl", 8, ChatVisibility.FULL, true,
                List.of(), HandPreference.RIGHT_HAND, false, true, ParticleStatus.ALL));
        client.send(new ServerboundChatCommandPacket("login"));
        assertTrue(commandResponse.await(10, TimeUnit.SECONDS),
                "An English-configured proxy should answer the Polish client's /login in Polish");
        assertTrue(client.isConnected(),
                "An unauthenticated cracked client must remain in limbo after a rejected login");
    }
}
