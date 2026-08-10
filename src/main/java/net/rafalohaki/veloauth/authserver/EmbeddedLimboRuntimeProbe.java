package net.rafalohaki.veloauth.authserver;

import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;
import org.geysermc.mcprotocollib.auth.GameProfile;
import org.geysermc.mcprotocollib.network.ClientSession;
import org.geysermc.mcprotocollib.network.Session;
import org.geysermc.mcprotocollib.network.event.session.DisconnectedEvent;
import org.geysermc.mcprotocollib.network.event.session.PacketErrorEvent;
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
import org.slf4j.Logger;

import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Player-level loopback preflight for a newly selected ViaVersion runtime. */
final class EmbeddedLimboRuntimeProbe {

    private static final Key DIMENSION_REGISTRY = Key.key("minecraft", "dimension_type");
    private static final Key END_WORLD = Key.key("minecraft", "the_end");
    private static final Key VELOCITY_FORWARDING = Key.key("velocity", "player_info");
    private static final Duration PROBE_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration PROBE_KEEP_ALIVE_INTERVAL = Duration.ofMillis(500);
    private static final int EXPECTED_SIGNALS = 6;

    private EmbeddedLimboRuntimeProbe() {
    }

    static void verify(ManagedProtocolRuntime runtime, Logger logger) {
        Objects.requireNonNull(runtime, "runtime");
        Objects.requireNonNull(logger, "logger");
        UUID playerId = UUID.randomUUID();
        String username = "VAuthProbe";
        try (EmbeddedLimboServer server = new EmbeddedLimboServer(
                new EmbeddedLimboServer.Config(
                        0,
                        1,
                        Duration.ofSeconds(3),
                        Duration.ofSeconds(6),
                        PROBE_KEEP_ALIVE_INTERVAL),
                runtime,
                new EmbeddedLimboServer.PlayerMessages(
                        Component.empty(), Component.empty(), Component.empty(), Component.empty()),
                logger)) {
            ClientSession client = null;
            try {
                server.start();
                server.expectPlayer(playerId, username);
                ProbeEvidence evidence = new ProbeEvidence();
                MinecraftProtocol protocol = new MinecraftProtocol(new GameProfile(playerId, username), null);
                int clientProtocol = protocol.getCodec().getProtocolVersion();
                if (!runtime.supportsProtocol(clientProtocol)) {
                    throw new IllegalStateException(
                            "Managed runtime does not support the bundled-client protocol " + clientProtocol);
                }
                client = ClientNetworkSessionFactory.factory()
                        .setAddress(LoopbackAddress.socket(0).getHostString(), server.port())
                        .setProtocol(protocol)
                        .setPacketHandlerExecutor(Runnable::run)
                        .create();
                client.addListener(evidence);
                client.connect(true);

                if (!evidence.await(PROBE_TIMEOUT)) {
                    throw new IllegalStateException(
                            "Bundled-client loopback login and keepalive did not complete within "
                                    + PROBE_TIMEOUT.toSeconds() + " seconds ("
                                    + evidence.describe(client, server) + ')');
                }
                TimeUnit.MILLISECONDS.sleep(PROBE_KEEP_ALIVE_INTERVAL.multipliedBy(2).toMillis());
                evidence.verify(client, server);
            } finally {
                if (client != null && client.isConnected()) {
                    client.disconnect("VeloAuth embedded runtime preflight complete");
                }
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted during embedded protocol runtime preflight", interrupted);
        } catch (RuntimeException | LinkageError failure) {
            throw new IllegalStateException(
                    "Embedded protocol runtime failed the bundled-client loopback preflight", failure);
        }
    }

    private static final class ProbeEvidence extends SessionAdapter {
        private final CountDownLatch signals = new CountDownLatch(EXPECTED_SIGNALS);
        private final AtomicBoolean forwardingRequest = new AtomicBoolean();
        private final AtomicBoolean loadingStarted = new AtomicBoolean();
        private final AtomicBoolean keepAliveReceived = new AtomicBoolean();
        private final AtomicInteger endDimensionId = new AtomicInteger(-1);
        private final AtomicReference<ClientboundLoginPacket> login = new AtomicReference<>();
        private final AtomicReference<ClientboundPlayerPositionPacket> position = new AtomicReference<>();
        private final AtomicReference<Throwable> clientFailure = new AtomicReference<>();

        @Override
        public void packetReceived(Session session, Packet packet) {
            if (packet instanceof ClientboundCustomQueryPacket query
                    && VELOCITY_FORWARDING.equals(query.getChannel())
                    && query.getData().length == 0
                    && forwardingRequest.compareAndSet(false, true)) {
                signals.countDown();
            } else if (packet instanceof ClientboundRegistryDataPacket registry
                    && DIMENSION_REGISTRY.equals(registry.getRegistry())) {
                for (int index = 0; index < registry.getEntries().size(); index++) {
                    if (END_WORLD.equals(registry.getEntries().get(index).getId())
                            && endDimensionId.compareAndSet(-1, index)) {
                        signals.countDown();
                        break;
                    }
                }
            } else if (packet instanceof ClientboundLoginPacket joined
                    && login.compareAndSet(null, joined)) {
                signals.countDown();
            } else if (packet instanceof ClientboundGameEventPacket event
                    && event.getNotification() == GameEvent.LEVEL_CHUNKS_LOAD_START
                    && loadingStarted.compareAndSet(false, true)) {
                signals.countDown();
            } else if (packet instanceof ClientboundPlayerPositionPacket positioned
                    && position.compareAndSet(null, positioned)) {
                signals.countDown();
            } else if (packet instanceof ClientboundKeepAlivePacket
                    && keepAliveReceived.compareAndSet(false, true)) {
                signals.countDown();
            }
        }

        @Override
        public void packetError(PacketErrorEvent event) {
            clientFailure.compareAndSet(null, event.getCause());
        }

        @Override
        public void disconnected(DisconnectedEvent event) {
            if (event.getCause() != null) {
                clientFailure.compareAndSet(null, event.getCause());
            }
        }

        boolean await(Duration timeout) throws InterruptedException {
            return signals.await(timeout.toMillis(), TimeUnit.MILLISECONDS);
        }

        void verify(ClientSession client, EmbeddedLimboServer server) {
            ClientboundLoginPacket joined = Objects.requireNonNull(login.get(), "missing Join Game packet");
            ClientboundPlayerPositionPacket positioned =
                    Objects.requireNonNull(position.get(), "missing player position packet");
            int endId = endDimensionId.get();
            if (!forwardingRequest.get()
                    || !loadingStarted.get()
                    || !keepAliveReceived.get()
                    || endId < 0
                    || joined.getCommonPlayerSpawnInfo().getDimension() != endId
                    || !END_WORLD.equals(joined.getCommonPlayerSpawnInfo().getWorldName())
                    || joined.getCommonPlayerSpawnInfo().getGameMode() != GameMode.SPECTATOR
                    || !Arrays.asList(joined.getWorldNames()).contains(END_WORLD)
                    || !joined.isEnforcesSecureChat()
                    || positioned.getPosition().getY() < 320.0
                    || !client.isConnected()
                    || server.playersInGame() != 1
                    || server.invalidRedirects() != 0
                    || server.timedOutConnections() != 0) {
                throw new IllegalStateException(
                        "Bundled-client loopback produced incomplete or unsafe limbo state");
            }
        }

        String describe(ClientSession client, EmbeddedLimboServer server) {
            return "forwarding=" + forwardingRequest.get()
                    + ", endRegistry=" + (endDimensionId.get() >= 0)
                    + ", login=" + (login.get() != null)
                    + ", loading=" + loadingStarted.get()
                    + ", position=" + (position.get() != null)
                    + ", keepalive=" + keepAliveReceived.get()
                    + ", connected=" + client.isConnected()
                    + ", serverConnections=" + server.activeConnections()
                    + ", playersInGame=" + server.playersInGame()
                    + ", invalidRedirects=" + server.invalidRedirects()
                    + ", timeouts=" + server.timedOutConnections()
                    + ", clientFailure=" + failureSummary();
        }

        private String failureSummary() {
            Throwable failure = clientFailure.get();
            return failure == null
                    ? "none"
                    : failure.getClass().getSimpleName() + ':' + failure.getMessage();
        }
    }
}
