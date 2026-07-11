package net.rafalohaki.veloauth.limbo;

import net.kyori.adventure.key.Key;
import net.kyori.adventure.text.Component;
import org.geysermc.mcprotocollib.network.Server;
import org.geysermc.mcprotocollib.network.event.server.ServerAdapter;
import org.geysermc.mcprotocollib.network.event.server.SessionAddedEvent;
import org.geysermc.mcprotocollib.network.event.server.SessionRemovedEvent;
import org.geysermc.mcprotocollib.network.event.session.SessionAdapter;
import org.geysermc.mcprotocollib.network.packet.Packet;
import org.geysermc.mcprotocollib.network.server.NetworkServer;
import org.geysermc.mcprotocollib.protocol.MinecraftConstants;
import org.geysermc.mcprotocollib.protocol.MinecraftProtocol;
import org.geysermc.mcprotocollib.protocol.data.game.entity.player.GameMode;
import org.geysermc.mcprotocollib.protocol.data.game.entity.player.PlayerSpawnInfo;
import org.geysermc.mcprotocollib.protocol.data.status.PlayerInfo;
import org.geysermc.mcprotocollib.protocol.data.status.ServerStatusInfo;
import org.geysermc.mcprotocollib.protocol.data.status.VersionInfo;
import org.geysermc.mcprotocollib.protocol.codec.MinecraftCodec;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.ClientboundLoginPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Spike (Etap 1) — minimal embedded Minecraft limbo server backed by MCProtocolLib's
 * {@link NetworkServer}. The whole purpose at this stage is to prove three things:
 *
 * <ol>
 *   <li>The shade excludes/relocations in {@code pom.xml} work — no {@code LinkageError}
 *       when the proxy loads the shaded jar.</li>
 *   <li>{@code ProxyServer.registerServer(...)} will open a TCP connection to our in-process
 *       {@link NetworkServer} bound on loopback.</li>
 *   <li>A vanilla client can reach PLAY state (receive {@link ClientboundLoginPacket}) and
 *       stay connected without being kicked for 60+ seconds (keep-alive is automatic via
 *       {@link MinecraftConstants#AUTOMATIC_KEEP_ALIVE_MANAGEMENT}).</li>
 * </ol>
 *
 * <p>This class is intentionally minimal. Configuration plumbing ({@code LimboConfig},
 * settings loader, {@code mode: embedded|external} flag) comes in Etap 5; modern-forwarding
 * HMAC verification comes in Etap 3; full Configuration-state join packets come in Etap 2.
 * What you see here is the smallest thing that could possibly work end-to-end.</p>
 *
 * <p><b>Threading:</b> {@link NetworkServer} owns its own Netty event-loop groups.
 * No {@code synchronized} anywhere — only atomics and volatile. Compliant with AGENTS.md
 * ("Never use {@code synchronized} — pins virtual threads").</p>
 */
public final class EmbeddedLimboServer {

    private static final Logger logger = LoggerFactory.getLogger(EmbeddedLimboServer.class);

    /** Static void-world JoinGame packet — identical for every connecting player. */
    private static final ClientboundLoginPacket JOIN_GAME = buildVoidJoinGame();

    private final String bindAddress;
    private final int port;

    private volatile Server server;
    private final AtomicInteger connectedPlayers = new AtomicInteger(0);

    public EmbeddedLimboServer(String bindAddress, int port) {
        this.bindAddress = bindAddress;
        this.port = port;
    }

    /** Actually allocated bind port — only meaningful after {@link #start()}. */
    public int getBoundPort() {
        Server s = server;
        if (s == null) {
            return -1;
        }
        // NetworkServer binds SocketAddress we gave it; for ephemeral port read it back.
        try {
            Object addr = s.getClass().getMethod("getLocalAddress").invoke(s);
            if (addr instanceof InetSocketAddress isa) {
                return isa.getPort();
            }
        } catch (Exception ignored) {
            // Fall through — return configured port
        }
        return port;
    }

    /** Binds the {@link NetworkServer} and configures all global flags. */
    public void start() {
        if (server != null) {
            throw new IllegalStateException("EmbeddedLimboServer already started");
        }

        SocketAddress bind = new InetSocketAddress(bindAddress, port);
        server = new NetworkServer(bind, MinecraftProtocol::new);

        // Velocity terminates Mojang encryption at the proxy; the loopback connection
        // proxy→embedded is plaintext. No Mojang auth either — proxy did it.
        server.setGlobalFlag(MinecraftConstants.ENCRYPT_CONNECTION, false);
        server.setGlobalFlag(MinecraftConstants.SHOULD_AUTHENTICATE, false);

        // Library handles periodic keep-alive and compression — no hand-rolled scheduler.
        server.setGlobalFlag(MinecraftConstants.AUTOMATIC_KEEP_ALIVE_MANAGEMENT, true);
        server.setGlobalFlag(MinecraftConstants.SERVER_COMPRESSION_THRESHOLD, 256);

        // Status (server-list ping) — Velocity's RegisteredServer.ping() needs this.
        server.setGlobalFlag(MinecraftConstants.SERVER_INFO_BUILDER_KEY, session -> buildStatus());

        // Login → Play transition: library invokes this handler once PLAY state is entered.
        server.setGlobalFlag(MinecraftConstants.SERVER_LOGIN_HANDLER_KEY, session -> {
            // Band-aid copied from MCProtocolLib's own MinecraftProtocolTest — there's a known
            // race where the server replies to ServerboundFinishConfigurationPacket before the
            // client transitions CONFIGURATION → GAME. Etap 2 will investigate the root cause;
            // for the spike we just sleep briefly.
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            session.send(JOIN_GAME);
        });

        // Per-session lifecycle hooks
        server.addListener(new LimboServerAdapter(this));

        if (!server.bind(true).isListening()) {
            throw new IllegalStateException("Failed to bind embedded limbo on " + bind);
        }

        logger.info("[Limbo] Embedded limbo server started on {}:{}", bindAddress, getBoundPort());
    }

    /** Gracefully stops the server and waits for active channels to close. */
    public void stop() {
        Server s = server;
        if (s == null) {
            return;
        }
        s.close(true);
        server = null;
        connectedPlayers.set(0);
        logger.info("[Limbo] Embedded limbo server stopped");
    }

    public int getConnectedPlayerCount() {
        return connectedPlayers.get();
    }

    private ServerStatusInfo buildStatus() {
        return new ServerStatusInfo(
                Component.text("VeloAuth — /login or /register"),
                new PlayerInfo(/* max */ 100, connectedPlayers.get(), new ArrayList<>()),
                new VersionInfo(
                        MinecraftCodec.CODEC.getMinecraftVersion(),
                        MinecraftCodec.CODEC.getProtocolVersion()),
                null,                 // favicon (PNG base64) — none in spike
                false                 // enforces secure chat
        );
    }

    /**
     * Build a minimal void-world {@link ClientboundLoginPacket}.
     *
     * <p>Constructor signature (verified via {@code javap} on the 26.2-SNAPSHOT jar):
     * {@code (int entityId, boolean hardcore, Key[] worldNames, int maxPlayers, int viewDistance,
     *  int simulationDistance, boolean reducedDebugInfo, boolean enableRespawnScreen,
     *  boolean doLimitedCrafting, PlayerSpawnInfo commonPlayerSpawnInfo, boolean onlineMode,
     *  boolean enforcesSecureChat)}. The {@code PlayerSpawnInfo} carries dimension/world/gamemode
     *  data. Note: DeepWiki/test sources document an 11-arg constructor — the live 26.2-SNAPSHOT
     *  has 12 args (added {@code onlineMode} before {@code enforcesSecureChat}).</p>
     */
    private static ClientboundLoginPacket buildVoidJoinGame() {
        Key overworld = Key.key("minecraft:overworld");
        PlayerSpawnInfo spawnInfo = new PlayerSpawnInfo(
                0,                              // dimension id
                overworld,                      // world name
                100,                            // hashed seed
                GameMode.SURVIVAL,              // current gamemode
                GameMode.SURVIVAL,              // previous gamemode (for spectator toggle)
                false,                          // debug
                false,                          // flat
                null,                           // last death pos
                100,                            // portal cooldown
                20                              // sea level
        );
        return new ClientboundLoginPacket(
                /* entityId */ 0,
                /* hardcore */ false,
                new Key[]{ overworld },         // world names (registry)
                /* maxPlayers */ 16,
                /* viewDistance */ 16,
                /* simulationDistance */ 16,
                /* reducedDebugInfo */ false,
                /* enableRespawnScreen */ false,
                /* doLimitedCrafting */ false,
                spawnInfo,
                /* onlineMode */ false,         // backend never sees Mojang auth
                /* enforcesSecureChat */ false
        );
    }

    /** Server-wide session lifecycle adapter — increments/decrements player counter. */
    private static final class LimboServerAdapter extends ServerAdapter {

        private final EmbeddedLimboServer owner;

        private LimboServerAdapter(EmbeddedLimboServer owner) {
            this.owner = owner;
        }

        @Override
        public void sessionAdded(SessionAddedEvent event) {
            int now = owner.connectedPlayers.incrementAndGet();
            logger.debug("[Limbo] Session added (online={})", now);
            event.getSession().addListener(new LimboPlayerAdapter());
        }

        @Override
        public void sessionRemoved(SessionRemovedEvent event) {
            int now = owner.connectedPlayers.decrementAndGet();
            logger.debug("[Limbo] Session removed (online={})", now);
        }
    }

    /**
     * Per-player session adapter. For the spike this only logs incoming packets at trace
     * level — we don't care about chat/movement yet because Velocity intercepts
     * {@code /login} etc. at the proxy command layer before they reach the backend.
     *
     * <p>Etap 3 will extend this to intercept {@code velocity:player_info}
     * Login Plugin Query for modern forwarding.</p>
     */
    private static final class LimboPlayerAdapter extends SessionAdapter {

        @Override
        public void packetReceived(org.geysermc.mcprotocollib.network.Session session, Packet packet) {
            // Intentionally empty for spike. Logging every packet would be too noisy on
            // a busy server; keep-alive acks (the only packets we expect) are silent.
        }
    }
}
