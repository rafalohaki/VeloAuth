package net.rafalohaki.veloauth.authserver;

import net.kyori.adventure.text.Component;
import org.geysermc.mcprotocollib.auth.GameProfile;
import org.geysermc.mcprotocollib.network.BuiltinFlags;
import org.geysermc.mcprotocollib.network.Session;
import org.geysermc.mcprotocollib.network.event.server.ServerAdapter;
import org.geysermc.mcprotocollib.network.event.server.SessionAddedEvent;
import org.geysermc.mcprotocollib.network.event.server.SessionRemovedEvent;
import org.geysermc.mcprotocollib.network.event.session.DisconnectedEvent;
import org.geysermc.mcprotocollib.network.event.session.DisconnectingEvent;
import org.geysermc.mcprotocollib.network.event.session.SessionAdapter;
import org.geysermc.mcprotocollib.network.packet.Packet;
import org.geysermc.mcprotocollib.protocol.MinecraftConstants;
import org.geysermc.mcprotocollib.protocol.MinecraftProtocol;
import org.geysermc.mcprotocollib.protocol.data.ProtocolState;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.time.Clock;
import java.time.Duration;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;

/** Loopback-only Minecraft holding server translated from a minimal 1.8 protocol base. */
final class EmbeddedLimboServer implements AutoCloseable {

    static final int PROTOCOL_VERSION = LegacyProtocolCodec.PROTOCOL_VERSION;
    static final String MINECRAFT_VERSION = LegacyProtocolCodec.MINECRAFT_VERSION;
    static final int MAX_FRAME_BYTES = 1024 * 1024;

    private static final int MAX_SOCKET_BACKLOG = 1024;
    private static final int READ_TIMEOUT_SECONDS = 30;
    private static final int WRITE_TIMEOUT_SECONDS = 10;
    private static final int KEEP_ALIVE_INTERVAL_SECONDS = 15;
    private static final Duration SHUTDOWN_TIMEOUT = Duration.ofSeconds(8);
    private static final Duration BIND_ADDRESS_TIMEOUT = Duration.ofSeconds(2);
    private static final LegacyProtocolCodec.JoinGame JOIN_GAME = new LegacyProtocolCodec.JoinGame(1);
    private static final LegacyProtocolCodec.PlayerPosition INITIAL_POSITION =
            new LegacyProtocolCodec.PlayerPosition(0.5, 64.0, 0.5, 0.0F, 0.0F);

    private final Config config;
    private final PlayerMessages playerMessages;
    private final Logger logger;
    private final ProtocolRuntime protocolRuntime;
    private final ExpectedRedirectRegistry expectedRedirects;
    private final Semaphore connectionSlots;
    private final java.util.Set<Session> acceptedSessions = ConcurrentHashMap.newKeySet();
    private final AtomicReference<State> state = new AtomicReference<>(State.NEW);
    private final AtomicInteger playersInGame = new AtomicInteger();
    private final LongAdder rejectedConnections = new LongAdder();
    private final LongAdder invalidRedirects = new LongAdder();
    private final LongAdder timedOutConnections = new LongAdder();

    private volatile BoundedNetworkServer server;

    EmbeddedLimboServer(
            Config config,
            ProtocolRuntime protocolRuntime,
            PlayerMessages playerMessages,
            Logger logger) {
        this(config, protocolRuntime, playerMessages, logger, Clock.systemUTC());
    }

    EmbeddedLimboServer(
            Config config,
            ProtocolRuntime protocolRuntime,
            PlayerMessages playerMessages,
            Logger logger,
            Clock clock) {
        this.config = Objects.requireNonNull(config, "config");
        this.protocolRuntime = Objects.requireNonNull(protocolRuntime, "protocolRuntime");
        this.playerMessages = Objects.requireNonNull(playerMessages, "playerMessages");
        this.logger = Objects.requireNonNull(logger, "logger");
        expectedRedirects = new ExpectedRedirectRegistry(
                config.maxConnections(), config.loginTimeout(), Objects.requireNonNull(clock, "clock"));
        connectionSlots = new Semaphore(config.maxConnections());
    }

    void start() {
        if (!state.compareAndSet(State.NEW, State.STARTING)) {
            throw new IllegalStateException("Embedded limbo can only be started once (state=" + state.get() + ')');
        }

        BoundedNetworkServer candidate = new BoundedNetworkServer(
                LoopbackAddress.socket(config.port()),
                EmbeddedLimboServer::createProtocol,
                protocolRuntime,
                MAX_FRAME_BYTES,
                Math.min(config.maxConnections(), MAX_SOCKET_BACKLOG));
        candidate.setGlobalFlag(BuiltinFlags.READ_TIMEOUT, READ_TIMEOUT_SECONDS);
        candidate.setGlobalFlag(BuiltinFlags.WRITE_TIMEOUT, WRITE_TIMEOUT_SECONDS);
        candidate.addListener(new LimboServerListener());
        server = candidate;

        try {
            candidate.bind(true);
            if (!candidate.isListening()) {
                throw new IllegalStateException(
                        "MCProtocolLib did not bind embedded limbo to loopback port " + config.port());
            }
            SocketAddress boundAddress = candidate.awaitLocalAddress(BIND_ADDRESS_TIMEOUT);
            if (!(boundAddress instanceof InetSocketAddress socketAddress)
                    || socketAddress.getAddress() == null
                    || !socketAddress.getAddress().isLoopbackAddress()
                    || socketAddress.getPort() <= 0) {
                throw new IllegalStateException(
                        "Embedded limbo did not publish a valid loopback listener address");
            }
            state.set(State.LISTENING);
        } catch (RuntimeException e) {
            state.set(State.FAILED);
            closeNetworkServer(candidate);
            throw new IllegalStateException(
                    "Failed to start embedded limbo on IPv4 loopback port " + config.port(), e);
        }
    }

    void expectPlayer(UUID uniqueId, String username) {
        if (state.get() != State.LISTENING) {
            throw new IllegalStateException("Embedded limbo is not accepting redirects");
        }
        expectedRedirects.expect(uniqueId, username);
    }

    boolean isListening() {
        BoundedNetworkServer current = server;
        return state.get() == State.LISTENING && current != null && current.isListening();
    }

    int port() {
        BoundedNetworkServer current = server;
        if (current != null && current.localAddress() instanceof InetSocketAddress address) {
            return address.getPort();
        }
        return config.port();
    }

    int activeConnections() {
        return acceptedSessions.size();
    }

    int playersInGame() {
        return playersInGame.get();
    }

    long rejectedConnections() {
        return rejectedConnections.sum();
    }

    long invalidRedirects() {
        return invalidRedirects.sum();
    }

    long timedOutConnections() {
        return timedOutConnections.sum();
    }

    @Override
    public void close() {
        State previous = state.getAndUpdate(current -> switch (current) {
            case CLOSED, STOPPING -> current;
            default -> State.STOPPING;
        });
        if (previous == State.CLOSED || previous == State.STOPPING) {
            return;
        }

        expectedRedirects.clear();
        BoundedNetworkServer current = server;
        server = null;
        if (current != null) {
            closeNetworkServer(current);
        }
        acceptedSessions.clear();
        playersInGame.set(0);
        state.set(State.CLOSED);
    }

    private void closeNetworkServer(BoundedNetworkServer current) {
        try {
            if (!current.closeAndAwait(SHUTDOWN_TIMEOUT)) {
                logger.warn("Embedded limbo Netty event loops did not terminate within {} seconds",
                        SHUTDOWN_TIMEOUT.toSeconds());
            }
        } catch (RuntimeException e) {
            logger.warn("Embedded limbo network shutdown failed", e);
        }
    }

    private static MinecraftProtocol createProtocol() {
        MinecraftProtocol protocol = new MinecraftProtocol(LegacyProtocolCodec.CODEC);
        protocol.setUseDefaultListeners(false);
        return protocol;
    }

    private LegacyProtocolCodec.StatusResponse statusInfo() {
        return new LegacyProtocolCodec.StatusResponse(
                "VeloAuth " + protocolRuntime.minimumVersionName() + '-'
                        + protocolRuntime.maximumVersionName(),
                playerMessages.statusMotd(), config.maxConnections(), playersInGame.get());
    }

    private final class LimboServerListener extends ServerAdapter {
        @Override
        public void sessionAdded(SessionAddedEvent event) {
            Session session = event.getSession();
            if (!isLoopback(session.getRemoteAddress()) || !connectionSlots.tryAcquire()) {
                rejectedConnections.increment();
                session.disconnect(playerMessages.overloaded());
                return;
            }

            acceptedSessions.add(session);
            EmbeddedSessionListener listener = new EmbeddedSessionListener();
            session.addListener(listener);
            listener.start(session);
        }

        @Override
        public void sessionRemoved(SessionRemovedEvent event) {
            if (acceptedSessions.remove(event.getSession())) {
                connectionSlots.release();
            }
        }

        private boolean isLoopback(SocketAddress remoteAddress) {
            return remoteAddress instanceof InetSocketAddress socketAddress
                    && socketAddress.getAddress() != null
                    && socketAddress.getAddress().isLoopbackAddress();
        }
    }

    private final class EmbeddedSessionListener extends SessionAdapter {
        private final AtomicBoolean enteredGame = new AtomicBoolean();
        private boolean loginReceived;
        private boolean keepAlivePending;
        private int keepAliveChallenge;
        private ScheduledFuture<?> handshakeTimeoutTask;
        private ScheduledFuture<?> loginTimeoutTask;
        private ScheduledFuture<?> keepAliveTask;

        void start(Session session) {
            handshakeTimeoutTask = session.getChannel().eventLoop().schedule(
                    () -> timeout(session), config.handshakeTimeout().toMillis(), TimeUnit.MILLISECONDS);
        }

        @Override
        public void packetReceived(Session session, Packet packet) {
            ProtocolState protocolState = session.getPacketProtocol().getInboundState();
            switch (protocolState) {
                case HANDSHAKE -> handleHandshake(session, packet);
                case STATUS -> handleStatus(session, packet);
                case LOGIN -> handleLogin(session, packet);
                case GAME -> handleGame(session, packet);
                case CONFIGURATION -> reject(session);
            }
        }

        private void handleHandshake(Session session, Packet packet) {
            if (!(packet instanceof LegacyProtocolCodec.Handshake handshake)) {
                reject(session);
                return;
            }
            cancel(handshakeTimeoutTask);
            MinecraftProtocol protocol = session.getPacketProtocol();
            if (handshake.protocolVersion() != PROTOCOL_VERSION) {
                reject(session);
                return;
            }
            if (handshake.intent() == LegacyProtocolCodec.Intent.STATUS) {
                protocol.setOutboundState(ProtocolState.STATUS);
                session.switchInboundState(() -> protocol.setInboundState(ProtocolState.STATUS));
                return;
            }

            protocol.setOutboundState(ProtocolState.LOGIN);
            loginTimeoutTask = session.getChannel().eventLoop().schedule(
                    () -> timeout(session), config.loginTimeout().toMillis(), TimeUnit.MILLISECONDS);
            session.switchInboundState(() -> protocol.setInboundState(ProtocolState.LOGIN));
        }

        private void handleStatus(Session session, Packet packet) {
            if (packet instanceof LegacyProtocolCodec.StatusRequest) {
                session.send(statusInfo());
            } else if (packet instanceof LegacyProtocolCodec.Ping ping) {
                session.send(new LegacyProtocolCodec.Pong(ping.value()));
            }
        }

        private void handleLogin(Session session, Packet packet) {
            if (!(packet instanceof LegacyProtocolCodec.LoginStart loginStart) || loginReceived) {
                reject(session);
                return;
            }
            loginReceived = true;
            ExpectedRedirectRegistry.ExpectedPlayer expected = expectedRedirects
                    .consume(loginStart.username())
                    .orElse(null);
            if (expected == null) {
                invalidRedirects.increment();
                reject(session);
                return;
            }

            GameProfile profile = new GameProfile(expected.uniqueId(), expected.username());
            session.setFlag(MinecraftConstants.PROFILE_KEY, profile);
            session.send(new LegacyProtocolCodec.LoginSuccess(expected.uniqueId(), expected.username()),
                    () -> enterGame(session));
        }

        private void enterGame(Session session) {
            if (!session.isConnected() || !enteredGame.compareAndSet(false, true)) {
                return;
            }
            MinecraftProtocol protocol = session.getPacketProtocol();
            protocol.setOutboundState(ProtocolState.GAME);
            session.switchInboundState(() -> protocol.setInboundState(ProtocolState.GAME));
            cancel(loginTimeoutTask);
            playersInGame.incrementAndGet();
            session.send(JOIN_GAME);
            session.send(INITIAL_POSITION);
            keepAliveTask = session.getChannel().eventLoop().scheduleAtFixedRate(
                    () -> tickKeepAlive(session),
                    KEEP_ALIVE_INTERVAL_SECONDS,
                    KEEP_ALIVE_INTERVAL_SECONDS,
                    TimeUnit.SECONDS);
        }

        private void handleGame(Session session, Packet packet) {
            if (!(packet instanceof LegacyProtocolCodec.KeepAlive keepAlive)) {
                return;
            }
            if (!keepAlivePending || keepAlive.challenge() != keepAliveChallenge) {
                reject(session);
                return;
            }
            keepAlivePending = false;
        }

        private void tickKeepAlive(Session session) {
            if (!session.isConnected()) {
                cancel(keepAliveTask);
                return;
            }
            if (keepAlivePending) {
                timeout(session);
                return;
            }
            keepAlivePending = true;
            keepAliveChallenge = ThreadLocalRandom.current().nextInt();
            session.send(new LegacyProtocolCodec.KeepAlive(keepAliveChallenge));
        }

        private void timeout(Session session) {
            timedOutConnections.increment();
            session.disconnect(playerMessages.timeout());
        }

        private void reject(Session session) {
            session.disconnect(playerMessages.invalidRedirect());
        }

        @Override
        public void disconnecting(DisconnectingEvent event) {
            if (event.getSession().getPacketProtocol().getOutboundState() == ProtocolState.LOGIN) {
                event.getSession().send(new LegacyProtocolCodec.LoginDisconnect(event.getReason()));
            }
        }

        @Override
        public void disconnected(DisconnectedEvent event) {
            cancel(handshakeTimeoutTask);
            cancel(loginTimeoutTask);
            cancel(keepAliveTask);
            if (enteredGame.compareAndSet(true, false)) {
                playersInGame.decrementAndGet();
            }
        }

        private void cancel(ScheduledFuture<?> task) {
            if (task != null) {
                task.cancel(false);
            }
        }
    }

    record Config(int port, int maxConnections, Duration handshakeTimeout, Duration loginTimeout) {
        Config {
            if (port < 0 || port > 65535) {
                throw new IllegalArgumentException("port must be in range 0-65535");
            }
            if (maxConnections <= 0) {
                throw new IllegalArgumentException("maxConnections must be positive");
            }
            if (handshakeTimeout == null || handshakeTimeout.isZero() || handshakeTimeout.isNegative()) {
                throw new IllegalArgumentException("handshakeTimeout must be positive");
            }
            if (loginTimeout == null || loginTimeout.isZero() || loginTimeout.isNegative()) {
                throw new IllegalArgumentException("loginTimeout must be positive");
            }
        }
    }

    record PlayerMessages(
            Component statusMotd,
            Component invalidRedirect,
            Component overloaded,
            Component timeout) {
        PlayerMessages {
            Objects.requireNonNull(statusMotd, "statusMotd");
            Objects.requireNonNull(invalidRedirect, "invalidRedirect");
            Objects.requireNonNull(overloaded, "overloaded");
            Objects.requireNonNull(timeout, "timeout");
        }
    }

    enum State {
        NEW,
        STARTING,
        LISTENING,
        STOPPING,
        FAILED,
        CLOSED
    }
}
