package net.rafalohaki.veloauth.authserver;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.BuildConstants;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

/** Single restart-scoped owner of the external or self-contained authentication topology. */
public final class AuthServerProvider implements AutoCloseable {

    public static final String EMBEDDED_SERVER_NAME = "veloauth-embedded-limbo";
    public static final int BASE_PROTOCOL = LegacyProtocolCodec.PROTOCOL_VERSION;
    public static final int MIN_SUPPORTED_PROTOCOL = BASE_PROTOCOL;

    private final ProxyServer proxyServer;
    private final Logger logger;
    private final Messages messages;
    private final Settings.AuthServerMode mode;
    private final String serverName;
    private final EmbeddedConfig embeddedConfig;
    private final Path dataDirectory;
    private final RuntimeFactory runtimeFactory;
    private final AtomicReference<State> state = new AtomicReference<>(State.NEW);
    private final ReentrantLock lifecycleLock = new ReentrantLock();

    private volatile ServerInfo ownedServerInfo;
    private volatile EmbeddedLimboServer embeddedServer;
    private volatile ProtocolRuntime protocolRuntime;

    private AuthServerProvider(
            ProxyServer proxyServer,
            Logger logger,
            Messages messages,
            Settings.AuthServerMode mode,
            String serverName,
            EmbeddedConfig embeddedConfig,
            Path dataDirectory,
            RuntimeFactory runtimeFactory) {
        this.proxyServer = Objects.requireNonNull(proxyServer, "proxyServer");
        this.logger = Objects.requireNonNull(logger, "logger");
        this.messages = messages;
        this.mode = Objects.requireNonNull(mode, "mode");
        this.serverName = Objects.requireNonNull(serverName, "serverName");
        this.embeddedConfig = embeddedConfig;
        this.dataDirectory = dataDirectory;
        this.runtimeFactory = runtimeFactory;
    }

    /** Creates a provider from the validated restart-scoped configuration. */
    public static AuthServerProvider create(
            ProxyServer proxyServer,
            Settings settings,
            Messages messages,
            Logger logger,
            Path dataDirectory) {
        return create(proxyServer, settings, messages, logger, dataDirectory,
                (directory, runtimeLogger) -> ManagedProtocolRuntime.open(
                        directory, runtimeLogger, BuildConstants.VERSION));
    }

    static AuthServerProvider create(
            ProxyServer proxyServer,
            Settings settings,
            Messages messages,
            Logger logger,
            Path dataDirectory,
            RuntimeFactory runtimeFactory) {
        Objects.requireNonNull(settings, "settings");
        Settings.AuthServerMode configuredMode = settings.getAuthServerMode();
        if (configuredMode == Settings.AuthServerMode.EXTERNAL) {
            return forExternal(proxyServer, settings.getAuthServerName(), logger);
        }

        Settings.EmbeddedAuthServerSettings embedded = settings.getEmbeddedAuthServerSettings();
        EmbeddedConfig snapshot = new EmbeddedConfig(
                embedded.getPort(),
                embedded.getMaxConnections(),
                Duration.ofSeconds(embedded.getHandshakeTimeoutSeconds()),
                Duration.ofSeconds(embedded.getLoginTimeoutSeconds()),
                embedded.isReviewedRuntimeUpdatesEnabled());
        return new AuthServerProvider(
                proxyServer,
                logger,
                Objects.requireNonNull(messages, "messages"),
                configuredMode,
                EMBEDDED_SERVER_NAME,
                snapshot,
                Objects.requireNonNull(dataDirectory, "dataDirectory").toAbsolutePath().normalize(),
                Objects.requireNonNull(runtimeFactory, "runtimeFactory"));
    }

    /** Compatibility factory used by existing external-mode integrations and tests. */
    public static AuthServerProvider forExternal(
            ProxyServer proxyServer,
            String serverName,
            Logger logger) {
        if (serverName == null || serverName.isBlank()) {
            throw new IllegalArgumentException("external auth server name must not be empty");
        }
        return new AuthServerProvider(
                proxyServer, logger, null, Settings.AuthServerMode.EXTERNAL, serverName,
                null, null, null);
    }

    /** Starts and atomically publishes the selected topology. */
    public void start() {
        if (!state.compareAndSet(State.NEW, State.STARTING)) {
            throw new IllegalStateException("Auth-server provider can only be started once (state=" + state.get() + ')');
        }
        if (mode == Settings.AuthServerMode.EXTERNAL) {
            lifecycleLock.lock();
            try {
                requireStarting();
                state.set(State.READY);
            } finally {
                lifecycleLock.unlock();
            }
            return;
        }

        ProtocolRuntime unopenedRuntime = null;
        EmbeddedLimboServer unpublishedServer = null;
        try {
            requireStarting();
            ensureReservedNameIsAvailable();
            ProtocolRuntime runtime = runtimeFactory.open(dataDirectory, logger);
            unopenedRuntime = runtime;
            requireStarting();
            verifyProtocolRuntime(runtime);

            EmbeddedLimboServer candidate = new EmbeddedLimboServer(
                    new EmbeddedLimboServer.Config(
                            embeddedConfig.port(), embeddedConfig.maxConnections(),
                            embeddedConfig.handshakeTimeout(), embeddedConfig.loginTimeout()),
                    runtime,
                    playerMessages(),
                    logger);
            unpublishedServer = candidate;
            candidate.start();
            requireStarting();

            ServerInfo serverInfo = new ServerInfo(serverName, LoopbackAddress.socket(candidate.port()));
            lifecycleLock.lock();
            try {
                requireStarting();
                protocolRuntime = runtime;
                embeddedServer = candidate;
                ownedServerInfo = serverInfo;
                unopenedRuntime = null;
                unpublishedServer = null;

                RegisteredServer registration = proxyServer.registerServer(serverInfo);
                Optional<RegisteredServer> published = proxyServer.getServer(serverName);
                if (registration == null || published.isEmpty()
                        || !serverInfo.equals(published.get().getServerInfo())) {
                    throw new IllegalStateException(
                            "Velocity did not publish the embedded auth-server registration");
                }
                runtime.confirmOperational();
                requireStarting();
                state.set(State.READY);
            } finally {
                lifecycleLock.unlock();
            }
        } catch (RuntimeException | LinkageError exception) {
            state.compareAndSet(State.STARTING, State.FAILED);
            closeUnpublishedServer(unpublishedServer);
            closeUnpublishedRuntime(unopenedRuntime);
            lifecycleLock.lock();
            try {
                rollbackPartialStart();
            } finally {
                lifecycleLock.unlock();
            }
            throw new IllegalStateException("Embedded auth-server startup failed", exception);
        }
    }

    private void requireStarting() {
        State current = state.get();
        if (current != State.STARTING) {
            throw new IllegalStateException(
                    "Auth-server provider startup was cancelled (state=" + current + ')');
        }
    }

    private static void verifyProtocolRuntime(ProtocolRuntime runtime) {
        if (runtime.minimumProtocol() != MIN_SUPPORTED_PROTOCOL
                || runtime.maximumProtocol() < MIN_SUPPORTED_PROTOCOL
                || !runtime.supportsProtocol(MIN_SUPPORTED_PROTOCOL)
                || !runtime.supportsProtocol(runtime.maximumProtocol())
                || runtime.minimumVersionName() == null
                || runtime.minimumVersionName().isBlank()
                || runtime.maximumVersionName() == null
                || runtime.maximumVersionName().isBlank()) {
            throw new IllegalStateException(
                    "Embedded protocol runtime does not provide the required Minecraft 1.8+ matrix");
        }
    }

    private void ensureReservedNameIsAvailable() {
        if (proxyServer.getServer(serverName).isPresent()) {
            throw new IllegalStateException(
                    "Velocity server name '" + serverName + "' is reserved by embedded mode but already exists");
        }
    }

    private EmbeddedLimboServer.PlayerMessages playerMessages() {
        return new EmbeddedLimboServer.PlayerMessages(
                messages.component("embedded.status.motd", NamedTextColor.GOLD),
                messages.component("embedded.disconnect.invalid_forwarding", NamedTextColor.RED),
                messages.component("embedded.disconnect.overloaded", NamedTextColor.RED),
                messages.component("embedded.disconnect.timeout", NamedTextColor.RED));
    }

    /** Returns the currently usable auth server without exposing a partially started listener. */
    public Optional<RegisteredServer> resolve() {
        if (state.get() != State.READY) {
            return Optional.empty();
        }
        if (mode == Settings.AuthServerMode.EXTERNAL) {
            return proxyServer.getServer(serverName);
        }

        ServerInfo serverInfo = ownedServerInfo;
        EmbeddedLimboServer engine = embeddedServer;
        if (serverInfo == null || engine == null || !engine.isListening()) {
            return Optional.empty();
        }
        return proxyServer.getServer(serverName)
                .filter(current -> serverInfo.equals(current.getServerInfo()));
    }

    /** Checks a server identity against the provider's restart-scoped topology. */
    public boolean isAuthServer(RegisteredServer server) {
        if (server == null) {
            return false;
        }
        if (mode == Settings.AuthServerMode.EXTERNAL) {
            return serverName.equals(server.getServerInfo().getName());
        }
        ServerInfo serverInfo = ownedServerInfo;
        return state.get() == State.READY && serverInfo != null
                && serverInfo.equals(server.getServerInfo());
    }

    /** Authorizes one upcoming Velocity redirect into the private loopback listener. */
    public Preparation prepare(Player player) {
        Objects.requireNonNull(player, "player");
        if (mode == Settings.AuthServerMode.EXTERNAL) {
            return Preparation.READY;
        }

        EmbeddedLimboServer engine = embeddedServer;
        ProtocolRuntime runtime = protocolRuntime;
        if (state.get() != State.READY || engine == null || runtime == null || !engine.isListening()) {
            return Preparation.UNAVAILABLE;
        }
        if (player.getProtocolVersion() == null
                || !runtime.supportsProtocol(player.getProtocolVersion().getProtocol())) {
            return Preparation.UNSUPPORTED_PROTOCOL;
        }
        try {
            engine.expectPlayer(player.getUniqueId(), player.getUsername());
            return Preparation.READY;
        } catch (ExpectedRedirectRegistry.CapacityExceededException exception) {
            return Preparation.CAPACITY_REACHED;
        } catch (IllegalArgumentException | IllegalStateException exception) {
            return Preparation.UNAVAILABLE;
        }
    }

    public String serverName() {
        return serverName;
    }

    public Settings.AuthServerMode mode() {
        return mode;
    }

    public String compatibilityDescription() {
        if (mode == Settings.AuthServerMode.EXTERNAL) {
            return "external-server-managed";
        }
        ProtocolRuntime runtime = protocolRuntime;
        String versionRange = runtime == null
                ? "1.8+"
                : runtime.minimumVersionName() + '-' + runtime.maximumVersionName();
        return "Minecraft " + versionRange + " (managed ViaVersion "
                + (runtime == null ? BuildConstants.EMBEDDED_VIAVERSION_VERSION : runtime.runtimeVersion()) + ')';
    }

    /** Stages the maintainer-reviewed candidate without touching the current translator. */
    public void stageProtocolRuntimeUpdate() {
        if (!isProtocolRuntimeUpdateEnabled()) {
            return;
        }
        ProtocolRuntime runtime = protocolRuntime;
        if (state.get() != State.READY || runtime == null) {
            return;
        }
        try {
            RuntimeSnapshotManager.UpdateResult result = new RuntimeSnapshotManager(dataDirectory, logger)
                    .stageReviewedRuntime(runtime.runtimeVersion());
            if (result == RuntimeSnapshotManager.UpdateResult.CURRENT) {
                logger.debug("Embedded ViaVersion runtime {} matches the reviewed candidate",
                        runtime.runtimeVersion());
            }
        } catch (RuntimeException exception) {
            logger.warn("Unable to stage the maintainer-reviewed embedded ViaVersion runtime; "
                    + "the current verified runtime remains active", exception);
        }
    }

    /** Returns whether this restart-scoped provider opted into reviewed runtime staging. */
    public boolean isProtocolRuntimeUpdateEnabled() {
        return mode == Settings.AuthServerMode.EMBEDDED
                && embeddedConfig.reviewedRuntimeUpdatesEnabled();
    }

    public boolean isReady() {
        return state.get() == State.READY && resolve().isPresent();
    }

    @Override
    public void close() {
        lifecycleLock.lock();
        try {
            if (!beginStopping()) {
                return;
            }
            unregisterOwnedServer();
            closeEmbeddedServer();
            closeProtocolRuntime();
            state.set(State.CLOSED);
        } finally {
            lifecycleLock.unlock();
        }
    }

    private boolean beginStopping() {
        while (true) {
            State current = state.get();
            if (current == State.CLOSED || current == State.STOPPING) {
                return false;
            }
            if (state.compareAndSet(current, State.STOPPING)) {
                return true;
            }
        }
    }

    private void rollbackPartialStart() {
        unregisterOwnedServer();
        closeEmbeddedServer();
        closeProtocolRuntime();
    }

    private void closeUnpublishedServer(EmbeddedLimboServer server) {
        if (server == null) {
            return;
        }
        try {
            server.close();
        } catch (RuntimeException | LinkageError exception) {
            logger.warn("Failed to close unpublished embedded auth server", exception);
        }
    }

    private void closeUnpublishedRuntime(ProtocolRuntime runtime) {
        if (runtime == null) {
            return;
        }
        try {
            runtime.close();
        } catch (RuntimeException | LinkageError exception) {
            logger.warn("Failed to close unpublished embedded protocol runtime", exception);
        }
    }

    private void unregisterOwnedServer() {
        ServerInfo serverInfo = ownedServerInfo;
        ownedServerInfo = null;
        if (serverInfo == null) {
            return;
        }
        try {
            Optional<RegisteredServer> current = proxyServer.getServer(serverName);
            if (current.isEmpty() || serverInfo.equals(current.get().getServerInfo())) {
                proxyServer.unregisterServer(serverInfo);
            } else {
                logger.warn("Embedded auth-server registration '{}' was replaced; leaving it untouched", serverName);
            }
        } catch (RuntimeException exception) {
            logger.warn("Failed to unregister embedded auth server '{}'", serverName, exception);
        }
    }

    private void closeEmbeddedServer() {
        EmbeddedLimboServer current = embeddedServer;
        embeddedServer = null;
        if (current == null) {
            return;
        }
        try {
            current.close();
        } catch (RuntimeException | LinkageError exception) {
            logger.warn("Failed to close embedded auth server", exception);
        }
    }

    private void closeProtocolRuntime() {
        ProtocolRuntime current = protocolRuntime;
        protocolRuntime = null;
        if (current == null) {
            return;
        }
        try {
            current.close();
        } catch (RuntimeException | LinkageError exception) {
            logger.warn("Failed to close embedded protocol runtime", exception);
        }
    }

    public enum Preparation {
        READY,
        UNAVAILABLE,
        UNSUPPORTED_PROTOCOL,
        CAPACITY_REACHED
    }

    @FunctionalInterface
    interface RuntimeFactory {
        ProtocolRuntime open(Path dataDirectory, Logger logger);
    }

    private record EmbeddedConfig(
            int port,
            int maxConnections,
            Duration handshakeTimeout,
            Duration loginTimeout,
            boolean reviewedRuntimeUpdatesEnabled) {
        private EmbeddedConfig {
            Objects.requireNonNull(handshakeTimeout, "handshakeTimeout");
            Objects.requireNonNull(loginTimeout, "loginTimeout");
        }
    }

    private enum State {
        NEW,
        STARTING,
        READY,
        STOPPING,
        FAILED,
        CLOSED
    }
}
