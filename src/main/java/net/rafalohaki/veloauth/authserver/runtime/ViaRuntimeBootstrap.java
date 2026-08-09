package net.rafalohaki.veloauth.authserver.runtime;

import com.viaversion.viaversion.ViaManagerImpl;
import com.viaversion.viaversion.api.Via;
import com.viaversion.viaversion.api.connection.UserConnection;
import com.viaversion.viaversion.api.platform.ViaPlatformLoader;
import com.viaversion.viaversion.api.protocol.packet.PacketWrapper;
import com.viaversion.viaversion.api.protocol.ProtocolManager;
import com.viaversion.viaversion.api.protocol.version.ProtocolVersion;
import com.viaversion.viaversion.api.protocol.version.VersionProvider;
import com.viaversion.viaversion.api.protocol.version.VersionType;
import com.viaversion.viaversion.api.type.Types;
import com.viaversion.viaversion.commands.ViaCommandHandler;
import com.viaversion.viaversion.configuration.AbstractViaConfig;
import com.viaversion.viaversion.platform.NoopInjector;
import com.viaversion.viaversion.platform.UserConnectionViaVersionPlatform;
import com.viaversion.viaversion.platform.ViaChannelInitializer;
import com.viaversion.viaversion.platform.ViaDecodeHandler;
import com.viaversion.viaversion.platform.ViaEncodeHandler;
import com.viaversion.viaversion.protocol.version.BaseVersionProvider;
import com.viaversion.viaversion.protocols.base.ClientboundLoginPackets;
import io.netty.channel.Channel;
import io.netty.channel.ChannelPipeline;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

/**
 * Child-classloader entry point for ViaVersion. This class must never be referenced directly by
 * the main plugin; {@code ManagedProtocolRuntime} loads a private copy beside the verified JAR.
 */
public final class ViaRuntimeBootstrap implements AutoCloseable {

    private static final int MINIMUM_PROTOCOL = 47; // Minecraft 1.8.x
    private static final String MINIMUM_VERSION_NAME = "1.8";
    private static final String MC_PROTOCOL_CODEC = "codec";
    private static final String ENCODER_NAME = "veloauth-via-encoder";
    private static final String DECODER_NAME = "veloauth-via-decoder";
    private static final String VELOCITY_FORWARDING_CHANNEL = "velocity:player_info";
    private static final Duration MAPPING_TIMEOUT = Duration.ofSeconds(30);
    private static final ReentrantLock SYSTEM_PROPERTY_LOCK = new ReentrantLock();

    private final Set<Integer> supportedProtocols;
    private final int maximumProtocol;
    private final String maximumVersionName;
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Map<Channel, UserConnection> connections = new ConcurrentHashMap<>();

    /** Initializes the private ViaVersion manager and waits for every required mapping. */
    public ViaRuntimeBootstrap(Path configDirectory, org.slf4j.Logger logger, String pluginVersion) {
        java.util.Objects.requireNonNull(logger, "logger");
        java.util.Objects.requireNonNull(configDirectory, "configDirectory");
        java.util.Objects.requireNonNull(pluginVersion, "pluginVersion");
        try {
            Files.createDirectories(configDirectory);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to create embedded protocol runtime directory", e);
        }

        EmbeddedPlatform platform = new EmbeddedPlatform(
                configDirectory.toFile(), pluginVersion);
        initializeManager(platform);
        try {
            awaitMappings();
            ProtocolMatrix matrix = discoverSupportedProtocols();
            supportedProtocols = matrix.supportedProtocols();
            maximumProtocol = matrix.maximumProtocol();
            maximumVersionName = matrix.maximumVersionName();
            logger.info("Embedded protocol translator ready (Minecraft {}-{}, {} protocol IDs)",
                    MINIMUM_VERSION_NAME, maximumVersionName,
                    supportedProtocols.size());
        } catch (RuntimeException | Error e) {
            destroyManager();
            throw e;
        }
    }

    public boolean supportsProtocol(int protocol) {
        return !closed.get() && supportedProtocols.contains(protocol);
    }

    public int minimumProtocol() {
        return MINIMUM_PROTOCOL;
    }

    public int maximumProtocol() {
        return maximumProtocol;
    }

    public String minimumVersionName() {
        return MINIMUM_VERSION_NAME;
    }

    public String maximumVersionName() {
        return maximumVersionName;
    }

    /** Adds ViaVersion between MCProtocolLib's frame codecs and packet codec. */
    public void inject(Channel channel) {
        java.util.Objects.requireNonNull(channel, "channel");
        if (closed.get()) {
            throw new IllegalStateException("Embedded protocol translator is closed");
        }
        ChannelPipeline pipeline = channel.pipeline();
        if (pipeline.get(MC_PROTOCOL_CODEC) == null) {
            throw new IllegalStateException("MCProtocolLib packet codec is missing from the channel pipeline");
        }
        if (pipeline.get(ENCODER_NAME) != null || pipeline.get(DECODER_NAME) != null) {
            throw new IllegalStateException("Embedded protocol translator was already injected");
        }

        UserConnection connection = ViaChannelInitializer.createUserConnection(channel, false);
        connections.put(channel, connection);
        channel.closeFuture().addListener(ignored -> connections.remove(channel, connection));
        pipeline.addBefore(MC_PROTOCOL_CODEC, DECODER_NAME, new ViaDecodeHandler(connection));
        pipeline.addBefore(MC_PROTOCOL_CODEC, ENCODER_NAME, new ViaEncodeHandler(connection));
    }

    /** Sends a login query directly in the negotiated client protocol without exposing the secret. */
    public void sendVelocityForwardingRequest(
            Channel channel, int transactionId, Runnable loginContinuation) {
        java.util.Objects.requireNonNull(channel, "channel");
        java.util.Objects.requireNonNull(loginContinuation, "loginContinuation");
        UserConnection connection = connections.get(channel);
        if (connection == null) {
            throw new IllegalStateException("Embedded protocol connection is not registered");
        }
        if (connection.getProtocolInfo().protocolVersion().olderThan(ProtocolVersion.v1_13)) {
            loginContinuation.run();
            return;
        }

        PacketWrapper request = PacketWrapper.create(ClientboundLoginPackets.CUSTOM_QUERY, connection);
        request.write(Types.VAR_INT, transactionId);
        request.write(Types.STRING, VELOCITY_FORWARDING_CHANNEL);
        request.write(Types.REMAINING_BYTES, new byte[0]);
        request.sendFutureRaw().addListener(result -> {
            if (result.isSuccess()) {
                loginContinuation.run();
            } else {
                channel.close();
            }
        });
    }

    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        connections.clear();
        destroyManager();
    }

    private static void destroyManager() {
        ((ViaManagerImpl) Via.getManager()).destroy();
    }

    private static void initializeManager(EmbeddedPlatform platform) {
        SYSTEM_PROPERTY_LOCK.lock();
        String previous = System.getProperty("ViaVersion");
        try {
            System.clearProperty("ViaVersion");
            ViaManagerImpl.initAndLoad(
                    platform,
                    new EmbeddedInjector(),
                    new ViaCommandHandler(false),
                    new EmbeddedPlatformLoader());
        } finally {
            if (previous == null) {
                System.clearProperty("ViaVersion");
            } else {
                System.setProperty("ViaVersion", previous);
            }
            SYSTEM_PROPERTY_LOCK.unlock();
        }
    }

    private static void awaitMappings() {
        ProtocolManager manager = Via.getManager().getProtocolManager();
        long deadline = System.nanoTime() + MAPPING_TIMEOUT.toNanos();
        while (!manager.hasLoadedMappings()) {
            if (manager.checkForMappingCompletion(true)) {
                continue;
            }
            if (System.nanoTime() >= deadline) {
                throw new IllegalStateException("ViaVersion mappings did not load within "
                        + MAPPING_TIMEOUT.toSeconds() + " seconds");
            }
            try {
                TimeUnit.MILLISECONDS.sleep(10);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while loading ViaVersion mappings", e);
            }
        }
    }

    private static ProtocolMatrix discoverSupportedProtocols() {
        if (ProtocolVersion.v1_8.getVersion() != MINIMUM_PROTOCOL
                || ProtocolVersion.v1_8.getVersionType() != VersionType.RELEASE) {
            throw new IllegalStateException("Downloaded ViaVersion does not expose the Minecraft 1.8 base protocol");
        }

        ProtocolManager manager = Via.getManager().getProtocolManager();
        Set<Integer> supported = new HashSet<>();
        int maximumProtocol = MINIMUM_PROTOCOL;
        String maximumVersionName = MINIMUM_VERSION_NAME;
        for (ProtocolVersion client : ProtocolVersion.getProtocols()) {
            int protocol = client.getVersion();
            if (client.getVersionType() != VersionType.RELEASE
                    || protocol < MINIMUM_PROTOCOL) {
                continue;
            }
            if (protocol != MINIMUM_PROTOCOL
                    && manager.getProtocolPath(client, ProtocolVersion.v1_8) == null) {
                throw new IllegalStateException("ViaVersion has no required protocol path "
                        + client.getName() + " -> 1.8");
            }
            supported.add(protocol);
            if (protocol > maximumProtocol) {
                maximumProtocol = protocol;
                maximumVersionName = client.getName();
            }
        }
        if (!supported.contains(MINIMUM_PROTOCOL) || !supported.contains(maximumProtocol)) {
            throw new IllegalStateException("ViaVersion does not expose a complete Minecraft 1.8+ protocol matrix");
        }
        return new ProtocolMatrix(Set.copyOf(supported), maximumProtocol, maximumVersionName);
    }

    private record ProtocolMatrix(
            Set<Integer> supportedProtocols,
            int maximumProtocol,
            String maximumVersionName) {
    }

    private static final class EmbeddedInjector extends NoopInjector {
        @Override
        public ProtocolVersion getServerProtocolVersion() {
            return ProtocolVersion.v1_8;
        }

        @Override
        public SortedSet<ProtocolVersion> getServerProtocolVersions() {
            TreeSet<ProtocolVersion> protocols = new TreeSet<>();
            protocols.add(ProtocolVersion.v1_8);
            return Collections.unmodifiableSortedSet(protocols);
        }

        @Override
        public String getEncoderName() {
            return ENCODER_NAME;
        }

        @Override
        public String getDecoderName() {
            return DECODER_NAME;
        }
    }

    private static final class EmbeddedPlatformLoader implements ViaPlatformLoader {
        @Override
        public void load() {
            Via.getManager().getProviders().use(VersionProvider.class, new BaseVersionProvider() {
                @Override
                public ProtocolVersion getClosestServerProtocol(UserConnection connection) {
                    return ProtocolVersion.v1_8;
                }
            });
        }

        @Override
        public void unload() {
            // The private ViaVersion scheduler and connection manager are destroyed by the manager.
        }
    }

    private static final class EmbeddedPlatform extends UserConnectionViaVersionPlatform {
        private final String pluginVersion;

        private EmbeddedPlatform(File dataFolder, String pluginVersion) {
            super(dataFolder);
            this.pluginVersion = pluginVersion;
        }

        @Override
        protected AbstractViaConfig createConfig() {
            return new EmbeddedViaConfig(
                    new File(getDataFolder(), "viaversion.yml"), createLogger("ViaVersion-Config"));
        }

        @Override
        public java.util.logging.Logger createLogger(String name) {
            java.util.logging.Logger jul = java.util.logging.Logger.getAnonymousLogger();
            jul.setUseParentHandlers(false);
            jul.setLevel(Level.ALL);
            jul.addHandler(new Slf4jHandler(LoggerFactory.getLogger("VeloAuth." + name)));
            return jul;
        }

        @Override
        public boolean isProxy() {
            return false;
        }

        @Override
        public String getPlatformName() {
            return "VeloAuth Embedded Limbo";
        }

        @Override
        public String getPlatformVersion() {
            return pluginVersion;
        }

        @Override
        public boolean kickPlayer(UserConnection connection, String message) {
            connection.getChannel().close();
            return true;
        }
    }

    private static final class EmbeddedViaConfig extends AbstractViaConfig {
        private EmbeddedViaConfig(File configFile, java.util.logging.Logger logger) {
            super(configFile, logger);
        }

        @Override
        public void reload() {
            super.reload();
            setCheckForUpdates(false);
        }

        @Override
        public boolean isCheckForUpdates() {
            return false;
        }

        @Override
        public boolean isSimulatePlayerTick() {
            return false;
        }

        @Override
        public int get1_13TabCompleteDelay() {
            return 0;
        }
    }

    private static final class Slf4jHandler extends Handler {
        private final org.slf4j.Logger delegate;

        private Slf4jHandler(org.slf4j.Logger delegate) {
            this.delegate = delegate;
        }

        @Override
        public void publish(LogRecord record) {
            if (record == null || !isLoggable(record)) {
                return;
            }
            String message = record.getMessage();
            Throwable thrown = record.getThrown();
            if (record.getLevel().intValue() >= Level.SEVERE.intValue()) {
                delegate.error(message, thrown);
            } else if (record.getLevel().intValue() >= Level.WARNING.intValue()) {
                delegate.warn(message, thrown);
            } else if (record.getLevel().intValue() >= Level.INFO.intValue()) {
                delegate.info(message, thrown);
            } else {
                delegate.debug(message, thrown);
            }
        }

        @Override
        public void flush() {
            // SLF4J owns flushing.
        }

        @Override
        public void close() {
            // SLF4J owns lifecycle.
        }
    }
}
