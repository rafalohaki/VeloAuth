package net.rafalohaki.veloauth.authserver;

import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.geysermc.mcprotocollib.auth.GameProfile;
import org.geysermc.mcprotocollib.network.ClientSession;
import org.geysermc.mcprotocollib.network.Session;
import org.geysermc.mcprotocollib.network.event.session.DisconnectedEvent;
import org.geysermc.mcprotocollib.network.event.session.PacketErrorEvent;
import org.geysermc.mcprotocollib.network.event.session.SessionAdapter;
import org.geysermc.mcprotocollib.network.factory.ClientNetworkSessionFactory;
import org.geysermc.mcprotocollib.network.packet.Packet;
import org.geysermc.mcprotocollib.protocol.MinecraftProtocol;
import org.geysermc.mcprotocollib.protocol.packet.common.clientbound.ClientboundKeepAlivePacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.ClientboundLoginPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.ClientboundSystemChatPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.serverbound.ServerboundChatCommandPacket;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.IntSupplier;

import static java.nio.file.StandardWatchEventKinds.ENTRY_CREATE;
import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

/**
 * Opt-in latest-protocol load generator coordinated by {@code profile-velocity-embedded.sh}.
 * This is a test-scope executable, not part of the plugin artifact or the normal unit suite.
 */
final class VelocityEmbeddedCapacityProfile {

    private static final int MAXIMUM_CONNECTIONS = 10_000;
    private static final Duration DEFAULT_BATCH_TIMEOUT = Duration.ofMinutes(10);
    private static final Duration DEFAULT_CONTROL_TIMEOUT = Duration.ofMinutes(5);
    private static final String EXPECTED_COMMAND_RESPONSE = "Account not registered!";
    private static final PlainTextComponentSerializer PLAIN = PlainTextComponentSerializer.plainText();

    private VelocityEmbeddedCapacityProfile() {
    }

    public static void main(String[] arguments) throws Throwable {
        ProfileConfiguration configuration = ProfileConfiguration.fromSystemProperties();
        Files.createDirectories(configuration.controlDirectory());
        try {
            run(configuration);
            Files.writeString(configuration.controlDirectory().resolve("profile.complete"),
                    "status=PASS\n", StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } catch (Throwable failure) {
            writeFailure(configuration.controlDirectory(), failure);
            throw failure;
        }
    }

    static List<Integer> parseTargets(String configuredTargets) {
        if (configuredTargets == null || configuredTargets.isBlank()) {
            throw new IllegalArgumentException("Capacity targets must not be blank");
        }
        List<Integer> targets = new ArrayList<>();
        int previous = 0;
        for (String token : configuredTargets.split(",", -1)) {
            if (!token.matches("[0-9]+")) {
                throw new IllegalArgumentException("Capacity target is not a positive integer: " + token);
            }
            int target;
            try {
                target = Integer.parseInt(token);
            } catch (NumberFormatException failure) {
                throw new IllegalArgumentException("Capacity target is out of range: " + token, failure);
            }
            if (target <= previous || target > MAXIMUM_CONNECTIONS) {
                throw new IllegalArgumentException(
                        "Capacity targets must be strictly ascending in range 1-" + MAXIMUM_CONNECTIONS);
            }
            targets.add(target);
            previous = target;
        }
        return List.copyOf(targets);
    }

    private static void run(ProfileConfiguration configuration)
            throws IOException, InterruptedException, TimeoutException {
        CapacityState state = new CapacityState();
        List<LoadClient> clients = new ArrayList<>(configuration.targets().getLast());
        Semaphore admission = new Semaphore(configuration.connectConcurrency());
        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int target : configuration.targets()) {
                connectToTarget(configuration, state, clients, admission, executor, target);
                state.awaitAtLeast(state::joined, target, configuration.batchTimeout(), "joined clients");
                state.awaitAtLeast(state::keepAlives, target, configuration.batchTimeout(), "keepalives");
                state.assertHealthy(clients, target);
                proveCommandPath(configuration, clients.get(target - 1));
                publishReady(configuration.controlDirectory(), state, target);
                awaitContinuation(configuration.controlDirectory(), target,
                        configuration.controlTimeout());
                state.assertHealthy(clients, target);
            }
        } finally {
            state.beginClosing();
            disconnectAll(clients);
        }
    }

    private static void connectToTarget(
            ProfileConfiguration configuration,
            CapacityState state,
            List<LoadClient> clients,
            Semaphore admission,
            ExecutorService executor,
            int target) throws InterruptedException, TimeoutException {
        List<Future<Void>> connections = new ArrayList<>(target - clients.size());
        for (int index = clients.size(); index < target; index++) {
            LoadClient client = new LoadClient(
                    configuration.host(), configuration.port(), username(index), state);
            clients.add(client);
            connections.add(executor.submit(() -> {
                admission.acquire();
                try {
                    client.connect(configuration.batchTimeout());
                    return null;
                } finally {
                    admission.release();
                }
            }));
        }

        long deadline = System.nanoTime() + configuration.batchTimeout().toNanos();
        for (Future<Void> connection : connections) {
            long remaining = deadline - System.nanoTime();
            if (remaining <= 0) {
                throw new TimeoutException("Timed out while connecting capacity clients");
            }
            try {
                connection.get(remaining, TimeUnit.NANOSECONDS);
            } catch (ExecutionException failure) {
                throw new IllegalStateException("Capacity client failed to connect", failure);
            }
        }
    }

    private static void proveCommandPath(
            ProfileConfiguration configuration,
            LoadClient client) throws InterruptedException, TimeoutException {
        client.sendCommand("login capacity-profile-placeholder");
        client.awaitCommandResponse(configuration.batchTimeout());
    }

    private static void publishReady(Path controlDirectory, CapacityState state, int target)
            throws IOException {
        String evidence = "target=" + target + '\n'
                + "joined=" + state.joined() + '\n'
                + "keepalives=" + state.keepAlives() + '\n'
                + "chat_messages=" + state.chatMessages() + '\n'
                + "disconnects=" + state.disconnects() + '\n'
                + "failures=" + state.failures() + '\n';
        Files.writeString(controlDirectory.resolve("plateau-" + target + ".ready"), evidence,
                StandardCharsets.UTF_8, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
    }

    private static void awaitContinuation(Path controlDirectory, int target, Duration timeout)
            throws IOException, InterruptedException, TimeoutException {
        Path continuation = controlDirectory.resolve("plateau-" + target + ".continue");
        if (Files.isRegularFile(continuation, LinkOption.NOFOLLOW_LINKS)) {
            return;
        }
        long deadline = System.nanoTime() + timeout.toNanos();
        try (WatchService watcher = FileSystems.getDefault().newWatchService()) {
            controlDirectory.register(watcher, ENTRY_CREATE, ENTRY_MODIFY);
            while (!Files.isRegularFile(continuation, LinkOption.NOFOLLOW_LINKS)) {
                long remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    throw new TimeoutException("Timed out waiting for capacity sampler at " + target);
                }
                WatchKey key = watcher.poll(remaining, TimeUnit.NANOSECONDS);
                if (key == null) {
                    throw new TimeoutException("Timed out waiting for capacity sampler at " + target);
                }
                for (WatchEvent<?> ignored : key.pollEvents()) {
                    // Recheck the exact regular-file path after every directory event.
                }
                if (!key.reset()) {
                    throw new IOException("Capacity control directory became unavailable");
                }
            }
        }
    }

    private static void disconnectAll(List<LoadClient> clients) {
        for (LoadClient client : clients) {
            client.disconnect();
        }
    }

    private static String username(int index) {
        return String.format(java.util.Locale.ROOT, "VCap%011d", index);
    }

    private static void writeFailure(Path controlDirectory, Throwable failure) {
        try {
            Files.createDirectories(controlDirectory);
            StringWriter trace = new StringWriter();
            failure.printStackTrace(new PrintWriter(trace));
            Files.writeString(controlDirectory.resolve("profile.failed"), trace.toString(),
                    StandardCharsets.UTF_8, StandardOpenOption.CREATE,
                    StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
        } catch (IOException ignored) {
            failure.addSuppressed(ignored);
        }
    }

    private record ProfileConfiguration(
            String host,
            int port,
            List<Integer> targets,
            int connectConcurrency,
            Duration batchTimeout,
            Duration controlTimeout,
            Path controlDirectory) {

        @SuppressWarnings("PMD.AvoidUsingHardCodedIP") // Only exact loopback literals are allowed.
        private static ProfileConfiguration fromSystemProperties() {
            String host = System.getProperty("veloauth.capacity.host", "::1");
            if (!"127.0.0.1".equals(host) && !"::1".equals(host)) {
                throw new IllegalArgumentException("Capacity profile may target loopback only");
            }
            int port = Integer.getInteger("veloauth.capacity.port", 25565);
            if (port < 1 || port > 65_535) {
                throw new IllegalArgumentException("Capacity port must be in range 1-65535");
            }
            List<Integer> targets = parseTargets(
                    System.getProperty("veloauth.capacity.targets", "1000,5000,10000"));
            int concurrency = Integer.getInteger("veloauth.capacity.connect-concurrency", 256);
            if (concurrency < 1 || concurrency > targets.getLast()) {
                throw new IllegalArgumentException("Capacity connect concurrency is out of range");
            }
            Path controlDirectory = Path.of(requiredProperty("veloauth.capacity.control-dir"));
            if (!controlDirectory.isAbsolute() || Files.isSymbolicLink(controlDirectory)) {
                throw new IllegalArgumentException(
                        "Capacity control directory must be an absolute non-symlink path");
            }
            Duration batchTimeout = positiveDurationProperty(
                    "veloauth.capacity.batch-timeout-seconds", DEFAULT_BATCH_TIMEOUT);
            Duration controlTimeout = positiveDurationProperty(
                    "veloauth.capacity.control-timeout-seconds", DEFAULT_CONTROL_TIMEOUT);
            return new ProfileConfiguration(host, port, targets, concurrency,
                    batchTimeout, controlTimeout, controlDirectory.toAbsolutePath().normalize());
        }

        private static String requiredProperty(String name) {
            String value = System.getProperty(name);
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("Missing required system property: " + name);
            }
            return value;
        }

        private static Duration positiveDurationProperty(String name, Duration fallback) {
            long seconds = Long.getLong(name, fallback.toSeconds());
            if (seconds <= 0) {
                throw new IllegalArgumentException(name + " must be positive");
            }
            return Duration.ofSeconds(seconds);
        }
    }

    private static final class CapacityState {

        private final ReentrantLock lock = new ReentrantLock();
        private final Condition changed = lock.newCondition();
        private final AtomicInteger joined = new AtomicInteger();
        private final AtomicInteger keepAlives = new AtomicInteger();
        private final AtomicInteger chatMessages = new AtomicInteger();
        private final AtomicInteger disconnects = new AtomicInteger();
        private final AtomicInteger failures = new AtomicInteger();
        private final AtomicBoolean closing = new AtomicBoolean();
        private final AtomicReference<String> firstFailure = new AtomicReference<>();

        private void recordJoined() {
            recordEvent(joined);
        }

        private void recordKeepAlive() {
            recordEvent(keepAlives);
        }

        private void recordChatMessage() {
            recordEvent(chatMessages);
        }

        private void recordDisconnect(String reason) {
            disconnects.incrementAndGet();
            if (!closing.get()) {
                recordFailure("unexpected disconnect: " + reason);
            } else {
                signalChanged();
            }
        }

        private void recordFailure(String reason) {
            failures.incrementAndGet();
            firstFailure.compareAndSet(null, reason);
            signalChanged();
        }

        private void recordEvent(AtomicInteger counter) {
            counter.incrementAndGet();
            signalChanged();
        }

        private void signalChanged() {
            lock.lock();
            try {
                changed.signalAll();
            } finally {
                lock.unlock();
            }
        }

        private void awaitAtLeast(
                IntSupplier counter, int expected, Duration timeout, String label)
                throws InterruptedException, TimeoutException {
            await(counter, expected, timeout, label);
        }

        private void await(
                IntSupplier counter,
                int expected,
                Duration timeout,
                String label) throws InterruptedException, TimeoutException {
            long remaining = timeout.toNanos();
            lock.lockInterruptibly();
            try {
                while (counter.getAsInt() < expected) {
                    assertNoFailure();
                    if (remaining <= 0) {
                        throw new TimeoutException("Timed out waiting for " + label
                                + "; observed=" + counter.getAsInt() + ", expected=" + expected);
                    }
                    remaining = changed.awaitNanos(remaining);
                }
                assertNoFailure();
            } finally {
                lock.unlock();
            }
        }

        private void assertHealthy(List<LoadClient> clients, int target) {
            assertNoFailure();
            long connected = clients.stream().limit(target).filter(LoadClient::isConnected).count();
            if (connected != target) {
                throw new IllegalStateException(
                        "Capacity plateau lost clients: connected=" + connected + ", target=" + target);
            }
        }

        private void assertNoFailure() {
            if (failures.get() != 0) {
                String reason = firstFailure.get();
                throw new IllegalStateException(reason == null
                        ? "Capacity client failed"
                        : reason);
            }
        }

        private void beginClosing() {
            closing.set(true);
        }

        private int joined() {
            return joined.get();
        }

        private int keepAlives() {
            return keepAlives.get();
        }

        private int chatMessages() {
            return chatMessages.get();
        }

        private int disconnects() {
            return disconnects.get();
        }

        private int failures() {
            return failures.get();
        }
    }

    private static final class LoadClient {

        private final ClientSession session;
        private final CompletableFuture<Void> joined = new CompletableFuture<>();
        private final CompletableFuture<Void> commandResponse = new CompletableFuture<>();
        private final AtomicBoolean joinRecorded = new AtomicBoolean();
        private final AtomicBoolean keepAliveRecorded = new AtomicBoolean();

        private LoadClient(
                String host,
                int port,
                String username,
                CapacityState state) {
            UUID playerId = UUID.nameUUIDFromBytes(
                    ("OfflinePlayer:" + username).getBytes(StandardCharsets.UTF_8));
            MinecraftProtocol protocol = new MinecraftProtocol(new GameProfile(playerId, username), null);
            this.session = ClientNetworkSessionFactory.factory()
                    .setAddress(host, port)
                    .setProtocol(protocol)
                    .setPacketHandlerExecutor(Runnable::run)
                    .create();
            session.addListener(new SessionAdapter() {
                @Override
                public void packetReceived(Session ignored, Packet packet) {
                    if (packet instanceof ClientboundLoginPacket && joinRecorded.compareAndSet(false, true)) {
                        state.recordJoined();
                        joined.complete(null);
                    } else if (packet instanceof ClientboundKeepAlivePacket
                            && keepAliveRecorded.compareAndSet(false, true)) {
                        state.recordKeepAlive();
                    } else if (packet instanceof ClientboundSystemChatPacket message) {
                        String text = PLAIN.serialize(message.getContent());
                        if (EXPECTED_COMMAND_RESPONSE.equals(text)) {
                            commandResponse.complete(null);
                        }
                        state.recordChatMessage();
                    }
                }

                @Override
                public void disconnected(DisconnectedEvent event) {
                    String reason = PLAIN.serialize(event.getReason());
                    if (event.getCause() != null) {
                        reason += ": " + event.getCause();
                    }
                    joined.completeExceptionally(new IllegalStateException(reason));
                    state.recordDisconnect(reason);
                }

                @Override
                public void packetError(PacketErrorEvent event) {
                    state.recordFailure("packet error: " + event.getCause());
                }
            });
        }

        private void connect(Duration timeout)
                throws InterruptedException, ExecutionException, TimeoutException {
            session.connect(true);
            joined.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
        }

        private void sendCommand(String command) {
            session.send(new ServerboundChatCommandPacket(command));
        }

        private void awaitCommandResponse(Duration timeout)
                throws InterruptedException, TimeoutException {
            try {
                commandResponse.get(timeout.toNanos(), TimeUnit.NANOSECONDS);
            } catch (ExecutionException failure) {
                throw new IllegalStateException("Capacity command response failed", failure);
            }
        }

        private boolean isConnected() {
            return session.isConnected();
        }

        private void disconnect() {
            if (session.isConnected()) {
                session.disconnect("capacity profile complete");
            }
        }
    }
}
