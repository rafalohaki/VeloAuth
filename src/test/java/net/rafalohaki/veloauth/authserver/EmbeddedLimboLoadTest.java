package net.rafalohaki.veloauth.authserver;

import io.netty.channel.Channel;
import net.kyori.adventure.text.Component;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.lang.management.ManagementFactory;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.connect;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.readFrame;
import static net.rafalohaki.veloauth.authserver.MinecraftWireTestSupport.sendLogin;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;

/** Opt-in direct-listener capacity benchmark; a real Velocity load test remains a release gate. */
class EmbeddedLimboLoadTest {

    private static final int DEFAULT_CONNECTIONS = 256;

    @Test
    void benchmarkConcurrentMinecraft18Logins() throws Exception {
        assumeTrue(Boolean.getBoolean("veloauth.benchmark"),
                "Manual benchmark disabled. Run with -Dveloauth.benchmark=true");
        int connectionCount = Integer.getInteger(
                "veloauth.benchmark.connections", DEFAULT_CONNECTIONS);
        int loginConcurrency = Integer.getInteger(
                "veloauth.benchmark.concurrency", Math.min(connectionCount, DEFAULT_CONNECTIONS));
        assumeTrue(connectionCount > 0, "Connection count must be positive");
        assumeTrue(loginConcurrency > 0 && loginConcurrency <= connectionCount,
                "Login concurrency must be in range 1..connections");

        EmbeddedLimboServer server = new EmbeddedLimboServer(
                new EmbeddedLimboServer.Config(
                        0,
                        connectionCount,
                        Duration.ofSeconds(10),
                        Duration.ofSeconds(15),
                        Duration.ofMinutes(1)),
                new NoopProtocolRuntime(),
                new EmbeddedLimboServer.PlayerMessages(
                        Component.text("VeloAuth benchmark"),
                        Component.text("invalid redirect"),
                        Component.text("overloaded"),
                        Component.text("timeout")),
                mock(Logger.class));
        List<Socket> clients = new ArrayList<>(connectionCount);
        try {
            server.start();
            forceGc();
            long heapBefore = usedHeap();
            for (int index = 0; index < connectionCount; index++) {
                String username = username(index);
                server.expectPlayer(playerId(username), username);
            }

            long startedAt = System.nanoTime();
            Semaphore concurrentLogins = new Semaphore(loginConcurrency);
            try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
                List<Future<Socket>> connections = new ArrayList<>(connectionCount);
                for (int index = 0; index < connectionCount; index++) {
                    String username = username(index);
                    connections.add(executor.submit(() -> {
                        concurrentLogins.acquire();
                        try {
                            return login(server.port(), username);
                        } finally {
                            concurrentLogins.release();
                        }
                    }));
                }
                for (Future<Socket> connection : connections) {
                    clients.add(connection.get(30, TimeUnit.SECONDS));
                }
            }
            long elapsedNanos = System.nanoTime() - startedAt;
            forceGc();
            long heapDelta = Math.max(0L, usedHeap() - heapBefore);

            assertEquals(connectionCount, server.activeConnections());
            assertEquals(connectionCount, server.playersInGame());
            assertEquals(0, server.rejectedConnections());
            assertEquals(0, server.invalidRedirects());
            assertEquals(0, server.timedOutConnections());

            double seconds = elapsedNanos / 1_000_000_000.0;
            System.out.printf(
                    "Embedded direct load: %,d clients, %,d concurrent logins, %.2f s, "
                            + "%.0f logins/s, %,d heap bytes/client%n",
                    connectionCount,
                    loginConcurrency,
                    seconds,
                    connectionCount / seconds,
                    heapDelta / connectionCount);
        } finally {
            for (Socket client : clients) {
                client.close();
            }
            server.close();
        }
    }

    private static Socket login(int port, String username) throws Exception {
        Socket socket = connect(port);
        try {
            sendLogin(socket, LegacyProtocolCodec.PROTOCOL_VERSION, username);
            readFrame(socket);
            readFrame(socket);
            readFrame(socket);
            return socket;
        } catch (Exception failure) {
            socket.close();
            throw failure;
        }
    }

    private static String username(int index) {
        return "Load" + index;
    }

    private static UUID playerId(String username) {
        return UUID.nameUUIDFromBytes(username.getBytes(StandardCharsets.UTF_8));
    }

    private static long usedHeap() {
        return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
    }

    private static void forceGc() throws InterruptedException {
        System.gc();
        TimeUnit.MILLISECONDS.sleep(250);
    }

    private static final class NoopProtocolRuntime implements ProtocolRuntime {
        @Override
        public boolean supportsProtocol(int protocol) {
            return protocol == LegacyProtocolCodec.PROTOCOL_VERSION;
        }

        @Override
        public int minimumProtocol() {
            return LegacyProtocolCodec.PROTOCOL_VERSION;
        }

        @Override
        public int maximumProtocol() {
            return LegacyProtocolCodec.PROTOCOL_VERSION;
        }

        @Override
        public String minimumVersionName() {
            return "1.8";
        }

        @Override
        public String maximumVersionName() {
            return "1.8";
        }

        @Override
        public String runtimeVersion() {
            return "benchmark";
        }

        @Override
        public void inject(Channel channel) {
            // The benchmark isolates the native protocol-47 listener without ViaVersion.
        }

        @Override
        public int clientProtocol(Channel channel) {
            return LegacyProtocolCodec.PROTOCOL_VERSION;
        }

        @Override
        public void close() {
            // Test-owned no-op.
        }
    }
}
