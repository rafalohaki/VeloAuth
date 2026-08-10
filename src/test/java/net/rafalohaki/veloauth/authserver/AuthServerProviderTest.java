package net.rafalohaki.veloauth.authserver;

import com.velocitypowered.api.network.ProtocolVersion;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import io.netty.channel.Channel;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServerProviderTest {

    private static final int PINNED_MAXIMUM_PROTOCOL = 776;

    @TempDir
    private Path temporaryDirectory;

    private final List<AuthServerProvider> providers = new ArrayList<>();

    @AfterEach
    void closeProviders() {
        providers.forEach(AuthServerProvider::close);
    }

    @Test
    void externalMode_Start_ShouldPreserveHistoricalRegistrationWithoutMutatingProxy() {
        ProxyServer proxy = mock(ProxyServer.class);
        Logger logger = mock(Logger.class);
        RegisteredServer external = registeredServer("limbo", 25565);
        when(proxy.getServer("limbo")).thenReturn(Optional.of(external));
        AuthServerProvider provider = track(AuthServerProvider.forExternal(proxy, "limbo", logger));

        provider.start();

        assertSame(external, provider.resolve().orElseThrow());
        assertTrue(provider.isAuthServer(external));
        assertEquals(AuthServerProvider.Preparation.READY, provider.prepare(mock(Player.class)));
        provider.close();
        provider.close();
        verify(proxy, never()).registerServer(any(ServerInfo.class));
        verify(proxy, never()).unregisterServer(any(ServerInfo.class));
    }

    @Test
    void externalMode_Create_ShouldNotOpenManagedRuntime() {
        ProxyServer proxy = mock(ProxyServer.class);
        Settings settings = mock(Settings.class);
        Logger logger = mock(Logger.class);
        AtomicBoolean runtimeOpened = new AtomicBoolean();
        RegisteredServer external = registeredServer("limbo", 25565);
        when(settings.getAuthServerMode()).thenReturn(Settings.AuthServerMode.EXTERNAL);
        when(settings.getAuthServerName()).thenReturn("limbo");
        when(proxy.getServer("limbo")).thenReturn(Optional.of(external));
        AuthServerProvider provider = track(AuthServerProvider.create(
                proxy, settings, new Messages(), logger, temporaryDirectory,
                (directory, runtimeLogger) -> {
                    runtimeOpened.set(true);
                    return new FakeProtocolRuntime();
                }));

        provider.start();

        assertFalse(runtimeOpened.get());
        assertSame(external, provider.resolve().orElseThrow());
        provider.stageProtocolRuntimeUpdate();
        assertFalse(Files.exists(temporaryDirectory.resolve("runtime")));
    }

    @Test
    void embedded_StartWithAutomaticPort_ShouldPublishLoopbackAndAcceptFullProtocolRange() {
        ProxyFixture fixture = proxyFixture();
        FakeProtocolRuntime runtime = new FakeProtocolRuntime();
        AuthServerProvider provider = track(embeddedProvider(fixture.proxy(), 0, runtime));

        provider.start();

        RegisteredServer registered = provider.resolve().orElseThrow();
        InetSocketAddress address = registered.getServerInfo().getAddress();
        assertEquals(AuthServerProvider.EMBEDDED_SERVER_NAME, registered.getServerInfo().getName());
        assertTrue(address.getAddress().isLoopbackAddress());
        assertTrue(address.getPort() > 0);
        assertTrue(provider.isReady());
        assertTrue(provider.isAuthServer(registered));
        assertEquals(AuthServerProvider.Preparation.READY,
                provider.prepare(player(ProtocolVersion.MINECRAFT_1_8)));
        assertEquals(AuthServerProvider.Preparation.READY,
                provider.prepare(player(ProtocolVersion.MINECRAFT_26_2)));
        assertEquals(AuthServerProvider.Preparation.UNSUPPORTED_PROTOCOL,
                provider.prepare(player(ProtocolVersion.MINECRAFT_1_7_6)));
        assertEquals(1, runtime.operationalConfirmations.get());

        provider.close();
        assertTrue(runtime.closed.get());
        assertTrue(provider.resolve().isEmpty());
        verify(fixture.proxy()).unregisterServer(registered.getServerInfo());
    }

    @Test
    void embedded_RuntimeWithFutureRelease_ShouldPublishDiscoveredCompatibility() {
        ProxyFixture fixture = proxyFixture();
        FakeProtocolRuntime runtime = new FakeProtocolRuntime(900, "27.0");
        AuthServerProvider provider = track(embeddedProvider(fixture.proxy(), 0, runtime));

        provider.start();

        assertTrue(provider.isReady());
        assertEquals("Minecraft 1.8-27.0 (managed ViaVersion 5.11.0)",
                provider.compatibilityDescription());
    }

    @Test
    void embedded_RuntimeWithoutCompleteMatrix_ShouldFailBeforeOpeningListener() throws Exception {
        int port = freePort();
        ProxyServer proxy = mock(ProxyServer.class);
        when(proxy.getServer(anyString())).thenReturn(Optional.empty());
        FakeProtocolRuntime runtime = new FakeProtocolRuntime() {
            @Override
            public boolean supportsProtocol(int protocol) {
                return protocol != maximumProtocol();
            }
        };
        AuthServerProvider provider = track(embeddedProvider(proxy, port, runtime));

        assertThrows(IllegalStateException.class, provider::start);

        assertTrue(runtime.closed.get());
        verify(proxy, never()).registerServer(any(ServerInfo.class));
        assertPortCanBeBound(port);
    }

    @Test
    void embedded_StartWithReservedName_ShouldFailBeforeRuntimeOrBinding() throws Exception {
        int port = freePort();
        ProxyServer proxy = mock(ProxyServer.class);
        RegisteredServer foreign = registeredServer(AuthServerProvider.EMBEDDED_SERVER_NAME, port + 1);
        when(proxy.getServer(AuthServerProvider.EMBEDDED_SERVER_NAME)).thenReturn(Optional.of(foreign));
        AtomicBoolean runtimeOpened = new AtomicBoolean();
        AuthServerProvider provider = track(embeddedProvider(proxy, port, runtimeOpened));

        assertThrows(IllegalStateException.class, provider::start);

        assertFalse(runtimeOpened.get());
        verify(proxy, never()).registerServer(any(ServerInfo.class));
        assertPortCanBeBound(port);
    }

    @Test
    void embedded_VelocityPublicationFailure_ShouldRollbackListenerAndRuntime() throws Exception {
        int port = freePort();
        ProxyServer proxy = mock(ProxyServer.class);
        AtomicReference<ServerInfo> attempted = new AtomicReference<>();
        when(proxy.getServer(anyString())).thenReturn(Optional.empty());
        when(proxy.registerServer(any(ServerInfo.class))).thenAnswer(invocation -> {
            ServerInfo info = invocation.getArgument(0);
            attempted.set(info);
            return registeredServer(info);
        });
        FakeProtocolRuntime runtime = new FakeProtocolRuntime();
        AuthServerProvider provider = track(embeddedProvider(proxy, port, runtime));

        assertThrows(IllegalStateException.class, provider::start);

        assertTrue(runtime.closed.get());
        assertEquals(0, runtime.operationalConfirmations.get());
        verify(proxy).unregisterServer(attempted.get());
        assertPortCanBeBound(port);
    }

    @Test
    void embedded_RuntimeActivationFailure_ShouldRollbackRegistrationListenerAndRuntime() throws Exception {
        int port = freePort();
        ProxyFixture fixture = proxyFixture();
        FakeProtocolRuntime runtime = new FakeProtocolRuntime() {
            @Override
            public void confirmOperational() {
                super.confirmOperational();
                throw new IllegalStateException("simulated runtime-manifest activation failure");
            }
        };
        AuthServerProvider provider = track(embeddedProvider(fixture.proxy(), port, runtime));

        assertThrows(IllegalStateException.class, provider::start);

        assertTrue(runtime.closed.get());
        assertEquals(1, runtime.operationalConfirmations.get());
        assertFalse(provider.isReady());
        assertTrue(provider.resolve().isEmpty());
        assertTrue(fixture.registration().get() == null);
        verify(fixture.proxy()).unregisterServer(any(ServerInfo.class));
        assertPortCanBeBound(port);
    }

    @Test
    void embedded_CloseDuringRuntimeOpen_ShouldNeverResurrectProviderOrListener() throws Exception {
        int port = freePort();
        ProxyServer proxy = mock(ProxyServer.class);
        when(proxy.getServer(anyString())).thenReturn(Optional.empty());
        CountDownLatch runtimeOpenStarted = new CountDownLatch(1);
        CountDownLatch allowRuntimeOpen = new CountDownLatch(1);
        FakeProtocolRuntime runtime = new FakeProtocolRuntime() {
            @Override
            public void close() {
                super.close();
                throw new LinkageError("simulated incompatible runtime cleanup");
            }
        };
        AuthServerProvider provider = track(embeddedProvider(proxy, port, (directory, logger) -> {
            runtimeOpenStarted.countDown();
            try {
                if (!allowRuntimeOpen.await(5, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("test runtime open was not released");
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("test runtime open was interrupted", interrupted);
            }
            return runtime;
        }));
        CompletableFuture<Void> startup = new CompletableFuture<>();
        Thread startupThread = Thread.ofVirtual().start(() -> {
            try {
                provider.start();
                startup.complete(null);
            } catch (Throwable failure) {
                startup.completeExceptionally(failure);
            }
        });

        try {
            assertTrue(runtimeOpenStarted.await(5, TimeUnit.SECONDS));
            provider.close();
        } finally {
            allowRuntimeOpen.countDown();
        }

        assertThrows(CompletionException.class, startup::join);
        startupThread.join(Duration.ofSeconds(5));
        assertFalse(startupThread.isAlive());
        assertTrue(runtime.closed.get());
        assertFalse(provider.isReady());
        assertTrue(provider.resolve().isEmpty());
        assertEquals(0, runtime.operationalConfirmations.get());
        verify(proxy, never()).registerServer(any(ServerInfo.class));
        assertPortCanBeBound(port);
    }

    @Test
    void embedded_CloseAfterForeignReplacement_ShouldNotUnregisterNewOwner() throws Exception {
        int port = freePort();
        ProxyFixture fixture = proxyFixture();
        AuthServerProvider provider = track(embeddedProvider(
                fixture.proxy(), port, new FakeProtocolRuntime()));
        provider.start();
        RegisteredServer foreign = registeredServer(AuthServerProvider.EMBEDDED_SERVER_NAME, port + 1);
        fixture.registration().set(foreign);

        provider.close();

        verify(fixture.proxy(), never()).unregisterServer(any(ServerInfo.class));
        assertSame(foreign, fixture.registration().get());
        assertPortCanBeBound(port);
    }

    private AuthServerProvider embeddedProvider(
            ProxyServer proxy, int port, ProtocolRuntime runtime) {
        return embeddedProvider(proxy, port, (directory, logger) -> runtime);
    }

    private AuthServerProvider embeddedProvider(
            ProxyServer proxy, int port, AtomicBoolean runtimeOpened) {
        return embeddedProvider(proxy, port, (directory, logger) -> {
            runtimeOpened.set(true);
            return new FakeProtocolRuntime();
        });
    }

    private AuthServerProvider embeddedProvider(
            ProxyServer proxy, int port, AuthServerProvider.RuntimeFactory runtimeFactory) {
        Settings settings = mock(Settings.class);
        Settings.EmbeddedAuthServerSettings embedded = mock(Settings.EmbeddedAuthServerSettings.class);
        when(settings.getAuthServerMode()).thenReturn(Settings.AuthServerMode.EMBEDDED);
        when(settings.getEmbeddedAuthServerSettings()).thenReturn(embedded);
        when(embedded.getPort()).thenReturn(port);
        when(embedded.getMaxConnections()).thenReturn(8);
        when(embedded.getHandshakeTimeoutSeconds()).thenReturn(2);
        when(embedded.getLoginTimeoutSeconds()).thenReturn(3);
        return AuthServerProvider.create(
                proxy, settings, new Messages(), mock(Logger.class), temporaryDirectory, runtimeFactory);
    }

    private static Player player(ProtocolVersion protocolVersion) {
        Player player = mock(Player.class);
        when(player.getProtocolVersion()).thenReturn(protocolVersion);
        when(player.getUniqueId()).thenReturn(UUID.randomUUID());
        when(player.getUsername()).thenReturn("PlayerOne");
        return player;
    }

    private static ProxyFixture proxyFixture() {
        ProxyServer proxy = mock(ProxyServer.class);
        AtomicReference<RegisteredServer> registration = new AtomicReference<>();
        when(proxy.getServer(anyString())).thenAnswer(invocation -> {
            RegisteredServer current = registration.get();
            if (current == null
                    || !current.getServerInfo().getName().equals(invocation.getArgument(0))) {
                return Optional.empty();
            }
            return Optional.of(current);
        });
        when(proxy.registerServer(any(ServerInfo.class))).thenAnswer(invocation -> {
            RegisteredServer registered = registeredServer(invocation.getArgument(0));
            registration.set(registered);
            return registered;
        });
        doAnswer(invocation -> {
            ServerInfo requested = invocation.getArgument(0);
            registration.updateAndGet(current -> current != null
                    && requested.equals(current.getServerInfo()) ? null : current);
            return null;
        }).when(proxy).unregisterServer(any(ServerInfo.class));
        return new ProxyFixture(proxy, registration);
    }

    private static RegisteredServer registeredServer(String name, int port) {
        return registeredServer(new ServerInfo(name, new InetSocketAddress("127.0.0.1", port)));
    }

    private static RegisteredServer registeredServer(ServerInfo info) {
        RegisteredServer server = mock(RegisteredServer.class);
        when(server.getServerInfo()).thenReturn(info);
        return server;
    }

    private AuthServerProvider track(AuthServerProvider provider) {
        providers.add(provider);
        return provider;
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket()) {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress("127.0.0.1", 0));
            return socket.getLocalPort();
        }
    }

    private static void assertPortCanBeBound(int port) throws Exception {
        try (ServerSocket socket = new ServerSocket()) {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress("127.0.0.1", port));
            assertFalse(socket.isClosed());
        }
    }

    private static class FakeProtocolRuntime implements ProtocolRuntime {
        private final AtomicBoolean closed = new AtomicBoolean();
        private final AtomicInteger operationalConfirmations = new AtomicInteger();
        private final int maximumProtocol;
        private final String maximumVersionName;

        private FakeProtocolRuntime() {
            this(PINNED_MAXIMUM_PROTOCOL, "26.2");
        }

        private FakeProtocolRuntime(int maximumProtocol, String maximumVersionName) {
            this.maximumProtocol = maximumProtocol;
            this.maximumVersionName = maximumVersionName;
        }

        @Override
        public boolean supportsProtocol(int protocol) {
            return protocol >= AuthServerProvider.MIN_SUPPORTED_PROTOCOL
                    && protocol <= maximumProtocol;
        }

        @Override
        public int minimumProtocol() {
            return AuthServerProvider.MIN_SUPPORTED_PROTOCOL;
        }

        @Override
        public int maximumProtocol() {
            return maximumProtocol;
        }

        @Override
        public String minimumVersionName() {
            return "1.8";
        }

        @Override
        public String maximumVersionName() {
            return maximumVersionName;
        }

        @Override
        public String runtimeVersion() {
            return "5.11.0";
        }

        @Override
        public void inject(Channel channel) {
            // Provider lifecycle tests exercise the 1.8 base without translation.
        }

        @Override
        public int clientProtocol(Channel channel) {
            return AuthServerProvider.MIN_SUPPORTED_PROTOCOL;
        }

        @Override
        public void confirmOperational() {
            operationalConfirmations.incrementAndGet();
        }

        @Override
        public void close() {
            closed.set(true);
        }
    }

    private record ProxyFixture(
            ProxyServer proxy,
            AtomicReference<RegisteredServer> registration) {
    }
}
