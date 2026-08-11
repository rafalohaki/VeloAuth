package net.rafalohaki.veloauth.integration;

import com.velocitypowered.api.proxy.ConnectionRequestBuilder;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.config.ProxyConfig;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import com.velocitypowered.api.proxy.server.ServerPing;
import com.velocitypowered.api.scheduler.ScheduledTask;
import com.velocitypowered.api.scheduler.Scheduler;
import net.kyori.adventure.text.Component;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import org.bstats.velocity.Metrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.Logger;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.Map;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings({"java:S100", "java:S1450"})
class ConnectionManagerLifecycleIntegrationTest {

    @Mock
    private ProxyServer proxyServer;

    @Mock
    private Logger logger;

    @Mock
    private AuthCache authCache;

    @Mock
    private Settings settings;

    private Messages messages;
    private ConnectionManager connectionManager;

    @BeforeEach
    void setUp() {
        messages = new Messages();
        messages.setLanguage("en");

        when(logger.isDebugEnabled()).thenReturn(false);
        when(logger.isInfoEnabled()).thenReturn(false);
        when(settings.getAuthServerName()).thenReturn("auth");
        when(settings.getConnectionTimeoutSeconds()).thenReturn(1);
        when(settings.getPingTimeoutMillis()).thenReturn(2000);
        when(settings.getAutoTransferDelayMillis()).thenReturn(1500);

        Metrics.Factory metricsFactory = org.mockito.Mockito.mock(Metrics.Factory.class);
        VeloAuth plugin = new VeloAuth(proxyServer, logger, Path.of("."), metricsFactory);
        connectionManager = new ConnectionManager(plugin, authCache, settings, messages);
    }

    @Test
    void testClearRetryAttempts_shouldCancelTrackedTasksIncludingTimeoutRetry() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        ScheduledTask pendingTransfer = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask backendWaitTask = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask timeoutRetryTask = org.mockito.Mockito.mock(ScheduledTask.class);

        putTask("pendingTransfers", playerUuid, pendingTransfer);
        putTask("backendWaitTasks", playerUuid, backendWaitTask);
        putTask("timeoutRetryTasks", playerUuid, timeoutRetryTask);
        putValue("timeoutRetryScheduled", playerUuid, Boolean.TRUE);
        putValue("retryAttempts", playerUuid, 2);
        putValue("forcedHostTargets", playerUuid, "backend");

        connectionManager.clearRetryAttempts(playerUuid);

        verify(pendingTransfer).cancel();
        verify(backendWaitTask).cancel();
        verify(timeoutRetryTask).cancel();
        assertTrue(getMap("pendingTransfers").isEmpty(), "Pending transfer tasks should be cleared on disconnect");
        assertTrue(getMap("backendWaitTasks").isEmpty(), "Backend wait tasks should be cleared on disconnect");
        assertTrue(getMap("timeoutRetryTasks").isEmpty(), "Timeout retry tasks should be cleared on disconnect");
        assertTrue(getMap("timeoutRetryScheduled").isEmpty(), "Timeout retry flags should be cleared on disconnect");
        assertTrue(getMap("retryAttempts").isEmpty(), "Retry counters should be cleared on disconnect");
        assertTrue(getMap("forcedHostTargets").isEmpty(), "Forced-host targets should be cleared on disconnect");
    }

    @Test
    void testTransferToBackend_successShouldCancelTrackedRetries() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ScheduledTask pendingTransfer = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask backendWaitTask = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask timeoutRetryTask = org.mockito.Mockito.mock(ScheduledTask.class);
        ConnectionRequestBuilder connectionRequestBuilder = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result result = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);

        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("LifecyclePlayer");
        when(player.isActive()).thenReturn(true);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(backendServer.ping()).thenReturn(
                CompletableFuture.completedFuture(org.mockito.Mockito.mock(com.velocitypowered.api.proxy.server.ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(player.createConnectionRequest(backendServer)).thenReturn(connectionRequestBuilder);
        when(connectionRequestBuilder.connect()).thenReturn(CompletableFuture.completedFuture(result));
        when(result.isSuccessful()).thenReturn(true);

        connectionManager.beginTransferSession(player);
        connectionManager.setForcedHostTarget(playerUuid, "backend");
        putStateTask(playerUuid, "pendingTransfer", pendingTransfer);
        putStateTask(playerUuid, "backendWait", backendWaitTask);
        putStateTask(playerUuid, "timeoutRetry", timeoutRetryTask);

        boolean transferred = connectionManager.transferToBackend(player);

        assertTrue(transferred, "Successful backend transfer should report success");
        verify(pendingTransfer).cancel();
        verify(backendWaitTask).cancel();
        verify(timeoutRetryTask).cancel();
        assertTrue(getMap("transferStates").isEmpty(), "Successful transfer should retire its owner generation");
        assertTrue(getMap("forcedHostTargets").isEmpty(), "Forced-host targets should be consumed after success");
    }

    @Test
    void manualAndAutoTransfer_SameGeneration_StartOneBackendConnection() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerConnection authConnection = org.mockito.Mockito.mock(ServerConnection.class);
        ConnectionRequestBuilder connectionRequestBuilder = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result result = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        CompletableFuture<ConnectionRequestBuilder.Result> pendingConnection = new CompletableFuture<>();
        CountDownLatch firstConnectionStarted = new CountDownLatch(1);
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = org.mockito.Mockito.mock(Scheduler.TaskBuilder.class);
        ScheduledTask autoTransfer = org.mockito.Mockito.mock(ScheduledTask.class);
        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<Consumer<ScheduledTask>> callbackCaptor =
                org.mockito.ArgumentCaptor.forClass(Consumer.class);

        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("ConcurrentPlayer");
        when(player.isActive()).thenReturn(true);
        when(player.getRemoteAddress()).thenReturn(new InetSocketAddress("127.0.0.1", 25565));
        when(player.getCurrentServer()).thenReturn(Optional.of(authConnection));
        when(authConnection.getServer()).thenReturn(authServer);
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(backendServer.ping()).thenReturn(
                CompletableFuture.completedFuture(org.mockito.Mockito.mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(player.createConnectionRequest(backendServer)).thenReturn(connectionRequestBuilder);
        when(connectionRequestBuilder.connect()).thenAnswer(ignored -> {
            firstConnectionStarted.countDown();
            return pendingConnection;
        });
        when(result.isSuccessful()).thenReturn(true);
        when(authCache.getAuthorizedPlayer(playerUuid)).thenReturn(new CachedAuthUser(
                playerUuid, "ConcurrentPlayer", "127.0.0.1", System.currentTimeMillis(), false, null));
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), callbackCaptor.capture())).thenReturn(taskBuilder);
        when(taskBuilder.delay(eq(1500L), eq(TimeUnit.MILLISECONDS))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(autoTransfer);
        connectionManager.beginTransferSession(player);
        connectionManager.setForcedHostTarget(playerUuid, "backend");
        connectionManager.autoTransferFromAuthServerToBackend(player);
        callbackCaptor.getValue().accept(autoTransfer);
        assertTrue(firstConnectionStarted.await(1, TimeUnit.SECONDS));

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> manualAttempt = executor.submit(() -> connectionManager.transferToBackend(player));
            try {
                assertTrue(manualAttempt.get(500, TimeUnit.MILLISECONDS),
                        "A manual request should coalesce with the active auto-transfer");
                verify(connectionRequestBuilder, times(1)).connect();
            } finally {
                pendingConnection.complete(result);
                manualAttempt.get(2, TimeUnit.SECONDS);
            }
        }
    }

    @Test
    void transferToBackend_PlayerDisconnectsDuringConnect_ShouldNotScheduleFallback() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ConnectionRequestBuilder backendRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result failedResult = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        CompletableFuture<ConnectionRequestBuilder.Result> pendingConnection = new CompletableFuture<>();
        CountDownLatch connectionStarted = new CountDownLatch(1);

        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("DisconnectingPlayer");
        when(player.isActive()).thenReturn(true);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(backendServer.ping()).thenReturn(
                CompletableFuture.completedFuture(org.mockito.Mockito.mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        when(player.createConnectionRequest(backendServer)).thenReturn(backendRequest);
        when(backendRequest.connect()).thenAnswer(ignored -> {
            connectionStarted.countDown();
            return pendingConnection;
        });
        when(failedResult.isSuccessful()).thenReturn(false);
        connectionManager.setForcedHostTarget(playerUuid, "backend");

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> attempt = executor.submit(() -> connectionManager.transferToBackend(player));
            assertTrue(connectionStarted.await(1, TimeUnit.SECONDS));
            when(player.isActive()).thenReturn(false);
            pendingConnection.complete(failedResult);

            assertFalse(attempt.get(2, TimeUnit.SECONDS),
                    "A disconnected player must not be routed through auth fallback");
        }
        verify(player, never()).createConnectionRequest(authServer);
    }

    @Test
    void directCompletion_OldPlayerAfterReconnect_DoesNotCancelNewAutoTransfer() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerConnection authConnection = org.mockito.Mockito.mock(ServerConnection.class);
        ConnectionRequestBuilder oldRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder newRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result oldResult = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        ConnectionRequestBuilder.Result newResult = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        CompletableFuture<ConnectionRequestBuilder.Result> oldConnection = new CompletableFuture<>();
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = org.mockito.Mockito.mock(Scheduler.TaskBuilder.class);
        ScheduledTask newAutoTransfer = org.mockito.Mockito.mock(ScheduledTask.class);
        CountDownLatch oldConnectionStarted = new CountDownLatch(1);
        CountDownLatch newConnectionStarted = new CountDownLatch(1);
        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<Consumer<ScheduledTask>> callbackCaptor =
                org.mockito.ArgumentCaptor.forClass(Consumer.class);

        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(oldPlayer.getUsername()).thenReturn("OldPlayer");
        when(oldPlayer.isActive()).thenReturn(true);
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);
        when(newPlayer.getUsername()).thenReturn("NewPlayer");
        when(newPlayer.isActive()).thenReturn(true);
        when(newPlayer.getRemoteAddress()).thenReturn(new InetSocketAddress("127.0.0.1", 25565));
        when(newPlayer.getCurrentServer()).thenReturn(Optional.of(authConnection));
        when(authConnection.getServer()).thenReturn(authServer);
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(backendServer.ping()).thenReturn(
                CompletableFuture.completedFuture(org.mockito.Mockito.mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(oldPlayer.createConnectionRequest(backendServer)).thenReturn(oldRequest);
        when(oldRequest.connect()).thenAnswer(ignored -> {
            oldConnectionStarted.countDown();
            return oldConnection;
        });
        when(newPlayer.createConnectionRequest(backendServer)).thenReturn(newRequest);
        when(newRequest.connect()).thenAnswer(ignored -> {
            newConnectionStarted.countDown();
            return CompletableFuture.completedFuture(newResult);
        });
        when(oldResult.isSuccessful()).thenReturn(true);
        when(newResult.isSuccessful()).thenReturn(true);
        when(authCache.getAuthorizedPlayer(playerUuid)).thenReturn(new CachedAuthUser(
                playerUuid, "NewPlayer", "127.0.0.1", System.currentTimeMillis(), false, null));
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), callbackCaptor.capture())).thenReturn(taskBuilder);
        when(taskBuilder.delay(eq(1500L), eq(TimeUnit.MILLISECONDS))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(newAutoTransfer);
        connectionManager.setForcedHostTarget(playerUuid, "backend");

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> oldAttempt = executor.submit(() -> connectionManager.transferToBackend(oldPlayer));
            assertTrue(oldConnectionStarted.await(1, TimeUnit.SECONDS));

            connectionManager.clearRetryAttempts(playerUuid);
            connectionManager.beginTransferSession(newPlayer);
            connectionManager.setForcedHostTarget(playerUuid, "backend");
            connectionManager.autoTransferFromAuthServerToBackend(newPlayer);

            when(oldPlayer.isActive()).thenReturn(false);
            oldConnection.complete(oldResult);
            assertFalse(oldAttempt.get(2, TimeUnit.SECONDS));
            verify(newAutoTransfer, never()).cancel();
            assertFalse(connectionManager.transferToBackend(oldPlayer),
                    "A stale concrete player must not reacquire B's UUID generation");

            callbackCaptor.getValue().accept(newAutoTransfer);
            assertTrue(newConnectionStarted.await(2, TimeUnit.SECONDS));
        }

        verify(oldRequest, times(1)).connect();
        verify(newRequest, times(1)).connect();
    }

    @Test
    void directFailure_OldPlayerReplacedDuringFallbackEligibility_DoesNotSendError() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerConnection authConnection = org.mockito.Mockito.mock(ServerConnection.class);
        ConnectionRequestBuilder backendRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result failedResult = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        CountDownLatch fallbackEligibilityReached = new CountDownLatch(1);
        CountDownLatch releaseFallbackEligibility = new CountDownLatch(1);

        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(oldPlayer.getUsername()).thenReturn("OldFailurePlayer");
        when(oldPlayer.isActive()).thenReturn(true);
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);
        when(newPlayer.getUsername()).thenReturn("NewFailurePlayer");
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(authConnection.getServer()).thenReturn(authServer);
        when(backendServer.ping()).thenReturn(
                CompletableFuture.completedFuture(org.mockito.Mockito.mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        when(oldPlayer.createConnectionRequest(backendServer)).thenReturn(backendRequest);
        when(backendRequest.connect()).thenReturn(CompletableFuture.completedFuture(failedResult));
        when(failedResult.isSuccessful()).thenReturn(false);
        when(oldPlayer.getCurrentServer()).thenAnswer(ignored -> {
            fallbackEligibilityReached.countDown();
            assertTrue(releaseFallbackEligibility.await(2, TimeUnit.SECONDS),
                    "Fallback eligibility hook should be released by the test");
            return Optional.of(authConnection);
        });
        connectionManager.setForcedHostTarget(playerUuid, "backend");

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> oldAttempt = executor.submit(() -> connectionManager.transferToBackend(oldPlayer));
            try {
                assertTrue(fallbackEligibilityReached.await(1, TimeUnit.SECONDS),
                        "A should pass the initial failure guard before replacement");
                org.mockito.Mockito.clearInvocations(oldPlayer);
                connectionManager.beginTransferSession(newPlayer);
                releaseFallbackEligibility.countDown();

                assertFalse(oldAttempt.get(2, TimeUnit.SECONDS));
                verify(oldPlayer, never()).sendMessage(any(Component.class));
            } finally {
                releaseFallbackEligibility.countDown();
            }
        }
    }

    @Test
    void findAvailableBackendForInitialConnectionShouldPreserveTryOrderAndExcludeAuthServer() {
        ProxyConfig proxyConfig = org.mockito.Mockito.mock(ProxyConfig.class);
        RegisteredServer firstBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer secondBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerPing firstPing = org.mockito.Mockito.mock(ServerPing.class);
        ServerPing secondPing = org.mockito.Mockito.mock(ServerPing.class);
        when(proxyServer.getConfiguration()).thenReturn(proxyConfig);
        when(proxyConfig.getAttemptConnectionOrder()).thenReturn(List.of("auth", "first", "second"));
        when(proxyServer.getServer("first")).thenReturn(Optional.of(firstBackend));
        when(proxyServer.getServer("second")).thenReturn(Optional.of(secondBackend));
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        when(firstBackend.getServerInfo()).thenReturn(
                new ServerInfo("first", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(secondBackend.getServerInfo()).thenReturn(
                new ServerInfo("second", InetSocketAddress.createUnresolved("127.0.0.1", 25567)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(firstBackend.ping()).thenReturn(CompletableFuture.completedFuture(firstPing));
        when(secondBackend.ping()).thenReturn(CompletableFuture.completedFuture(secondPing));

        Optional<RegisteredServer> selected = connectionManager
                .findAvailableBackendServerForInitialConnectionAsync().join();

        assertSame(firstBackend, selected.orElse(null), "The first reachable try-list backend should win");
        verify(authServer, never()).ping();
    }

    @Test
    void findAvailableBackend_FirstReachable_ShouldNotWaitForLowerPriorityPing() throws Exception {
        ProxyConfig proxyConfig = org.mockito.Mockito.mock(ProxyConfig.class);
        RegisteredServer firstBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer slowBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerPing firstPing = org.mockito.Mockito.mock(ServerPing.class);
        CompletableFuture<ServerPing> slowPing = new CompletableFuture<>();
        when(proxyServer.getConfiguration()).thenReturn(proxyConfig);
        when(proxyConfig.getAttemptConnectionOrder()).thenReturn(List.of("first", "slow"));
        when(proxyServer.getServer("first")).thenReturn(Optional.of(firstBackend));
        when(proxyServer.getServer("slow")).thenReturn(Optional.of(slowBackend));
        when(firstBackend.getServerInfo()).thenReturn(
                new ServerInfo("first", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(slowBackend.getServerInfo()).thenReturn(
                new ServerInfo("slow", InetSocketAddress.createUnresolved("127.0.0.1", 25567)));
        when(firstBackend.ping()).thenReturn(CompletableFuture.completedFuture(firstPing));
        when(slowBackend.ping()).thenReturn(slowPing);

        Optional<RegisteredServer> selected = connectionManager
                .findAvailableBackendServerForInitialConnectionAsync()
                .get(500, TimeUnit.MILLISECONDS);

        assertSame(firstBackend, selected.orElse(null),
                "A reachable first-choice backend must not wait for lower-priority timeouts");
        assertFalse(slowPing.isDone());
    }

    @Test
    void findAvailableBackend_LowerPriorityReachable_ShouldWaitForEarlierResult() {
        ProxyConfig proxyConfig = org.mockito.Mockito.mock(ProxyConfig.class);
        RegisteredServer firstBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer secondBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        CompletableFuture<ServerPing> firstPing = new CompletableFuture<>();
        ServerPing secondPing = org.mockito.Mockito.mock(ServerPing.class);
        when(proxyServer.getConfiguration()).thenReturn(proxyConfig);
        when(proxyConfig.getAttemptConnectionOrder()).thenReturn(List.of("first", "second"));
        when(proxyServer.getServer("first")).thenReturn(Optional.of(firstBackend));
        when(proxyServer.getServer("second")).thenReturn(Optional.of(secondBackend));
        when(firstBackend.getServerInfo()).thenReturn(
                new ServerInfo("first", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(secondBackend.getServerInfo()).thenReturn(
                new ServerInfo("second", InetSocketAddress.createUnresolved("127.0.0.1", 25567)));
        when(firstBackend.ping()).thenReturn(firstPing);
        when(secondBackend.ping()).thenReturn(CompletableFuture.completedFuture(secondPing));

        CompletableFuture<Optional<RegisteredServer>> selection = connectionManager
                .findAvailableBackendServerForInitialConnectionAsync();
        assertFalse(selection.isDone(),
                "A lower-priority backend cannot win before the earlier candidate resolves");

        firstPing.completeExceptionally(new IllegalStateException("offline"));

        assertSame(secondBackend, selection.join().orElse(null));
    }

    @Test
    void findAvailableBackend_Fallback_ShouldNotPingTryCandidateTwice() {
        ProxyConfig proxyConfig = org.mockito.Mockito.mock(ProxyConfig.class);
        RegisteredServer unavailableTryBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer fallbackBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerPing fallbackPing = org.mockito.Mockito.mock(ServerPing.class);
        when(proxyServer.getConfiguration()).thenReturn(proxyConfig);
        when(proxyConfig.getAttemptConnectionOrder()).thenReturn(List.of("offline"));
        when(proxyServer.getServer("offline")).thenReturn(Optional.of(unavailableTryBackend));
        when(proxyServer.getAllServers()).thenReturn(List.of(unavailableTryBackend, fallbackBackend));
        when(unavailableTryBackend.getServerInfo()).thenReturn(
                new ServerInfo("offline", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(fallbackBackend.getServerInfo()).thenReturn(
                new ServerInfo("fallback", InetSocketAddress.createUnresolved("127.0.0.1", 25567)));
        when(unavailableTryBackend.ping()).thenReturn(
                CompletableFuture.failedFuture(new IllegalStateException("offline")));
        when(fallbackBackend.ping()).thenReturn(CompletableFuture.completedFuture(fallbackPing));

        Optional<RegisteredServer> selected = connectionManager
                .findAvailableBackendServerForInitialConnectionAsync().join();

        assertSame(fallbackBackend, selected.orElse(null));
        verify(unavailableTryBackend, times(1)).ping();
    }

    @Test
    void findAvailableBackend_RepeatedOutage_ShouldThrottleFallbackWarnings() {
        ProxyConfig proxyConfig = org.mockito.Mockito.mock(ProxyConfig.class);
        RegisteredServer unavailableBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        when(proxyServer.getConfiguration()).thenReturn(proxyConfig);
        when(proxyConfig.getAttemptConnectionOrder()).thenReturn(List.of("offline"));
        when(proxyServer.getServer("offline")).thenReturn(Optional.of(unavailableBackend));
        when(proxyServer.getAllServers()).thenReturn(List.of(unavailableBackend));
        when(unavailableBackend.getServerInfo()).thenReturn(
                new ServerInfo("offline", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(unavailableBackend.ping()).thenReturn(
                CompletableFuture.failedFuture(new IllegalStateException("offline")));

        connectionManager.findAvailableBackendServerForInitialConnectionAsync().join();
        connectionManager.findAvailableBackendServerForInitialConnectionAsync().join();

        verify(logger, times(1)).warn(
                "No reachable server from the Velocity try list; attempting fallback");
    }

    @Test
    void backendWaitSchedulerCallback_shouldNotBlockWhileForcedHostPingIsPending() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer forcedBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerConnection authConnection = org.mockito.Mockito.mock(ServerConnection.class);
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = org.mockito.Mockito.mock(Scheduler.TaskBuilder.class);
        ScheduledTask scheduledTask = org.mockito.Mockito.mock(ScheduledTask.class);
        CompletableFuture<ServerPing> pendingPing = new CompletableFuture<>();
        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<Consumer<ScheduledTask>> callbackCaptor =
                org.mockito.ArgumentCaptor.forClass(Consumer.class);

        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("AsyncRetryPlayer");
        when(player.isActive()).thenReturn(true);
        when(player.getCurrentServer()).thenReturn(Optional.of(authConnection));
        when(authConnection.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(forcedBackend.getServerInfo()).thenReturn(
                new ServerInfo("forced", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(forcedBackend.ping()).thenReturn(pendingPing);
        when(proxyServer.getServer("forced")).thenReturn(Optional.of(forcedBackend));
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), callbackCaptor.capture())).thenReturn(taskBuilder);
        when(taskBuilder.delay(eq(5L), eq(TimeUnit.SECONDS))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(scheduledTask);

        connectionManager.setForcedHostTarget(playerUuid, "forced");
        Method scheduleRetry = ConnectionManager.class
                .getDeclaredMethod("scheduleBackendWaitRetry", Player.class, int.class);
        scheduleRetry.setAccessible(true);
        scheduleRetry.invoke(connectionManager, player, 1);

        CompletableFuture<Void> callback = CompletableFuture.runAsync(
                () -> callbackCaptor.getValue().accept(scheduledTask));
        try {
            assertDoesNotThrow(() -> callback.get(500, TimeUnit.MILLISECONDS),
                    "Velocity scheduler callback must return before an unresolved ping completes");
            assertFalse(pendingPing.isDone());
        } finally {
            when(player.isActive()).thenReturn(false);
            pendingPing.complete(org.mockito.Mockito.mock(ServerPing.class));
            callback.get(2, TimeUnit.SECONDS);
        }
    }

    @Test
    void shutdown_LateAsyncSchedule_ShouldNotPublishNewTask() throws Exception {
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        ConcurrentMap<UUID, ScheduledTask> lateTasks = new ConcurrentHashMap<>();
        when(proxyServer.getScheduler()).thenReturn(scheduler);

        connectionManager.shutdown();

        Method scheduleOwnedTask = ConnectionManager.class.getDeclaredMethod(
                "scheduleOwnedTask",
                ConcurrentMap.class,
                UUID.class,
                long.class,
                TimeUnit.class,
                Runnable.class);
        scheduleOwnedTask.setAccessible(true);
        scheduleOwnedTask.invoke(
                connectionManager,
                lateTasks,
                UUID.randomUUID(),
                1L,
                TimeUnit.SECONDS,
                (Runnable) () -> {
                    throw new AssertionError("A task must not run after shutdown");
                });

        assertTrue(lateTasks.isEmpty());
        verify(scheduler, never()).buildTask(
                any(), org.mockito.ArgumentMatchers.<Consumer<ScheduledTask>>any());
    }

    @SuppressWarnings("unchecked")
    private Map<UUID, Object> getMap(String fieldName) throws Exception {
        Field field = ConnectionManager.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return (Map<UUID, Object>) field.get(connectionManager);
    }

    private void putTask(String fieldName, UUID playerUuid, ScheduledTask task) throws Exception {
        getMap(fieldName).put(playerUuid, task);
    }

    private void putValue(String fieldName, UUID playerUuid, Object value) throws Exception {
        getMap(fieldName).put(playerUuid, value);
    }

    @SuppressWarnings("unchecked")
    private void putStateTask(UUID playerUuid, String fieldName, ScheduledTask task) throws Exception {
        Object state = getMap("transferStates").get(playerUuid);
        Field field = state.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        ((java.util.concurrent.atomic.AtomicReference<ScheduledTask>) field.get(state)).set(task);
    }
}
