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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.doAnswer;
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
    void clearTransferState_ConcreteOwner_CancelsAllOwnedTasks() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        ScheduledTask pendingTransfer = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask backendWaitTask = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask timeoutRetryTask = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask authReadyRetryTask = org.mockito.Mockito.mock(ScheduledTask.class);
        when(player.getUniqueId()).thenReturn(playerUuid);

        connectionManager.beginTransferSession(player);
        connectionManager.setForcedHostTarget(player, "backend");
        putStateTask(playerUuid, "pendingTransfer", pendingTransfer);
        putStateTask(playerUuid, "backendWait", backendWaitTask);
        putStateTask(playerUuid, "timeoutRetry", timeoutRetryTask);
        putStateTask(playerUuid, "authReadyRetry", authReadyRetryTask);

        connectionManager.clearTransferState(player);

        verify(pendingTransfer).cancel();
        verify(backendWaitTask).cancel();
        verify(timeoutRetryTask).cancel();
        verify(authReadyRetryTask).cancel();
        assertTrue(getMap("transferStates").isEmpty(), "Owned transfer state should be cleared on disconnect");
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
        connectionManager.setForcedHostTarget(player, "backend");
        putStateTask(playerUuid, "pendingTransfer", pendingTransfer);
        putStateTask(playerUuid, "backendWait", backendWaitTask);
        putStateTask(playerUuid, "timeoutRetry", timeoutRetryTask);

        boolean transferred = connectionManager.transferToBackend(player);

        assertTrue(transferred, "Successful backend transfer should report success");
        verify(pendingTransfer).cancel();
        verify(backendWaitTask).cancel();
        verify(timeoutRetryTask).cancel();
        assertTrue(getMap("transferStates").isEmpty(), "Successful transfer should retire its owner generation");
    }

    @Test
    void transferToBackend_NoBackendAvailable_AcceptsOwnedBackgroundWait() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        ProxyConfig proxyConfig = org.mockito.Mockito.mock(ProxyConfig.class);
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = org.mockito.Mockito.mock(Scheduler.TaskBuilder.class);
        ScheduledTask backendWaitTask = org.mockito.Mockito.mock(ScheduledTask.class);

        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("WaitingPlayer");
        when(player.isActive()).thenReturn(true);
        when(proxyServer.getConfiguration()).thenReturn(proxyConfig);
        when(proxyConfig.getAttemptConnectionOrder()).thenReturn(List.of());
        when(proxyServer.getAllServers()).thenReturn(List.of());
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), org.mockito.ArgumentMatchers.<Consumer<ScheduledTask>>any()))
                .thenReturn(taskBuilder);
        when(taskBuilder.delay(eq(5L), eq(TimeUnit.SECONDS))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(backendWaitTask);

        connectionManager.beginTransferSession(player);

        boolean accepted = connectionManager.transferToBackend(player);

        assertTrue(accepted,
                "An owned background wait is an accepted transfer request, not a hard failure");
        verify(player, never()).createConnectionRequest(any(RegisteredServer.class));
        verify(taskBuilder).schedule();
        assertSame(player, getStateOwner(playerUuid),
                "The waiting generation must retain ownership for its scheduled retry");
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
        connectionManager.setForcedHostTarget(player, "backend");
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
    void transferToBackend_LogoutClearsStateDuringConnect_ShouldNotScheduleFallback() throws Exception {
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
        connectionManager.beginTransferSession(player);
        connectionManager.setForcedHostTarget(player, "backend");

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> attempt = executor.submit(() -> connectionManager.transferToBackend(player));
            assertTrue(connectionStarted.await(1, TimeUnit.SECONDS));
            connectionManager.clearTransferState(player);
            when(player.isActive()).thenReturn(false);
            org.mockito.Mockito.clearInvocations(player);
            pendingConnection.complete(failedResult);

            assertFalse(attempt.get(2, TimeUnit.SECONDS),
                    "A disconnected player must not be routed through auth fallback");
        }
        verify(player, never()).createConnectionRequest(authServer);
        verify(player, never()).sendMessage(any(Component.class));
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
        connectionManager.beginTransferSession(oldPlayer);
        connectionManager.setForcedHostTarget(oldPlayer, "backend");

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> oldAttempt = executor.submit(() -> connectionManager.transferToBackend(oldPlayer));
            assertTrue(oldConnectionStarted.await(1, TimeUnit.SECONDS));

            connectionManager.clearTransferState(oldPlayer);
            connectionManager.beginTransferSession(newPlayer);
            connectionManager.setForcedHostTarget(newPlayer, "backend");
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
        connectionManager.beginTransferSession(oldPlayer);
        connectionManager.setForcedHostTarget(oldPlayer, "backend");

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
    void authFallbackCompletion_OldGeneration_DoesNotReplaceNewPendingTransfer() {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerConnection backendConnection = org.mockito.Mockito.mock(ServerConnection.class);
        ConnectionRequestBuilder backendRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder authRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result backendFailure = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        ConnectionRequestBuilder.Result authSuccess = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        CompletableFuture<ConnectionRequestBuilder.Result> authFallback = new CompletableFuture<>();
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = org.mockito.Mockito.mock(Scheduler.TaskBuilder.class);
        ScheduledTask newPendingTransfer = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask staleRetry = org.mockito.Mockito.mock(ScheduledTask.class);

        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(oldPlayer.getUsername()).thenReturn("OldFallbackPlayer");
        when(oldPlayer.isActive()).thenReturn(true);
        when(oldPlayer.getCurrentServer()).thenReturn(Optional.of(backendConnection));
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);
        when(newPlayer.getUsername()).thenReturn("NewFallbackPlayer");
        when(newPlayer.getRemoteAddress()).thenReturn(new InetSocketAddress("127.0.0.1", 25565));
        when(backendConnection.getServer()).thenReturn(backendServer);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(backendServer.ping()).thenReturn(
                CompletableFuture.completedFuture(org.mockito.Mockito.mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        when(oldPlayer.createConnectionRequest(backendServer)).thenReturn(backendRequest);
        when(oldPlayer.createConnectionRequest(authServer)).thenReturn(authRequest);
        when(backendRequest.connect()).thenReturn(CompletableFuture.completedFuture(backendFailure));
        when(authRequest.connect()).thenReturn(authFallback);
        when(backendFailure.isSuccessful()).thenReturn(false);
        when(authSuccess.isSuccessful()).thenReturn(true);
        when(authCache.getAuthorizedPlayer(playerUuid)).thenReturn(new CachedAuthUser(
                playerUuid, "NewFallbackPlayer", "127.0.0.1", System.currentTimeMillis(), false, null));
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), org.mockito.ArgumentMatchers.<Consumer<ScheduledTask>>any()))
                .thenReturn(taskBuilder);
        when(taskBuilder.delay(eq(1500L), eq(TimeUnit.MILLISECONDS))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(newPendingTransfer, staleRetry);

        connectionManager.beginTransferSession(oldPlayer);
        connectionManager.setForcedHostTarget(oldPlayer, "backend");
        assertTrue(connectionManager.transferToBackend(oldPlayer));
        connectionManager.beginTransferSession(newPlayer);
        connectionManager.autoTransferFromAuthServerToBackend(newPlayer);

        authFallback.complete(authSuccess);

        verify(newPendingTransfer, never()).cancel();
        verify(backendRequest).connect();
        verify(authRequest).connect();
        verify(taskBuilder, times(1)).schedule();
    }

    @Test
    void authFallbackAdmission_ReplacedAfterLastGuard_DoesNotConnectToAuthServer() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerConnection backendConnection = org.mockito.Mockito.mock(ServerConnection.class);
        ConnectionRequestBuilder backendRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder authRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result backendFailure = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(oldPlayer.getUsername()).thenReturn("OldFallbackAdmissionPlayer");
        when(oldPlayer.isActive()).thenReturn(true);
        when(oldPlayer.getCurrentServer()).thenReturn(Optional.of(backendConnection));
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);
        when(backendConnection.getServer()).thenReturn(backendServer);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(backendServer.ping()).thenReturn(CompletableFuture.completedFuture(
                org.mockito.Mockito.mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        when(oldPlayer.createConnectionRequest(backendServer)).thenReturn(backendRequest);
        when(oldPlayer.createConnectionRequest(authServer)).thenReturn(authRequest);
        when(backendRequest.connect()).thenReturn(CompletableFuture.completedFuture(backendFailure));
        when(backendFailure.isSuccessful()).thenReturn(false);
        when(logger.isInfoEnabled()).thenAnswer(ignored -> {
            connectionManager.beginTransferSession(newPlayer);
            return true;
        });
        connectionManager.beginTransferSession(oldPlayer);
        connectionManager.setForcedHostTarget(oldPlayer, "backend");

        assertTrue(connectionManager.transferToBackend(oldPlayer));

        verify(oldPlayer, never()).createConnectionRequest(authServer);
        verify(authRequest, never()).connect();
        assertSame(newPlayer, getStateOwner(playerUuid));
    }

    @Test
    void backendRetryAfterLimbo_CurrentOwner_StartsOneOwnedConnection() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerConnection backendConnection = org.mockito.Mockito.mock(ServerConnection.class);
        ServerConnection authConnection = org.mockito.Mockito.mock(ServerConnection.class);
        ConnectionRequestBuilder initialRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder authRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder retryRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result backendFailure = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        ConnectionRequestBuilder.Result authSuccess = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        ConnectionRequestBuilder.Result retrySuccess = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = org.mockito.Mockito.mock(Scheduler.TaskBuilder.class);
        ScheduledTask pendingTransfer = org.mockito.Mockito.mock(ScheduledTask.class);
        CountDownLatch retryStarted = new CountDownLatch(1);
        java.util.concurrent.atomic.AtomicInteger currentServerCalls =
                new java.util.concurrent.atomic.AtomicInteger();
        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<Consumer<ScheduledTask>> callbackCaptor =
                org.mockito.ArgumentCaptor.forClass(Consumer.class);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("LimboRetryPlayer");
        when(player.isActive()).thenReturn(true);
        when(player.getCurrentServer()).thenAnswer(ignored ->
                currentServerCalls.getAndIncrement() == 0
                        ? Optional.of(backendConnection)
                        : Optional.of(authConnection));
        when(backendConnection.getServer()).thenReturn(backendServer);
        when(authConnection.getServer()).thenReturn(authServer);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(backendServer.ping()).thenReturn(CompletableFuture.completedFuture(
                org.mockito.Mockito.mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        when(player.createConnectionRequest(backendServer)).thenReturn(initialRequest, retryRequest);
        when(player.createConnectionRequest(authServer)).thenReturn(authRequest);
        when(initialRequest.connect()).thenReturn(CompletableFuture.completedFuture(backendFailure));
        when(authRequest.connect()).thenReturn(CompletableFuture.completedFuture(authSuccess));
        when(retryRequest.connect()).thenAnswer(ignored -> {
            retryStarted.countDown();
            return CompletableFuture.completedFuture(retrySuccess);
        });
        when(backendFailure.isSuccessful()).thenReturn(false);
        when(authSuccess.isSuccessful()).thenReturn(true);
        when(retrySuccess.isSuccessful()).thenReturn(true);
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), callbackCaptor.capture())).thenReturn(taskBuilder);
        when(taskBuilder.delay(eq(1500L), eq(TimeUnit.MILLISECONDS))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(pendingTransfer);
        connectionManager.beginTransferSession(player);
        connectionManager.setForcedHostTarget(player, "backend");

        assertTrue(connectionManager.transferToBackend(player));
        callbackCaptor.getValue().accept(pendingTransfer);

        assertTrue(retryStarted.await(2, TimeUnit.SECONDS));
        verify(initialRequest).connect();
        verify(authRequest).connect();
        verify(retryRequest).connect();
    }

    @Test
    void timeoutRetryCompletion_OldGeneration_DoesNotMutateNewTimeoutChain() {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerConnection authConnection = org.mockito.Mockito.mock(ServerConnection.class);
        ConnectionRequestBuilder oldInitialRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder oldRetryRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder newInitialRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder newRetryRequest = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result oldRetrySuccess = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        ConnectionRequestBuilder.Result newRetrySuccess = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        CompletableFuture<ConnectionRequestBuilder.Result> oldRetry = new CompletableFuture<>();
        CompletableFuture<ConnectionRequestBuilder.Result> newRetry = new CompletableFuture<>();
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = org.mockito.Mockito.mock(Scheduler.TaskBuilder.class);
        ScheduledTask oldTimeoutTask = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask newTimeoutTask = org.mockito.Mockito.mock(ScheduledTask.class);
        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<Consumer<ScheduledTask>> callbackCaptor =
                org.mockito.ArgumentCaptor.forClass(Consumer.class);

        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(oldPlayer.getUsername()).thenReturn("OldTimeoutPlayer");
        when(oldPlayer.isActive()).thenReturn(true);
        when(oldPlayer.getCurrentServer()).thenReturn(Optional.of(authConnection));
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);
        when(newPlayer.getUsername()).thenReturn("NewTimeoutPlayer");
        when(newPlayer.isActive()).thenReturn(true);
        when(newPlayer.getCurrentServer()).thenReturn(Optional.of(authConnection));
        when(authConnection.getServer()).thenReturn(authServer);
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(backendServer.ping()).thenReturn(
                CompletableFuture.completedFuture(org.mockito.Mockito.mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(oldPlayer.createConnectionRequest(backendServer)).thenReturn(oldInitialRequest, oldRetryRequest);
        when(newPlayer.createConnectionRequest(backendServer)).thenReturn(newInitialRequest, newRetryRequest);
        when(oldInitialRequest.connect()).thenReturn(
                CompletableFuture.failedFuture(new java.util.concurrent.TimeoutException("old initial timeout")));
        when(oldRetryRequest.connect()).thenReturn(oldRetry);
        when(newInitialRequest.connect()).thenReturn(
                CompletableFuture.failedFuture(new java.util.concurrent.TimeoutException("new initial timeout")));
        when(newRetryRequest.connect()).thenReturn(newRetry);
        when(oldRetrySuccess.isSuccessful()).thenReturn(true);
        when(newRetrySuccess.isSuccessful()).thenReturn(true);
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), callbackCaptor.capture())).thenReturn(taskBuilder);
        when(taskBuilder.delay(eq(400L), eq(TimeUnit.MILLISECONDS))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(oldTimeoutTask, newTimeoutTask);

        connectionManager.beginTransferSession(oldPlayer);
        connectionManager.setForcedHostTarget(oldPlayer, "backend");
        assertTrue(connectionManager.transferToBackend(oldPlayer));
        callbackCaptor.getAllValues().get(0).accept(oldTimeoutTask);

        connectionManager.clearTransferState(oldPlayer);
        connectionManager.beginTransferSession(newPlayer);
        connectionManager.setForcedHostTarget(newPlayer, "backend");
        assertTrue(connectionManager.transferToBackend(newPlayer));
        oldRetry.complete(oldRetrySuccess);

        verify(newTimeoutTask, never()).cancel();
        callbackCaptor.getAllValues().get(1).accept(newTimeoutTask);
        verify(newRetryRequest).connect();
        newRetry.complete(newRetrySuccess);
    }

    @Test
    @SuppressWarnings("unchecked")
    void backendWaitSelection_OldGeneration_DoesNotConnectOrReschedule() {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        RegisteredServer forcedBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerConnection authConnection = org.mockito.Mockito.mock(ServerConnection.class);
        ProxyConfig proxyConfig = org.mockito.Mockito.mock(ProxyConfig.class);
        CompletableFuture<ServerPing> oldWaitSelection = new CompletableFuture<>();
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = org.mockito.Mockito.mock(Scheduler.TaskBuilder.class);
        ScheduledTask oldWaitTask = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask newWaitTask = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask staleReschedule = org.mockito.Mockito.mock(ScheduledTask.class);
        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<Consumer<ScheduledTask>> callbackCaptor =
                org.mockito.ArgumentCaptor.forClass(Consumer.class);

        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(oldPlayer.getUsername()).thenReturn("OldWaitPlayer");
        when(oldPlayer.isActive()).thenReturn(true);
        when(oldPlayer.getCurrentServer()).thenReturn(Optional.of(authConnection));
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);
        when(newPlayer.getUsername()).thenReturn("NewWaitPlayer");
        when(newPlayer.isActive()).thenReturn(true);
        when(newPlayer.getCurrentServer()).thenReturn(Optional.of(authConnection));
        when(authConnection.getServer()).thenReturn(authServer);
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(forcedBackend.getServerInfo()).thenReturn(
                new ServerInfo("forced", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(forcedBackend.ping()).thenReturn(
                CompletableFuture.failedFuture(new IllegalStateException("initial outage")),
                oldWaitSelection);
        when(proxyServer.getServer("forced")).thenReturn(Optional.of(forcedBackend));
        when(proxyServer.getConfiguration()).thenReturn(proxyConfig);
        when(proxyConfig.getAttemptConnectionOrder()).thenReturn(List.of());
        when(proxyServer.getAllServers()).thenReturn(List.of());
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), callbackCaptor.capture())).thenReturn(taskBuilder);
        when(taskBuilder.delay(eq(5L), eq(TimeUnit.SECONDS))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(oldWaitTask, newWaitTask, staleReschedule);

        connectionManager.beginTransferSession(oldPlayer);
        connectionManager.setForcedHostTarget(oldPlayer, "forced");
        assertTrue(connectionManager.transferToBackend(oldPlayer));
        callbackCaptor.getAllValues().get(0).accept(oldWaitTask);

        connectionManager.beginTransferSession(newPlayer);
        assertTrue(connectionManager.transferToBackend(newPlayer));
        oldWaitSelection.completeExceptionally(new IllegalStateException("still offline"));

        verify(newWaitTask, never()).cancel();
        verify(oldPlayer, never()).createConnectionRequest(forcedBackend);
        verify(forcedBackend, times(2)).ping();
        verify(taskBuilder, times(2)).schedule();
    }

    @Test
    void autoTransfer_RepeatedTriggers_ReplaceOnlySameOwnerTask() {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = org.mockito.Mockito.mock(Scheduler.TaskBuilder.class);
        ScheduledTask oldFirstTask = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask oldReplacementTask = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask newTask = org.mockito.Mockito.mock(ScheduledTask.class);
        ScheduledTask staleOldTask = org.mockito.Mockito.mock(ScheduledTask.class);

        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(oldPlayer.getUsername()).thenReturn("OldAutoPlayer");
        when(oldPlayer.getRemoteAddress()).thenReturn(new InetSocketAddress("127.0.0.1", 25565));
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);
        when(newPlayer.getUsername()).thenReturn("NewAutoPlayer");
        when(newPlayer.getRemoteAddress()).thenReturn(new InetSocketAddress("127.0.0.1", 25565));
        when(authCache.getAuthorizedPlayer(playerUuid)).thenReturn(new CachedAuthUser(
                playerUuid, "AutoPlayer", "127.0.0.1", System.currentTimeMillis(), false, null));
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), org.mockito.ArgumentMatchers.<Consumer<ScheduledTask>>any()))
                .thenReturn(taskBuilder);
        when(taskBuilder.delay(eq(1500L), eq(TimeUnit.MILLISECONDS))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(oldFirstTask, oldReplacementTask, newTask, staleOldTask);

        connectionManager.beginTransferSession(oldPlayer);
        connectionManager.autoTransferFromAuthServerToBackend(oldPlayer);
        connectionManager.autoTransferFromAuthServerToBackend(oldPlayer);
        verify(oldFirstTask).cancel();

        connectionManager.beginTransferSession(newPlayer);
        connectionManager.autoTransferFromAuthServerToBackend(newPlayer);
        connectionManager.autoTransferFromAuthServerToBackend(oldPlayer);

        verify(oldReplacementTask).cancel();
        verify(newTask, never()).cancel();
        verify(taskBuilder, times(3)).schedule();
    }

    @Test
    void delayedDisconnect_OldConnection_DoesNotCancelReplacementState() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        ScheduledTask newPendingTransfer = org.mockito.Mockito.mock(ScheduledTask.class);
        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);

        connectionManager.beginTransferSession(oldPlayer);
        connectionManager.beginTransferSession(newPlayer);
        putStateTask(playerUuid, "pendingTransfer", newPendingTransfer);

        connectionManager.clearTransferState(oldPlayer);

        verify(newPendingTransfer, never()).cancel();
        assertSame(newPlayer, getStateOwner(playerUuid),
                "A delayed disconnect must not retire B's concrete owner state");
    }

    @Test
    void beginTransferSession_DisplacedTaskCancellation_HappensOutsideLifecycleLock() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player replacementPlayer = org.mockito.Mockito.mock(Player.class);
        Player probePlayer = org.mockito.Mockito.mock(Player.class);
        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(replacementPlayer.getUniqueId()).thenReturn(playerUuid);
        when(probePlayer.getUniqueId()).thenReturn(playerUuid);
        try (CancellationProbe probe = cancellationProbe(probePlayer)) {
            connectionManager.beginTransferSession(oldPlayer);
            putStateTask(playerUuid, "pendingTransfer", probe.task());

            connectionManager.beginTransferSession(replacementPlayer);
        }

        assertSame(probePlayer, getStateOwner(playerUuid));
    }

    @Test
    void shutdown_StateTaskCancellation_HappensOutsideLifecycleLock() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        Player probePlayer = org.mockito.Mockito.mock(Player.class);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(probePlayer.getUniqueId()).thenReturn(UUID.randomUUID());
        try (CancellationProbe probe = cancellationProbe(probePlayer)) {
            connectionManager.beginTransferSession(player);
            putStateTask(playerUuid, "pendingTransfer", probe.task());

            connectionManager.shutdown();
        }

        assertTrue(getMap("transferStates").isEmpty());
    }

    @Test
    void authReadyPingCompletion_OldGeneration_DoesNotScheduleRetryOrHangTransfer() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        CompletableFuture<ServerPing> pendingPing = new CompletableFuture<>();
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = org.mockito.Mockito.mock(Scheduler.TaskBuilder.class);
        ScheduledTask staleRetry = org.mockito.Mockito.mock(ScheduledTask.class);
        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(oldPlayer.getUsername()).thenReturn("OldAuthPingPlayer");
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        when(authServer.ping()).thenReturn(pendingPing);
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), any(Runnable.class)))
                .thenReturn(taskBuilder);
        when(taskBuilder.delay(eq(50L), eq(TimeUnit.MILLISECONDS))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(staleRetry);
        connectionManager.beginTransferSession(oldPlayer);

        CompletableFuture<Boolean> transfer = connectionManager.transferToAuthServerAsync(oldPlayer);
        connectionManager.beginTransferSession(newPlayer);
        pendingPing.completeExceptionally(new IllegalStateException("old ping failed"));

        assertTrue(transfer.isDone(), "Retiring an auth-ready ping must settle its transfer future");
        assertFalse(transfer.join());
        verify(scheduler, never()).buildTask(any(), any(Runnable.class));
        verify(oldPlayer, never()).createConnectionRequest(authServer);
        assertSame(newPlayer, getStateOwner(playerUuid));
    }

    @Test
    void authReadyRetry_Shutdown_CancelsTaskAndSettlesTransferFuture() {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        Scheduler scheduler = org.mockito.Mockito.mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = org.mockito.Mockito.mock(Scheduler.TaskBuilder.class);
        ScheduledTask readinessRetry = org.mockito.Mockito.mock(ScheduledTask.class);
        AtomicReference<Consumer<ScheduledTask>> callback = new AtomicReference<>();
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("ShutdownAuthReadyPlayer");
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        when(authServer.ping()).thenReturn(
                CompletableFuture.failedFuture(new IllegalStateException("not ready")));
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        when(scheduler.buildTask(any(), org.mockito.ArgumentMatchers.<Consumer<ScheduledTask>>any()))
                .thenAnswer(invocation -> {
                    callback.set(invocation.getArgument(1));
                    return taskBuilder;
                });
        when(taskBuilder.delay(eq(50L), eq(TimeUnit.MILLISECONDS))).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(readinessRetry);
        connectionManager.beginTransferSession(player);

        CompletableFuture<Boolean> transfer = connectionManager.transferToAuthServerAsync(player);
        connectionManager.shutdown();
        callback.get().accept(readinessRetry);

        verify(readinessRetry).cancel();
        assertTrue(transfer.isDone(), "Cancelling auth readiness must settle the public transfer future");
        assertFalse(transfer.join());
        verify(authServer, times(1)).ping();
        verify(player, never()).createConnectionRequest(authServer);
    }

    @Test
    void authConnectCompletion_OldGeneration_DoesNotMessageOrRetireReplacement() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ConnectionRequestBuilder request = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        CompletableFuture<ConnectionRequestBuilder.Result> pendingConnect = new CompletableFuture<>();
        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(oldPlayer.getUsername()).thenReturn("OldAuthConnectPlayer");
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        when(authServer.ping()).thenReturn(CompletableFuture.completedFuture(
                org.mockito.Mockito.mock(ServerPing.class)));
        when(oldPlayer.createConnectionRequest(authServer)).thenReturn(request);
        when(request.connect()).thenReturn(pendingConnect);
        connectionManager.beginTransferSession(oldPlayer);

        CompletableFuture<Boolean> transfer = connectionManager.transferToAuthServerAsync(oldPlayer);
        connectionManager.beginTransferSession(newPlayer);
        pendingConnect.completeExceptionally(new IllegalStateException("old connect failed"));

        assertFalse(transfer.join());
        verify(oldPlayer, never()).sendMessage(any(Component.class));
        assertSame(newPlayer, getStateOwner(playerUuid));
    }

    @Test
    void authConnectCompletion_Shutdown_DoesNotMessageOrResurrectState() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ConnectionRequestBuilder request = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        CompletableFuture<ConnectionRequestBuilder.Result> pendingConnect = new CompletableFuture<>();
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("ShutdownAuthConnectPlayer");
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        when(authServer.ping()).thenReturn(CompletableFuture.completedFuture(
                org.mockito.Mockito.mock(ServerPing.class)));
        when(player.createConnectionRequest(authServer)).thenReturn(request);
        when(request.connect()).thenReturn(pendingConnect);
        connectionManager.beginTransferSession(player);

        CompletableFuture<Boolean> transfer = connectionManager.transferToAuthServerAsync(player);
        connectionManager.shutdown();
        pendingConnect.completeExceptionally(new IllegalStateException("shutdown connect failed"));

        assertFalse(transfer.join());
        verify(player, never()).sendMessage(any(Component.class));
        assertTrue(getMap("transferStates").isEmpty());
    }

    @Test
    void backendPingCompletion_Shutdown_DoesNotConnectMessageOrResurrectState() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        CompletableFuture<ServerPing> pendingPing = new CompletableFuture<>();
        CountDownLatch pingStarted = new CountDownLatch(1);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("ShutdownBackendPingPlayer");
        when(player.isActive()).thenReturn(true);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(backendServer.ping()).thenAnswer(ignored -> {
            pingStarted.countDown();
            return pendingPing;
        });
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        connectionManager.beginTransferSession(player);
        connectionManager.setForcedHostTarget(player, "backend");

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> transfer = executor.submit(() -> connectionManager.transferToBackend(player));
            assertTrue(pingStarted.await(1, TimeUnit.SECONDS));
            connectionManager.shutdown();
            pendingPing.complete(org.mockito.Mockito.mock(ServerPing.class));

            assertFalse(transfer.get(2, TimeUnit.SECONDS));
        }

        verify(player, never()).createConnectionRequest(backendServer);
        verify(player, never()).sendMessage(any(Component.class));
        assertTrue(getMap("transferStates").isEmpty());
    }

    @Test
    void backendConnectCompletion_Shutdown_DoesNotMessageOrResurrectState() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ConnectionRequestBuilder request = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result failedResult = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        CompletableFuture<ConnectionRequestBuilder.Result> pendingConnect = new CompletableFuture<>();
        CountDownLatch connectStarted = new CountDownLatch(1);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("ShutdownBackendConnectPlayer");
        when(player.isActive()).thenReturn(true);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(backendServer.ping()).thenReturn(CompletableFuture.completedFuture(
                org.mockito.Mockito.mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(player.createConnectionRequest(backendServer)).thenReturn(request);
        when(request.connect()).thenAnswer(ignored -> {
            connectStarted.countDown();
            return pendingConnect;
        });
        when(failedResult.isSuccessful()).thenReturn(false);
        connectionManager.beginTransferSession(player);
        connectionManager.setForcedHostTarget(player, "backend");

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> transfer = executor.submit(() -> connectionManager.transferToBackend(player));
            assertTrue(connectStarted.await(1, TimeUnit.SECONDS));
            org.mockito.Mockito.clearInvocations(player);
            connectionManager.shutdown();
            pendingConnect.complete(failedResult);

            assertFalse(transfer.get(2, TimeUnit.SECONDS));
        }

        verify(player, never()).sendMessage(any(Component.class));
        assertTrue(getMap("transferStates").isEmpty());
    }

    @Test
    void backendConnectAdmission_ShutdownDuringLastActiveCheck_DoesNotCreateRequest() {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ConnectionRequestBuilder request = org.mockito.Mockito.mock(ConnectionRequestBuilder.class);
        ConnectionRequestBuilder.Result result = org.mockito.Mockito.mock(ConnectionRequestBuilder.Result.class);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("ShutdownAdmissionPlayer");
        when(player.isActive()).thenReturn(true).thenAnswer(ignored -> {
            connectionManager.shutdown();
            return true;
        });
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(backendServer.ping()).thenReturn(CompletableFuture.completedFuture(
                org.mockito.Mockito.mock(ServerPing.class)));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(player.createConnectionRequest(backendServer)).thenReturn(request);
        when(request.connect()).thenReturn(CompletableFuture.completedFuture(result));
        when(result.isSuccessful()).thenReturn(true);
        connectionManager.beginTransferSession(player);
        connectionManager.setForcedHostTarget(player, "backend");

        assertFalse(connectionManager.transferToBackend(player));

        verify(player, never()).createConnectionRequest(backendServer);
    }

    @Test
    @SuppressWarnings("unchecked")
    void forcedHostPingAdmission_ReplacedDuringResolution_DoesNotPingOldTarget() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        RegisteredServer forcedBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(oldPlayer.getUsername()).thenReturn("OldForcedAdmissionPlayer");
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);
        when(forcedBackend.getServerInfo()).thenReturn(
                new ServerInfo("forced", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(forcedBackend.ping()).thenReturn(CompletableFuture.completedFuture(
                org.mockito.Mockito.mock(ServerPing.class)));
        when(proxyServer.getServer("forced")).thenAnswer(ignored -> {
            connectionManager.beginTransferSession(newPlayer);
            return Optional.of(forcedBackend);
        });
        connectionManager.beginTransferSession(oldPlayer);
        connectionManager.setForcedHostTarget(oldPlayer, "forced");
        Object oldState = getMap("transferStates").get(playerUuid);
        Method retrySelection = ConnectionManager.class.getDeclaredMethod(
                "findAvailableBackendServerForRetryAsync", Player.class, oldState.getClass());
        retrySelection.setAccessible(true);

        CompletableFuture<Optional<RegisteredServer>> selection =
                (CompletableFuture<Optional<RegisteredServer>>) retrySelection.invoke(
                        connectionManager, oldPlayer, oldState);

        assertTrue(selection.join().isEmpty());
        verify(forcedBackend, never()).ping();
        assertSame(newPlayer, getStateOwner(playerUuid));
    }

    @Test
    void shutdown_InFlightCallbacksCannotPublishOrResurrectState() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUniqueId()).thenReturn(playerUuid);

        connectionManager.shutdown();
        connectionManager.beginTransferSession(player);

        assertTrue(getMap("transferStates").isEmpty(),
                "A session beginning after shutdown must not publish transfer ownership");
        assertFalse(connectionManager.transferToBackend(player));
        assertTrue(getMap("transferStates").isEmpty(),
                "A public transfer after shutdown must not lazily resurrect ownership");
    }

    @Test
    void initialBackendPingAdmission_AfterShutdown_ReturnsEmptyWithoutPing() {
        ProxyConfig proxyConfig = org.mockito.Mockito.mock(ProxyConfig.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(proxyServer.getConfiguration()).thenReturn(proxyConfig);
        when(proxyConfig.getAttemptConnectionOrder()).thenReturn(List.of("backend"));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(backendServer.ping()).thenReturn(CompletableFuture.completedFuture(
                org.mockito.Mockito.mock(ServerPing.class)));
        connectionManager.shutdown();

        Optional<RegisteredServer> selected = connectionManager
                .findAvailableBackendServerForInitialConnectionAsync().join();

        assertTrue(selected.isEmpty());
        verify(backendServer, never()).ping();
    }

    @Test
    void initialBackendPingCompletion_AfterShutdown_ReturnsEmpty() {
        ProxyConfig proxyConfig = org.mockito.Mockito.mock(ProxyConfig.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        CompletableFuture<ServerPing> pendingPing = new CompletableFuture<>();
        when(proxyServer.getConfiguration()).thenReturn(proxyConfig);
        when(proxyConfig.getAttemptConnectionOrder()).thenReturn(List.of("backend"));
        when(proxyServer.getServer("backend")).thenReturn(Optional.of(backendServer));
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(backendServer.ping()).thenReturn(pendingPing);

        CompletableFuture<Optional<RegisteredServer>> selection =
                connectionManager.findAvailableBackendServerForInitialConnectionAsync();
        connectionManager.shutdown();
        pendingPing.complete(org.mockito.Mockito.mock(ServerPing.class));

        assertTrue(selection.join().isEmpty());
        verify(backendServer).ping();
    }

    @Test
    void fallbackBackendPingCompletion_AfterShutdown_ReturnsEmpty() {
        FallbackSelectionFixture fixture = preparePendingFallbackSelection();

        CompletableFuture<Optional<RegisteredServer>> selection =
                connectionManager.findAvailableBackendServerForInitialConnectionAsync();
        verify(fixture.fallbackBackend()).ping();
        connectionManager.shutdown();
        fixture.pendingPing().complete(org.mockito.Mockito.mock(ServerPing.class));

        assertTrue(selection.join().isEmpty());
    }

    @Test
    @SuppressWarnings("unchecked")
    void fallbackBackendPingCompletion_AfterOwnerReplacement_ReturnsEmpty() throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player oldPlayer = org.mockito.Mockito.mock(Player.class);
        Player newPlayer = org.mockito.Mockito.mock(Player.class);
        when(oldPlayer.getUniqueId()).thenReturn(playerUuid);
        when(newPlayer.getUniqueId()).thenReturn(playerUuid);
        FallbackSelectionFixture fixture = preparePendingFallbackSelection();
        connectionManager.beginTransferSession(oldPlayer);
        Object oldState = getMap("transferStates").get(playerUuid);
        Method selectionMethod = ConnectionManager.class.getDeclaredMethod(
                "findAvailableBackendServerAsync", oldState.getClass());
        selectionMethod.setAccessible(true);

        CompletableFuture<Optional<RegisteredServer>> selection =
                (CompletableFuture<Optional<RegisteredServer>>) selectionMethod.invoke(
                        connectionManager, oldState);
        verify(fixture.fallbackBackend()).ping();
        connectionManager.beginTransferSession(newPlayer);
        fixture.pendingPing().complete(org.mockito.Mockito.mock(ServerPing.class));

        assertTrue(selection.join().isEmpty());
        assertSame(newPlayer, getStateOwner(playerUuid));
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

        connectionManager.beginTransferSession(player);
        connectionManager.setForcedHostTarget(player, "forced");
        Object state = getMap("transferStates").get(playerUuid);
        Method scheduleRetry = ConnectionManager.class
                .getDeclaredMethod("scheduleBackendWaitRetry", Player.class, state.getClass(), int.class);
        scheduleRetry.setAccessible(true);
        scheduleRetry.invoke(connectionManager, player, state, 1);

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
        Player player = org.mockito.Mockito.mock(Player.class);
        UUID playerUuid = UUID.randomUUID();
        AtomicReference<ScheduledTask> lateTask = new AtomicReference<>();
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(proxyServer.getScheduler()).thenReturn(scheduler);
        connectionManager.beginTransferSession(player);
        Object state = getMap("transferStates").get(playerUuid);

        connectionManager.shutdown();

        Method scheduleOwnedTask = ConnectionManager.class.getDeclaredMethod(
                "scheduleOwnedTask",
                state.getClass(),
                AtomicReference.class,
                long.class,
                TimeUnit.class,
                Runnable.class);
        scheduleOwnedTask.setAccessible(true);
        scheduleOwnedTask.invoke(
                connectionManager,
                state,
                lateTask,
                1L,
                TimeUnit.SECONDS,
                (Runnable) () -> {
                    throw new AssertionError("A task must not run after shutdown");
                });

        assertNull(lateTask.get());
        verify(scheduler, never()).buildTask(
                any(), org.mockito.ArgumentMatchers.<Consumer<ScheduledTask>>any());
    }

    @SuppressWarnings("unchecked")
    private Map<UUID, Object> getMap(String fieldName) throws Exception {
        Field field = ConnectionManager.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return (Map<UUID, Object>) field.get(connectionManager);
    }

    private Player getStateOwner(UUID playerUuid) throws Exception {
        Object state = getMap("transferStates").get(playerUuid);
        Method owner = state.getClass().getDeclaredMethod("owner");
        owner.setAccessible(true);
        return (Player) owner.invoke(state);
    }

    private CancellationProbe cancellationProbe(Player probePlayer) throws Exception {
        ScheduledTask task = org.mockito.Mockito.mock(ScheduledTask.class);
        CountDownLatch probeReady = new CountDownLatch(1);
        CountDownLatch startPublication = new CountDownLatch(1);
        CountDownLatch publicationFinished = new CountDownLatch(1);
        ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        Future<?> publication = executor.submit(() -> {
            probeReady.countDown();
            awaitLatch(startPublication);
            connectionManager.beginTransferSession(probePlayer);
            publicationFinished.countDown();
        });
        assertTrue(probeReady.await(1, TimeUnit.SECONDS),
                "Cancellation probe must be parked before the lifecycle operation starts");
        doAnswer(ignored -> {
            startPublication.countDown();
            assertTrue(publicationFinished.await(1, TimeUnit.SECONDS),
                    "Task cancellation must not hold the lifecycle publication lock");
            publication.get(1, TimeUnit.SECONDS);
            return null;
        }).when(task).cancel();
        return new CancellationProbe(task, executor);
    }

    private static void awaitLatch(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while staging lifecycle cancellation", interrupted);
        }
    }

    private FallbackSelectionFixture preparePendingFallbackSelection() {
        ProxyConfig proxyConfig = org.mockito.Mockito.mock(ProxyConfig.class);
        RegisteredServer unavailableTryBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer fallbackBackend = org.mockito.Mockito.mock(RegisteredServer.class);
        CompletableFuture<ServerPing> pendingPing = new CompletableFuture<>();
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
        when(fallbackBackend.ping()).thenReturn(pendingPing);
        return new FallbackSelectionFixture(fallbackBackend, pendingPing);
    }

    @SuppressWarnings("unchecked")
    private void putStateTask(UUID playerUuid, String fieldName, ScheduledTask task) throws Exception {
        Object state = getMap("transferStates").get(playerUuid);
        Field field = state.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        ((java.util.concurrent.atomic.AtomicReference<ScheduledTask>) field.get(state)).set(task);
    }

    private record CancellationProbe(ScheduledTask task, ExecutorService executor) implements AutoCloseable {
        @Override
        public void close() {
            executor.shutdownNow();
        }
    }

    private record FallbackSelectionFixture(
            RegisteredServer fallbackBackend, CompletableFuture<ServerPing> pendingPing) {
    }
}
