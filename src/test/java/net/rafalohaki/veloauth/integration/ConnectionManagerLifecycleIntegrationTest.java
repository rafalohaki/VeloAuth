package net.rafalohaki.veloauth.integration;

import com.velocitypowered.api.proxy.ConnectionRequestBuilder;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import com.velocitypowered.api.scheduler.ScheduledTask;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.i18n.Messages;
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
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertTrue;
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

        connectionManager.setForcedHostTarget(playerUuid, "backend");
        putTask("pendingTransfers", playerUuid, pendingTransfer);
        putTask("backendWaitTasks", playerUuid, backendWaitTask);
        putTask("timeoutRetryTasks", playerUuid, timeoutRetryTask);
        putValue("timeoutRetryScheduled", playerUuid, Boolean.TRUE);

        boolean transferred = connectionManager.transferToBackend(player);

        assertTrue(transferred, "Successful backend transfer should report success");
        verify(pendingTransfer).cancel();
        verify(backendWaitTask).cancel();
        verify(timeoutRetryTask).cancel();
        assertTrue(getMap("pendingTransfers").isEmpty(), "Pending transfer tasks should be cleared after success");
        assertTrue(getMap("backendWaitTasks").isEmpty(), "Backend wait tasks should be cleared after success");
        assertTrue(getMap("timeoutRetryTasks").isEmpty(), "Timeout retry tasks should be cleared after success");
        assertTrue(getMap("timeoutRetryScheduled").isEmpty(), "Timeout retry flags should be cleared after success");
        assertTrue(getMap("forcedHostTargets").isEmpty(), "Forced-host targets should be consumed after success");
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
}
