package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.scheduler.ScheduledTask;
import com.velocitypowered.api.scheduler.Scheduler;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import org.bstats.velocity.Metrics;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.nio.file.Path;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AuthTimeoutSchedulerTest {

    @Test
    void shutdown_LateSchedule_ShouldNotPublishNewTask() {
        ProxyServer proxyServer = mock(ProxyServer.class);
        Scheduler velocityScheduler = mock(Scheduler.class);
        Logger logger = mock(Logger.class);
        Settings settings = mock(Settings.class);
        Player player = mock(Player.class);
        VeloAuth plugin = new VeloAuth(
                proxyServer, logger, Path.of("."), mock(Metrics.Factory.class));
        AuthTimeoutScheduler scheduler = new AuthTimeoutScheduler(
                plugin,
                settings,
                mock(Messages.class),
                mock(AuthCache.class),
                mock(ConnectionManager.class));

        when(proxyServer.getScheduler()).thenReturn(velocityScheduler);
        when(settings.getAuthServerTimeoutSeconds()).thenReturn(30);
        when(player.getUniqueId()).thenReturn(UUID.randomUUID());

        scheduler.shutdown();
        scheduler.schedule(player);

        verify(velocityScheduler, never()).buildTask(
                any(), org.mockito.ArgumentMatchers.<Consumer<ScheduledTask>>any());
    }

    @Test
    void cancel_LogoutCallbackRunsLate_DoesNotDisconnectPlayer() {
        ProxyServer proxyServer = mock(ProxyServer.class);
        Scheduler velocityScheduler = mock(Scheduler.class);
        Scheduler.TaskBuilder taskBuilder = mock(Scheduler.TaskBuilder.class);
        ScheduledTask scheduledTask = mock(ScheduledTask.class);
        Logger logger = mock(Logger.class);
        Settings settings = mock(Settings.class);
        Messages messages = mock(Messages.class);
        AuthCache authCache = mock(AuthCache.class);
        ConnectionManager connectionManager = mock(ConnectionManager.class);
        Player player = mock(Player.class);
        UUID playerUuid = UUID.randomUUID();
        AtomicReference<Consumer<ScheduledTask>> callback = new AtomicReference<>();
        VeloAuth plugin = new VeloAuth(
                proxyServer, logger, Path.of("."), mock(Metrics.Factory.class));
        AuthTimeoutScheduler scheduler = new AuthTimeoutScheduler(
                plugin, settings, messages, authCache, connectionManager);

        when(proxyServer.getScheduler()).thenReturn(velocityScheduler);
        when(settings.getAuthServerTimeoutSeconds()).thenReturn(30);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.isActive()).thenReturn(true);
        when(connectionManager.isPlayerOnAuthServer(player)).thenReturn(true);
        when(velocityScheduler.buildTask(
                any(), org.mockito.ArgumentMatchers.<Consumer<ScheduledTask>>any()))
                .thenAnswer(invocation -> {
                    callback.set(invocation.getArgument(1));
                    return taskBuilder;
                });
        when(taskBuilder.delay(30, TimeUnit.SECONDS)).thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(scheduledTask);

        scheduler.schedule(player);
        scheduler.cancel(playerUuid);
        callback.get().accept(scheduledTask);

        verify(scheduledTask).cancel();
        verify(player, never()).disconnect(any());
        verifyNoInteractions(messages, authCache, connectionManager);
    }
}
