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
    void schedule_UnauthenticatedPlayer_SendsRepeatingReminder() {
        ReminderFixture fixture = new ReminderFixture(30);
        fixture.scheduler.schedule(fixture.player);

        verify(fixture.reminderBuilder).delay(10, TimeUnit.SECONDS);
        verify(fixture.reminderBuilder).repeat(10, TimeUnit.SECONDS);
        fixture.reminderCallback().accept(fixture.reminderTask);

        verify(fixture.player).sendMessage(org.mockito.ArgumentMatchers
                .<net.kyori.adventure.text.Component>any());
        verify(fixture.reminderTask, never()).cancel();
    }

    @Test
    void reminderCallback_PlayerAuthorized_CancelsItselfWithoutMessage() {
        ReminderFixture fixture = new ReminderFixture(30);
        fixture.scheduler.schedule(fixture.player);
        when(fixture.authCache.isPlayerAuthorized(
                org.mockito.ArgumentMatchers.eq(fixture.playerUuid),
                org.mockito.ArgumentMatchers.any())).thenReturn(true);

        fixture.reminderCallback().accept(fixture.reminderTask);

        verify(fixture.player, never()).sendMessage(org.mockito.ArgumentMatchers
                .<net.kyori.adventure.text.Component>any());
        verify(fixture.reminderTask).cancel();
    }

    @Test
    void cancel_PendingReminder_CancelsReminderTask() {
        ReminderFixture fixture = new ReminderFixture(30);
        fixture.scheduler.schedule(fixture.player);

        fixture.scheduler.cancel(fixture.playerUuid);

        verify(fixture.reminderTask).cancel();
    }

    @Test
    void schedule_TimeoutDisabled_StillSchedulesReminder() {
        ReminderFixture fixture = new ReminderFixture(0);
        fixture.scheduler.schedule(fixture.player);

        verify(fixture.reminderBuilder).repeat(10, TimeUnit.SECONDS);
        verify(fixture.reminderBuilder).schedule();
    }

    /** Shared wiring for the repeating-reminder scenarios: reminder task first, kick task second. */
    private static final class ReminderFixture {
        final Scheduler velocityScheduler = mock(Scheduler.class);
        final Scheduler.TaskBuilder reminderBuilder = mock(Scheduler.TaskBuilder.class);
        final Scheduler.TaskBuilder timeoutBuilder = mock(Scheduler.TaskBuilder.class);
        final ScheduledTask reminderTask = mock(ScheduledTask.class);
        final ScheduledTask timeoutTask = mock(ScheduledTask.class);
        final AuthCache authCache = mock(AuthCache.class);
        final ConnectionManager connectionManager = mock(ConnectionManager.class);
        final Player player = mock(Player.class);
        final UUID playerUuid = UUID.randomUUID();
        final AuthTimeoutScheduler scheduler;
        private final java.util.List<Consumer<ScheduledTask>> callbacks = new java.util.ArrayList<>();

        ReminderFixture(int timeoutSeconds) {
            ProxyServer proxyServer = mock(ProxyServer.class);
            Settings settings = mock(Settings.class);
            Messages messages = new Messages();
            messages.setLanguage("en");
            VeloAuth plugin = new VeloAuth(
                    proxyServer, mock(Logger.class), Path.of("."), mock(Metrics.Factory.class));
            scheduler = new AuthTimeoutScheduler(
                    plugin, settings, messages, authCache, connectionManager);

            when(proxyServer.getScheduler()).thenReturn(velocityScheduler);
            when(settings.getAuthServerTimeoutSeconds()).thenReturn(timeoutSeconds);
            when(player.getUniqueId()).thenReturn(playerUuid);
            when(player.isActive()).thenReturn(true);
            when(connectionManager.isPlayerOnAuthServer(player)).thenReturn(true);
            when(velocityScheduler.buildTask(
                    any(), org.mockito.ArgumentMatchers.<Consumer<ScheduledTask>>any()))
                    .thenAnswer(invocation -> {
                        callbacks.add(invocation.getArgument(1));
                        return callbacks.size() == 1 ? reminderBuilder : timeoutBuilder;
                    });
            stubBuilder(reminderBuilder, reminderTask);
            stubBuilder(timeoutBuilder, timeoutTask);
        }

        private static void stubBuilder(Scheduler.TaskBuilder builder, ScheduledTask task) {
            when(builder.delay(org.mockito.ArgumentMatchers.anyLong(), any()))
                    .thenReturn(builder);
            when(builder.repeat(org.mockito.ArgumentMatchers.anyLong(), any()))
                    .thenReturn(builder);
            when(builder.schedule()).thenReturn(task);
        }

        Consumer<ScheduledTask> reminderCallback() {
            return callbacks.get(0);
        }
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
        when(taskBuilder.delay(org.mockito.ArgumentMatchers.anyLong(), any()))
                .thenReturn(taskBuilder);
        when(taskBuilder.repeat(org.mockito.ArgumentMatchers.anyLong(), any()))
                .thenReturn(taskBuilder);
        when(taskBuilder.schedule()).thenReturn(scheduledTask);

        scheduler.schedule(player);
        scheduler.cancel(playerUuid);
        callback.get().accept(scheduledTask);

        verify(scheduledTask, org.mockito.Mockito.atLeastOnce()).cancel();
        verify(player, never()).disconnect(any());
        verifyNoInteractions(messages, authCache, connectionManager);
    }
}
