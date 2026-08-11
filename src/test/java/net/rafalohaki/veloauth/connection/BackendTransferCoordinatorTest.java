package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.net.InetSocketAddress;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BackendTransferCoordinatorTest {

    private ConnectionManager lifecycle;
    private BackendSelector selector;
    private Player player;
    private PlayerTransferState state;
    private BackendTransferCoordinator coordinator;

    @BeforeEach
    void setUp() {
        lifecycle = mock(ConnectionManager.class);
        selector = mock(BackendSelector.class);
        player = mock(Player.class);
        state = new PlayerTransferState(UUID.randomUUID(), player, 1L);
        Settings settings = mock(Settings.class);
        Logger logger = mock(Logger.class);
        Messages messages = mock(Messages.class);
        coordinator = new BackendTransferCoordinator(
                lifecycle, selector, mock(AuthCache.class), settings, logger, messages);

        when(lifecycle.currentState(player)).thenReturn(state);
        when(lifecycle.isStale(state)).thenReturn(false);
        when(lifecycle.resetTasksIfCurrent(state, false)).thenReturn(true);
        when(lifecycle.scheduleOwnedTask(any(), any(), anyLong(), any(), any()))
                .thenReturn(true);
        when(selector.resolveForcedHostTarget(player, state)).thenReturn(Optional.empty());
    }

    @Test
    void transfer_NoBackendAvailable_ReturnsWaitingOutcome() {
        when(selector.findAvailableBackendServer(state)).thenReturn(Optional.empty());

        BackendTransferOutcome outcome = coordinator.transfer(player);

        assertSame(BackendTransferOutcome.WAITING_FOR_BACKEND, outcome);
        verify(lifecycle).scheduleOwnedTask(
                eq(state), same(state.backendWait()), eq(5L),
                eq(java.util.concurrent.TimeUnit.SECONDS), any(Runnable.class));
    }

    @Test
    void transfer_ConnectionAlreadyOwned_ReturnsCoalescedOutcome() {
        RegisteredServer backend = mock(RegisteredServer.class);
        when(backend.getServerInfo()).thenReturn(new com.velocitypowered.api.proxy.server.ServerInfo(
                "backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(selector.resolveForcedHostTarget(player, state)).thenReturn(Optional.of(backend));
        when(player.isActive()).thenReturn(true);
        state.backendConnectionActive().set(true);

        BackendTransferOutcome outcome = coordinator.transfer(player);

        assertSame(BackendTransferOutcome.COALESCED, outcome);
        verify(lifecycle, never()).startConnectionIfCurrent(any(), any(), any());
        verify(lifecycle, never()).finishIfCurrent(any(), anyBoolean());
    }
}
