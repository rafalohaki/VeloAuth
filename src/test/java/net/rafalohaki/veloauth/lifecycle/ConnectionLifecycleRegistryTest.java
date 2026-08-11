package net.rafalohaki.veloauth.lifecycle;

import com.velocitypowered.api.proxy.Player;
import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ConnectionLifecycleRegistryTest {

    @Test
    void markRetired_CleanupPrecedesRetirementAndReplacementPublication() throws Exception {
        ConnectionLifecycleRegistry registry = new ConnectionLifecycleRegistry();
        UUID playerId = UUID.randomUUID();
        Player first = player(playerId);
        Player replacement = player(playerId);
        registry.activate(first, ignored -> { });
        ConnectionLifecycleRegistry.Operation firstOperation = registry.capture(first);
        CountDownLatch cleanupEntered = new CountDownLatch(1);
        CountDownLatch releaseCleanup = new CountDownLatch(1);
        CountDownLatch replacementAttempted = new CountDownLatch(1);
        AtomicInteger order = new AtomicInteger();
        AtomicInteger cleanupOrder = new AtomicInteger();
        AtomicInteger replacementOrder = new AtomicInteger();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> retired = executor.submit(() -> registry.markRetired(first, () -> {
                cleanupEntered.countDown();
                assertTrue(registry.isCurrent(firstOperation),
                        "Cleanup must run before the retirement linearization point");
                await(releaseCleanup);
                cleanupOrder.set(order.incrementAndGet());
            }));
            assertTrue(cleanupEntered.await(2, TimeUnit.SECONDS));
            Future<ConnectionLifecycleRegistry.Operation> activated = executor.submit(() -> {
                replacementAttempted.countDown();
                return registry.activate(replacement,
                        ignored -> replacementOrder.set(order.incrementAndGet()));
            });
            assertTrue(replacementAttempted.await(2, TimeUnit.SECONDS));
            releaseCleanup.countDown();

            assertTrue(retired.get(2, TimeUnit.SECONDS));
            assertNotNull(activated.get(2, TimeUnit.SECONDS));
        }

        assertEquals(1, cleanupOrder.get());
        assertEquals(2, replacementOrder.get());
        assertFalse(registry.isCurrent(firstOperation));
        assertNotNull(registry.capture(replacement));
    }

    @Test
    void close_RacingLateActivateIsRejectedBeforeInFlightEffectDrains() throws Exception {
        ConnectionLifecycleRegistry registry = new ConnectionLifecycleRegistry();
        UUID playerId = UUID.randomUUID();
        Player first = player(playerId);
        Player late = player(playerId);
        registry.activate(first, ignored -> { });
        ConnectionLifecycleRegistry.Operation operation = registry.capture(first);
        CountDownLatch effectEntered = new CountDownLatch(1);
        CountDownLatch releaseEffect = new CountDownLatch(1);
        CountDownLatch lateActivateAttempted = new CountDownLatch(1);
        AtomicBoolean latePublication = new AtomicBoolean();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> effect = executor.submit(() -> registry.runIfCurrent(operation, () -> {
                effectEntered.countDown();
                await(releaseEffect);
            }));
            assertTrue(effectEntered.await(2, TimeUnit.SECONDS));
            Future<?> close = executor.submit(registry::close);
            awaitClosed(registry, operation);
            Future<ConnectionLifecycleRegistry.Operation> lateActivation = executor.submit(() -> {
                lateActivateAttempted.countDown();
                return registry.activate(late, ignored -> latePublication.set(true));
            });
            assertTrue(lateActivateAttempted.await(2, TimeUnit.SECONDS));
            releaseEffect.countDown();
            assertTrue(effect.get(2, TimeUnit.SECONDS));
            close.get(2, TimeUnit.SECONDS);
            assertNull(lateActivation.get(2, TimeUnit.SECONDS),
                    "Activation that starts after the close barrier must be rejected");
        }

        assertFalse(latePublication.get());
        assertNull(registry.capture(late));
    }

    @Test
    void close_LateActivateCannotPublishGeneration() {
        ConnectionLifecycleRegistry registry = new ConnectionLifecycleRegistry();
        UUID playerId = UUID.randomUUID();
        Player first = player(playerId);
        Player late = player(playerId);
        registry.activate(first, ignored -> { });
        ConnectionLifecycleRegistry.Operation captured = registry.capture(first);
        assertNotNull(captured);

        registry.close();
        AtomicBoolean latePublication = new AtomicBoolean();
        ConnectionLifecycleRegistry.Operation activated =
                registry.activate(late, ignored -> latePublication.set(true));

        assertNull(activated, "Shutdown must reject late activation explicitly");
        assertFalse(latePublication.get(), "Shutdown must reject activation after its barrier");
        assertFalse(registry.isCurrent(captured), "Shutdown must retire already captured operations");
        assertNull(registry.capture(late), "A late PostLogin cannot resurrect lifecycle state");
    }

    @Test
    void activate_CallbackFailureRetiresReplacementWithoutRestoringPreviousOwner() {
        ConnectionLifecycleRegistry registry = new ConnectionLifecycleRegistry();
        UUID playerId = UUID.randomUUID();
        Player first = player(playerId);
        Player replacement = player(playerId);
        ConnectionLifecycleRegistry.Operation firstOperation =
                registry.activate(first, ignored -> { });
        assertNotNull(firstOperation);

        assertThrows(IllegalStateException.class, () -> registry.activate(
                replacement, ignored -> {
                    throw new IllegalStateException("controlled publication failure");
                }));

        assertFalse(registry.isCurrent(firstOperation),
                "A failed replacement must not restore the superseded owner");
        assertNull(registry.capture(replacement),
                "A partially published replacement must not retain a current capability");
    }

    private Player player(UUID playerId) {
        Player player = mock(Player.class);
        when(player.getUniqueId()).thenReturn(playerId);
        return player;
    }

    private void await(CountDownLatch latch) {
        try {
            assertTrue(latch.await(2, TimeUnit.SECONDS));
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AssertionError(exception);
        }
    }

    private void awaitClosed(
            ConnectionLifecycleRegistry registry,
            ConnectionLifecycleRegistry.Operation operation) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (registry.isCurrent(operation) && System.nanoTime() < deadline) {
            Thread.onSpinWait();
        }
        assertFalse(registry.isCurrent(operation), "Close barrier did not become visible");
    }
}
