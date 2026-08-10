package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.scheduler.ScheduledTask;
import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

class ScheduledTaskRegistryTest {

    @Test
    void replace_OlderCallbackRunsLater_ShouldNotRemoveOrExecuteNewerTask() {
        UUID playerId = UUID.randomUUID();
        ConcurrentMap<UUID, ScheduledTask> tasks = new ConcurrentHashMap<>();
        ScheduledTask firstTask = mock(ScheduledTask.class);
        ScheduledTask secondTask = mock(ScheduledTask.class);
        AtomicReference<Consumer<ScheduledTask>> firstCallback = new AtomicReference<>();
        AtomicReference<Consumer<ScheduledTask>> secondCallback = new AtomicReference<>();
        AtomicInteger firstActions = new AtomicInteger();
        AtomicInteger secondActions = new AtomicInteger();

        ScheduledTaskRegistry.replace(tasks, playerId, callback -> {
            firstCallback.set(callback);
            return firstTask;
        }, firstActions::incrementAndGet);
        ScheduledTaskRegistry.replace(tasks, playerId, callback -> {
            secondCallback.set(callback);
            return secondTask;
        }, secondActions::incrementAndGet);

        firstCallback.get().accept(firstTask);

        assertEquals(1, tasks.size());
        assertTrue(tasks.containsKey(playerId));
        assertEquals(0, firstActions.get());
        verify(firstTask).cancel();
        verify(secondTask, never()).cancel();

        secondCallback.get().accept(secondTask);
        assertTrue(tasks.isEmpty());
        assertEquals(1, secondActions.get());
    }

    @Test
    void replace_CallbackRunsDuringScheduling_ShouldExecuteOnceWithoutLeakingTask() {
        UUID playerId = UUID.randomUUID();
        ConcurrentMap<UUID, ScheduledTask> tasks = new ConcurrentHashMap<>();
        ScheduledTask task = mock(ScheduledTask.class);
        AtomicInteger actions = new AtomicInteger();

        ScheduledTaskRegistry.replace(tasks, playerId, callback -> {
            callback.accept(task);
            return task;
        }, actions::incrementAndGet);

        assertTrue(tasks.isEmpty());
        assertEquals(1, actions.get());
    }

    @Test
    void replace_CallbackRacesWithTaskPublication_ShouldExecuteOnceWithoutLeakingTask()
            throws Exception {
        UUID playerId = UUID.randomUUID();
        ScheduledTask task = mock(ScheduledTask.class);
        RemovalGatedMap tasks = new RemovalGatedMap(task);
        AtomicInteger actions = new AtomicInteger();
        AtomicReference<Future<?>> callbackFuture = new AtomicReference<>();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            ScheduledTaskRegistry.replace(tasks, playerId, callback -> {
                callbackFuture.set(executor.submit(() -> callback.accept(task)));
                tasks.awaitAttemptedTaskRemoval();
                return task;
            }, actions::incrementAndGet);

            tasks.releaseAttemptedTaskRemoval();
            callbackFuture.get().get(5, TimeUnit.SECONDS);
        }

        assertTrue(tasks.isEmpty());
        assertEquals(1, actions.get());
    }

    private static final class RemovalGatedMap extends ConcurrentHashMap<UUID, ScheduledTask> {
        private final ScheduledTask publishedTask;
        private final CountDownLatch attemptedTaskRemoval = new CountDownLatch(1);
        private final CountDownLatch releaseTaskRemoval = new CountDownLatch(1);

        private RemovalGatedMap(ScheduledTask publishedTask) {
            this.publishedTask = publishedTask;
        }

        @Override
        public boolean remove(Object key, Object value) {
            boolean removed = super.remove(key, value);
            if (value == publishedTask) {
                attemptedTaskRemoval.countDown();
                await(releaseTaskRemoval);
            }
            return removed;
        }

        private void awaitAttemptedTaskRemoval() {
            try {
                attemptedTaskRemoval.await(100, TimeUnit.MILLISECONDS);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while staging task publication", interrupted);
            }
        }

        private void releaseAttemptedTaskRemoval() {
            releaseTaskRemoval.countDown();
        }

        private static void await(CountDownLatch latch) {
            try {
                latch.await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while reproducing task race", interrupted);
            }
        }
    }
}
