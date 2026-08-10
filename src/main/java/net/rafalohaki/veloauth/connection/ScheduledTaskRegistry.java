package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.scheduler.ScheduledTask;
import com.velocitypowered.api.scheduler.TaskStatus;

import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;

/** Ownership-safe operations for replaceable one-shot Velocity tasks keyed by player UUID. */
final class ScheduledTaskRegistry {

    private ScheduledTaskRegistry() {
    }

    static ScheduledTask replace(
            ConcurrentMap<UUID, ScheduledTask> tasks,
            UUID playerId,
            Function<Consumer<ScheduledTask>, ScheduledTask> scheduler,
            Runnable action) {
        Objects.requireNonNull(tasks, "tasks");
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(scheduler, "scheduler");
        Objects.requireNonNull(action, "action");

        PendingTask pending = new PendingTask();
        ScheduledTask previous = tasks.put(playerId, pending);
        if (previous != null) {
            previous.cancel();
        }

        ScheduledTask scheduled;
        try {
            scheduled = Objects.requireNonNull(scheduler.apply(ignored -> {
                if (tasks.remove(playerId, pending)) {
                    action.run();
                }
            }), "scheduled task");
        } catch (RuntimeException | LinkageError failure) {
            tasks.remove(playerId, pending);
            pending.cancel();
            throw failure;
        }

        pending.attach(scheduled);
        return scheduled;
    }

    static boolean cancel(ConcurrentMap<UUID, ScheduledTask> tasks, UUID playerId) {
        ScheduledTask task = tasks.remove(playerId);
        if (task != null) {
            task.cancel();
            return true;
        }
        return false;
    }

    static void cancelAll(ConcurrentMap<UUID, ScheduledTask> tasks) {
        tasks.forEach((playerId, task) -> {
            if (tasks.remove(playerId, task)) {
                task.cancel();
            }
        });
    }

    private static final class PendingTask implements ScheduledTask {
        private final AtomicBoolean cancelled = new AtomicBoolean();
        private final AtomicReference<ScheduledTask> delegate = new AtomicReference<>();

        private void attach(ScheduledTask task) {
            if (!delegate.compareAndSet(null, task)) {
                throw new IllegalStateException("Scheduled task was already attached");
            }
            if (cancelled.get()) {
                task.cancel();
            }
        }

        @Override
        public Object plugin() {
            ScheduledTask task = delegate.get();
            return task == null ? ScheduledTaskRegistry.class : task.plugin();
        }

        @Override
        public TaskStatus status() {
            if (cancelled.get()) {
                return TaskStatus.CANCELLED;
            }
            ScheduledTask task = delegate.get();
            return task == null ? TaskStatus.SCHEDULED : task.status();
        }

        @Override
        public void cancel() {
            cancelled.set(true);
            ScheduledTask task = delegate.get();
            if (task != null) {
                task.cancel();
            }
        }
    }
}
