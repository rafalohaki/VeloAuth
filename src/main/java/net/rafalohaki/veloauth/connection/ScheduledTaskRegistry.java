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
        return replace(new TaskSlot() {
            @Override
            public ScheduledTask replace(ScheduledTask task) {
                return tasks.put(playerId, task);
            }

            @Override
            public boolean clear(ScheduledTask task) {
                return tasks.remove(playerId, task);
            }
        }, scheduler, action);
    }

    static ScheduledTask replace(
            AtomicReference<ScheduledTask> task,
            Function<Consumer<ScheduledTask>, ScheduledTask> scheduler,
            Runnable action) {
        Objects.requireNonNull(task, "task");
        PreparedTask prepared = prepare(new TaskSlot() {
            @Override
            public ScheduledTask replace(ScheduledTask replacement) {
                return task.getAndSet(replacement);
            }

            @Override
            public boolean clear(ScheduledTask expected) {
                return task.compareAndSet(expected, null);
            }
        }, action);
        prepared.cancelPrevious();
        return prepared.schedule(scheduler);
    }

    static PreparedTask prepare(AtomicReference<ScheduledTask> task, Runnable action) {
        Objects.requireNonNull(task, "task");
        return prepare(new TaskSlot() {
            @Override
            public ScheduledTask replace(ScheduledTask replacement) {
                return task.getAndSet(replacement);
            }

            @Override
            public boolean clear(ScheduledTask expected) {
                return task.compareAndSet(expected, null);
            }
        }, action);
    }

    private static ScheduledTask replace(
            TaskSlot taskSlot,
            Function<Consumer<ScheduledTask>, ScheduledTask> scheduler,
            Runnable action) {
        PreparedTask prepared = prepare(taskSlot, action);
        prepared.cancelPrevious();
        return prepared.schedule(scheduler);
    }

    private static PreparedTask prepare(TaskSlot taskSlot, Runnable action) {
        Objects.requireNonNull(taskSlot, "taskSlot");
        Objects.requireNonNull(action, "action");

        PendingTask pending = new PendingTask();
        ScheduledTask previous = taskSlot.replace(pending);
        return new PreparedTask(taskSlot, pending, previous, action);
    }

    static boolean cancel(AtomicReference<ScheduledTask> task) {
        Objects.requireNonNull(task, "task");
        ScheduledTask scheduled = task.getAndSet(null);
        if (scheduled == null) {
            return false;
        }
        scheduled.cancel();
        return true;
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

    private interface TaskSlot {
        ScheduledTask replace(ScheduledTask task);

        boolean clear(ScheduledTask task);
    }

    static final class PreparedTask {
        private final TaskSlot taskSlot;
        private final PendingTask pending;
        private final ScheduledTask previous;
        private final Runnable action;

        private PreparedTask(
                TaskSlot taskSlot, PendingTask pending, ScheduledTask previous, Runnable action) {
            this.taskSlot = taskSlot;
            this.pending = pending;
            this.previous = previous;
            this.action = action;
        }

        void cancelPrevious() {
            if (previous != null) {
                previous.cancel();
            }
        }

        ScheduledTask schedule(Function<Consumer<ScheduledTask>, ScheduledTask> scheduler) {
            Objects.requireNonNull(scheduler, "scheduler");
            ScheduledTask scheduled;
            try {
                scheduled = Objects.requireNonNull(scheduler.apply(ignored -> {
                    if (taskSlot.clear(pending)) {
                        action.run();
                    }
                }), "scheduled task");
            } catch (RuntimeException | LinkageError failure) {
                taskSlot.clear(pending);
                pending.cancel();
                throw failure;
            }

            pending.attach(scheduled);
            return scheduled;
        }
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
