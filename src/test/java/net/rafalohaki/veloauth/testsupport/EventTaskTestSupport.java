package net.rafalohaki.veloauth.testsupport;

import com.velocitypowered.api.event.Continuation;
import com.velocitypowered.api.event.EventTask;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/** Deterministically executes Velocity event tasks through their public continuation contract. */
public final class EventTaskTestSupport {

    private static final Duration COMPLETION_TIMEOUT = Duration.ofSeconds(5);

    private EventTaskTestSupport() {
    }

    public static void await(EventTask task) {
        Objects.requireNonNull(task, "task");
        CompletableFuture<Void> completion = new CompletableFuture<>();
        task.execute(new Continuation() {
            @Override
            public void resume() {
                completion.complete(null);
            }

            @Override
            public void resumeWithException(Throwable exception) {
                completion.completeExceptionally(exception);
            }
        });
        completion.orTimeout(COMPLETION_TIMEOUT.toMillis(), java.util.concurrent.TimeUnit.MILLISECONDS).join();
    }
}
