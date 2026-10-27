package net.rafalohaki.veloauth.dialog;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.scheduler.ScheduledTask;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

/** Per-connection state of one dialog interaction (login form, premium notice or ownership check). */
final class DialogSession {

    final Player player;
    final CompletableFuture<Void> done = new CompletableFuture<>();
    final AtomicBoolean finished = new AtomicBoolean();
    final AtomicInteger pending = new AtomicInteger();
    final ReentrantLock chainLock = new ReentrantLock();
    CompletableFuture<Void> chain = CompletableFuture.completedFuture(null);
    volatile String language;
    volatile Form form = Form.LOGIN;
    volatile boolean formShown;
    volatile boolean noticeOnly;
    /** Premium ownership check (limbo + profile-key verification); null for other sessions. */
    volatile PremiumCheck premiumCheck;
    volatile ScheduledTask keepAliveTask;
    volatile ScheduledTask timeoutTask;
    private final Consumer<DialogSession> onFinish;

    DialogSession(Player player, String language, Consumer<DialogSession> onFinish) {
        this.player = player;
        this.language = language;
        this.onFinish = onFinish;
    }

    boolean isActive() {
        return !finished.get();
    }

    void finish() {
        if (!finished.compareAndSet(false, true)) {
            return;
        }
        cancel(keepAliveTask);
        cancel(timeoutTask);
        PremiumCheck check = premiumCheck;
        if (check != null) {
            check.cancelTasks();
        }
        onFinish.accept(this);
        done.complete(null);
    }

    static void cancel(ScheduledTask task) {
        if (task != null) {
            task.cancel();
        }
    }

    /** State of a premium-nick ownership check running on the auth server. */
    static final class PremiumCheck {
        final UUID premiumUuid;
        final Runnable onVerified;
        final AtomicBoolean decided = new AtomicBoolean();
        volatile boolean keyVerified;
        volatile boolean inPlay;
        volatile ScheduledTask decisionTask;
        volatile ScheduledTask actionBarTask;

        PremiumCheck(UUID premiumUuid, Runnable onVerified) {
            this.premiumUuid = premiumUuid;
            this.onVerified = onVerified;
        }

        void cancelTasks() {
            cancel(decisionTask);
            cancel(actionBarTask);
        }
    }
}
