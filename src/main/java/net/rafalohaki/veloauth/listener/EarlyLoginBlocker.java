package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.Continuation;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import org.slf4j.Logger;

import java.util.concurrent.CompletableFuture;

/**
 * Startup queue for connections arriving before VeloAuth finishes initialization.
 * Instead of kicking players, holds their PreLogin event until the plugin is ready,
 * then runs the full {@link AuthListener#onPreLogin} pipeline on the queued event.
 * <p>
 * The delegation is what makes the queue safe. Velocity snapshots the handler list
 * when an event is fired, so {@code AuthListener} — registered in phase 8 of async
 * initialization — is invisible to any event queued here, no matter its priority.
 * Merely releasing the event would let it complete with no premium check and no
 * {@code forceOnlineMode()}, handing a premium nickname an offline UUID on a proxy
 * with {@code online-mode = false}. This blocker is therefore the <em>only</em>
 * VeloAuth handler a queued event will ever see, and must invoke the auth pipeline
 * itself before resuming.
 * <p>
 * Failure paths deny by setting the event result before the continuation resumes:
 * Velocity treats {@code resumeWithException} as log-and-continue, so an exception
 * alone would release the connection with the default (allowed) result.
 */
public class EarlyLoginBlocker {

    private final VeloAuth plugin;
    private final Logger logger;

    EarlyLoginBlocker(VeloAuth plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
    }

    @Subscribe(priority = 100)
    public EventTask onPreLogin(PreLoginEvent event) {
        if (plugin.isInitialized()) {
            // AuthListener was registered before this event fired, so it is in the
            // snapshot and has already run at Short.MAX_VALUE priority. Nothing to do.
            return null;
        }

        String username = event.getUsername();
        logger.info("STARTUP QUEUE: Player {} is waiting for VeloAuth initialization...", username);

        return EventTask.resumeWhenComplete(
                plugin.getInitializationFuture()
                        .thenCompose(ignored -> delegateToAuthPipeline(event, username))
                        .exceptionally(throwable -> {
                            logger.warn("STARTUP QUEUE: Initialization failed or auth delegation "
                                            + "errored for {} - denying connection", username, throwable);
                            // i18n not available here — Messages is initialized after EarlyLoginBlocker registers
                            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                                    Component.text("VeloAuth ⏳",
                                            NamedTextColor.RED)));
                            return null;
                        })
        );
    }

    /**
     * Runs the queued event through the real auth pipeline and completes when the
     * pipeline does. {@code AuthListener.onPreLogin} is designed for Netty threads:
     * fast synchronous validation, then an {@link EventTask} whose I/O already hops
     * to the virtual-thread executor — so invoking it from the initialization
     * future's completion thread blocks nothing.
     */
    private CompletableFuture<Void> delegateToAuthPipeline(PreLoginEvent event, String username) {
        AuthListener authListener = plugin.getAuthListener();
        if (authListener == null) {
            // Initialization reported success without a registered listener; the
            // thrown exception routes into the deny branch above (fail-closed).
            throw new IllegalStateException(
                    "AuthListener unavailable after initialization for " + username);
        }

        logger.info("STARTUP QUEUE: VeloAuth initialized, running auth checks for {}", username);
        EventTask delegated = authListener.onPreLogin(event);
        if (delegated == null) {
            // Synchronous outcome: the result (deny / force mode) is already on the event.
            return CompletableFuture.completedFuture(null);
        }

        // Legal per the Velocity API: a plugin may execute an EventTask against its own
        // Continuation. The future absorbs a double resume (complete() is idempotent),
        // so a misbehaving task cannot throw IllegalStateException into the pipeline.
        CompletableFuture<Void> completion = new CompletableFuture<>();
        delegated.execute(new Continuation() {
            @Override
            public void resume() {
                completion.complete(null);
            }

            @Override
            public void resumeWithException(Throwable exception) {
                completion.completeExceptionally(exception);
            }
        });
        return completion;
    }
}
