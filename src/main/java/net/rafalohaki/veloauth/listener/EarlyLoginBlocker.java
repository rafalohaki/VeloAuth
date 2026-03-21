package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import org.slf4j.Logger;

import java.util.concurrent.TimeUnit;

/**
 * Startup queue for connections arriving before VeloAuth finishes initialization.
 * Instead of kicking players, holds their PreLogin event until the plugin is ready,
 * then allows normal processing to continue.
 * <p>
 * Timeout: 30 seconds. If init takes longer, the player is denied with a retry message.
 */
public class EarlyLoginBlocker {

    private static final long INIT_WAIT_TIMEOUT_SECONDS = 30;

    private final VeloAuth plugin;
    private final Logger logger;

    public EarlyLoginBlocker(VeloAuth plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
    }

    @Subscribe(priority = 100)
    public EventTask onPreLogin(PreLoginEvent event) {
        if (plugin.isInitialized()) {
            return null;
        }

        String username = event.getUsername();
        logger.info("STARTUP QUEUE: Player {} is waiting for VeloAuth initialization...", username);

        return EventTask.resumeWhenComplete(
                plugin.getInitializationFuture()
                        .orTimeout(INIT_WAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                        .thenRun(() -> logger.info("STARTUP QUEUE: VeloAuth initialized, releasing {}", username))
                        .exceptionally(throwable -> {
                            logger.warn("STARTUP QUEUE: Timed out or init failed for {} - denying connection",
                                    username);
                            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                                    Component.text("VeloAuth is starting. Please try connecting again in a moment.",
                                            NamedTextColor.RED)));
                            return null;
                        })
        );
    }
}
