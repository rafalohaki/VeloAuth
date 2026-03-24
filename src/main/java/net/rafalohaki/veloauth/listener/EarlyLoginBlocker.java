package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import org.slf4j.Logger;

/**
 * Startup queue for connections arriving before VeloAuth finishes initialization.
 * Instead of kicking players, holds their PreLogin event until the plugin is ready,
 * then allows normal processing to continue.
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
            return null;
        }

        String username = event.getUsername();
        logger.info("STARTUP QUEUE: Player {} is waiting for VeloAuth initialization...", username);

        return EventTask.resumeWhenComplete(
                plugin.getInitializationFuture()
                        .thenRun(() -> logger.info("STARTUP QUEUE: VeloAuth initialized, releasing {}", username))
                        .exceptionally(throwable -> {
                            logger.warn("STARTUP QUEUE: Initialization failed or shutdown started for {} - denying connection",
                                    username);
                            // i18n not available here — Messages is initialized after EarlyLoginBlocker registers
                            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                                    Component.text("VeloAuth ⏳",
                                            NamedTextColor.RED)));
                            return null;
                        })
        );
    }
}
