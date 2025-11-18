package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import org.slf4j.Logger;

/**
 * Simple early login blocker that prevents connections during VeloAuth initialization.
 * This class is registered BEFORE any other components to ensure players cannot
 * connect before the authentication system is fully ready.
 */
public class EarlyLoginBlocker {

    private final VeloAuth plugin;
    private final Logger logger;

    /**
     * Creates a new early login blocker.
     *
     * @param plugin VeloAuth plugin instance
     */
    public EarlyLoginBlocker(VeloAuth plugin) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
    }

    /**
     * Blocks PreLogin attempts until VeloAuth is fully initialized.
     * This has the highest priority to ensure it runs before any other handlers.
     *
     * @param event PreLoginEvent to potentially block
     */
    @Subscribe(priority = 100)
    public void onPreLogin(PreLoginEvent event) {
        String username = event.getUsername();
        
        // CRITICAL: Block connections until plugin is fully initialized
        if (!plugin.isInitialized()) {
            logger.warn("🔒 BLOKADA STARTU: Gracz {} próbował połączyć się przed pełną inicjalizacją VeloAuth - blokada EarlyLoginBlocker",
                    username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text("VeloAuth się uruchamia. Spróbuj połączyć się ponownie za chwilę.",
                            NamedTextColor.RED)
            ));
            return;
        }

        // If initialized, allow normal processing by other handlers
        logger.debug("EarlyLoginBlocker: VeloAuth zainicjalizowany, pozwalam na połączenie dla {}", username);
    }
}
