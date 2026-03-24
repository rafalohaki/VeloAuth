package net.rafalohaki.veloauth.listener;

import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.premium.PremiumResolverService;
import org.slf4j.Logger;

/**
 * Factory for creating listener handlers.
 * Single public entry point — handlers themselves are package-private.
 */
public final class ListenerFactory {

    private ListenerFactory() {
        // Utility class
    }

    public static PreLoginHandler createPreLoginHandler(AuthCache authCache,
                                                        PremiumResolverService premiumResolverService,
                                                        Settings settings,
                                                        DatabaseManager databaseManager,
                                                        Messages messages,
                                                        Logger logger) {
        return new PreLoginHandler(authCache, premiumResolverService, settings,
                databaseManager, messages, logger);
    }

    public static PostLoginHandler createPostLoginHandler(AuthCache authCache,
                                                          DatabaseManager databaseManager,
                                                          Messages messages,
                                                          Logger logger) {
        return new PostLoginHandler(authCache, databaseManager, messages, logger);
    }

    public static EarlyLoginBlocker createEarlyLoginBlocker(VeloAuth plugin) {
        return new EarlyLoginBlocker(plugin);
    }
}
