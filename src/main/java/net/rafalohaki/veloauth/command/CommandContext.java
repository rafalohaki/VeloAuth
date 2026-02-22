package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.i18n.SimpleMessages;
import net.rafalohaki.veloauth.util.DatabaseErrorHandler;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import net.rafalohaki.veloauth.util.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;

/**
 * Shared context for all command implementations.
 * Provides access to common services and template methods used by extracted commands.
 */
class CommandContext {

    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final VeloAuth plugin;
    private final DatabaseManager databaseManager;
    private final AuthCache authCache;
    private final Settings settings;
    private final Messages messages;
    private final Logger logger;
    private final SimpleMessages sm;
    private final IPRateLimiter ipRateLimiter;

    CommandContext(VeloAuth plugin, DatabaseManager databaseManager,
                   AuthCache authCache, Settings settings, Messages messages) {
        this.plugin = plugin;
        this.databaseManager = databaseManager;
        this.authCache = authCache;
        this.settings = settings;
        this.messages = messages;
        this.logger = plugin.getLogger();
        this.ipRateLimiter = new IPRateLimiter(10, 5);
        this.sm = new SimpleMessages(messages);
    }

    VeloAuth plugin() { return plugin; }
    DatabaseManager databaseManager() { return databaseManager; }
    AuthCache authCache() { return authCache; }
    Settings settings() { return settings; }
    Messages messages() { return messages; }
    Logger logger() { return logger; }
    SimpleMessages sm() { return sm; }
    IPRateLimiter ipRateLimiter() { return ipRateLimiter; }

    /**
     * Template method for common authentication pre-checks:
     * 1. Validate player source
     * 2. Check brute force protection
     * 3. Fetch player from database with error handling
     *
     * @param source      command source
     * @param commandName name of the command for logging
     * @return AuthenticationContext if all checks pass, null otherwise
     */
    AuthenticationContext validateAndAuthenticatePlayer(CommandSource source, String commandName) {
        Player player = CommandHelper.validatePlayerSource(source, messages);
        if (player == null) {
            return null;
        }

        InetAddress playerAddress = PlayerAddressUtils.getPlayerAddress(player);

        if (playerAddress != null && authCache.isBlocked(playerAddress)) {
            player.sendMessage(sm.bruteForceBlocked());
            if (logger.isWarnEnabled()) {
                logger.warn(SECURITY_MARKER, "[BRUTE FORCE BLOCK] IP {} attempted {}", playerAddress.getHostAddress(), commandName);
            }
            return null;
        }

        String username = player.getUsername();
        var dbResult = databaseManager.findPlayerByNickname(username).join();

        if (handleDatabaseError(dbResult, player, commandName + " lookup for")) {
            return null;
        }

        return new AuthenticationContext(player, username, playerAddress, dbResult.getValue());
    }

    /**
     * Checks premium status with error handling and logging.
     */
    DatabaseManager.DbResult<Boolean> checkPremiumStatus(Player player, String operation) {
        DatabaseManager.DbResult<Boolean> result = databaseManager.isPremium(player.getUsername()).join();
        if (result.isDatabaseError()) {
            if (logger.isErrorEnabled()) {
                logger.error(SECURITY_MARKER, "[DATABASE ERROR] {} failed for {}: {}", operation, player.getUsername(), result.getErrorMessage());
            }
            player.sendMessage(sm.errorDatabase());
        }
        return result;
    }

    /**
     * Handles database errors consistently across all commands.
     */
    boolean handleDatabaseError(DatabaseManager.DbResult<?> result, Player player, String operation) {
        return DatabaseErrorHandler.handleError(result, player, operation, logger, messages);
    }

    /**
     * Resets brute-force and rate-limit counters for the given IP address.
     */
    void resetSecurityCounters(InetAddress playerAddress) {
        SecurityUtils.resetSecurityCounters(playerAddress, authCache, ipRateLimiter);
    }

    /**
     * Sends a database error message to the player.
     */
    void sendDatabaseErrorMessage(Player player) {
        player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
    }
}
