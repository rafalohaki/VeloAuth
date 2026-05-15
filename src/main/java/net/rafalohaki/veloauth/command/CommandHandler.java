package net.rafalohaki.veloauth.command;

import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;

/**
 * Orchestrator for VeloAuth command registration and lifecycle.
 * Individual commands are implemented in separate classes:
 * {@link LoginCommand}, {@link RegisterCommand}, {@link ChangePasswordCommand},
 * {@link UnregisterCommand}, {@link VAuthCommand}.
 * <p>
 * Shared logic and services are provided via {@link CommandContext}.
 * Authentication state is carried via {@link AuthenticationContext}.
 */
public class CommandHandler {

    private static final String COMMAND_LOGIN = "login";
    private static final String[] COMMAND_LOGIN_ALIASES = {"log", "l"};
    private static final String COMMAND_REGISTER = "register";
    private static final String[] COMMAND_REGISTER_ALIASES = {"reg"};
    @SuppressWarnings("java:S2068") // Not a password - this is a command name constant
    private static final String COMMAND_CHANGE_PASSWORD = "changepassword"; // NOSONAR
    private static final String COMMAND_UNREGISTER = "unregister";
    private static final String COMMAND_VAUTH = "vauth";
    private static final String COMMAND_TWO_FACTOR = "2fa";
    private static final String[] COMMAND_TWO_FACTOR_ALIASES = {"totp", "twofa"};

    private final VeloAuth plugin;
    private final Messages messages;
    private final Logger logger;
    private final CommandContext ctx;

    /**
     * Creates a new CommandHandler.
     *
     * @param plugin          VeloAuth plugin instance
     * @param databaseManager database manager
     * @param authCache       authorization cache
     * @param settings        plugin settings
     * @param messages        i18n message system
     */
    public CommandHandler(VeloAuth plugin, DatabaseManager databaseManager,
                          AuthCache authCache, Settings settings, Messages messages) {
        this.plugin = plugin;
        this.messages = messages;
        this.logger = plugin.getLogger();
        this.ctx = new CommandContext(plugin, databaseManager, authCache, settings, messages);
    }

    /**
     * Registers all commands with the Velocity command manager.
     */
    public void registerCommands() {
        var commandManager = plugin.getServer().getCommandManager();

        commandManager.register(commandManager.metaBuilder(COMMAND_LOGIN).aliases(COMMAND_LOGIN_ALIASES).build(), new LoginCommand(ctx));
        commandManager.register(commandManager.metaBuilder(COMMAND_REGISTER).aliases(COMMAND_REGISTER_ALIASES).build(), new RegisterCommand(ctx));
        commandManager.register(commandManager.metaBuilder(COMMAND_CHANGE_PASSWORD).build(), new ChangePasswordCommand(ctx));

        commandManager.register(commandManager.metaBuilder(COMMAND_UNREGISTER).build(), new UnregisterCommand(ctx));
        commandManager.register(commandManager.metaBuilder(COMMAND_VAUTH).build(), new VAuthCommand(ctx));
        commandManager.register(commandManager.metaBuilder(COMMAND_TWO_FACTOR).aliases(COMMAND_TWO_FACTOR_ALIASES).build(),
                new TwoFactorCommand(ctx));

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.commands.registered"));
        }
    }

    /**
     * Unregisters all commands from the Velocity command manager.
     */
    public void unregisterCommands() {
        var commandManager = plugin.getServer().getCommandManager();

        unregisterCommandAliases(commandManager, COMMAND_LOGIN, COMMAND_LOGIN_ALIASES);
        unregisterCommandAliases(commandManager, COMMAND_REGISTER, COMMAND_REGISTER_ALIASES);
        unregisterCommandAliases(commandManager, COMMAND_CHANGE_PASSWORD);
        unregisterCommandAliases(commandManager, COMMAND_UNREGISTER);
        unregisterCommandAliases(commandManager, COMMAND_VAUTH);
        unregisterCommandAliases(commandManager, COMMAND_TWO_FACTOR, COMMAND_TWO_FACTOR_ALIASES);

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("admin.commands_unregistered"));
        }
    }

    private void unregisterCommandAliases(com.velocitypowered.api.command.CommandManager commandManager,
                                          String primaryAlias, String... aliases) {
        commandManager.unregister(primaryAlias);
        for (String alias : aliases) {
            commandManager.unregister(alias);
        }
    }
}
