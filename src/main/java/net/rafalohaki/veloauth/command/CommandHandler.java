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
 * {@link LogoutCommand}, {@link UnregisterCommand}, {@link VAuthCommand}.
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
    private static final String COMMAND_LOGOUT = "logout";
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
     * Wraps a command so that everything it renders through {@link Messages} on the executing
     * thread uses the invoking player's language (multi-language player messages).
     */
    private com.velocitypowered.api.command.SimpleCommand localized(com.velocitypowered.api.command.SimpleCommand delegate) {
        return new com.velocitypowered.api.command.SimpleCommand() {
            @Override
            public void execute(Invocation invocation) {
                com.velocitypowered.api.proxy.Player player =
                        invocation.source() instanceof com.velocitypowered.api.proxy.Player p ? p : null;
                messages.runAsPlayer(player, () -> delegate.execute(invocation));
            }

            @Override
            public java.util.List<String> suggest(Invocation invocation) {
                return delegate.suggest(invocation);
            }

            @Override
            public java.util.concurrent.CompletableFuture<java.util.List<String>> suggestAsync(Invocation invocation) {
                return delegate.suggestAsync(invocation);
            }

            @Override
            public boolean hasPermission(Invocation invocation) {
                return delegate.hasPermission(invocation);
            }
        };
    }

    /**
     * Registers all commands with the Velocity command manager.
     */
    public void registerCommands() {
        var commandManager = plugin.getServer().getCommandManager();

        commandManager.register(commandManager.metaBuilder(COMMAND_LOGIN).aliases(COMMAND_LOGIN_ALIASES).build(), localized(new LoginCommand(ctx)));
        commandManager.register(commandManager.metaBuilder(COMMAND_REGISTER).aliases(COMMAND_REGISTER_ALIASES).build(), localized(new RegisterCommand(ctx)));
        commandManager.register(commandManager.metaBuilder(COMMAND_CHANGE_PASSWORD).build(), localized(new ChangePasswordCommand(ctx)));
        commandManager.register(commandManager.metaBuilder(COMMAND_LOGOUT).build(), localized(new LogoutCommand(ctx)));

        commandManager.register(commandManager.metaBuilder(COMMAND_UNREGISTER).build(), localized(new UnregisterCommand(ctx)));
        commandManager.register(commandManager.metaBuilder(COMMAND_VAUTH).build(), localized(new VAuthCommand(ctx)));
        commandManager.register(commandManager.metaBuilder(COMMAND_TWO_FACTOR).aliases(COMMAND_TWO_FACTOR_ALIASES).build(),
                localized(new TwoFactorCommand(ctx)));

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.commands.registered"));
        }
    }

    /**
     * Creates the bridge used by the dialog (GUI) authentication flow. The bridge drives the
     * very same {@code /login}, {@code /register} and {@code /2fa verify} pipelines as the chat
     * commands, so every security rule applies identically to both entry points.
     */
    public DialogAuthBridge createDialogAuthBridge() {
        return new DialogAuthBridge(ctx);
    }

    /**
     * Unregisters all commands from the Velocity command manager.
     */
    public void unregisterCommands() {
        var commandManager = plugin.getServer().getCommandManager();

        unregisterCommandAliases(commandManager, COMMAND_LOGIN, COMMAND_LOGIN_ALIASES);
        unregisterCommandAliases(commandManager, COMMAND_REGISTER, COMMAND_REGISTER_ALIASES);
        unregisterCommandAliases(commandManager, COMMAND_CHANGE_PASSWORD);
        unregisterCommandAliases(commandManager, COMMAND_LOGOUT);
        unregisterCommandAliases(commandManager, COMMAND_UNREGISTER);
        unregisterCommandAliases(commandManager, COMMAND_VAUTH);
        unregisterCommandAliases(commandManager, COMMAND_TWO_FACTOR, COMMAND_TWO_FACTOR_ALIASES);

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("admin.commands_unregistered"));
        }
    }

    /**
     * Releases resources held by the command layer (currently the IP rate limiter).
     * Safe to call after {@link #unregisterCommands()}; idempotent.
     */
    public void shutdown() {
        ctx.shutdown();
    }

    private void unregisterCommandAliases(com.velocitypowered.api.command.CommandManager commandManager,
                                          String primaryAlias, String... aliases) {
        commandManager.unregister(primaryAlias);
        for (String alias : aliases) {
            commandManager.unregister(alias);
        }
    }
}
