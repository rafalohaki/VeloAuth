package net.rafalohaki.veloauth.command;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;

/**
 * Handles the /register command.
 * Creates a new player account and delegates post-auth flow to {@link PostAuthFlow}.
 * <p>
 * This command is hidden from players who are already authenticated
 * and not on the auth server (via {@link #hasPermission}).
 */
class RegisterCommand implements SimpleCommand {

    private static final String ERROR_DATABASE_QUERY = "error.database.query";

    private final CommandContext ctx;

    RegisterCommand(CommandContext ctx) {
        this.ctx = ctx;
    }

    /**
     * Hides this command from players who are already authenticated.
     * When a player is on a backend server (not auth server), the command
     * will not appear in tab-completion and cannot be executed.
     * Console always has access.
     */
    @Override
    public boolean hasPermission(Invocation invocation) {
        if (!(invocation.source() instanceof Player player)) {
            return true; // Console always has access
        }
        // Only show/allow command when player is on auth server (needs to authenticate)
        return ctx.plugin().getConnectionManager().isPlayerOnAuthServer(player);
    }

    @Override
    @SuppressWarnings("FutureReturnValueIgnored")
    public void execute(Invocation invocation) {
        CommandSource source = invocation.source();
        String[] args = invocation.arguments();

        Player player = CommandHelper.validatePlayerSource(source, ctx.messages());
        if (player == null) {
            return;
        }

        ValidationUtils.ValidationResult validationResult = ValidationUtils.validateArgumentCount(args, 2, ctx.messages().get("auth.register.usage"));
        if (!validationResult.valid()) {
            player.sendMessage(ValidationUtils.createWarningComponent(validationResult.getErrorMessage()));
            return;
        }

        String password = args[0];
        String confirmPassword = args[1];

        ValidationUtils.ValidationResult passwordValidation = ValidationUtils.validatePassword(password, ctx.settings());
        if (!passwordValidation.valid()) {
            player.sendMessage(ValidationUtils.createErrorComponent(passwordValidation.getErrorMessage()));
            return;
        }

        ValidationUtils.ValidationResult matchValidation = ValidationUtils.validatePasswordMatch(password, confirmPassword);
        if (!matchValidation.valid()) {
            player.sendMessage(ValidationUtils.createErrorComponent(matchValidation.getErrorMessage()));
            return;
        }

        CommandHelper.runAsyncCommandWithTimeout(() -> processRegistration(player, password),
                ctx.messages(), source, ERROR_DATABASE_QUERY, "auth.registration.timeout");
    }

    private void processRegistration(Player player, String password) {
        AuthenticationContext authContext = ctx.validateAndAuthenticatePlayer(player, "registration");
        if (authContext == null) {
            return;
        }

        if (authContext.registeredPlayer() != null) {
            authContext.player().sendMessage(ctx.sm().alreadyRegistered());
            return;
        }

        String hashedPassword = BCrypt.with(BCrypt.Version.VERSION_2Y)
                .hashToString(ctx.settings().getBcryptCost(), password.toCharArray());

        RegisteredPlayer newPlayer = new RegisteredPlayer(
                authContext.username(), hashedPassword,
                PlayerAddressUtils.getPlayerIp(authContext.player()),
                authContext.player().getUniqueId().toString()
        );

        var saveResult = ctx.databaseManager().savePlayer(newPlayer).join();
        if (ctx.handleDatabaseError(saveResult, authContext.player(), "Failed to save new player")) {
            return;
        }

        boolean saved = Boolean.TRUE.equals(saveResult.getValue());
        if (!saved) {
            ctx.sendDatabaseErrorMessage(authContext.player());
            return;
        }

        authContext.player().sendMessage(ctx.sm().registerSuccess());
        PostAuthFlow.execute(ctx, authContext, newPlayer, "registered");
    }
}
