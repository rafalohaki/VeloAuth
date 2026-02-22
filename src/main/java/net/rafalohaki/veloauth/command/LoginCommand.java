package net.rafalohaki.veloauth.command;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import net.rafalohaki.veloauth.util.SecurityUtils;

/**
 * Handles the /login command.
 * Validates credentials against the database and delegates
 * post-auth flow to {@link PostAuthFlow}.
 */
class LoginCommand implements SimpleCommand {

    private static final String ERROR_DATABASE_QUERY = "error.database.query";

    private final CommandContext ctx;

    LoginCommand(CommandContext ctx) {
        this.ctx = ctx;
    }

    @Override
    @SuppressWarnings("FutureReturnValueIgnored")
    public void execute(Invocation invocation) {
        CommandSource source = invocation.source();
        String[] args = invocation.arguments();

        if (args.length != 1) {
            source.sendMessage(ctx.sm().usageLogin());
            return;
        }

        String password = args[0];

        CommandHelper.runAsyncCommand(() -> processLogin(source, password),
                ctx.messages(), source, ERROR_DATABASE_QUERY);
    }

    private void processLogin(CommandSource source, String password) {
        Player player = (Player) source;

        AuthenticationContext authContext = ctx.validateAndAuthenticatePlayer(source, "login");
        if (authContext == null) {
            return;
        }

        if (ctx.authCache().isPlayerAuthorized(player.getUniqueId(), PlayerAddressUtils.getPlayerIp(player))) {
            player.sendMessage(ctx.sm().alreadyLogged());
            return;
        }

        if (authContext.registeredPlayer() == null) {
            player.sendMessage(ctx.sm().notRegistered());
            return;
        }
        String hash = authContext.registeredPlayer().getHash();
        if (hash == null || hash.isBlank()) {
            player.sendMessage(ctx.sm().notRegistered());
            return;
        }

        BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), hash);

        if (result.verified) {
            handleSuccessfulLogin(authContext);
        } else {
            handleFailedLogin(authContext);
        }
    }

    private void handleSuccessfulLogin(AuthenticationContext authContext) {
        try {
            authContext.registeredPlayer().updateLoginData(PlayerAddressUtils.getPlayerIp(authContext.player()));
            var saveResult = ctx.databaseManager().savePlayer(authContext.registeredPlayer()).join();

            if (ctx.handleDatabaseError(saveResult, authContext.player(), "Failed to save login data for")) {
                return;
            }

            authContext.player().sendMessage(ctx.sm().loginSuccess());
            PostAuthFlow.execute(ctx, authContext, authContext.registeredPlayer(), "logged in");

        } catch (Exception e) {
            if (ctx.logger().isErrorEnabled()) {
                ctx.logger().error("Error processing successful login: {}", authContext.username(), e);
            }
            ctx.sendDatabaseErrorMessage(authContext.player());
        }
    }

    private void handleFailedLogin(AuthenticationContext authContext) {
        boolean blocked = SecurityUtils.registerFailedLogin(authContext.playerAddress(), ctx.authCache());

        if (blocked) {
            authContext.player().sendMessage(ctx.sm().bruteForceBlocked());
            if (ctx.logger().isWarnEnabled()) {
                ctx.logger().warn("Player {} blocked for brute force from IP {}",
                        authContext.username(), PlayerAddressUtils.getPlayerIp(authContext.player()));
            }
        } else {
            authContext.player().sendMessage(ctx.sm().loginFailed());
            if (ctx.logger().isDebugEnabled()) {
                ctx.logger().debug("Failed login attempt for player {} from IP {}",
                        authContext.username(), PlayerAddressUtils.getPlayerIp(authContext.player()));
            }
        }
    }
}
