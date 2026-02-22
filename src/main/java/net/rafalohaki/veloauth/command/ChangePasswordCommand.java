package net.rafalohaki.veloauth.command;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/**
 * Handles the /changepassword command.
 * Verifies old password, validates new one, and updates the database.
 */
class ChangePasswordCommand implements SimpleCommand {

    private static final String ERROR_DATABASE_QUERY = "error.database.query";
    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");

    private final CommandContext ctx;

    ChangePasswordCommand(CommandContext ctx) {
        this.ctx = ctx;
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

        ValidationUtils.ValidationResult validationResult = ValidationUtils.validateArgumentCount(args, 2, ctx.messages().get("auth.changepassword.usage"));
        if (!validationResult.valid()) {
            player.sendMessage(ValidationUtils.createWarningComponent(validationResult.getErrorMessage()));
            return;
        }

        String oldPassword = args[0];
        String newPassword = args[1];

        ValidationUtils.ValidationResult passwordValidation = ValidationUtils.validatePassword(newPassword, ctx.settings());
        if (!passwordValidation.valid()) {
            player.sendMessage(ValidationUtils.createErrorComponent(passwordValidation.getErrorMessage()));
            return;
        }

        CommandHelper.runAsyncCommand(() -> processPasswordChange(player, oldPassword, newPassword),
                ctx.messages(), source, ERROR_DATABASE_QUERY);
    }

    private void processPasswordChange(Player player, String oldPassword, String newPassword) {
        AuthenticationContext authCtx = preparePasswordChange(player);
        if (authCtx == null) {
            return;
        }

        if (!verifyOldPassword(authCtx, oldPassword)) {
            return;
        }

        if (!updatePassword(authCtx, newPassword)) {
            return;
        }

        finalizePasswordChange(authCtx);
    }

    private AuthenticationContext preparePasswordChange(Player player) {
        AuthenticationContext authCtx = ctx.validateAndAuthenticatePlayer(player, "password change");
        if (authCtx == null) {
            return null;
        }
        if (authCtx.registeredPlayer() == null) {
            authCtx.player().sendMessage(ctx.sm().notRegistered());
            return null;
        }
        return authCtx;
    }

    private boolean verifyOldPassword(AuthenticationContext authCtx, String oldPassword) {
        BCrypt.Result result = BCrypt.verifyer().verify(oldPassword.toCharArray(), authCtx.registeredPlayer().getHash());
        if (!result.verified) {
            authCtx.player().sendMessage(ctx.sm().incorrectOldPassword());
            return false;
        }
        return true;
    }

    private boolean updatePassword(AuthenticationContext authCtx, String newPassword) {
        String newHashedPassword = BCrypt.with(BCrypt.Version.VERSION_2Y)
                .hashToString(ctx.settings().getBcryptCost(), newPassword.toCharArray());
        authCtx.registeredPlayer().setHash(newHashedPassword);
        var saveResult = ctx.databaseManager().savePlayer(authCtx.registeredPlayer()).join();
        if (ctx.handleDatabaseError(saveResult, authCtx.player(), "Password change save failed for")) {
            return false;
        }
        boolean saved = Boolean.TRUE.equals(saveResult.getValue());
        if (!saved) {
            ctx.sendDatabaseErrorMessage(authCtx.player());
            return false;
        }
        return true;
    }

    private void finalizePasswordChange(AuthenticationContext authCtx) {
        var premiumResult = ctx.checkPremiumStatus(authCtx.player(), "Premium check during password change");
        if (!premiumResult.isDatabaseError() && Boolean.TRUE.equals(premiumResult.getValue())) {
            ctx.authCache().removePremiumPlayer(authCtx.username());
        }
        ctx.authCache().endSession(authCtx.player().getUniqueId());

        // Disconnect duplicate sessions for the same username
        ctx.plugin().getServer().getAllPlayers().stream()
                .filter(p -> !p.equals(authCtx.player()))
                .filter(p -> p.getUsername().equalsIgnoreCase(authCtx.username()))
                .forEach(p -> {
                    p.disconnect(ctx.sm().kickMessage());
                    if (ctx.logger().isWarnEnabled()) {
                        ctx.logger().warn("Disconnected duplicate player {} — password changed from IP {}",
                                authCtx.username(), PlayerAddressUtils.getPlayerIp(authCtx.player()));
                    }
                });

        authCtx.player().sendMessage(ctx.sm().changePasswordSuccess());
        if (ctx.logger().isInfoEnabled()) {
            ctx.logger().info(AUTH_MARKER, "Player {} changed password from IP {}",
                    authCtx.username(), PlayerAddressUtils.getPlayerIp(authCtx.player()));
        }
    }
}
