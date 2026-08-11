package net.rafalohaki.veloauth.command;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry;
import net.rafalohaki.veloauth.util.SecurityUtils;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.concurrent.CompletionException;

/**
 * Handles the /changepassword command.
 * Verifies old password, validates new one, and updates the database.
 */
class ChangePasswordCommand implements SimpleCommand {

    private static final String ERROR_DATABASE_QUERY = "error.database.query";
    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");

    private final CommandContext ctx;

    ChangePasswordCommand(CommandContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public boolean hasPermission(Invocation invocation) {
        // Restricts /changepassword to authorized players — unauthenticated callers cannot
        // change passwords, which closes a brute-force vector.
        return CommandHelper.isPlayerAuthorized(invocation, ctx);
    }

    @Override
    @SuppressWarnings("FutureReturnValueIgnored")
    public void execute(Invocation invocation) {
        CommandHelper.CommandInputs inputs = CommandHelper.requirePlayerAndArgs(
                invocation, ctx.messages(), 2, "auth.changepassword.usage");
        if (inputs == null) {
            return;
        }
        Player player = inputs.player();
        String oldPassword = inputs.args()[0];
        String newPassword = inputs.args()[1];
        var passwordSettings = ctx.settings().captureOperationSettings().password();

        if (!CommandHelper.requireValidPassword(player, newPassword, passwordSettings, ctx.messages())) {
            return;
        }

        ConnectionLifecycleRegistry.Operation operation = ctx.captureConnectionOperation(player);
        if (operation == null) {
            return;
        }
        ctx.runAsyncCommand(player, operation,
                () -> processPasswordChange(
                        player, oldPassword, newPassword, operation, passwordSettings),
                ERROR_DATABASE_QUERY);
    }

    private void processPasswordChange(
            Player player, String oldPassword, String newPassword,
            ConnectionLifecycleRegistry.Operation operation,
            Settings.PasswordSettings passwordSettings) {
        if (!ctx.beginConnectionCommand(player, operation)) {
            return;
        }

        try {
            AuthenticationContext authCtx = preparePasswordChange(player, operation);
            if (authCtx == null) {
                return;
            }

            if (!verifyOldPassword(authCtx, oldPassword)) {
                return;
            }

            if (!updatePassword(authCtx, newPassword, passwordSettings)) {
                return;
            }

            finalizePasswordChange(authCtx);
        } finally {
            ctx.releaseCommandLock(operation.playerId(), operation);
        }
    }

    private AuthenticationContext preparePasswordChange(
            Player player, ConnectionLifecycleRegistry.Operation operation) {
        AuthenticationContext authCtx = ctx.validateAndAuthenticatePlayer(
                player, "password change", operation);
        if (authCtx == null) {
            return null;
        }
        if (authCtx.registeredPlayer() == null) {
            ctx.runIfConnectionCurrent(operation,
                    () -> authCtx.player().sendMessage(ctx.messages().component(
                            "auth.login.not_registered", NamedTextColor.RED)));
            return null;
        }
        return authCtx;
    }

    private boolean verifyOldPassword(AuthenticationContext authCtx, String oldPassword) {
        String hash = authCtx.registeredPlayer().getHash();
        if (hash == null || hash.isBlank()) {
            // Premium accounts have no password hash — same guard as LoginCommand,
            // otherwise BCrypt.verify throws IllegalArgumentException on null hash.
            ctx.runIfConnectionCurrent(authCtx.connectionOperation(),
                    () -> authCtx.player().sendMessage(ctx.messages().component(
                            "auth.login.not_registered", NamedTextColor.RED)));
            return false;
        }
        BCrypt.Result result = BCrypt.verifyer().verify(oldPassword.toCharArray(), hash);
        if (!ctx.isConnectionCurrent(authCtx.connectionOperation())) {
            return false;
        }
        if (!result.verified) {
            ctx.runIfConnectionCurrent(authCtx.connectionOperation(), () -> {
                authCtx.player().sendMessage(ctx.messages().component(
                        "auth.changepassword.incorrect_old_password", NamedTextColor.RED));
                SecurityUtils.registerFailedLogin(
                        authCtx.playerAddress(), authCtx.username(), ctx.authCache());
            });
            return false;
        }
        return true;
    }

    private boolean updatePassword(
            AuthenticationContext authCtx,
            String newPassword,
            Settings.PasswordSettings passwordSettings) {
        String newHashedPassword = BCrypt.with(BCrypt.Version.VERSION_2Y)
                .hashToString(passwordSettings.bcryptCost(), newPassword.toCharArray());
        if (!ctx.isConnectionCurrent(authCtx.connectionOperation())) {
            return false;
        }
        authCtx.registeredPlayer().setHash(newHashedPassword);
        try {
            var saveResult = ctx.databaseManager().savePlayer(authCtx.registeredPlayer()).join();
            if (ctx.handleDatabaseError(saveResult, authCtx.username(), authCtx.player(),
                    "Password change save failed for", authCtx.connectionOperation())) {
                return false;
            }
            boolean saved = Boolean.TRUE.equals(saveResult.getValue());
            if (!saved) {
                ctx.runIfConnectionCurrent(authCtx.connectionOperation(),
                        () -> ctx.sendDatabaseErrorMessage(authCtx.player()));
                return false;
            }
            return true;
        } catch (CompletionException e) {
            ctx.logger().error(DB_MARKER, "Failed to save password change for player {}", authCtx.username(), e);
            ctx.runIfConnectionCurrent(authCtx.connectionOperation(),
                    () -> ctx.sendDatabaseErrorMessage(authCtx.player()));
            return false;
        }
    }

    private void finalizePasswordChange(AuthenticationContext authCtx) {
        java.util.UUID playerId = authCtx.connectionOperation().playerId();
        String playerIp = authCtx.playerAddress() == null
                ? "unknown"
                : authCtx.playerAddress().getHostAddress();

        // The password commit is account-scoped and durable. Revoke UUID state before any
        // optional lookup or connection-bound effect, even when the originating connection was
        // retired while the database commit was in flight.
        ctx.authCache().endSession(playerId);
        ctx.authCache().removeAuthorizedPlayer(playerId);
        savePasswordChangeAudit(authCtx.username(), playerIp);

        // A committed password change revokes duplicate sessions even if its origin disconnected.
        Player origin = authCtx.player();
        disconnectDuplicateSessions(origin, authCtx.username(), playerIp);

        ctx.runIfConnectionCurrent(authCtx.connectionOperation(),
                () -> authCtx.player().sendMessage(ctx.messages().component(
                        "auth.changepassword.success", NamedTextColor.GREEN)));
        if (ctx.logger().isInfoEnabled()) {
            ctx.logger().info(AUTH_MARKER, "Player {} changed password from IP {}",
                    authCtx.username(), playerIp);
        }

        // Premium cache refresh is best-effort. It deliberately follows every mandatory
        // post-commit security effect so a slow or failed lookup cannot delay account revocation.
        var premiumResult = ctx.checkPremiumStatus(
                authCtx.username(), origin, "Premium check during password change",
                authCtx.connectionOperation());
        if (!premiumResult.isDatabaseError() && Boolean.TRUE.equals(premiumResult.getValue())) {
            ctx.authCache().removePremiumPlayer(authCtx.username());
        }
    }

    private void savePasswordChangeAudit(String username, String playerIp) {
        AuditLogService audit = ctx.plugin().getAuditLogService();
        if (audit == null) {
            return;
        }
        try {
            audit.save(AuditEventType.PASSWORD_CHANGE, username, playerIp);
        } catch (RuntimeException auditFailure) {
            ctx.logger().error(AUTH_MARKER,
                    "Failed to submit password-change audit for {}", username, auditFailure);
        }
    }

    @SuppressWarnings("PMD.CompareObjectsWithEquals")
    private void disconnectDuplicateSessions(Player origin, String username, String playerIp) {
        for (Player connected : ctx.plugin().getServer().getAllPlayers()) {
            if (connected == origin) {
                continue;
            }
            try {
                if (!connected.getUsername().equalsIgnoreCase(username)) {
                    continue;
                }
                connected.disconnect(ctx.messages().component(
                        "general.kick.message", NamedTextColor.YELLOW));
                if (ctx.logger().isWarnEnabled()) {
                    ctx.logger().warn(
                            "Disconnected duplicate player {} — password changed from IP {}",
                            username, playerIp);
                }
            } catch (RuntimeException disconnectFailure) {
                ctx.logger().error(AUTH_MARKER,
                        "Failed to disconnect duplicate session for {} after password change",
                        username, disconnectFailure);
            }
        }
    }
}
