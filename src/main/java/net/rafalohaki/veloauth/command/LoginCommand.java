package net.rafalohaki.veloauth.command;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.auth.totp.PendingTotpState;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import net.rafalohaki.veloauth.util.SecurityUtils;

import java.net.InetAddress;

/**
 * Handles the /login command.
 * Validates credentials against the database and delegates
 * post-auth flow to {@link PostAuthFlow}.
 * <p>
 * This command is hidden from players who are already authenticated
 * and not on the auth server (via {@link #hasPermission}).
 */
class LoginCommand implements SimpleCommand {

    private static final String ERROR_DATABASE_QUERY = "error.database.query";

    private final CommandContext ctx;

    LoginCommand(CommandContext ctx) {
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

        if (args.length != 1) {
            player.sendMessage(ctx.sm().usageLogin());
            return;
        }

        String password = args[0];

        ctx.runAsyncCommand(source, () -> processLogin(player, password), ERROR_DATABASE_QUERY);
    }

    private void processLogin(Player player, String password) {
        if (!ctx.tryAcquireCommandLock(player.getUniqueId())) {
            ctx.sendCommandInProgress(player);
            return;
        }
        try {
            InetAddress playerAddress = PlayerAddressUtils.getPlayerAddress(player);
            if (playerAddress != null && ctx.ipRateLimiter().isRateLimited(playerAddress)) {
                player.sendMessage(ctx.sm().bruteForceBlocked());
                return;
            }

            AuthenticationContext authContext = ctx.validateAndAuthenticatePlayer(player, "login");
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
        } finally {
            ctx.releaseCommandLock(player.getUniqueId());
        }
    }

    private void handleSuccessfulLogin(AuthenticationContext authContext) {
        try {
            authContext.registeredPlayer().updateLoginData(PlayerAddressUtils.getPlayerIp(authContext.player()));
            var saveResult = ctx.databaseManager().savePlayer(authContext.registeredPlayer()).join();

            if (ctx.handleDatabaseError(saveResult, authContext.player(), "Failed to save login data for")) {
                return;
            }

            // 2FA gate — if the account has a TOTP token AND the feature is currently enabled,
            // park the player in a pending state instead of transferring to backend. The /2fa verify
            // command completes the transfer once the player produces a valid code.
            if (shouldRequireTotp(authContext.registeredPlayer())) {
                parkForTotpVerify(authContext);
                return;
            }

            if (PostAuthFlow.execute(ctx, authContext, authContext.registeredPlayer(), "logged in")) {
                authContext.player().sendMessage(ctx.sm().loginSuccess());
                emitAudit(AuditEventType.LOGIN_OK, authContext, null);
            }

        } catch (java.util.concurrent.CompletionException e) {
            if (ctx.logger().isErrorEnabled()) {
                ctx.logger().error("Error processing successful login: {}", authContext.username(), e);
            }
            ctx.sendDatabaseErrorMessage(authContext.player());
        }
    }

    /**
     * True iff the player has a TOTP secret AND the two-factor feature is currently enabled
     * by configuration. The master switch is checked here on purpose: an operator who sets
     * {@code two-factor.enabled=false} expects existing tokens to stop being enforced.
     */
    private boolean shouldRequireTotp(RegisteredPlayer dbPlayer) {
        if (!ctx.settings().getTwoFactorSettings().isEnabled()) {
            return false;
        }
        String token = dbPlayer.getTotpToken();
        return token != null && !token.isBlank();
    }

    private void parkForTotpVerify(AuthenticationContext authContext) {
        Player player = authContext.player();
        String ip = PlayerAddressUtils.getPlayerIp(player);
        ctx.pendingTotpStore().put(PendingTotpState.forLogin(player.getUniqueId(), authContext.registeredPlayer(), ip));
        player.sendMessage(ctx.sm().twoFactorLoginPendingPrompt());

        if (ctx.logger().isDebugEnabled()) {
            ctx.logger().debug("Player {} parked for 2FA verification (IP {})", authContext.username(), ip);
        }
    }

    private void handleFailedLogin(AuthenticationContext authContext) {
        boolean blocked = SecurityUtils.registerFailedLogin(authContext.playerAddress(), authContext.username(), ctx.authCache());

        InetAddress playerAddress = authContext.playerAddress();
        if (playerAddress != null) {
            ctx.ipRateLimiter().incrementAttempts(playerAddress);
        }

        if (blocked) {
            authContext.player().sendMessage(ctx.sm().bruteForceBlocked());
            if (ctx.logger().isWarnEnabled()) {
                ctx.logger().warn("Player {} blocked for brute force from IP {}",
                        authContext.username(), PlayerAddressUtils.getPlayerIp(authContext.player()));
            }
            emitAudit(AuditEventType.LOGIN_FAIL, authContext, "brute-force-blocked");
        } else {
            authContext.player().sendMessage(ctx.sm().loginFailed());
            if (ctx.logger().isDebugEnabled()) {
                ctx.logger().debug("Failed login attempt for player {} from IP {}",
                        authContext.username(), PlayerAddressUtils.getPlayerIp(authContext.player()));
            }
            emitAudit(AuditEventType.LOGIN_FAIL, authContext, "wrong-password");
        }
    }

    private void emitAudit(AuditEventType type, AuthenticationContext authContext, String details) {
        AuditLogService audit = ctx.plugin().getAuditLogService();
        if (audit == null) {
            return;
        }
        audit.record(type, authContext.username(),
                PlayerAddressUtils.getPlayerIp(authContext.player()), details);
    }
}
