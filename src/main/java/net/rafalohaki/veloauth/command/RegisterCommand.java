package net.rafalohaki.veloauth.command;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;

import java.net.InetAddress;
import java.util.concurrent.CompletionException;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/**
 * Handles the /register command.
 * Creates a new player account and delegates post-auth flow to {@link PostAuthFlow}.
 * <p>
 * This command is hidden from players who are already authenticated
 * and not on the auth server (via {@link #hasPermission}).
 */
class RegisterCommand implements SimpleCommand {

    private static final String ERROR_DATABASE_QUERY = "error.database.query";
    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");

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

        ValidationUtils.ValidationResult passwordValidation =
                ValidationUtils.validatePassword(password, ctx.settings(), ctx.messages());
        if (!passwordValidation.valid()) {
            player.sendMessage(ValidationUtils.createErrorComponent(passwordValidation.getErrorMessage()));
            return;
        }

        ValidationUtils.ValidationResult matchValidation =
                ValidationUtils.validatePasswordMatch(password, confirmPassword, ctx.messages());
        if (!matchValidation.valid()) {
            player.sendMessage(ValidationUtils.createErrorComponent(matchValidation.getErrorMessage()));
            return;
        }

        ctx.runAsyncCommandWithTimeout(source, () -> processRegistration(player, password),
                ERROR_DATABASE_QUERY, "auth.registration.timeout");
    }

    private void processRegistration(Player player, String password) {
        if (!ctx.tryAcquireCommandLock(player.getUniqueId())) {
            ctx.sendCommandInProgress(player);
            return;
        }
        InetAddress playerAddress = PlayerAddressUtils.getPlayerAddress(player);
        if (!canProceedWithoutAddress(player, playerAddress)) {
            return;
        }
        IpLockState ipLock = tryAcquireRegistrationIpLock(player, playerAddress);
        if (!ipLock.proceed()) {
            return;
        }
        try {
            executeRegistrationFlow(player, password, playerAddress);
        } catch (CompletionException e) {
            ctx.logger().error(DB_MARKER, "Database error during registration for player {}", player.getUsername(), e);
            ctx.sendDatabaseErrorMessage(player);
        } finally {
            ctx.releaseCommandLock(player.getUniqueId());
            if (ipLock.acquired()) {
                ctx.releaseRegistrationLock(playerAddress);
            }
        }
    }

    // Fail-closed when we can't identify the IP and IP-limiting is enabled. Without an
    // InetAddress we cannot acquire the per-IP lock that closes the TOCTOU on
    // `ip-limit-registrations`; allowing the register to proceed would let two concurrent
    // null-address registers both bypass the cap. Null addresses are rare (buggy upstream
    // proxy / non-standard transport); the operator can disable ip-limit-registrations
    // if they accept that risk.
    private boolean canProceedWithoutAddress(Player player, InetAddress playerAddress) {
        if (playerAddress != null || ctx.settings().getIpLimitRegistrations() <= 0) {
            return true;
        }
        ctx.logger().warn(DB_MARKER,
                "Refusing registration of {} — cannot resolve remote IP (ip-limit-registrations enabled)",
                player.getUsername());
        player.sendMessage(ctx.sm().bruteForceBlocked());
        ctx.releaseCommandLock(player.getUniqueId());
        return false;
    }

    // Closes the TOCTOU window on ip-limit-registrations: serializes concurrent /register
    // from the same IP. Without this gate, two parallel registers could both observe
    // count < limit and both succeed, exceeding the configured ceiling.
    private IpLockState tryAcquireRegistrationIpLock(Player player, InetAddress playerAddress) {
        if (playerAddress == null) {
            return new IpLockState(true, false);
        }
        if (ctx.tryAcquireRegistrationLock(playerAddress)) {
            return new IpLockState(true, true);
        }
        ctx.sendCommandInProgress(player);
        ctx.releaseCommandLock(player.getUniqueId());
        return new IpLockState(false, false);
    }

    private record IpLockState(boolean proceed, boolean acquired) { }

    private void executeRegistrationFlow(Player player, String password, InetAddress playerAddress) {
        if (playerAddress != null && ctx.ipRateLimiter().isRateLimited(playerAddress)) {
            player.sendMessage(ctx.sm().bruteForceBlocked());
            return;
        }

        AuthenticationContext authContext = ctx.validateAndAuthenticatePlayer(player, "registration");
        if (authContext == null) {
            return;
        }

        if (authContext.registeredPlayer() != null) {
            authContext.player().sendMessage(ctx.sm().alreadyRegistered());
            return;
        }

        if (exceedsIpRegistrationLimit(authContext)) {
            player.sendMessage(Component.text(ctx.messages().get("register.ip_limit_reached")));
            return;
        }

        RegisteredPlayer newPlayer = buildNewPlayer(authContext, password);
        if (!persistNewPlayer(authContext, newPlayer)) {
            return;
        }

        if (PostAuthFlow.execute(ctx, authContext, newPlayer, "registered")) {
            authContext.player().sendMessage(ctx.sm().registerSuccess());
            emitRegisterAudit(authContext);
        }
    }

    private boolean exceedsIpRegistrationLimit(AuthenticationContext authContext) {
        String playerIp = PlayerAddressUtils.getPlayerIp(authContext.player());
        long ipCount = ctx.databaseManager().countRegistrationsByIp(playerIp).join();
        return ipCount >= ctx.settings().getIpLimitRegistrations();
    }

    private RegisteredPlayer buildNewPlayer(AuthenticationContext authContext, String password) {
        String hashedPassword = BCrypt.with(BCrypt.Version.VERSION_2Y)
                .hashToString(ctx.settings().getBcryptCost(), password.toCharArray());
        return new RegisteredPlayer(
                authContext.username(), hashedPassword,
                PlayerAddressUtils.getPlayerIp(authContext.player()),
                authContext.player().getUniqueId().toString());
    }

    private boolean persistNewPlayer(AuthenticationContext authContext, RegisteredPlayer newPlayer) {
        var saveResult = ctx.databaseManager().savePlayer(newPlayer).join();
        if (ctx.handleDatabaseError(saveResult, authContext.player(), "Failed to save new player")) {
            return false;
        }
        if (!Boolean.TRUE.equals(saveResult.getValue())) {
            ctx.sendDatabaseErrorMessage(authContext.player());
            return false;
        }
        return true;
    }

    private void emitRegisterAudit(AuthenticationContext authContext) {
        AuditLogService audit = ctx.plugin().getAuditLogService();
        if (audit != null) {
            audit.save(AuditEventType.REGISTER, authContext.username(),
                    PlayerAddressUtils.getPlayerIp(authContext.player()));
        }
    }
}
