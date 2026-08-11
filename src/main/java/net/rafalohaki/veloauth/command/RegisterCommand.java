package net.rafalohaki.veloauth.command;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry;
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

    @Override
    public boolean hasPermission(Invocation invocation) {
        return CommandHelper.isPlayerOnAuthServerAndNeedsAuthentication(invocation, ctx);
    }

    @Override
    @SuppressWarnings("FutureReturnValueIgnored")
    public void execute(Invocation invocation) {
        CommandHelper.CommandInputs inputs = CommandHelper.requirePlayerAndArgs(
                invocation, ctx.messages(), 2, "auth.register.usage");
        if (inputs == null) {
            return;
        }
        Player player = inputs.player();
        String password = inputs.args()[0];
        String confirmPassword = inputs.args()[1];
        var passwordSettings = ctx.settings().captureOperationSettings().password();

        if (!CommandHelper.requireValidPassword(player, password, passwordSettings, ctx.messages())
                || !CommandHelper.requirePasswordsMatch(player, password, confirmPassword, ctx.messages())) {
            return;
        }

        ConnectionLifecycleRegistry.Operation operation = ctx.captureConnectionOperation(player);
        if (operation == null) {
            return;
        }
        var commitPermit = new DatabaseManager.RegistrationCommitPermit();
        ctx.runRegistrationCommandWithTimeout(
                player, operation, commitPermit,
                () -> processRegistration(
                        player, password, operation, passwordSettings, commitPermit),
                ERROR_DATABASE_QUERY);
    }

    private void processRegistration(
            Player player, String password,
            ConnectionLifecycleRegistry.Operation operation,
            Settings.PasswordSettings passwordSettings,
            DatabaseManager.RegistrationCommitPermit commitPermit) {
        if (commitPermit.isCancelled()) {
            return;
        }
        if (!ctx.beginConnectionCommand(player, operation, commitPermit)) {
            return;
        }
        InetAddress playerAddress = PlayerAddressUtils.getPlayerAddress(player);
        if (!canProceedWithoutAddress(
                player, playerAddress, operation, passwordSettings, commitPermit)) {
            return;
        }
        IpLockState ipLock = tryAcquireRegistrationIpLock(
                player, playerAddress, operation, commitPermit);
        if (!ipLock.proceed()) {
            return;
        }
        try {
            executeRegistrationFlow(
                    player, password, playerAddress, operation, passwordSettings,
                    commitPermit);
        } catch (CompletionException e) {
            if (commitPermit.tryCompleteWithoutCommit()
                    || !commitPermit.isCancelled()) {
                ctx.logger().error(DB_MARKER,
                        "Database error during registration for player {}",
                        player.getUsername(), e);
                ctx.runIfConnectionCurrent(
                        operation, () -> ctx.sendDatabaseErrorMessage(player));
            }
        } finally {
            ctx.releaseCommandLock(operation.playerId(), operation);
            ctx.releaseRegistrationLock(ipLock.lease());
        }
    }

    // Fail-closed when we can't identify the IP and IP-limiting is enabled. Without an
    // InetAddress we cannot acquire the per-IP lock that closes the TOCTOU on
    // `ip-limit-registrations`; allowing the register to proceed would let two concurrent
    // null-address registers both bypass the cap. Null addresses are rare (buggy upstream
    // proxy / non-standard transport); the operator can disable ip-limit-registrations
    // if they accept that risk.
    private boolean canProceedWithoutAddress(
            Player player, InetAddress playerAddress,
            ConnectionLifecycleRegistry.Operation operation,
            Settings.PasswordSettings passwordSettings,
            DatabaseManager.RegistrationCommitPermit commitPermit) {
        if (playerAddress != null || passwordSettings.ipLimitRegistrations() <= 0) {
            return true;
        }
        ctx.logger().warn(DB_MARKER,
                "Refusing registration of {} — cannot resolve remote IP (ip-limit-registrations enabled)",
                player.getUsername());
        ctx.completeRegistrationWithoutCommit(
                operation, commitPermit,
                () -> player.sendMessage(ctx.sm().bruteForceBlocked()));
        ctx.releaseCommandLock(operation.playerId(), operation);
        return false;
    }

    // Closes the TOCTOU window on ip-limit-registrations: serializes concurrent /register
    // from the same IP. Without this gate, two parallel registers could both observe
    // count < limit and both succeed, exceeding the configured ceiling.
    private IpLockState tryAcquireRegistrationIpLock(
            Player player, InetAddress playerAddress,
            ConnectionLifecycleRegistry.Operation operation,
            DatabaseManager.RegistrationCommitPermit commitPermit) {
        if (playerAddress == null) {
            return new IpLockState(true, null);
        }
        CommandContext.RegistrationLockLease lease =
                ctx.tryAcquireRegistrationLock(playerAddress);
        if (lease != null) {
            return new IpLockState(true, lease);
        }
        ctx.completeRegistrationWithoutCommit(
                operation, commitPermit,
                () -> ctx.sendCommandInProgress(player));
        ctx.releaseCommandLock(operation.playerId(), operation);
        return new IpLockState(false, null);
    }

    private record IpLockState(
            boolean proceed, CommandContext.RegistrationLockLease lease) { }

    private void executeRegistrationFlow(
            Player player, String password, InetAddress playerAddress,
            ConnectionLifecycleRegistry.Operation operation,
            Settings.PasswordSettings passwordSettings,
            DatabaseManager.RegistrationCommitPermit commitPermit) {
        if (commitPermit.isCancelled()) {
            return;
        }
        if (ctx.rejectRateLimited(player, playerAddress, operation, commitPermit)) {
            return;
        }

        AuthenticationContext authContext = ctx.validateAndAuthenticatePlayer(
                player, "registration", operation, commitPermit);
        if (authContext == null) {
            return;
        }

        if (authContext.registeredPlayer() != null) {
            ctx.completeRegistrationWithoutCommit(
                    authContext.connectionOperation(), commitPermit,
                    () -> authContext.player().sendMessage(ctx.sm().alreadyRegistered()));
            return;
        }

        if (exceedsIpRegistrationLimit(authContext, passwordSettings)) {
            ctx.completeRegistrationWithoutCommit(
                    authContext.connectionOperation(), commitPermit,
                    () -> player.sendMessage(ctx.messages().component(
                            "register.ip_limit_reached", NamedTextColor.RED)));
            return;
        }

        if (commitPermit.isCancelled()
                || !ctx.isConnectionCurrent(authContext.connectionOperation())) {
            return;
        }

        RegisteredPlayer newPlayer = buildNewPlayer(authContext, password, passwordSettings);
        if (!persistNewPlayer(authContext, newPlayer, commitPermit)) {
            return;
        }

        if (PostAuthFlow.execute(ctx, authContext, newPlayer, "registered")) {
            ctx.runIfConnectionCurrent(authContext.connectionOperation(), () -> {
                authContext.player().sendMessage(ctx.sm().registerSuccess());
                emitRegisterAudit(authContext);
            });
        }
    }

    private boolean exceedsIpRegistrationLimit(
            AuthenticationContext authContext,
            Settings.PasswordSettings passwordSettings) {
        String playerIp = PlayerAddressUtils.getPlayerIp(authContext.player());
        long ipCount = ctx.databaseManager().countRegistrationsByIp(playerIp).join();
        return ipCount >= passwordSettings.ipLimitRegistrations();
    }

    private RegisteredPlayer buildNewPlayer(
            AuthenticationContext authContext,
            String password,
            Settings.PasswordSettings passwordSettings) {
        String hashedPassword = BCrypt.with(BCrypt.Version.VERSION_2Y)
                .hashToString(passwordSettings.bcryptCost(), password.toCharArray());
        return new RegisteredPlayer(
                authContext.username(), hashedPassword,
                PlayerAddressUtils.getPlayerIp(authContext.player()),
                authContext.player().getUniqueId().toString());
    }

    private boolean persistNewPlayer(
            AuthenticationContext authContext, RegisteredPlayer newPlayer,
            DatabaseManager.RegistrationCommitPermit commitPermit) {
        if (commitPermit.isCancelled()
                || !ctx.isConnectionCurrent(authContext.connectionOperation())) {
            return false;
        }
        var saveResult = ctx.databaseManager()
                .registerPlayerIfAbsent(newPlayer, commitPermit).join();
        if (!ctx.isConnectionCurrent(authContext.connectionOperation())) {
            return false;
        }
        if (saveResult.isDatabaseError()
                && !commitPermit.tryCompleteWithoutCommit()
                && commitPermit.isCancelled()) {
            return false;
        }
        if (ctx.handleDatabaseError(saveResult, authContext.username(), authContext.player(),
                "Failed to register new player", authContext.connectionOperation())) {
            return false;
        }
        return handleRegistrationOutcome(
                authContext, saveResult.getValue(), commitPermit);
    }

    private boolean handleRegistrationOutcome(
            AuthenticationContext authContext,
            DatabaseManager.RegistrationResult outcome,
            DatabaseManager.RegistrationCommitPermit commitPermit) {
        if (outcome == null) {
            ctx.runIfConnectionCurrent(authContext.connectionOperation(),
                    () -> ctx.sendDatabaseErrorMessage(authContext.player()));
            return false;
        }
        return switch (outcome) {
            case CREATED -> true;
            case DUPLICATE -> {
                ctx.runIfConnectionCurrent(authContext.connectionOperation(),
                        () -> authContext.player().sendMessage(ctx.sm().alreadyRegistered()));
                yield false;
            }
            case CANCELLED -> false;
            case COMMIT_UNKNOWN -> {
                if (commitPermit.claimCommitUnknownMessage()) {
                    ctx.runIfConnectionCurrent(authContext.connectionOperation(),
                            () -> authContext.player().sendMessage(ctx.messages().component(
                                    "auth.registration.commit_unknown", NamedTextColor.RED)));
                }
                yield false;
            }
        };
    }

    private void emitRegisterAudit(AuthenticationContext authContext) {
        AuditLogService audit = ctx.plugin().getAuditLogService();
        if (audit != null) {
            audit.save(AuditEventType.REGISTER, authContext.username(),
                    PlayerAddressUtils.getPlayerIp(authContext.player()));
        }
    }
}
