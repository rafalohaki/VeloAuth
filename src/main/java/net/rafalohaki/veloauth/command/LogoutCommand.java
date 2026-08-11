package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;

/**
 * Retires the invoking player's concrete connection before requesting its terminal disconnect.
 * The later {@code DisconnectEvent} repeats the same owner-aware cleanup idempotently.
 */
class LogoutCommand implements SimpleCommand {

    private static final String AUDIT_DETAILS = "connection-termination-requested";

    private final CommandContext context;

    LogoutCommand(CommandContext context) {
        this.context = context;
    }

    @Override
    public void execute(Invocation invocation) {
        CommandHelper.CommandInputs inputs = CommandHelper.requirePlayerAndArgs(
                invocation, context.messages(), 0, "auth.logout.usage");
        if (inputs == null) {
            return;
        }

        Player player = inputs.player();
        if (!player.isActive()) {
            return;
        }

        // Velocity documents Player access after disconnect as undefined. Capture audit identity first.
        String username = player.getUsername();
        String playerIp = PlayerAddressUtils.getPlayerIp(player);
        try {
            context.retireConnectionOperation(player);
        } catch (RuntimeException cleanupFailure) {
            context.logger().error(
                    "Failed to retire logout connection for {}", username, cleanupFailure);
        }
        try {
            player.disconnect(context.sm().authLoggedOut());
        } catch (RuntimeException disconnectFailure) {
            context.logger().error(
                    "Failed to request terminal logout disconnect for {}", username,
                    disconnectFailure);
        }

        AuditLogService auditLogService = context.auditLogService();
        if (auditLogService != null) {
            auditLogService.save(AuditEventType.LOGOUT, username, playerIp, AUDIT_DETAILS);
        }
    }
}
