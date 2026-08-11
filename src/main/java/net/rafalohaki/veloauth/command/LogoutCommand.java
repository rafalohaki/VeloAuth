package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;

/**
 * Terminates the invoking player's concrete proxy connection. Disconnect cleanup remains owned by
 * {@code AuthListener}, which can compare the concrete connection before clearing UUID-keyed state.
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
        player.disconnect(context.sm().authLoggedOut());

        AuditLogService auditLogService = context.auditLogService();
        if (auditLogService != null) {
            auditLogService.save(AuditEventType.LOGOUT, username, playerIp, AUDIT_DETAILS);
        }
    }
}
