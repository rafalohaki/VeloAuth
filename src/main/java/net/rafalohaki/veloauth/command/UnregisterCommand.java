package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.DatabaseErrorHandler;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.UUID;

/**
 * Handles the admin /unregister command.
 * Deletes a player account from the database and cleans up all caches.
 */
class UnregisterCommand implements SimpleCommand {

    private static final String ERROR_DATABASE_QUERY = "error.database.query";
    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");

    private final CommandContext ctx;

    UnregisterCommand(CommandContext ctx) {
        this.ctx = ctx;
    }

    @Override
    @SuppressWarnings("FutureReturnValueIgnored")
    public void execute(Invocation invocation) {
        CommandSource source = invocation.source();
        String[] args = invocation.arguments();

        if (!CommandHelper.checkAdminPermission(source, ctx.messages())) {
            return;
        }

        if (args.length != 1) {
            CommandHelper.sendError(source, ctx.messages(), "admin.unregister.usage");
            return;
        }

        String nickname = args[0];

        CommandHelper.runAsyncCommand(() -> processAdminUnregistration(source, nickname),
                ctx.messages(), source, ERROR_DATABASE_QUERY);
    }

    private void processAdminUnregistration(CommandSource source, String nickname) {
        try {
            var dbResult = ctx.databaseManager().findPlayerByNickname(nickname).join();

            if (handleDatabaseError(dbResult, source, nickname, "Admin unregistration failed for")) {
                return;
            }

            RegisteredPlayer registeredPlayer = dbResult.getValue();
            if (registeredPlayer == null) {
                source.sendMessage(ValidationUtils.createErrorComponent(ctx.messages().get("admin.player_not_found", nickname)));
                return;
            }

            UUID playerUuid = parsePlayerUuid(registeredPlayer, nickname, source);
            if (playerUuid == null) {
                return;
            }

            var deleteResult = ctx.databaseManager().deletePlayer(nickname).join();

            if (handleDatabaseError(deleteResult, source, nickname, "Admin unregistration delete failed for")) {
                return;
            }

            boolean deleted = Boolean.TRUE.equals(deleteResult.getValue());
            if (deleted) {
                ctx.authCache().removeAuthorizedPlayer(playerUuid);
                ctx.authCache().endSession(playerUuid);
                ctx.authCache().removePremiumPlayer(nickname);

                ctx.plugin().getServer().getPlayer(nickname).ifPresent(player -> {
                    player.disconnect(ctx.sm().kickMessage());
                    ctx.logger().info("Disconnected player {} — account deleted by admin", nickname);
                });

                CommandHelper.sendSuccess(source, ctx.messages().get("admin.account_deleted", nickname));
                String adminName = source instanceof Player player ? player.getUsername() : "CONSOLE";
                ctx.logger().info(AUTH_MARKER, "Admin {} deleted player account: {}", adminName, nickname);

            } else {
                CommandHelper.sendError(source, ctx.messages(), ERROR_DATABASE_QUERY);
                ctx.logger().error(DB_MARKER, "Failed to delete player account: {} (admin action)", nickname);
            }

        } catch (Exception e) {
            ctx.logger().error(DB_MARKER, "Error during admin account deletion: {}", nickname, e);
            CommandHelper.sendError(source, ctx.messages(), ERROR_DATABASE_QUERY);
        }
    }

    private boolean handleDatabaseError(DatabaseManager.DbResult<?> result, CommandSource source, String nickname, String operation) {
        return DatabaseErrorHandler.handleError(result, source, nickname, operation, ctx.logger(), ctx.messages());
    }

    private UUID parsePlayerUuid(RegisteredPlayer registeredPlayer, String nickname, CommandSource source) {
        try {
            return UUID.fromString(registeredPlayer.getUuid());
        } catch (IllegalArgumentException e) {
            ctx.logger().warn("Invalid UUID for player {}: {}", nickname, registeredPlayer.getUuid());
            source.sendMessage(ValidationUtils.createErrorComponent(ctx.messages().get("admin.uuid_invalid")));
            return null;
        }
    }
}
