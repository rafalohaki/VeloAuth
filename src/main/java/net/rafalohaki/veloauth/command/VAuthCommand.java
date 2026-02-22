package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import net.rafalohaki.veloauth.model.RegisteredPlayer;

import java.util.List;

/**
 * Komenda /vauth - komendy administratora.
 * Extracted from CommandHandler for single-responsibility.
 */
class VAuthCommand implements SimpleCommand {

    private static final String CONFLICT_PREFIX = "   §7";

    private final CommandContext ctx;

    VAuthCommand(CommandContext ctx) {
        this.ctx = ctx;
    }

    @Override
    public void execute(Invocation invocation) {
        CommandSource source = invocation.source();
        String[] args = invocation.arguments();

        if (!CommandHelper.checkAdminPermission(source, ctx.messages())) {
            return;
        }

        if (args.length == 0) {
            sendAdminHelp(source);
            return;
        }

        String subcommand = args[0].toLowerCase();

        switch (subcommand) {
            case "reload" -> handleReloadCommand(source);
            case "cache-reset" -> handleCacheResetCommand(source, args);
            case "stats" -> handleStatsCommand(source);
            case "conflicts" -> handleConflictsCommand(source);
            default -> source.sendMessage(ctx.sm().adminReloadFailed());
        }
    }

    private void handleReloadCommand(CommandSource source) {
        boolean success = ctx.plugin().reloadConfig();
        if (success) {
            source.sendMessage(ctx.sm().adminReloadSuccess());
        } else {
            source.sendMessage(ctx.sm().adminReloadFailed());
        }
    }

    private void handleConflictsCommand(CommandSource source) {
        source.sendMessage(ValidationUtils.createWarningComponent(ctx.messages().get("admin.conflicts.header")));
        var conflictsFuture = ctx.databaseManager().findPlayersInConflictMode();
        var conflicts = conflictsFuture.join();

        if (conflicts.isEmpty()) {
            source.sendMessage(ValidationUtils.createSuccessComponent(ctx.messages().get("admin.conflicts.none")));
            return;
        }

        source.sendMessage(ValidationUtils.createWarningComponent(
            ctx.messages().get("admin.conflicts.found", conflicts.size())));

        for (int i = 0; i < conflicts.size(); i++) {
            RegisteredPlayer conflict = conflicts.get(i);
            StringBuilder conflictInfo = new StringBuilder();
            conflictInfo.append("§e").append(i + 1).append(". §f").append(conflict.getNickname()).append("\n");
            conflictInfo.append(CONFLICT_PREFIX).append(ctx.messages().get("admin.conflicts.uuid", conflict.getUuid())).append("\n");
            conflictInfo.append(CONFLICT_PREFIX).append(ctx.messages().get("admin.conflicts.ip", conflict.getIp())).append("\n");

            long conflictTime = conflict.getConflictTimestamp();
            if (conflictTime > 0) {
                long hoursAgo = (System.currentTimeMillis() - conflictTime) / (1000 * 60 * 60);
                conflictInfo.append(CONFLICT_PREFIX).append(ctx.messages().get("admin.conflicts.hours_ago", hoursAgo)).append("\n");
            }

            if (conflict.getOriginalNickname() != null &&
                !conflict.getOriginalNickname().equals(conflict.getNickname())) {
                conflictInfo.append(CONFLICT_PREFIX).append(ctx.messages().get("admin.conflicts.original_nick", conflict.getOriginalNickname())).append("\n");
            }

            boolean isPremium = ctx.databaseManager().isPlayerPremiumRuntime(conflict);
            String statusKey = isPremium ? "admin.conflicts.status_premium" : "admin.conflicts.status_offline";
            conflictInfo.append(CONFLICT_PREFIX).append(ctx.messages().get(statusKey)).append("\n");

            source.sendMessage(ValidationUtils.createWarningComponent(conflictInfo.toString()));
        }

        source.sendMessage(ValidationUtils.createWarningComponent(""));
        source.sendMessage(ValidationUtils.createWarningComponent(ctx.messages().get("admin.conflicts.tips_header")));
        source.sendMessage(ValidationUtils.createWarningComponent(ctx.messages().get("admin.conflicts.tip_premium")));
        source.sendMessage(ValidationUtils.createWarningComponent(ctx.messages().get("admin.conflicts.tip_offline")));
        source.sendMessage(ValidationUtils.createWarningComponent(ctx.messages().get("admin.conflicts.tip_admin")));
    }

    private void handleCacheResetCommand(CommandSource source, String[] args) {
        if (args.length == 2) {
            String nickname = args[1];
            ctx.plugin().getServer().getPlayer(nickname).ifPresentOrElse(
                    player -> {
                        ctx.authCache().removeAuthorizedPlayer(player.getUniqueId());
                        source.sendMessage(ValidationUtils.createSuccessComponent(ctx.messages().get("admin.cache_reset.player", nickname)));
                    },
                    () -> source.sendMessage(ValidationUtils.createErrorComponent(ctx.messages().get("admin.cache_reset.player_not_found", nickname)))
            );
        } else {
            ctx.authCache().clearAll();
            source.sendMessage(ValidationUtils.createSuccessComponent(ctx.messages().get("admin.cache_reset.success")));
        }
    }

    private void handleStatsCommand(CommandSource source) {
        var totalF = ctx.databaseManager().getTotalRegisteredAccounts();
        var premiumF = ctx.databaseManager().getTotalPremiumAccounts();
        var nonPremiumF = ctx.databaseManager().getTotalNonPremiumAccounts();

        java.util.concurrent.CompletableFuture.allOf(totalF, premiumF, nonPremiumF).join();
        int total = totalF.join();
        int premium = premiumF.join();
        int nonPremium = nonPremiumF.join();
        double pct = total > 0 ? (premium * 100.0 / total) : 0.0;

        var cacheStats = ctx.authCache().getStats();
        int dbCacheSize = ctx.databaseManager().getCacheSize();
        String dbStatus = ctx.databaseManager().isConnected() ? ctx.messages().get("database.connected") : ctx.messages().get("database.disconnected");

        StringBuilder statsMessage = new StringBuilder();
        statsMessage.append(ctx.messages().get("admin.stats.header")).append("\n");
        statsMessage.append(ctx.messages().get("admin.stats.premium_accounts", premium)).append("\n");
        statsMessage.append(ctx.messages().get("admin.stats.nonpremium_accounts", nonPremium)).append("\n");
        statsMessage.append(ctx.messages().get("admin.stats.total_accounts", total)).append("\n");
        statsMessage.append(ctx.messages().get("admin.stats.premium_percentage", pct)).append("\n");
        statsMessage.append(ctx.messages().get("admin.stats.authorized_players", cacheStats.authorizedPlayersCount())).append("\n");
        statsMessage.append(ctx.messages().get("admin.stats.premium_cache", cacheStats.premiumCacheCount())).append("\n");
        statsMessage.append(ctx.messages().get("admin.stats.database_cache", dbCacheSize)).append("\n");
        statsMessage.append(ctx.messages().get("admin.stats.database_status", (Object) dbStatus));

        CommandHelper.sendWarning(source, statsMessage.toString());
    }

    private void sendAdminHelp(CommandSource source) {
        source.sendMessage(ctx.sm().adminHelpHeader());
        source.sendMessage(ctx.sm().adminHelpReload());
        source.sendMessage(ctx.sm().adminHelpCache());
        source.sendMessage(ctx.sm().adminHelpStats());
        source.sendMessage(ctx.sm().adminHelpConflicts());
    }

    @Override
    public List<String> suggest(Invocation invocation) {
        String[] args = invocation.arguments();

        if (args.length == 1) {
            return List.of("reload", "cache-reset", "stats", "conflicts");
        }

        return List.of();
    }
}
