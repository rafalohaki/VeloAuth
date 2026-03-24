package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.model.RegisteredPlayer;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletionException;
import net.rafalohaki.veloauth.database.DatabaseManager;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

/**
 * Komenda /vauth - komendy administratora.
 * Extracted from CommandHandler for single-responsibility.
 */
class VAuthCommand implements SimpleCommand {

    private static final String ERROR_DATABASE_QUERY = "error.database.query";
    private static final String CONFLICT_PREFIX = "   §7";
    private static final String RELOAD_WARNING_KEY = "admin.reload.warning";
    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");

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
            default -> {
                source.sendMessage(ValidationUtils.createErrorComponent(
                    ctx.messages().get("admin.unknown_command", subcommand)));
                sendAdminHelp(source);
            }
        }
    }

    private void handleReloadCommand(CommandSource source) {
        boolean success = ctx.plugin().reloadConfig();
        if (success) {
            source.sendMessage(ctx.sm().adminReloadSuccess());
            sendLocalizedReloadWarning(source);
        } else {
            source.sendMessage(ctx.sm().adminReloadFailed());
        }
    }

    private void handleConflictsCommand(CommandSource source) {
        ctx.runAsyncCommand(source, () -> processConflictsCommand(source), ERROR_DATABASE_QUERY);
    }

    private void handleCacheResetCommand(CommandSource source, String[] args) {
        if (args.length == 2) {
            String nickname = args[1];
            ctx.runAsyncCommand(source, () -> processSinglePlayerCacheReset(source, nickname), ERROR_DATABASE_QUERY);
        } else {
            ctx.authCache().clearAll();
            source.sendMessage(ValidationUtils.createSuccessComponent(ctx.messages().get("admin.cache_reset.success")));
        }
    }

    private void handleStatsCommand(CommandSource source) {
        ctx.runAsyncCommand(source, () -> processStatsCommand(source), ERROR_DATABASE_QUERY);
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

    private void processConflictsCommand(CommandSource source) {
        if (!ctx.ensureDatabaseConnected(source, "Admin conflicts command")) {
            return;
        }

        List<RegisteredPlayer> conflicts;
        try {
            conflicts = ctx.databaseManager().findPlayersInConflictMode().join();
        } catch (CompletionException e) {
            ctx.logger().error(DB_MARKER, "Failed to fetch conflict players", e);
            ctx.sendDatabaseErrorMessage(source);
            return;
        }
        if (conflicts == null || !ctx.ensureDatabaseConnected(source, "Admin conflicts command")) {
            return;
        }

        source.sendMessage(ValidationUtils.createWarningComponent(ctx.messages().get("admin.conflicts.header")));

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
                conflictInfo.append(CONFLICT_PREFIX)
                        .append(ctx.messages().get("admin.conflicts.original_nick", conflict.getOriginalNickname()))
                        .append("\n");
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

    private void processSinglePlayerCacheReset(CommandSource source, String nickname) {
        PlayerLookupResult playerLookup = resolvePlayerUuid(source, nickname);
        if (playerLookup.handledError()) {
            return;
        }

        UUID playerUuid = playerLookup.playerUuid();
        if (playerUuid == null) {
            source.sendMessage(ValidationUtils.createErrorComponent(
                    ctx.messages().get("admin.cache_reset.player_not_found", nickname)));
            return;
        }

        if (ctx.authCache().findAuthorizedPlayer(playerUuid).isEmpty()) {
            source.sendMessage(ValidationUtils.createErrorComponent(
                    ctx.messages().get("admin.cache_reset.player_not_found", nickname)));
            return;
        }

        ctx.authCache().removeAuthorizedPlayer(playerUuid);
        ctx.authCache().endSession(playerUuid);
        source.sendMessage(ValidationUtils.createSuccessComponent(
                ctx.messages().get("admin.cache_reset.player", nickname)));
    }

    private void processStatsCommand(CommandSource source) {
        if (!ctx.ensureDatabaseConnected(source, "Admin stats command")) {
            return;
        }

        var totalF = ctx.databaseManager().getTotalRegisteredAccounts();
        var premiumF = ctx.databaseManager().getTotalPremiumAccounts();
        var nonPremiumF = ctx.databaseManager().getTotalNonPremiumAccounts();

        try {
            java.util.concurrent.CompletableFuture.allOf(totalF, premiumF, nonPremiumF).join();
        } catch (CompletionException e) {
            ctx.logger().error(DB_MARKER, "Failed to fetch player statistics", e);
            ctx.sendDatabaseErrorMessage(source);
            return;
        }
        if (!ctx.ensureDatabaseConnected(source, "Admin stats command")) {
            return;
        }

        int total = totalF.join();
        int premium = premiumF.join();
        int nonPremium = nonPremiumF.join();
        double pct = total > 0 ? (premium * 100.0 / total) : 0.0;

        var cacheStats = ctx.authCache().getStats();
        int dbCacheSize = ctx.databaseManager().getCacheSize();
        String dbStatus = ctx.databaseManager().isConnected()
                ? ctx.messages().get("database.connected")
                : ctx.messages().get("database.disconnected");

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

    private PlayerLookupResult resolvePlayerUuid(CommandSource source, String nickname) {
        return ctx.plugin().getServer().getPlayer(nickname)
                .map(player -> new PlayerLookupResult(player.getUniqueId(), false))
                .orElseGet(() -> resolveRegisteredPlayerUuid(source, nickname));
    }

    private PlayerLookupResult resolveRegisteredPlayerUuid(CommandSource source, String nickname) {
        DatabaseManager.DbResult<RegisteredPlayer> dbResult;
        try {
            dbResult = ctx.databaseManager().findPlayerByNickname(nickname).join();
        } catch (CompletionException e) {
            ctx.logger().error(DB_MARKER, "Failed to look up player {} for cache reset", nickname, e);
            ctx.sendDatabaseErrorMessage(source);
            return new PlayerLookupResult(null, true);
        }
        if (ctx.handleDatabaseError(dbResult, source, nickname, "Admin cache reset lookup")) {
            return new PlayerLookupResult(null, true);
        }

        RegisteredPlayer registeredPlayer = dbResult.getValue();
        if (registeredPlayer == null) {
            return new PlayerLookupResult(null, false);
        }

        try {
            return new PlayerLookupResult(UUID.fromString(registeredPlayer.getUuid()), false);
        } catch (IllegalArgumentException e) {
            source.sendMessage(ValidationUtils.createErrorComponent(ctx.messages().get("admin.uuid_invalid")));
            return new PlayerLookupResult(null, true);
        }
    }

    private void sendLocalizedReloadWarning(CommandSource source) {
        String warningMessage = ctx.messages().get(RELOAD_WARNING_KEY);
        if (RELOAD_WARNING_KEY.equals(warningMessage)
                || ("Missing: " + RELOAD_WARNING_KEY).equals(warningMessage)) {
            return;
        }
        source.sendMessage(ValidationUtils.createWarningComponent(warningMessage));
    }

    private record PlayerLookupResult(UUID playerUuid, boolean handledError) {}
}
