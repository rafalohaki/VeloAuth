package net.rafalohaki.veloauth.command;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.DatabaseErrorHandler;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import net.rafalohaki.veloauth.util.SecurityUtils;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.util.List;
import java.util.UUID;

/**
 * Handler komend autoryzacji VeloAuth.
 * Obsługuje /login, /register, /changepassword z BCrypt hashing i thread-safety.
 * <p>
 * Wszystkie operacje są asynchroniczne z Virtual Threads dla wydajności.
 */
public class CommandHandler {

    // Stałe dla nazw komend
    private static final String COMMAND_LOGIN = "login";
    private static final String COMMAND_REGISTER = "register";
    @SuppressWarnings("java:S2068") // Not a password - this is a command name constant for user input
    private static final String COMMAND_CHANGE_PASSWORD = "changepassword"; // NOSONAR - Command name, not password
    private static final String COMMAND_UNREGISTER = "unregister";
    private static final String COMMAND_VAUTH = "vauth";

    // Stałe dla wiadomości
    private static final String ERROR_DATABASE_QUERY = "error.database.query";
    
    // Stałe dla formatowania
    private static final String CONFLICT_PREFIX = "   §7";

    // Markery SLF4J dla kategoryzowanego logowania
    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");
    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");

    private final VeloAuth plugin;
    private final DatabaseManager databaseManager;
    private final AuthCache authCache;
    private final Settings settings;
    private final Messages messages;
    private final Logger logger;
    private final net.rafalohaki.veloauth.i18n.SimpleMessages sm;

    /**
     * IP-based rate limiting - uses dedicated IPRateLimiter class.
     */
    private final IPRateLimiter ipRateLimiter;

    /**
     * Tworzy nowy CommandHandler.
     *
     * @param plugin          VeloAuth plugin instance
     * @param databaseManager Manager bazy danych
     * @param authCache       Cache autoryzacji
     * @param settings        Ustawienia pluginu
     * @param messages        System wiadomości (i18n)
     */
    public CommandHandler(VeloAuth plugin, DatabaseManager databaseManager,
                          AuthCache authCache, Settings settings, Messages messages) {
        this.plugin = plugin;
        this.databaseManager = databaseManager;
        this.authCache = authCache;
        this.settings = settings;
        this.messages = messages;
        this.logger = plugin.getLogger();
        this.ipRateLimiter = new IPRateLimiter(10, 5); // 10 attempts per 5 minutes
        this.sm = new net.rafalohaki.veloauth.i18n.SimpleMessages(messages);
    }

    /**
     * Rejestruje wszystkie komendy.
     */
    public void registerCommands() {
        var commandManager = plugin.getServer().getCommandManager();

        // Rejestracja komend gracza
        commandManager.register(commandManager.metaBuilder(COMMAND_LOGIN).aliases("log", "l").build(), new LoginCommand());
        commandManager.register(commandManager.metaBuilder(COMMAND_REGISTER).aliases("reg").build(), new RegisterCommand());
        commandManager.register(commandManager.metaBuilder(COMMAND_CHANGE_PASSWORD).build(), new ChangePasswordCommand());

        // Rejestracja komend administratora
        commandManager.register(commandManager.metaBuilder(COMMAND_UNREGISTER).build(), new UnregisterCommand());
        commandManager.register(commandManager.metaBuilder(COMMAND_VAUTH).build(), new VAuthCommand());

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("connection.commands.registered"));
        }
    }

    /**
     * Wyrejestrowuje wszystkie komendy.
     */
    public void unregisterCommands() {
        var commandManager = plugin.getServer().getCommandManager();

        commandManager.unregister(COMMAND_LOGIN);
        commandManager.unregister(COMMAND_REGISTER);
        commandManager.unregister(COMMAND_CHANGE_PASSWORD);
        commandManager.unregister(COMMAND_UNREGISTER);
        commandManager.unregister(COMMAND_VAUTH);

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("admin.commands_unregistered"));
        }
    }

    /**
     * Template method for common authentication pre-checks:
     * 1. Validate player source
     * 2. Check brute force protection
     * 3. Fetch player from database with error handling
     *
     * @param source      Command source
     * @param commandName Name of the command for logging
     * @return AuthenticationContext if all checks pass, null otherwise
     */
    private AuthenticationContext validateAndAuthenticatePlayer(CommandSource source, String commandName) {
        Player player = CommandHelper.validatePlayerSource(source, messages);
        if (player == null) {
            return null;
        }

        InetAddress playerAddress = PlayerAddressUtils.getPlayerAddress(player);

        // Check brute force protection
        if (playerAddress != null && authCache.isBlocked(playerAddress)) {
            player.sendMessage(sm.bruteForceBlocked());
            if (logger.isWarnEnabled()) {
                logger.warn(SECURITY_MARKER, "[BRUTE FORCE BLOCK] IP {} attempted {}", playerAddress.getHostAddress(), commandName);
            }
            return null;
        }

        // Fetch player from database
        String username = player.getUsername();
        var dbResult = databaseManager.findPlayerByNickname(username).join();

        if (handleDatabaseError(dbResult, player, commandName + " lookup for")) {
            return null;
        }

        RegisteredPlayer registeredPlayer = dbResult.getValue();
        return new AuthenticationContext(player, username, playerAddress, registeredPlayer);
    }

    /**
     * Template method for premium status checking with error handling.
     *
     * @param player    Player to check
     * @param operation Operation name for logging
     * @return DbResult<Boolean> with premium status, or error result
     */
    private DatabaseManager.DbResult<Boolean> checkPremiumStatus(Player player, String operation) {
        DatabaseManager.DbResult<Boolean> result = databaseManager.isPremium(player.getUsername()).join();
        if (result.isDatabaseError()) {
            if (logger.isErrorEnabled()) {
                logger.error(SECURITY_MARKER, "[DATABASE ERROR] {} failed for {}: {}", operation, player.getUsername(), result.getErrorMessage());
            }
            player.sendMessage(sm.errorDatabase());
        }
        return result;
    }

    /**
     * Handles database errors consistently across all commands.
     * Delegates to DatabaseErrorHandler utility for standardized error handling.
     *
     * @param result    Database result to check
     * @param player    Player to send error message to
     * @param operation Description of the operation being performed
     * @return true if there was a database error (handled), false if operation can continue
     */
    private boolean handleDatabaseError(DatabaseManager.DbResult<?> result, Player player, String operation) {
        return DatabaseErrorHandler.handleError(result, player, operation, logger, messages);
    }

    /**
         * Context object for authentication operations to reduce parameter passing.
         */
        private record AuthenticationContext(Player player, String username, InetAddress playerAddress,
                                             RegisteredPlayer registeredPlayer) {
    }

    /**
     * Resets brute-force and rate-limit counters for the given IP address.
     * Shared by LoginCommand and RegisterCommand on successful auth.
     */
    private void resetSecurityCounters(InetAddress playerAddress) {
        SecurityUtils.resetSecurityCounters(playerAddress, authCache, ipRateLimiter);
    }

    /**
     * Komenda /login <hasło>
     */
    private class LoginCommand implements SimpleCommand {

        @Override
        @SuppressWarnings("FutureReturnValueIgnored")
        public void execute(Invocation invocation) {
            CommandSource source = invocation.source();
            String[] args = invocation.arguments();

            if (args.length != 1) {
                source.sendMessage(sm.usageLogin());
                return;
            }

            String password = args[0];

            // Asynchroniczne logowanie z Virtual Threads
            CommandHelper.runAsyncCommand(() -> processLogin(source, password),
                    messages, source, ERROR_DATABASE_QUERY);
        }

        private void processLogin(CommandSource source, String password) {
            Player player = (Player) source;

            // Use template method for common checks
            AuthenticationContext authContext = validateAndAuthenticatePlayer(source, COMMAND_LOGIN);
            if (authContext == null) {
                return;
            }

            // Additional login-specific checks
            if (authCache.isPlayerAuthorized(player.getUniqueId(), PlayerAddressUtils.getPlayerIp(player))) {
                player.sendMessage(sm.alreadyLogged());
                return;
            }

            // Verify player is registered and has a password hash
            if (authContext.registeredPlayer == null) {
                player.sendMessage(sm.notRegistered());
                return;
            }
            String hash = authContext.registeredPlayer.getHash();
            if (hash == null || hash.isBlank()) {
                player.sendMessage(sm.notRegistered());
                return;
            }

            // Verify password
            BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), hash);

            if (result.verified) {
                handleSuccessfulLogin(authContext);
            } else {
                handleFailedLogin(authContext);
            }
        }

        private void handleSuccessfulLogin(AuthenticationContext authContext) {
            try {
                // Update login data
                authContext.registeredPlayer.updateLoginData(PlayerAddressUtils.getPlayerIp(authContext.player));
                var saveResult = databaseManager.savePlayer(authContext.registeredPlayer).join();

                if (handleDatabaseError(saveResult, authContext.player, "Failed to save login data for")) {
                    return;
                }

                // Check premium status using template
                var premiumResult = checkPremiumStatus(authContext.player, "Premium status check during login");
                if (premiumResult.isDatabaseError()) {
                    return;
                }

                boolean isPremium = Boolean.TRUE.equals(premiumResult.getValue());
                CachedAuthUser cachedUser = CachedAuthUser.fromRegisteredPlayer(authContext.registeredPlayer, isPremium);
                authCache.addAuthorizedPlayer(authContext.player.getUniqueId(), cachedUser);

                // Start session and reset security counters
                authCache.startSession(authContext.player.getUniqueId(), authContext.username, PlayerAddressUtils.getPlayerIp(authContext.player));
                resetSecurityCounters(authContext.playerAddress);

                authContext.player.sendMessage(sm.loginSuccess());
                if (logger.isDebugEnabled()) {
                    logger.debug(AUTH_MARKER, "Gracz {} zalogował się pomyślnie z IP {} - sesja rozpoczęta",
                            authContext.username, PlayerAddressUtils.getPlayerIp(authContext.player));
                }

                plugin.getConnectionManager().transferToBackend(authContext.player);

            } catch (Exception e) {
                if (logger.isErrorEnabled()) {
                    logger.error("Błąd podczas przetwarzania udanego logowania: {}", authContext.username, e);
                }
                sendDatabaseErrorMessage(authContext.player);
            }
        }

        private void handleFailedLogin(AuthenticationContext authContext) {
            boolean blocked = SecurityUtils.registerFailedLogin(authContext.playerAddress, authCache);

            if (blocked) {
                authContext.player.sendMessage(sm.bruteForceBlocked());
                if (logger.isWarnEnabled()) {
                    logger.warn("Gracz {} zablokowany za brute force z IP {}",
                            authContext.username, PlayerAddressUtils.getPlayerIp(authContext.player));
                }
            } else {
                authContext.player.sendMessage(sm.loginFailed());
                if (logger.isDebugEnabled()) {
                    logger.debug("Nieudana próba logowania gracza {} z IP {}",
                            authContext.username, PlayerAddressUtils.getPlayerIp(authContext.player));
                }
            }
        }
    }

    /**
     * Komenda /register <hasło> <powtórz>
     */
    private class RegisterCommand implements SimpleCommand {

        @Override
        @SuppressWarnings("FutureReturnValueIgnored")
        public void execute(Invocation invocation) {
            CommandSource source = invocation.source();
            String[] args = invocation.arguments();

            Player player = CommandHelper.validatePlayerSource(source, messages);
            if (player == null) {
                return;
            }

            ValidationUtils.ValidationResult validationResult = ValidationUtils.validateArgumentCount(args, 2, messages.get("auth.register.usage"));
            if (!validationResult.valid()) {
                player.sendMessage(ValidationUtils.createWarningComponent(validationResult.getErrorMessage()));
                return;
            }

            String password = args[0];
            String confirmPassword = args[1];

            // Validate passwords
            ValidationUtils.ValidationResult passwordValidation = ValidationUtils.validatePassword(password, settings);
            if (!passwordValidation.valid()) {
                player.sendMessage(ValidationUtils.createErrorComponent(passwordValidation.getErrorMessage()));
                return;
            }

            ValidationUtils.ValidationResult matchValidation = ValidationUtils.validatePasswordMatch(password, confirmPassword);
            if (!matchValidation.valid()) {
                player.sendMessage(ValidationUtils.createErrorComponent(matchValidation.getErrorMessage()));
                return;
            }

            // Asynchroniczna rejestracja z Virtual Threads
            CommandHelper.runAsyncCommandWithTimeout(() -> processRegistration(player, password),
                    messages, source, ERROR_DATABASE_QUERY, "auth.registration.timeout");
        }

        private void processRegistration(Player player, String password) {
            // Use template method for common checks
            AuthenticationContext authContext = validateAndAuthenticatePlayer(player, "registration");
            if (authContext == null) {
                return;
            }

            // Player already exists - template found them but registration should fail
            if (authContext.registeredPlayer != null) {
                authContext.player.sendMessage(sm.alreadyRegistered());
                return;
            }

            // Create new player
            String hashedPassword = BCrypt.with(BCrypt.Version.VERSION_2Y)
                    .hashToString(settings.getBcryptCost(), password.toCharArray());

            RegisteredPlayer newPlayer = new RegisteredPlayer(
                    authContext.username, hashedPassword,
                    PlayerAddressUtils.getPlayerIp(authContext.player),
                    authContext.player.getUniqueId().toString()
            );

            // Save to database
            var saveResult = databaseManager.savePlayer(newPlayer).join();
            if (handleDatabaseError(saveResult, authContext.player, "Failed to save new player")) {
                return;
            }

            boolean saved = Boolean.TRUE.equals(saveResult.getValue());
            if (!saved) {
                sendDatabaseErrorMessage(authContext.player);
                return;
            }

            // Check premium status using template
            var premiumResult = checkPremiumStatus(authContext.player, "Premium status check during registration");
            if (premiumResult.isDatabaseError()) {
                return;
            }

            boolean isPremium = Boolean.TRUE.equals(premiumResult.getValue());
            CachedAuthUser cachedUser = CachedAuthUser.fromRegisteredPlayer(newPlayer, isPremium);
            authCache.addAuthorizedPlayer(authContext.player.getUniqueId(), cachedUser);
            authCache.startSession(authContext.player.getUniqueId(), authContext.username, PlayerAddressUtils.getPlayerIp(authContext.player));

            // Reset security counters on success
            resetSecurityCounters(authContext.playerAddress);

            authContext.player.sendMessage(sm.registerSuccess());
            if (logger.isInfoEnabled()) {
                logger.info(AUTH_MARKER, "Gracz {} zarejestrowany pomyślnie z IP {}",
                        authContext.username, PlayerAddressUtils.getPlayerIp(authContext.player));
            }

            plugin.getConnectionManager().transferToBackend(authContext.player);
        }
    }

    /**
     * Komenda /changepassword <stare> <nowe>
     */
    private class ChangePasswordCommand implements SimpleCommand {

        @Override
        @SuppressWarnings("FutureReturnValueIgnored")
        public void execute(Invocation invocation) {
            CommandSource source = invocation.source();
            String[] args = invocation.arguments();

            Player player = CommandHelper.validatePlayerSource(source, messages);
            if (player == null) {
                return;
            }

            ValidationUtils.ValidationResult validationResult = ValidationUtils.validateArgumentCount(args, 2, messages.get("auth.changepassword.usage"));
            if (!validationResult.valid()) {
                player.sendMessage(ValidationUtils.createWarningComponent(validationResult.getErrorMessage()));
                return;
            }

            String oldPassword = args[0];
            String newPassword = args[1];

            // Validate new password
            ValidationUtils.ValidationResult passwordValidation = ValidationUtils.validatePassword(newPassword, settings);
            if (!passwordValidation.valid()) {
                player.sendMessage(ValidationUtils.createErrorComponent(passwordValidation.getErrorMessage()));
                return;
            }

            // Asynchroniczna zmiana hasła z Virtual Threads
            CommandHelper.runAsyncCommand(() -> processPasswordChange(player, oldPassword, newPassword),
                    messages, source, ERROR_DATABASE_QUERY);
        }

        private void processPasswordChange(Player player, String oldPassword, String newPassword) {
            AuthenticationContext ctx = preparePasswordChange(player);
            if (ctx == null) {
                return;
            }

            if (!checkOldPassword(ctx, oldPassword)) {
                return;
            }

            if (!updatePassword(ctx, newPassword)) {
                return;
            }

            finalizePasswordChange(ctx);
        }

        private AuthenticationContext preparePasswordChange(Player player) {
            AuthenticationContext ctx = validateAndAuthenticatePlayer(player, "password change");
            if (ctx == null) {
                return null;
            }
            if (ctx.registeredPlayer == null) {
                ctx.player.sendMessage(sm.notRegistered());
                return null;
            }
            return ctx;
        }

        private boolean checkOldPassword(AuthenticationContext ctx, String oldPassword) {
            BCrypt.Result result = BCrypt.verifyer().verify(oldPassword.toCharArray(), ctx.registeredPlayer.getHash());
            if (!result.verified) {
                ctx.player.sendMessage(sm.incorrectOldPassword());
                return false;
            }
            return true;
        }

        private boolean updatePassword(AuthenticationContext ctx, String newPassword) {
            String newHashedPassword = BCrypt.with(BCrypt.Version.VERSION_2Y)
                    .hashToString(settings.getBcryptCost(), newPassword.toCharArray());
            ctx.registeredPlayer.setHash(newHashedPassword);
            var saveResult = databaseManager.savePlayer(ctx.registeredPlayer).join();
            if (handleDatabaseError(saveResult, ctx.player, "Password change save failed for")) {
                return false;
            }
            boolean saved = Boolean.TRUE.equals(saveResult.getValue());
            if (!saved) {
                sendDatabaseErrorMessage(ctx.player);
                return false;
            }
            return true;
        }

        private void finalizePasswordChange(AuthenticationContext ctx) {
            var premiumResult = checkPremiumStatus(ctx.player, "Premium check during password change");
            if (!premiumResult.isDatabaseError() && Boolean.TRUE.equals(premiumResult.getValue())) {
                authCache.removePremiumPlayer(ctx.username);
            }
            authCache.endSession(ctx.player.getUniqueId());
            plugin.getServer().getAllPlayers().stream()
                    .filter(p -> !p.equals(ctx.player))
                    .filter(p -> p.getUsername().equalsIgnoreCase(ctx.username))
                    .forEach(p -> {
                        p.disconnect(sm.kickMessage());
                        if (logger.isWarnEnabled()) {
                            logger.warn("Rozłączono duplikat gracza {} - zmiana hasła z IP {}",
                                    ctx.username, PlayerAddressUtils.getPlayerIp(ctx.player));
                        }
                    });
            ctx.player.sendMessage(sm.changePasswordSuccess());
            if (logger.isInfoEnabled()) {
                logger.info(AUTH_MARKER, "Gracz {} zmienił hasło z IP {}",
                        ctx.username, PlayerAddressUtils.getPlayerIp(ctx.player));
            }
        }
    }

    /**
     * Komenda /unregister <nickname> - tylko dla admina
     * Usuwa konto gracza z bazy danych.
     */
    private class UnregisterCommand implements SimpleCommand {

        @Override
        @SuppressWarnings("FutureReturnValueIgnored")
        public void execute(Invocation invocation) {
            CommandSource source = invocation.source();
            String[] args = invocation.arguments();

            if (!CommandHelper.checkAdminPermission(source, messages)) {
                return;
            }

            if (args.length != 1) {
                CommandHelper.sendError(source, messages, "admin.unregister.usage");
                return;
            }

            String nickname = args[0];

            // Asynchroniczne usuwanie konta z Virtual Threads
            CommandHelper.runAsyncCommand(() -> processAdminUnregistration(source, nickname),
                    messages, source, ERROR_DATABASE_QUERY);
        }

        private void processAdminUnregistration(CommandSource source, String nickname) {
            try {
                // Find player in database
                var dbResult = databaseManager.findPlayerByNickname(nickname).join();

                if (handleDatabaseError(dbResult, source, nickname, "Admin unregistration failed for")) {
                    return;
                }

                RegisteredPlayer registeredPlayer = dbResult.getValue();
                if (registeredPlayer == null) {
                    source.sendMessage(ValidationUtils.createErrorComponent(messages.get("admin.player_not_found", nickname)));
                    return;
                }

                // Parse UUID and remove from auth cache
                UUID playerUuid = parsePlayerUuid(registeredPlayer, nickname, source);
                if (playerUuid == null) {
                    return;
                }

                // Delete from database
                var deleteResult = databaseManager.deletePlayer(nickname).join();

                if (handleDatabaseError(deleteResult, source, nickname, "Admin unregistration delete failed for")) {
                    return;
                }

                boolean deleted = Boolean.TRUE.equals(deleteResult.getValue());
                if (deleted) {
                    // Clean up cache and disconnect player
                    authCache.removeAuthorizedPlayer(playerUuid);
                    authCache.endSession(playerUuid);
                    authCache.removePremiumPlayer(nickname);

                    plugin.getServer().getPlayer(nickname).ifPresent(player -> {
                        player.disconnect(sm.kickMessage());
                        logger.info("Rozłączono gracza {} - usunięcie konta przez admina", nickname);
                    });

                    CommandHelper.sendSuccess(source, messages.get("admin.account_deleted", nickname));
                    String adminName = source instanceof Player player ? player.getUsername() : "CONSOLE";
                    logger.info(AUTH_MARKER, "Administrator {} usunął konto gracza {}", adminName, nickname);

                } else {
                    CommandHelper.sendError(source, messages, ERROR_DATABASE_QUERY);
                    logger.error(DB_MARKER, "Nie udało się usunąć konta gracza {} przez admina", nickname);
                }

            } catch (Exception e) {
                logger.error(DB_MARKER, "Błąd podczas admin-usuwania konta gracza: {}", nickname, e);
                CommandHelper.sendError(source, messages, ERROR_DATABASE_QUERY);
            }
        }

        private boolean handleDatabaseError(DatabaseManager.DbResult<?> result, CommandSource source, String nickname, String operation) {
            return DatabaseErrorHandler.handleError(result, source, nickname, operation, logger, messages);
        }

        private UUID parsePlayerUuid(RegisteredPlayer registeredPlayer, String nickname, CommandSource source) {
            try {
                return UUID.fromString(registeredPlayer.getUuid());
            } catch (IllegalArgumentException e) {
                logger.warn("Nieprawidłowy UUID dla gracza {}: {}", nickname, registeredPlayer.getUuid());
                source.sendMessage(ValidationUtils.createErrorComponent(messages.get("admin.uuid_invalid")));
                return null;
            }
        }
    }

    /**
     * Komenda /vauth - komendy administratora
     */
    private class VAuthCommand implements SimpleCommand {

        @Override
        public void execute(Invocation invocation) {
            CommandSource source = invocation.source();
            String[] args = invocation.arguments();

            if (!CommandHelper.checkAdminPermission(source, messages)) {
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
                default -> source.sendMessage(sm.adminReloadFailed());
            }
        }
        
        private void handleReloadCommand(CommandSource source) {
            boolean success = plugin.reloadConfig();
            if (success) {
                source.sendMessage(sm.adminReloadSuccess());
            } else {
                source.sendMessage(sm.adminReloadFailed());
            }
        }
        
        private void handleConflictsCommand(CommandSource source) {
            source.sendMessage(ValidationUtils.createWarningComponent(messages.get("admin.conflicts.header")));
            var conflictsFuture = databaseManager.findPlayersInConflictMode();
            var conflicts = conflictsFuture.join();
            
            if (conflicts.isEmpty()) {
                source.sendMessage(ValidationUtils.createSuccessComponent(messages.get("admin.conflicts.none")));
                return;
            }
            
            source.sendMessage(ValidationUtils.createWarningComponent(
                messages.get("admin.conflicts.found", conflicts.size())));
            
            for (int i = 0; i < conflicts.size(); i++) {
                RegisteredPlayer conflict = conflicts.get(i);
                StringBuilder conflictInfo = new StringBuilder();
                conflictInfo.append("§e").append(i + 1).append(". §f").append(conflict.getNickname()).append("\n");
                conflictInfo.append(CONFLICT_PREFIX).append(messages.get("admin.conflicts.uuid", conflict.getUuid())).append("\n");
                conflictInfo.append(CONFLICT_PREFIX).append(messages.get("admin.conflicts.ip", conflict.getIp())).append("\n");
                
                // Show conflict timestamp if available
                long conflictTime = conflict.getConflictTimestamp();
                if (conflictTime > 0) {
                    long hoursAgo = (System.currentTimeMillis() - conflictTime) / (1000 * 60 * 60);
                    conflictInfo.append(CONFLICT_PREFIX).append(messages.get("admin.conflicts.hours_ago", hoursAgo)).append("\n");
                }
                
                // Show original nickname if different
                if (conflict.getOriginalNickname() != null && 
                    !conflict.getOriginalNickname().equals(conflict.getNickname())) {
                    conflictInfo.append(CONFLICT_PREFIX).append(messages.get("admin.conflicts.original_nick", conflict.getOriginalNickname())).append("\n");
                }
                
                // Show premium status using runtime detection
                boolean isPremium = databaseManager.isPlayerPremiumRuntime(conflict);
                String statusKey = isPremium ? "admin.conflicts.status_premium" : "admin.conflicts.status_offline";
                conflictInfo.append(CONFLICT_PREFIX).append(messages.get(statusKey)).append("\n");
                
                source.sendMessage(ValidationUtils.createWarningComponent(conflictInfo.toString()));
            }
            
            source.sendMessage(ValidationUtils.createWarningComponent(""));
            source.sendMessage(ValidationUtils.createWarningComponent(messages.get("admin.conflicts.tips_header")));
            source.sendMessage(ValidationUtils.createWarningComponent(messages.get("admin.conflicts.tip_premium")));
            source.sendMessage(ValidationUtils.createWarningComponent(messages.get("admin.conflicts.tip_offline")));
            source.sendMessage(ValidationUtils.createWarningComponent(messages.get("admin.conflicts.tip_admin")));
        }
        
        private void handleCacheResetCommand(CommandSource source, String[] args) {
            if (args.length == 2) {
                String nickname = args[1];
                plugin.getServer().getPlayer(nickname).ifPresentOrElse(
                        player -> {
                            authCache.removeAuthorizedPlayer(player.getUniqueId());
                            source.sendMessage(ValidationUtils.createSuccessComponent(messages.get("admin.cache_reset.player", nickname)));
                        },
                        () -> source.sendMessage(ValidationUtils.createErrorComponent(messages.get("admin.cache_reset.player_not_found", nickname)))
                );
            } else {
                authCache.clearAll();
                source.sendMessage(ValidationUtils.createSuccessComponent(messages.get("admin.cache_reset.success")));
            }
        }
        
        private void handleStatsCommand(CommandSource source) {
            var totalF = databaseManager.getTotalRegisteredAccounts();
            var premiumF = databaseManager.getTotalPremiumAccounts();
            var nonPremiumF = databaseManager.getTotalNonPremiumAccounts();

            // Wait for all database operations to complete
            java.util.concurrent.CompletableFuture.allOf(totalF, premiumF, nonPremiumF).join();
            int total = totalF.join();
            int premium = premiumF.join();
            int nonPremium = nonPremiumF.join();
            double pct = total > 0 ? (premium * 100.0 / total) : 0.0;

            // Get cache stats AFTER database operations complete
            var cacheStats = authCache.getStats();
            int dbCacheSize = databaseManager.getCacheSize();
            String dbStatus = databaseManager.isConnected() ? messages.get("database.connected") : messages.get("database.disconnected");

            // Build complete stats message in fixed order
            StringBuilder statsMessage = new StringBuilder();
            statsMessage.append(messages.get("admin.stats.header")).append("\n");
            statsMessage.append(messages.get("admin.stats.premium_accounts", premium)).append("\n");
            statsMessage.append(messages.get("admin.stats.nonpremium_accounts", nonPremium)).append("\n");
            statsMessage.append(messages.get("admin.stats.total_accounts", total)).append("\n");
            statsMessage.append(messages.get("admin.stats.premium_percentage", pct)).append("\n");
            statsMessage.append(messages.get("admin.stats.authorized_players", cacheStats.authorizedPlayersCount())).append("\n");
            statsMessage.append(messages.get("admin.stats.premium_cache", cacheStats.premiumCacheCount())).append("\n");
            statsMessage.append(messages.get("admin.stats.database_cache", dbCacheSize)).append("\n");
            statsMessage.append(messages.get("admin.stats.database_status", (Object) dbStatus));

            // Send complete message as single component
            CommandHelper.sendWarning(source, statsMessage.toString());
        }

        private void sendAdminHelp(CommandSource source) {
            source.sendMessage(sm.adminHelpHeader());
            source.sendMessage(sm.adminHelpReload());
            source.sendMessage(sm.adminHelpCache());
            source.sendMessage(sm.adminHelpStats());
            source.sendMessage(sm.adminHelpConflicts());
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

    /**
     * Sends a database error message to the player.
     * Extracted method to reduce code duplication.
     *
     * @param player Player to send the message to
     */
    private void sendDatabaseErrorMessage(Player player) {
        player.sendMessage(ValidationUtils.createErrorComponent(messages.get(ERROR_DATABASE_QUERY)));
    }

}
