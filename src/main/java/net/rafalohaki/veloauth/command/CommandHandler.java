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
    private static final String COMMAND_CHANGE_PASSWORD = "changepassword";
    private static final String COMMAND_UNREGISTER = "unregister";
    private static final String COMMAND_VAUTH = "vauth";

    // Stałe dla wiadomości
    private static final String ERROR_DATABASE_QUERY = "error.database.query";

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
    }

    /**
     * Rejestruje wszystkie komendy.
     */
    public void registerCommands() {
        var commandManager = plugin.getServer().getCommandManager();

        // Rejestracja komend gracza
        commandManager.register(commandManager.metaBuilder(COMMAND_LOGIN).aliases("log", "l").build(), new LoginCommand());
        commandManager.register(commandManager.metaBuilder(COMMAND_REGISTER).aliases("reg", "r").build(), new RegisterCommand());
        commandManager.register(commandManager.metaBuilder(COMMAND_CHANGE_PASSWORD).build(), new ChangePasswordCommand());

        // Rejestracja komend administratora
        commandManager.register(commandManager.metaBuilder(COMMAND_UNREGISTER).build(), new UnregisterCommand());
        commandManager.register(commandManager.metaBuilder(COMMAND_VAUTH).build(), new VAuthCommand());

        if (logger.isInfoEnabled()) {
            logger.info(messages.get("connection.commands.registered"));
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

        if (logger.isInfoEnabled()) {
            logger.info("Komendy wyrejestrowane");
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

        InetAddress playerAddress = ValidationUtils.getPlayerAddress(player);

        // Check brute force protection
        if (playerAddress != null && authCache.isBlocked(playerAddress)) {
            player.sendMessage(ValidationUtils.createErrorComponent(messages.get("security.brute_force.blocked")));
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
        var premiumResult = databaseManager.isPremium(player.getUsername()).join();

        if (premiumResult.isDatabaseError()) {
            if (logger.isErrorEnabled()) {
                logger.error(SECURITY_MARKER, "[DATABASE ERROR] {} failed for {}: {}", operation, player.getUsername(), premiumResult.getErrorMessage());
            }
            player.sendMessage(ValidationUtils.createErrorComponent(messages.get(ERROR_DATABASE_QUERY)));
        }

        return premiumResult;
    }

    /**
     * Handles database errors consistently across all commands.
     *
     * @param result    Database result to check
     * @param player    Player to send error message to
     * @param operation Description of the operation being performed
     * @return true if there was a database error (handled), false if operation can continue
     */
    private boolean handleDatabaseError(DatabaseManager.DbResult<?> result, Player player, String operation) {
        if (result.isDatabaseError()) {
            if (logger.isErrorEnabled()) {
                logger.error(SECURITY_MARKER, "[DATABASE ERROR] {} failed for {}: {}", operation, player.getUsername(), result.getErrorMessage());
            }
            player.sendMessage(ValidationUtils.createErrorComponent(messages.get(ERROR_DATABASE_QUERY)));
            return true;
        }
        return false;
    }

    /**
         * Context object for authentication operations to reduce parameter passing.
         */
        private record AuthenticationContext(Player player, String username, InetAddress playerAddress,
                                             RegisteredPlayer registeredPlayer) {
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
                CommandHelper.sendError(source, messages, "auth.login.usage");
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
            if (authCache.isPlayerAuthorized(player.getUniqueId(), ValidationUtils.getPlayerIp(player))) {
                player.sendMessage(ValidationUtils.createSuccessComponent(messages.get("auth.login.already_logged_in")));
                return;
            }

            // Verify password
            BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), authContext.registeredPlayer.getHash());

            if (result.verified) {
                handleSuccessfulLogin(authContext);
            } else {
                handleFailedLogin(authContext);
            }
        }

        private void handleSuccessfulLogin(AuthenticationContext authContext) {
            try {
                // Update login data
                authContext.registeredPlayer.updateLoginData(ValidationUtils.getPlayerIp(authContext.player));
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
                authCache.startSession(authContext.player.getUniqueId(), authContext.username, ValidationUtils.getPlayerIp(authContext.player));
                resetSecurityCounters(authContext.playerAddress);

                authContext.player.sendMessage(ValidationUtils.createSuccessComponent(messages.get("auth.login.success")));
                if (logger.isInfoEnabled()) {
                    logger.info(AUTH_MARKER, "Gracz {} zalogował się pomyślnie z IP {} - sesja rozpoczęta",
                            authContext.username, ValidationUtils.getPlayerIp(authContext.player));
                }

                plugin.getConnectionManager().transferToBackend(authContext.player);

            } catch (Exception e) {
                if (logger.isErrorEnabled()) {
                    logger.error("Błąd podczas przetwarzania udanego logowania: {}", authContext.username, e);
                }
                authContext.player.sendMessage(ValidationUtils.createErrorComponent(messages.get(ERROR_DATABASE_QUERY)));
            }
        }

        private void handleFailedLogin(AuthenticationContext authContext) {
            boolean blocked = false;
            if (authContext.playerAddress != null) {
                blocked = authCache.registerFailedLogin(authContext.playerAddress);
            }

            if (blocked) {
                authContext.player.sendMessage(ValidationUtils.createErrorComponent(messages.get("security.brute_force.blocked")));
                if (logger.isWarnEnabled()) {
                    logger.warn("Gracz {} zablokowany za brute force z IP {}",
                            authContext.username, ValidationUtils.getPlayerIp(authContext.player));
                }
            } else {
                authContext.player.sendMessage(ValidationUtils.createErrorComponent(messages.get("auth.login.incorrect_password")));
                if (logger.isDebugEnabled()) {
                    logger.debug("Nieudana próba logowania gracza {} z IP {}",
                            authContext.username, ValidationUtils.getPlayerIp(authContext.player));
                }
            }
        }

        private void resetSecurityCounters(InetAddress playerAddress) {
            if (playerAddress != null) {
                authCache.resetLoginAttempts(playerAddress);
                ipRateLimiter.reset(playerAddress);
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
                authContext.player.sendMessage(ValidationUtils.createErrorComponent(messages.get("auth.register.already_registered")));
                return;
            }

            // Create new player
            String hashedPassword = BCrypt.with(BCrypt.Version.VERSION_2Y)
                    .hashToString(settings.getBcryptCost(), password.toCharArray());

            RegisteredPlayer newPlayer = new RegisteredPlayer(
                    authContext.username, hashedPassword,
                    ValidationUtils.getPlayerIp(authContext.player),
                    authContext.player.getUniqueId().toString()
            );

            // Save to database
            var saveResult = databaseManager.savePlayer(newPlayer).join();
            if (handleDatabaseError(saveResult, authContext.player, "Failed to save new player")) {
                return;
            }

            boolean saved = Boolean.TRUE.equals(saveResult.getValue());
            if (!saved) {
                authContext.player.sendMessage(ValidationUtils.createErrorComponent(messages.get(ERROR_DATABASE_QUERY)));
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
            authCache.startSession(authContext.player.getUniqueId(), authContext.username, ValidationUtils.getPlayerIp(authContext.player));

            // Reset security counters on success
            resetSecurityCounters(authContext.playerAddress);

            authContext.player.sendMessage(ValidationUtils.createSuccessComponent(messages.get("auth.register.success")));
            if (logger.isInfoEnabled()) {
                logger.info(AUTH_MARKER, "Gracz {} zarejestrowany pomyślnie z IP {}",
                        authContext.username, ValidationUtils.getPlayerIp(authContext.player));
            }

            plugin.getConnectionManager().transferToBackend(authContext.player);
        }

        private void resetSecurityCounters(InetAddress playerAddress) {
            if (playerAddress != null) {
                authCache.resetLoginAttempts(playerAddress);
                ipRateLimiter.reset(playerAddress);
            }
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
            // Use template method for common checks
            AuthenticationContext authContext = validateAndAuthenticatePlayer(player, "password change");
            if (authContext == null) {
                return;
            }

            // Player must exist for password change
            if (authContext.registeredPlayer == null) {
                authContext.player.sendMessage(ValidationUtils.createErrorComponent(messages.get("auth.login.not_registered")));
                return;
            }

            // Verify old password
            BCrypt.Result result = BCrypt.verifyer().verify(oldPassword.toCharArray(), authContext.registeredPlayer.getHash());
            if (!result.verified) {
                authContext.player.sendMessage(ValidationUtils.createErrorComponent(messages.get("auth.changepassword.incorrect_old_password")));
                return;
            }

            // Hash and update password
            String newHashedPassword = BCrypt.with(BCrypt.Version.VERSION_2Y)
                    .hashToString(settings.getBcryptCost(), newPassword.toCharArray());

            authContext.registeredPlayer.setHash(newHashedPassword);
            var saveResult = databaseManager.savePlayer(authContext.registeredPlayer).join();

            if (handleDatabaseError(saveResult, authContext.player, "Password change save failed for")) {
                return;
            }

            boolean saved = Boolean.TRUE.equals(saveResult.getValue());
            if (!saved) {
                authContext.player.sendMessage(ValidationUtils.createErrorComponent(messages.get(ERROR_DATABASE_QUERY)));
                return;
            }

            // Handle premium status and session cleanup
            var premiumResult = checkPremiumStatus(authContext.player, "Premium check during password change");
            if (!premiumResult.isDatabaseError() && Boolean.TRUE.equals(premiumResult.getValue())) {
                authCache.removePremiumPlayer(authContext.username);
            }

            // End current session and disconnect duplicates
            authCache.endSession(authContext.player.getUniqueId());
            plugin.getServer().getAllPlayers().stream()
                    .filter(p -> !p.equals(authContext.player))
                    .filter(p -> p.getUsername().equalsIgnoreCase(authContext.username))
                    .forEach(p -> {
                        p.disconnect(ValidationUtils.createWarningComponent(messages.get("general.kick.message")));
                        if (logger.isWarnEnabled()) {
                            logger.warn("Rozłączono duplikat gracza {} - zmiana hasła z IP {}",
                                    authContext.username, ValidationUtils.getPlayerIp(authContext.player));
                        }
                    });

            authContext.player.sendMessage(ValidationUtils.createSuccessComponent(messages.get("auth.changepassword.success")));
            if (logger.isInfoEnabled()) {
                logger.info(AUTH_MARKER, "Gracz {} zmienił hasło z IP {}",
                        authContext.username, ValidationUtils.getPlayerIp(authContext.player));
            }
        }
    }

    /**
     * Komenda /unregister <nickname> - tylko dla admina
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
                    source.sendMessage(ValidationUtils.createErrorComponent("Gracz " + nickname + " nie został znaleziony w bazie danych!"));
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
                        player.disconnect(ValidationUtils.createErrorComponent(messages.get("general.kick.message")));
                        logger.info("Rozłączono gracza {} - usunięcie konta przez admina", nickname);
                    });

                    CommandHelper.sendSuccess(source, "Konto gracza " + nickname + " zostało usunięte!");
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
            if (result.isDatabaseError()) {
                logger.error(SECURITY_MARKER, "[DATABASE ERROR] {} {}: {}",
                        operation, nickname, result.getErrorMessage());
                CommandHelper.sendError(source, messages, ERROR_DATABASE_QUERY);
                return true;
            }
            return false;
        }

        private UUID parsePlayerUuid(RegisteredPlayer registeredPlayer, String nickname, CommandSource source) {
            try {
                return UUID.fromString(registeredPlayer.getUuid());
            } catch (IllegalArgumentException e) {
                logger.warn("Nieprawidłowy UUID dla gracza {}: {}", nickname, registeredPlayer.getUuid());
                source.sendMessage(ValidationUtils.createErrorComponent("Błąd: nieprawidłowy UUID gracza!"));
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
                default -> sendAdminHelp(source);
            }
        }
        
        private void handleReloadCommand(CommandSource source) {
            boolean success = plugin.reloadConfig();
            if (success) {
                source.sendMessage(ValidationUtils.createSuccessComponent(messages.get("admin.reload.success")));
            } else {
                source.sendMessage(ValidationUtils.createErrorComponent(messages.get("admin.reload.failed")));
            }
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
            CommandHelper.sendWarning(source, "=== VeloAuth Admin ===");
            CommandHelper.sendWarning(source, "/vauth reload - Reload configuration");
            CommandHelper.sendWarning(source, "/vauth cache-reset [player] - Clear cache");
            CommandHelper.sendWarning(source, "/vauth stats - Show statistics");
        }

        @Override
        public List<String> suggest(Invocation invocation) {
            String[] args = invocation.arguments();

            if (args.length == 1) {
                return List.of("reload", "cache-reset", "stats");
            }

            return List.of();
        }
    }

}
