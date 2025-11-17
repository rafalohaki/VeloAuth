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
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Handler komend autoryzacji VeloAuth.
 * Obsługuje /login, /register, /changepassword z BCrypt hashing i thread-safety.
 * <p>
 * Wszystkie operacje są asynchroniczne z Virtual Threads dla wydajności.
 */
public class CommandHandler {

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
        commandManager.register(commandManager.metaBuilder("login").aliases("log", "l").build(), new LoginCommand());
        commandManager.register(commandManager.metaBuilder("register").aliases("reg", "r").build(), new RegisterCommand());
        commandManager.register(commandManager.metaBuilder("changepassword").build(), new ChangePasswordCommand());

        // Rejestracja komend administratora
        commandManager.register(commandManager.metaBuilder("unregister").build(), new UnregisterCommand());
        commandManager.register(commandManager.metaBuilder("vauth").build(), new VAuthCommand());

        logger.info("Komendy zarejestrowane: /login, /register, /changepassword (gracze), /unregister (admin), /vauth (admin)");
    }

    /**
     * Wyrejestrowuje wszystkie komendy.
     */
    public void unregisterCommands() {
        var commandManager = plugin.getServer().getCommandManager();

        commandManager.unregister("login");
        commandManager.unregister("register");
        commandManager.unregister("changepassword");
        commandManager.unregister("unregister");
        commandManager.unregister("vauth");

        logger.info("Komendy wyrejestrowane");
    }

    /**
     * Resets security counters (brute force and IP rate limiter) for successful authentication.
     * Centralized utility to avoid code duplication across login/registration flows.
     */
    private void resetSecurityCounters(InetAddress playerAddress) {
        if (playerAddress != null) {
            authCache.resetLoginAttempts(playerAddress);
            ipRateLimiter.reset(playerAddress);
        }
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

            if (!(source instanceof Player player)) {
                source.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.ONLY_PLAYERS));
                return;
            }

            if (args.length != 1) {
                player.sendMessage(ValidationUtils.createWarningComponent(CommandMessages.LOGIN_USAGE));
                return;
            }

            String password = args[0];

            // Sprawdź IP-based rate limiting PRZED sprawdzeniem autoryzacji
            InetAddress playerAddress = ValidationUtils.getPlayerAddress(player);
            if (playerAddress != null && ipRateLimiter.isRateLimited(playerAddress)) {
                player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.RATE_LIMITED_LOGIN));
                logger.warn(SECURITY_MARKER, "IP {} zablokowany za rate limiting ({} prób w 5 min)",
                        playerAddress.getHostAddress(), ipRateLimiter.getAttempts(playerAddress));
                return;
            }
            if (playerAddress != null) {
                ipRateLimiter.incrementAttempts(playerAddress);
            }

            // Sprawdź czy gracz już jest autoryzowany
            if (authCache.isPlayerAuthorized(player.getUniqueId(), ValidationUtils.getPlayerIp(player))) {
                player.sendMessage(ValidationUtils.createSuccessComponent(CommandMessages.ALREADY_LOGGED_IN));
                return;
            }

            // Sprawdź brute force
            if (playerAddress != null && authCache.isBlocked(playerAddress)) {
                player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.BRUTE_FORCE_BLOCKED_GENERIC));
                return;
            }

            // Asynchroniczne logowanie z Virtual Threads
            // skipcq: JAVA-W1087 - Future handled with exceptionally, fire-and-forget operation
            CompletableFuture.runAsync(() -> processLogin(player, password, playerAddress),
                            VirtualThreadExecutorProvider.getVirtualExecutor())
                    .exceptionally(throwable -> {
                        logger.error("Błąd podczas asynchronicznego logowania gracza: " + player.getUsername(), throwable);
                        player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                        return null;
                    });
        }

        private void processLogin(Player player, String password, InetAddress playerAddress) {
            try {
                String lowercaseNick = player.getUsername().toLowerCase();

                // Znajdź gracza w bazie danych
                var dbResult = databaseManager.findPlayerByNickname(lowercaseNick).join();
                
                // CRITICAL: Fail-secure on database errors
                if (dbResult.isDatabaseError()) {
                    logger.error(SECURITY_MARKER, "[DATABASE ERROR] Login failed for {}: {}", 
                            player.getUsername(), dbResult.getErrorMessage());
                    player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                    return;
                }

                RegisteredPlayer registeredPlayer = dbResult.getValue();
                if (registeredPlayer == null) {
                    player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.NOT_REGISTERED));
                    return;
                }

                // Weryfikacja hasła z BCrypt
                BCrypt.Result result = BCrypt.verifyer().verify(password.toCharArray(), registeredPlayer.getHash());

                if (result.verified) {
                    // Sukces logowania
                    handleSuccessfulLogin(player, registeredPlayer, playerAddress);
                } else {
                    // Nieudane logowanie
                    handleFailedLogin(player, playerAddress);
                }

            } catch (Exception e) {
                logger.error(DB_MARKER, "Błąd podczas logowania gracza: " + player.getUsername(), e);
                player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.LOGIN_ERROR));
            }
        }

        private void handleSuccessfulLogin(Player player, RegisteredPlayer registeredPlayer, InetAddress playerAddress) {
            try {
                // Aktualizuj dane logowania
                registeredPlayer.updateLoginData(ValidationUtils.getPlayerIp(player));
                var saveResult = databaseManager.savePlayer(registeredPlayer).join();
                
                // CRITICAL: Fail-secure on database errors
                if (saveResult.isDatabaseError()) {
                    logger.error(SECURITY_MARKER, "[DATABASE ERROR] Failed to save login data for {}: {}", 
                            player.getUsername(), saveResult.getErrorMessage());
                    player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                    return;
                }
                
                if (!saveResult.getValue()) {
                    logger.error(DB_MARKER, "Nie udało się zapisać danych logowania dla gracza: {}", player.getUsername());
                    player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                    return;
                }

                // Dodaj do cache autoryzacji
                var premiumResult = databaseManager.isPremium(player.getUsername()).join();
                
                // CRITICAL: Fail-secure on database errors
                if (premiumResult.isDatabaseError()) {
                    logger.error(SECURITY_MARKER, "[DATABASE ERROR] Failed to check premium status for {}: {}", 
                            player.getUsername(), premiumResult.getErrorMessage());
                    player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                    return;
                }
                
                boolean isPremium = premiumResult.getValue();
                CachedAuthUser cachedUser = CachedAuthUser.fromRegisteredPlayer(registeredPlayer, isPremium);
                authCache.addAuthorizedPlayer(player.getUniqueId(), cachedUser);

                // NOWOŚĆ: Rozpocznij aktywną sesję - zapobiega session hijacking
                authCache.startSession(player.getUniqueId(), player.getUsername(), ValidationUtils.getPlayerIp(player));

                // Resetuj próby brute force i IP rate limiter po sukcesie
                resetSecurityCounters(playerAddress);

                player.sendMessage(ValidationUtils.createSuccessComponent(CommandMessages.LOGIN_SUCCESS));
                logger.info(AUTH_MARKER, "Gracz {} zalogował się pomyślnie z IP {} - sesja rozpoczęta",
                        player.getUsername(), ValidationUtils.getPlayerIp(player));

                // Transfer na backend server
                plugin.getConnectionManager().transferToBackend(player);

            } catch (Exception e) {
                logger.error("Błąd podczas przetwarzania udanego logowania: " + player.getUsername(), e);
                player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.GENERIC_ERROR));
            }
        }

        private void handleFailedLogin(Player player, InetAddress playerAddress) {
            // Zarejestruj nieudaną próbę
            boolean blocked = false;
            if (playerAddress != null) {
                blocked = authCache.registerFailedLogin(playerAddress);
            }

            if (blocked) {
                player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.BRUTE_FORCE_BLOCKED));
                logger.warn("Gracz {} zablokowany za brute force z IP {}",
                        player.getUsername(), ValidationUtils.getPlayerIp(player));
            } else {
                player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.INVALID_PASSWORD));
                logger.debug("Nieudana próba logowania gracza {} z IP {}",
                        player.getUsername(), ValidationUtils.getPlayerIp(player));
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

            if (!(source instanceof Player player)) {
                source.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.ONLY_PLAYERS));
                return;
            }

            ValidationUtils.ValidationResult validationResult = ValidationUtils.validateArgumentCount(args, 2, CommandMessages.REGISTER_USAGE);
            if (!validationResult.valid()) {
                player.sendMessage(ValidationUtils.createWarningComponent(validationResult.getErrorMessage()));
                return;
            }

            String password = args[0];
            String confirmPassword = args[1];

            // Sprawdź IP-based rate limiting dla rejestracji
            InetAddress playerAddress = ValidationUtils.getPlayerAddress(player);
            if (playerAddress != null && ipRateLimiter.isRateLimited(playerAddress)) {
                player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.RATE_LIMITED_REGISTER));
                logger.warn("IP {} zablokowany za rate limiting podczas rejestracji ({} prób)",
                        playerAddress.getHostAddress(), ipRateLimiter.getAttempts(playerAddress));
                return;
            }
            if (playerAddress != null) {
                ipRateLimiter.incrementAttempts(playerAddress);
            }

            // Walidacja hasła
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
            // skipcq: JAVA-W1087 - Future handled with exceptionally, fire-and-forget operation
            CompletableFuture.runAsync(() -> processRegistration(player, password),
                            VirtualThreadExecutorProvider.getVirtualExecutor())
                    .orTimeout(30, TimeUnit.SECONDS)
                    .exceptionally(throwable -> {
                        if (throwable instanceof java.util.concurrent.TimeoutException) {
                            logger.error("Timeout during registration for {}", player.getUsername());
                            player.sendMessage(ValidationUtils.createErrorComponent("Timeout rejestracji - spróbuj ponownie"));
                        } else {
                            logger.error("Błąd podczas asynchronicznej rejestracji gracza: " + player.getUsername(), throwable);
                            player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                        }
                        return null;
                    });
        }

        private void processRegistration(Player player, String password) {
            InetAddress playerAddress = ValidationUtils.getPlayerAddress(player);

            // DODATKOWE SPRAWDZENIE BRUTE FORCE dla rejestracji
            if (playerAddress != null && authCache.isBlocked(playerAddress)) {
                player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.BRUTE_FORCE_BLOCKED_GENERIC));
                logger.warn(SECURITY_MARKER, "[BRUTE FORCE BLOCK] IP {} próbował rejestracji",
                        playerAddress.getHostAddress());
                return;
            }

            try {
                String lowercaseNick = player.getUsername().toLowerCase();

                // Uruchom wszystko w transakcji dla atomowości
                // skipcq: JAVA-W1087 - Future handled with whenComplete, fire-and-forget operation
                databaseManager.executeInTransaction(() -> {
                    // 1. Sprawdź czy gracz już istnieje
                    var existingResult = databaseManager.findPlayerByNickname(lowercaseNick).join();
                    
                    // CRITICAL: Fail-secure on database errors
                    if (existingResult.isDatabaseError()) {
                        logger.error(SECURITY_MARKER, "[DATABASE ERROR] Registration check failed for {}: {}", 
                                player.getUsername(), existingResult.getErrorMessage());
                        player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                        return false;
                    }

                    RegisteredPlayer existingPlayer = existingResult.getValue();
                    if (existingPlayer != null) {
                        player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.ALREADY_REGISTERED));
                        return false;
                    }

                    // 2. Stwórz nowego gracza z hashem BCrypt
                    String hashedPassword = BCrypt.with(BCrypt.Version.VERSION_2Y)
                            .hashToString(settings.getBcryptCost(), password.toCharArray());

                    RegisteredPlayer newPlayer = new RegisteredPlayer(
                            player.getUsername(),
                            hashedPassword,
                            ValidationUtils.getPlayerIp(player),
                            player.getUniqueId().toString()
                    );

                    // 3. Zapisz do bazy danych
                    var saveResult = databaseManager.savePlayer(newPlayer).join();
                    
                    // CRITICAL: Fail-secure on database errors
                    if (saveResult.isDatabaseError()) {
                        logger.error(SECURITY_MARKER, "[DATABASE ERROR] Failed to save new player {}: {}", 
                                player.getUsername(), saveResult.getErrorMessage());
                        player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                        return false;
                    }
                    
                    if (!saveResult.getValue()) {
                        player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.REGISTER_ERROR));
                        logger.error(DB_MARKER, "Nie udało się zapisać nowego gracza: {}", lowercaseNick);
                        return false;
                    }

                    // 4. Resetuj próby brute force przy sukcesie
                    if (playerAddress != null) {
                        authCache.resetLoginAttempts(playerAddress);
                        ipRateLimiter.reset(playerAddress);
                    }

                    player.sendMessage(ValidationUtils.createSuccessComponent(CommandMessages.REGISTER_SUCCESS));
                    logger.info(AUTH_MARKER, "Gracz {} zarejestrował się z IP {}",
                            player.getUsername(), ValidationUtils.getPlayerIp(player));

                    // 5. Auto-login po rejestracji - dodaj do cache autoryzacji
                    var premiumResult = databaseManager.isPremium(player.getUsername()).join();
                    
                    // CRITICAL: Fail-secure on database errors
                    if (premiumResult.isDatabaseError()) {
                        logger.error(SECURITY_MARKER, "[DATABASE ERROR] Failed to check premium status for {}: {}", 
                                player.getUsername(), premiumResult.getErrorMessage());
                        player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                        return false;
                    }
                    
                    boolean isPremium = premiumResult.getValue();
                    CachedAuthUser cachedUser = CachedAuthUser.fromRegisteredPlayer(newPlayer, isPremium);
                    authCache.addAuthorizedPlayer(player.getUniqueId(), cachedUser);
                    authCache.startSession(player.getUniqueId(), player.getUsername(), ValidationUtils.getPlayerIp(player));

                    // 6. Transfer na backend server (poza transakcją)
                    plugin.getConnectionManager().transferToBackend(player);

                    return true;

                }).whenComplete((success, throwable) -> {
                    if (throwable != null) {
                        logger.error("Błąd transakcji rejestracji: " + player.getUsername(), throwable);
                        player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.REGISTER_ERROR));
                    }
                });

            } catch (Exception e) {
                logger.error(DB_MARKER, "Błąd podczas rejestracji gracza: " + player.getUsername(), e);
                player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.REGISTER_ERROR));
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

            if (!(source instanceof Player player)) {
                source.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.ONLY_PLAYERS));
                return;
            }

            ValidationUtils.ValidationResult validationResult = ValidationUtils.validateArgumentCount(args, 2, CommandMessages.CHANGE_PASSWORD_USAGE);
            if (!validationResult.valid()) {
                player.sendMessage(ValidationUtils.createWarningComponent(validationResult.getErrorMessage()));
                return;
            }

            String oldPassword = args[0];
            String newPassword = args[1];

            // Walidacja nowego hasła
            ValidationUtils.ValidationResult passwordValidation = ValidationUtils.validatePassword(newPassword, settings);
            if (!passwordValidation.valid()) {
                player.sendMessage(ValidationUtils.createErrorComponent(passwordValidation.getErrorMessage()));
                return;
            }

            // Asynchroniczna zmiana hasła z Virtual Threads
            // skipcq: JAVA-W1087 - Future handled with exceptionally, fire-and-forget operation
            CompletableFuture.runAsync(() -> processPasswordChange(player, oldPassword, newPassword),
                            VirtualThreadExecutorProvider.getVirtualExecutor())
                    .exceptionally(throwable -> {
                        logger.error("Błąd podczas asynchronicznej zmiany hasła gracza: " + player.getUsername(), throwable);
                        player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                        return null;
                    });
        }

        private void processPasswordChange(Player player, String oldPassword, String newPassword) {
            InetAddress playerAddress = ValidationUtils.getPlayerAddress(player);

            // DODATKOWE SPRAWDZENIE BRUTE FORCE dla zmiany hasła
            if (playerAddress != null && authCache.isBlocked(playerAddress)) {
                player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.BRUTE_FORCE_BLOCKED_GENERIC));
                logger.warn(SECURITY_MARKER, "[BRUTE FORCE BLOCK] IP {} próbował zmienić hasło",
                        playerAddress.getHostAddress());
                return;
            }

            try {
                String lowercaseNick = player.getUsername().toLowerCase();

                // Znajdź gracza w bazie danych
                var dbResult = databaseManager.findPlayerByNickname(lowercaseNick).join();
                
                // CRITICAL: Fail-secure on database errors
                if (dbResult.isDatabaseError()) {
                    logger.error(SECURITY_MARKER, "[DATABASE ERROR] Password change failed for {}: {}", 
                            player.getUsername(), dbResult.getErrorMessage());
                    player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                    return;
                }
                
                RegisteredPlayer registeredPlayer = dbResult.getValue();
                if (registeredPlayer == null) {
                    player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.NOT_REGISTERED));
                    return;
                }

                // Weryfikacja starego hasła z BCrypt
                BCrypt.Result result = BCrypt.verifyer().verify(oldPassword.toCharArray(), registeredPlayer.getHash());

                if (!result.verified) {
                    player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.INVALID_OLD_PASSWORD));
                    return;
                }

                // Hash nowego hasła z BCrypt
                String newHashedPassword = BCrypt.with(BCrypt.Version.VERSION_2Y)
                        .hashToString(settings.getBcryptCost(), newPassword.toCharArray());

                // Aktualizuj hasło
                registeredPlayer.setHash(newHashedPassword);
                registeredPlayer.updateLoginData(ValidationUtils.getPlayerIp(player));

                // Zapisz do bazy danych
                var saveResult = databaseManager.savePlayer(registeredPlayer).join();
                
                // CRITICAL: Fail-secure on database errors
                if (saveResult.isDatabaseError()) {
                    logger.error(SECURITY_MARKER, "[DATABASE ERROR] Password change save failed for {}: {}", 
                            player.getUsername(), saveResult.getErrorMessage());
                    player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                    return;
                }
                
                boolean saved = saveResult.getValue();

                if (saved) {
                    // WAŻNE: Usuń z cache NATYCHMIAST dla bezpieczeństwa
                    authCache.removeAuthorizedPlayer(player.getUniqueId());

                    // Zakończ sesję przy zmianie hasła
                    authCache.endSession(player.getUniqueId());

                    // Jeśli gracz ma premium, sprawdź status i usuń z premium cache
                    var premiumCheckResult = databaseManager.isPremium(player.getUsername()).join();
                    
                    // CRITICAL: Fail-secure on database errors
                    if (premiumCheckResult.isDatabaseError()) {
                        logger.error(SECURITY_MARKER, "[DATABASE ERROR] Premium check failed during password change for {}: {}", 
                                player.getUsername(), premiumCheckResult.getErrorMessage());
                        // Continue with password change even if premium check fails
                    } else if (premiumCheckResult.getValue()) {
                        authCache.removePremiumPlayer(player.getUsername());
                        logger.debug("Usunięto premium status cache dla: {}", player.getUsername());
                    }

                    // Rozłącz wszystkie duplikaty tego gracza
                    plugin.getServer().getAllPlayers().stream()
                            .filter(p -> !p.equals(player))
                            .filter(p -> p.getUsername().equalsIgnoreCase(lowercaseNick))
                            .forEach(p -> {
                                p.disconnect(ValidationUtils.createWarningComponent(CommandMessages.PASSWORD_CHANGED_DISCONNECT));
                                logger.warn("Rozłączono duplikat gracza {} - zmiana hasła z IP {}",
                                        lowercaseNick, ValidationUtils.getPlayerIp(player));
                            });

                    player.sendMessage(ValidationUtils.createSuccessComponent(CommandMessages.PASSWORD_CHANGED_SUCCESS));
                    logger.info(AUTH_MARKER, "Gracz {} zmienił hasło z IP {}",
                            player.getUsername(), ValidationUtils.getPlayerIp(player));

                } else {
                    player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.PASSWORD_CHANGE_ERROR));
                    logger.error(DB_MARKER, "Nie udało się zapisać nowego hasła dla gracza {}", player.getUsername());
                }

            } catch (Exception e) {
                logger.error(DB_MARKER, "Błąd podczas zmiany hasła gracza: " + player.getUsername(), e);
                player.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.PASSWORD_CHANGE_ERROR));
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

            // Sprawdzenie uprawnień administratora
            if (!source.hasPermission("veloauth.admin")) {
                source.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.UNREGISTER_ADMIN_ONLY));
                return;
            }

            // Walidacja argumentów - wymagany nickname
            if (args.length != 1) {
                source.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.UNREGISTER_USAGE));
                return;
            }

            String nickname = args[0];

            // Asynchroniczne usuwanie konta z Virtual Threads
            // skipcq: JAVA-W1087 - Future handled with exceptionally, fire-and-forget operation
            CompletableFuture.runAsync(() -> processAdminUnregistration(source, nickname),
                            VirtualThreadExecutorProvider.getVirtualExecutor())
                    .exceptionally(throwable -> {
                        logger.error("Błąd podczas asynchronicznego usuwania konta gracza: " + nickname, throwable);
                        source.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.UNREGISTER_ERROR));
                        return null;
                    });
        }

        private void processAdminUnregistration(CommandSource source, String nickname) {
            try {
                String lowercaseNick = nickname.toLowerCase();

                // Znajdź gracza w bazie danych
                var dbResult = databaseManager.findPlayerByNickname(lowercaseNick).join();
                
                // CRITICAL: Fail-secure on database errors
                if (dbResult.isDatabaseError()) {
                    logger.error(SECURITY_MARKER, "[DATABASE ERROR] Admin unregistration failed for {}: {}", 
                            nickname, dbResult.getErrorMessage());
                    source.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                    return;
                }
                
                RegisteredPlayer registeredPlayer = dbResult.getValue();
                if (registeredPlayer == null) {
                    source.sendMessage(ValidationUtils.createErrorComponent("Gracz " + nickname + " nie został znaleziony w bazie danych!"));
                    return;
                }

                // Pobierz UUID z RegisteredPlayer do operacji cache
                UUID playerUuid;
                try {
                    playerUuid = UUID.fromString(registeredPlayer.getUuid());
                } catch (IllegalArgumentException e) {
                    logger.warn("Nieprawidłowy UUID dla gracza {}: {}", nickname, registeredPlayer.getUuid());
                    source.sendMessage(ValidationUtils.createErrorComponent("Błąd: nieprawidłowy UUID gracza!"));
                    return;
                }

                // Usuń z bazy danych (bez weryfikacji hasła - admin ma pełne uprawnienia)
                var deleteResult = databaseManager.deletePlayer(lowercaseNick).join();
                
                // CRITICAL: Fail-secure on database errors
                if (deleteResult.isDatabaseError()) {
                    logger.error(SECURITY_MARKER, "[DATABASE ERROR] Admin unregistration delete failed for {}: {}", 
                            nickname, deleteResult.getErrorMessage());
                    source.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
                    return;
                }
                
                boolean deleted = deleteResult.getValue();

                if (deleted) {
                    // Usuń z cache autoryzacji używając UUID
                    authCache.removeAuthorizedPlayer(playerUuid);
                    authCache.endSession(playerUuid);
                    
                    // Usuń z premium cache jeśli był
                    authCache.removePremiumPlayer(nickname);

                    // Rozłącz gracza jeśli jest online
                    plugin.getServer().getPlayer(nickname).ifPresent(player -> {
                        player.disconnect(ValidationUtils.createErrorComponent(CommandMessages.ACCOUNT_DELETED_DISCONNECT));
                        logger.info("Rozłączono gracza {} - usunięcie konta przez admina", nickname);
                    });

                    source.sendMessage(ValidationUtils.createSuccessComponent("Konto gracza " + nickname + " zostało usunięte!"));
                    logger.info(AUTH_MARKER, "Administrator {} usunął konto gracza {}", 
                            source instanceof Player ? ((Player) source).getUsername() : "CONSOLE", nickname);

                } else {
                    source.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.UNREGISTER_ERROR));
                    logger.error(DB_MARKER, "Nie udało się usunąć konta gracza {} przez admina", nickname);
                }

            } catch (Exception e) {
                logger.error(DB_MARKER, "Błąd podczas admin-usuwania konta gracza: " + nickname, e);
                source.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.UNREGISTER_ERROR));
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

            if (!source.hasPermission("veloauth.admin")) {
                source.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.NO_PERMISSION));
                return;
            }

            if (args.length == 0) {
                sendAdminHelp(source);
                return;
            }

            String subcommand = args[0].toLowerCase();

            switch (subcommand) {
                case "reload" -> {
                    boolean success = plugin.reloadConfig();
                    if (success) {
                        source.sendMessage(ValidationUtils.createSuccessComponent(CommandMessages.CONFIG_RELOAD_SUCCESS));
                    } else {
                        source.sendMessage(ValidationUtils.createErrorComponent(CommandMessages.CONFIG_RELOAD_ERROR));
                    }
                }
                case "cache-reset" -> {
                    if (args.length == 2) {
                        String nickname = args[1];
                        // Znajdź gracza i usuń z cache
                        plugin.getServer().getPlayer(nickname).ifPresentOrElse(
                                player -> {
                                    authCache.removeAuthorizedPlayer(player.getUniqueId());
                                    source.sendMessage(ValidationUtils.createSuccessComponent(String.format(CommandMessages.CACHE_RESET_PLAYER, nickname)));
                                },
                                () -> source.sendMessage(ValidationUtils.createErrorComponent(String.format(CommandMessages.PLAYER_NOT_ONLINE, nickname)))
                        );
                    } else {
                        authCache.clearAll();
                        source.sendMessage(ValidationUtils.createSuccessComponent(CommandMessages.CACHE_RESET_ALL));
                    }
                }
                case "stats" -> {
                    var stats = authCache.getStats();
                    source.sendMessage(ValidationUtils.createWarningComponent(CommandMessages.STATS_HEADER));
                    source.sendMessage(ValidationUtils.createWarningComponent(String.format(CommandMessages.STATS_AUTHORIZED_PLAYERS, stats.authorizedPlayersCount())));
                    source.sendMessage(ValidationUtils.createWarningComponent(String.format(CommandMessages.STATS_BRUTE_FORCE_ENTRIES, stats.bruteForceEntriesCount())));
                    source.sendMessage(ValidationUtils.createWarningComponent(String.format(CommandMessages.STATS_PREMIUM_CACHE, stats.premiumCacheCount())));
                    source.sendMessage(ValidationUtils.createWarningComponent(String.format(CommandMessages.STATS_CACHE_HIT_RATE, stats.cacheHits(), stats.cacheMisses(), stats.getHitRate())));
                    source.sendMessage(ValidationUtils.createWarningComponent(String.format(CommandMessages.STATS_TOTAL_REQUESTS, stats.getTotalRequests())));
                    source.sendMessage(ValidationUtils.createWarningComponent(String.format(CommandMessages.STATS_DATABASE_CONNECTED, databaseManager.isConnected() ? "Połączona" : "Rozłączona")));
                    source.sendMessage(ValidationUtils.createWarningComponent(String.format(CommandMessages.STATS_DATABASE_CACHE, databaseManager.getCacheSize())));
                }
                default -> sendAdminHelp(source);
            }
        }

        private void sendAdminHelp(CommandSource source) {
            source.sendMessage(ValidationUtils.createWarningComponent(CommandMessages.ADMIN_HELP_HEADER));
            source.sendMessage(ValidationUtils.createWarningComponent(CommandMessages.ADMIN_HELP_RELOAD));
            source.sendMessage(ValidationUtils.createWarningComponent(CommandMessages.ADMIN_HELP_CACHE_RESET));
            source.sendMessage(ValidationUtils.createWarningComponent(CommandMessages.ADMIN_HELP_STATS));
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
