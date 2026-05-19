package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;

import java.util.concurrent.CompletableFuture;

/**
 * Utility class for common command operations to reduce duplication.
 * Provides reusable methods for validation, messaging, and async execution.
 */
public final class CommandHelper {

    private static final String MSG_KEY_SERVER_SHUTTING_DOWN = "system.shutting_down";
    private static final String MSG_KEY_SERVER_OVERLOADED = "system.overloaded";

    private CommandHelper() {
        // Utility class - prevent instantiation
    }

    /**
     * Validates that command source is a player and returns the player instance.
     *
     * @param source   Command source to validate
     * @param messages Messages for error reporting
     * @return Player instance if valid, null if invalid (error already sent)
     */
    public static Player validatePlayerSource(CommandSource source, Messages messages) {
        if (!(source instanceof Player player)) {
            source.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.player_only")));
            return null;
        }
        return player;
    }

    /**
     * Player-source + argument-count validation bundled into one call. Returns the player and
     * args when both checks pass; returns {@code null} when either fails (an error message has
     * already been sent to the source). Consolidates the boilerplate that every player command
     * used to copy at the top of its {@code execute}.
     */
    public static CommandInputs requirePlayerAndArgs(
            SimpleCommand.Invocation invocation, Messages messages, int requiredArgs, String usageKey) {
        Player player = validatePlayerSource(invocation.source(), messages);
        if (player == null) {
            return null;
        }
        String[] args = invocation.arguments();
        if (args.length != requiredArgs) {
            player.sendMessage(ValidationUtils.createWarningComponent(messages.get(usageKey)));
            return null;
        }
        return new CommandInputs(player, args);
    }

    /**
     * Player-source check + at-least-one-arg requirement. Used by commands that dispatch on
     * a subcommand keyword (e.g. {@code /2fa setup}).
     */
    public static CommandInputs requirePlayerWithAtLeastOneArg(
            SimpleCommand.Invocation invocation, Messages messages,
            net.kyori.adventure.text.Component usageMessage) {
        Player player = validatePlayerSource(invocation.source(), messages);
        if (player == null) {
            return null;
        }
        String[] args = invocation.arguments();
        if (args.length == 0) {
            player.sendMessage(usageMessage);
            return null;
        }
        return new CommandInputs(player, args);
    }

    /**
     * Carrier for the result of {@link #requirePlayerAndArgs(SimpleCommand.Invocation, Messages, int, String)}
     * — keeps the (player, args) pair as one return value so callers don't repeat the early-return guard.
     */
    public record CommandInputs(Player player, String[] args) { }

    /**
     * {@link SimpleCommand#hasPermission} helper for commands that should only be reachable
     * while the player is parked on the auth limbo. Console always returns {@code true}.
     */
    public static boolean isPlayerOnAuthServer(SimpleCommand.Invocation invocation, CommandContext ctx) {
        if (!(invocation.source() instanceof Player player)) {
            return true;
        }
        return ctx.plugin().getConnectionManager().isPlayerOnAuthServer(player);
    }

    /**
     * {@link SimpleCommand#hasPermission} helper for commands that require an already-authorized
     * player (e.g. {@code /changepassword}). Console always returns {@code true}.
     */
    public static boolean isPlayerAuthorized(SimpleCommand.Invocation invocation, CommandContext ctx) {
        if (!(invocation.source() instanceof Player player)) {
            return true;
        }
        return ctx.authCache().isPlayerAuthorized(
                player.getUniqueId(), PlayerAddressUtils.getPlayerIp(player));
    }

    /**
     * Runs {@link ValidationUtils#validatePassword} and short-circuits the caller with a player
     * error message when the password is rejected.
     *
     * @return {@code true} when the password passes policy; {@code false} after sending the error.
     */
    public static boolean requireValidPassword(
            Player player, String password, Settings settings, Messages messages) {
        ValidationUtils.ValidationResult result =
                ValidationUtils.validatePassword(password, settings, messages);
        if (!result.valid()) {
            player.sendMessage(ValidationUtils.createErrorComponent(result.getErrorMessage()));
            return false;
        }
        return true;
    }

    /**
     * Runs {@link ValidationUtils#validatePasswordMatch} and short-circuits the caller with a
     * player error message when the two passwords disagree.
     */
    public static boolean requirePasswordsMatch(
            Player player, String password, String confirm, Messages messages) {
        ValidationUtils.ValidationResult result =
                ValidationUtils.validatePasswordMatch(password, confirm, messages);
        if (!result.valid()) {
            player.sendMessage(ValidationUtils.createErrorComponent(result.getErrorMessage()));
            return false;
        }
        return true;
    }

    /**
     * Admin-permission gate bundled with the {@code (source, args)} unpack. Returns the inputs
     * when {@code source} holds {@code veloauth.admin}; returns {@code null} after sending the
     * standard permission error otherwise. Pairs with {@link AdminCommandInputs}.
     */
    public static AdminCommandInputs requireAdmin(
            SimpleCommand.Invocation invocation, Messages messages) {
        CommandSource source = invocation.source();
        if (!checkAdminPermission(source, messages)) {
            return null;
        }
        return new AdminCommandInputs(source, invocation.arguments());
    }

    /** Carrier for {@link #requireAdmin}. */
    public record AdminCommandInputs(CommandSource source, String[] args) { }

    /**
     * Convenience wrapper: gate by admin permission, then run {@code body} with the unpacked
     * {@code (source, args)}. Callers that need the typical "permission check → bail on null →
     * unpack inputs" boilerplate use this directly instead of repeating those 6-7 lines.
     */
    public static void runAsAdmin(SimpleCommand.Invocation invocation, Messages messages,
                                  java.util.function.BiConsumer<CommandSource, String[]> body) {
        AdminCommandInputs inputs = requireAdmin(invocation, messages);
        if (inputs == null) {
            return;
        }
        body.accept(inputs.source(), inputs.args());
    }

    /**
     * Checks if source has admin permission and sends error message if not.
     *
     * @param source   Command source to check
     * @param messages Messages for error reporting
     * @return true if has permission, false if not (error already sent)
     */
    public static boolean checkAdminPermission(CommandSource source, Messages messages) {
        if (!source.hasPermission("veloauth.admin")) {
            source.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.permission")));
            return false;
        }
        return true;
    }

    /**
     * Sends an error message to the command source.
     *
     * @param source  Command source to send message to
     * @param message Error message to send
     */
    public static void sendError(CommandSource source, String message) {
        source.sendMessage(ValidationUtils.createErrorComponent(message));
    }

    /**
     * Sends a localized error message to the command source.
     *
     * @param source   Command source to send message to
     * @param messages Messages for localization
     * @param key      Message key to localize
     */
    public static void sendError(CommandSource source, Messages messages, String key) {
        source.sendMessage(ValidationUtils.createErrorComponent(messages.get(key)));
    }

    /**
     * Sends a success message to the command source.
     *
     * @param source  Command source to send message to
     * @param message Success message to send
     */
    public static void sendSuccess(CommandSource source, String message) {
        source.sendMessage(ValidationUtils.createSuccessComponent(message));
    }

    /**
     * Sends a localized success message to the command source.
     *
     * @param source   Command source to send message to
     * @param messages Messages for localization
     * @param key      Message key to localize
     */
    public static void sendSuccess(CommandSource source, Messages messages, String key) {
        source.sendMessage(ValidationUtils.createSuccessComponent(messages.get(key)));
    }

    /**
     * Sends a warning message to the command source.
     *
     * @param source  Command source to send message to
     * @param message Warning message to send
     */
    public static void sendWarning(CommandSource source, String message) {
        source.sendMessage(ValidationUtils.createWarningComponent(message));
    }

    /**
     * Handles async command exceptions (PMD CPD fix - extracted duplicate error handling).
     *
     * @param throwable Exception that occurred
     * @param source    Command source for error messages
     * @param messages  Messages for error reporting
     * @param errorKey  Message key for database errors
     */
    private static void handleAsyncCommandException(Throwable throwable, CommandSource source, 
                                                     Messages messages, String errorKey) {
        if (throwable instanceof java.util.concurrent.RejectedExecutionException) {
            source.sendMessage(ValidationUtils.createErrorComponent(messages.get(MSG_KEY_SERVER_OVERLOADED)));
        } else {
            source.sendMessage(ValidationUtils.createErrorComponent(messages.get(errorKey)));
        }
    }

    /**
     * Executes a command asynchronously with standard exception handling.
     *
     * @param task     Command task to execute
     * @param messages Messages for error reporting
     * @param source   Command source for error messages
     * @param errorKey Message key for database errors
     */
    public static void runAsyncCommand(Runnable task, Messages messages,
                                       CommandSource source, String errorKey) {
        // Check if executor is shutting down
        if (VirtualThreadExecutorProvider.isShutdown()) {
            source.sendMessage(ValidationUtils.createErrorComponent(messages.get(MSG_KEY_SERVER_SHUTTING_DOWN)));
            return;
        }

        try {
            // skipcq: JAVA-W1087 - Future handled with exceptionally, fire-and-forget operation
            CompletableFuture.runAsync(task, VirtualThreadExecutorProvider.getVirtualExecutor())
                    .exceptionally(throwable -> {
                        handleAsyncCommandException(throwable, source, messages, errorKey);
                        return null;
                    });
        } catch (java.util.concurrent.RejectedExecutionException e) {
            source.sendMessage(ValidationUtils.createErrorComponent(messages.get(MSG_KEY_SERVER_SHUTTING_DOWN)));
        }
    }

    /**
     * Executes a command asynchronously with timeout and standard exception handling.
     *
     * @param task       Command task to execute
     * @param messages   Messages for error reporting
     * @param source     Command source for error messages
     * @param errorKey   Message key for database errors
     * @param timeoutKey Message key for timeout errors
     */
    public static void runAsyncCommandWithTimeout(Runnable task, Messages messages,
                                                  CommandSource source, String errorKey, String timeoutKey) {
        // Check if executor is shutting down
        if (VirtualThreadExecutorProvider.isShutdown()) {
            source.sendMessage(ValidationUtils.createErrorComponent(messages.get(MSG_KEY_SERVER_SHUTTING_DOWN)));
            return;
        }

        try {
            // skipcq: JAVA-W1087 - Future handled with exceptionally, fire-and-forget operation
            CompletableFuture.runAsync(task, VirtualThreadExecutorProvider.getVirtualExecutor())
                    .orTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
                    .exceptionally(throwable -> {
                        if (throwable instanceof java.util.concurrent.TimeoutException) {
                            source.sendMessage(ValidationUtils.createErrorComponent(messages.get(timeoutKey)));
                        } else {
                            handleAsyncCommandException(throwable, source, messages, errorKey);
                        }
                        return null;
                    });
        } catch (java.util.concurrent.RejectedExecutionException e) {
            source.sendMessage(ValidationUtils.createErrorComponent(messages.get(MSG_KEY_SERVER_SHUTTING_DOWN)));
        }
    }
}
