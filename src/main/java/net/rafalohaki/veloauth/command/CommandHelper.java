package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.i18n.Messages;
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
