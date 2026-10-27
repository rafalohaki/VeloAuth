package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.auth.totp.PendingTotpState;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;

import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Consumer;
import javax.annotation.Nullable;

/**
 * Entry point used by the dialog (GUI) authentication flow.
 *
 * <p>Instead of re-implementing authentication, every method here invokes the exact code path
 * of the corresponding chat command ({@link LoginCommand#processLogin},
 * {@link RegisterCommand#processRegistration}, {@link TwoFactorCommand#processVerify}). Those
 * paths report their outcome to the player through {@link Messages}; the bridge captures those
 * messages on the calling thread and turns the end state (authorized, 2FA pending, failed) into a
 * {@link Result} the dialog layer can render.
 *
 * <p>All methods block (database + BCrypt) and must be called from a virtual thread, never from
 * a Netty event loop.
 */
public final class DialogAuthBridge {

    /** Outcome of a bridged authentication attempt. */
    public enum Outcome { SUCCESS, TOTP_REQUIRED, FAILED }

    /**
     * @param outcome  final state after the attempt
     * @param messageKey localization key of the most relevant player message (may be null)
     * @param messageArgs arguments for {@code messageKey}
     * @param message already-rendered message in the proxy default language (may be null)
     */
    public record Result(Outcome outcome, String messageKey, Object[] messageArgs, Component message) {
        public static Result failed(String key) {
            return new Result(Outcome.FAILED, key, new Object[0], null);
        }
    }

    private static final String KEY_GENERIC = "connection.error.generic";

    private final CommandContext ctx;
    private final LoginCommand loginCommand;
    private final RegisterCommand registerCommand;
    private final TwoFactorCommand twoFactorCommand;

    DialogAuthBridge(CommandContext ctx) {
        this.ctx = ctx;
        this.loginCommand = new LoginCommand(ctx);
        this.registerCommand = new RegisterCommand(ctx);
        this.twoFactorCommand = new TwoFactorCommand(ctx);
    }

    /** Looks the player up to decide between the login and the register form. */
    public Optional<Boolean> isRegistered(Player player) {
        try {
            DatabaseManager.DbResult<?> result =
                    ctx.databaseManager().findPlayerByNickname(player.getUsername()).join();
            if (result == null || result.isDatabaseError()) {
                return Optional.empty();
            }
            return Optional.of(result.getValue() != null);
        } catch (RuntimeException e) {
            ctx.logger().error("Database error while preparing dialog for {}", player.getUsername(), e);
            return Optional.empty();
        }
    }

    public Settings.PasswordSettings passwordSettings() {
        return ctx.settings().captureOperationSettings().password();
    }

    /** Runs the /login pipeline with the given password. */
    public Result login(Player player, String password) {
        return runCaptured(player, operation -> loginCommand.processLogin(player, password, operation));
    }

    /** Runs a chat-command pipeline as the player and classifies the messages it produced. */
    private Result runCaptured(Player player, Consumer<ConnectionLifecycleRegistry.Operation> pipeline) {
        ConnectionLifecycleRegistry.Operation operation = ctx.captureConnectionOperation(player);
        if (operation == null) {
            return Result.failed(KEY_GENERIC);
        }
        Messages.beginCapture();
        List<Messages.CapturedMessage> captured;
        try {
            ctx.messages().runAsPlayer(player, () -> pipeline.accept(operation));
        } finally {
            captured = Messages.endCapture();
        }
        return classify(player, captured);
    }

    /** Runs the /register pipeline (validation + persistence + post-auth flow). */
    public Result register(Player player, String password, String confirm) {
        Settings.PasswordSettings passwordSettings = passwordSettings();
        Result rejected = precheckPassword(password, confirm, passwordSettings);
        if (rejected != null) {
            return rejected;
        }
        return runCaptured(player, operation -> {
            if (CommandHelper.requireValidPassword(player, password, passwordSettings, ctx.messages())
                    && CommandHelper.requirePasswordsMatch(player, password, confirm, ctx.messages())) {
                registerCommand.processRegistration(player, password, operation, passwordSettings,
                        new DatabaseManager.RegistrationCommitPermit());
            }
        });
    }

    /**
     * Cheap pre-checks with re-localizable keys so the dialog can show them in the player's own
     * language; the full validator in the register pipeline remains authoritative.
     */
    @Nullable
    private static Result precheckPassword(String password, String confirm, Settings.PasswordSettings passwordSettings) {
        if (password == null || password.isEmpty()) {
            return Result.failed("validation.password.empty");
        }
        if (password.length() < passwordSettings.minLength()) {
            return new Result(Outcome.FAILED, "validation.password.too_short",
                    new Object[] {passwordSettings.minLength()}, null);
        }
        if (password.length() > passwordSettings.maxLength()) {
            return new Result(Outcome.FAILED, "validation.password.too_long",
                    new Object[] {passwordSettings.maxLength()}, null);
        }
        if (!password.equals(confirm)) {
            return Result.failed("validation.password.mismatch");
        }
        return null;
    }

    /** Runs the /2fa verify pipeline for a pending post-password login. */
    public Result verifyTotp(Player player, String code) {
        String[] args = {"verify", code == null ? "" : code.trim()};
        return runCaptured(player, operation -> twoFactorCommand.processVerify(player, args, operation));
    }

    /** Whether the player is fully authorized with a live session. */
    public boolean isAuthenticated(Player player) {
        UUID uuid = player.getUniqueId();
        String ip = PlayerAddressUtils.getPlayerIp(player);
        return ctx.authCache().isPlayerAuthorized(uuid, ip)
                && ctx.authCache().hasActiveSession(uuid, player.getUsername(), ip);
    }

    /** Whether a password check already passed and the account now waits for a TOTP code. */
    public boolean isTotpPending(Player player) {
        return ctx.pendingTotpStore().get(player.getUniqueId())
                .map(state -> state.kind() == PendingTotpState.Kind.LOGIN)
                .orElse(false);
    }

    private Result classify(Player player, List<Messages.CapturedMessage> captured) {
        if (isAuthenticated(player)) {
            Messages.CapturedMessage last = lastOrNull(captured);
            return new Result(Outcome.SUCCESS,
                    last != null ? last.key() : null,
                    last != null ? last.args() : new Object[0],
                    last != null ? last.component() : null);
        }
        if (isTotpPending(player)) {
            return new Result(Outcome.TOTP_REQUIRED, "2fa.login.pending_prompt", new Object[0], null);
        }
        Messages.CapturedMessage last = lastOrNull(captured);
        if (last == null) {
            return Result.failed(KEY_GENERIC);
        }
        return new Result(Outcome.FAILED, last.key(), last.args(), last.component());
    }

    private static Messages.CapturedMessage lastOrNull(List<Messages.CapturedMessage> captured) {
        if (captured == null || captured.isEmpty()) {
            return null;
        }
        // Prefer the last message with a known key (re-localizable), else the last message.
        for (int index = captured.size() - 1; index >= 0; index--) {
            if (captured.get(index).key() != null) {
                return captured.get(index);
            }
        }
        return captured.get(captured.size() - 1);
    }

    /** Convenience for the dialog layer: render a captured result in the player's language. */
    public Component render(Result result, String language, NamedTextColor color) {
        if (result.messageKey() != null) {
            return ctx.messages().componentForLanguage(language, result.messageKey(), color, result.messageArgs());
        }
        if (result.message() != null) {
            return result.message();
        }
        return ctx.messages().componentForLanguage(language, KEY_GENERIC, color);
    }
}
