package net.rafalohaki.veloauth.dialog;

import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.nbt.CompoundBinaryTag;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.command.DialogAuthBridge;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.Locale;

/**
 * Login / register / TOTP forms of a dialog session: which form to show, what a button click
 * means and how VeloAuth's answer is turned into the next form. Everything that authenticates
 * goes through {@link DialogAuthBridge}, exactly like the chat commands.
 */
final class DialogFormFlow {

    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final String BRUTE_FORCE_BLOCKED_KEY = "security.brute_force.blocked";

    private final DialogAuthBridge bridge;
    private final DialogForms forms;
    private final VelocityDialogTransport transport;
    private final Messages messages;
    private final Settings settings;
    private final Logger logger;
    private final DialogSessionHost host;

    DialogFormFlow(DialogAuthBridge bridge, DialogForms forms, VelocityDialogTransport transport,
                   Messages messages, Settings settings, Logger logger, DialogSessionHost host) {
        this.bridge = bridge;
        this.forms = forms;
        this.transport = transport;
        this.messages = messages;
        this.settings = settings;
        this.logger = logger;
        this.host = host;
    }

    /** Opens login or register depending on whether the account exists. */
    void showInitialForm(DialogSession session) {
        bridge.isRegistered(session.player).ifPresentOrElse(
                registered -> showForm(session, registered ? Form.LOGIN : Form.REGISTER),
                () -> host.disconnect(session, "connection.error.database"));
    }

    void showForm(DialogSession session, Form form) {
        if (!session.isActive()) {
            return;
        }
        session.form = form;
        session.formShown = true;
        boolean allowCancel = settings.getDialogSettings().isAllowCancel();
        String name = session.player.getUsername();
        CompoundBinaryTag dialog = switch (form) {
            case LOGIN -> forms.login(session.language, name, allowCancel);
            case REGISTER -> forms.register(session.language, name, allowCancel);
            case TOTP -> forms.totp(session.language, allowCancel);
        };
        if (!transport.show(session.player, dialog)) {
            // Connection gone - nothing more to do here.
            session.finish();
        }
    }

    void handleClick(DialogSession session, DialogClick click) {
        switch (click.action()) {
            case "login" -> handleLoginClick(session, click);
            case "register" -> handleRegisterClick(session, click);
            case "totp" -> handleTotpClick(session, click);
            case "back" -> handleBackClick(session, click);
            case "exit" -> host.disconnect(session, "dialog.cancelled");
            default -> showForm(session, session.form);
        }
    }

    private void handleLoginClick(DialogSession session, DialogClick click) {
        String password = click.text("password");
        if (password == null || password.isEmpty()) {
            showError(session, text(session, "dialog.error.empty_password"), Form.LOGIN);
            return;
        }
        handleResult(session, bridge.login(session.player, password), Form.LOGIN);
    }

    private void handleRegisterClick(DialogSession session, DialogClick click) {
        String password = click.text("password");
        String confirm = click.text("confirm");
        if (password == null || password.isEmpty()) {
            showError(session, text(session, "dialog.error.empty_password"), Form.REGISTER);
            return;
        }
        handleResult(session, bridge.register(session.player, password, confirm == null ? "" : confirm), Form.REGISTER);
    }

    private void handleTotpClick(DialogSession session, DialogClick click) {
        String code = click.text("code");
        if (code == null || code.isBlank()) {
            showError(session, text(session, "dialog.error.empty_code"), Form.TOTP);
            return;
        }
        handleResult(session, bridge.verifyTotp(session.player, code), Form.TOTP);
    }

    private void handleBackClick(DialogSession session, DialogClick click) {
        Player player = session.player;
        Form form = parseForm(click.text("form"), session.form);
        if (form == Form.TOTP && !bridge.isTotpPending(player)) {
            form = Form.LOGIN;
        }
        if (form != Form.TOTP) {
            // Re-check the account state so "back" always lands on the right form,
            // e.g. after a /login attempt on an account that is not registered yet.
            form = bridge.isRegistered(player).map(r -> r ? Form.LOGIN : Form.REGISTER).orElse(form);
        }
        showForm(session, form);
    }

    private static Form parseForm(String raw, Form fallback) {
        if (raw == null) {
            return fallback;
        }
        try {
            return Form.valueOf(raw.toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException unknown) {
            return fallback;
        }
    }

    private void handleResult(DialogSession session, DialogAuthBridge.Result result, Form form) {
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "Dialog {} result for {}: {} ({})", form, session.player.getUsername(),
                    result.outcome(), result.messageKey());
        }
        if (result.outcome() == DialogAuthBridge.Outcome.SUCCESS) {
            host.authenticated(session, form);
        } else if (result.outcome() == DialogAuthBridge.Outcome.TOTP_REQUIRED) {
            showForm(session, Form.TOTP);
        } else {
            onFailed(session, result, form);
        }
    }

    private void onFailed(DialogSession session, DialogAuthBridge.Result result, Form form) {
        Player player = session.player;
        if (!player.isActive()) {
            session.finish();
            return;
        }
        if (BRUTE_FORCE_BLOCKED_KEY.equals(result.messageKey())) {
            // Same outcome as VeloAuth's own pre-login block: the connection is refused
            // with the localized "too many attempts" message instead of looping the form.
            logger.warn(AUTH_MARKER, "Disconnecting {} from dialog login - brute-force block reached",
                    player.getUsername());
            host.disconnect(session, BRUTE_FORCE_BLOCKED_KEY);
            return;
        }
        Component message = bridge.render(result, session.language, NamedTextColor.RED);
        Form returnTo = form == Form.TOTP && !bridge.isTotpPending(player) ? Form.LOGIN : form;
        showError(session, message, returnTo);
    }

    private void showError(DialogSession session, Component message, Form returnTo) {
        if (!session.isActive()) {
            return;
        }
        if (!transport.show(session.player, forms.error(session.language, message, returnTo))) {
            session.finish();
        }
    }

    private Component text(DialogSession session, String key) {
        return messages.componentForLanguage(session.language, key, NamedTextColor.RED);
    }
}
