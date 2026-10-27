package net.rafalohaki.veloauth.dialog;

import net.kyori.adventure.nbt.CompoundBinaryTag;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;

import java.util.Locale;
import java.util.function.IntSupplier;

/**
 * Builds the NBT payloads of the login, register, 2FA, error and premium-name dialogs in a given
 * language. Pure presentation: no session state, nothing is sent from here.
 */
final class DialogForms {

    private static final int INPUT_WIDTH = 200;
    private static final int BUTTON_WIDTH = 150;
    private static final int BODY_WIDTH = 250;
    private static final int MIN_PASSWORD_FIELD_LENGTH = 32;
    private static final int TOTP_FIELD_LENGTH = 12;
    private static final String CONFIRMATION = "minecraft:confirmation";
    private static final String NOTICE = "minecraft:notice";

    private final Messages messages;
    private final Settings settings;
    private final IntSupplier maxPasswordLength;

    DialogForms(Messages messages, Settings settings, IntSupplier maxPasswordLength) {
        this.messages = messages;
        this.settings = settings;
        this.maxPasswordLength = maxPasswordLength;
    }

    CompoundBinaryTag login(String lang, String playerName, boolean allowCancel) {
        DialogNbt.DialogBuilder builder = DialogNbt
                .dialog(allowCancel ? CONFIRMATION : NOTICE, text(lang, "dialog.login.title", NamedTextColor.GOLD))
                .body(DialogNbt.plainMessage(text(lang, "dialog.login.body", NamedTextColor.WHITE, playerName), BODY_WIDTH))
                .input(DialogNbt.textInput("password",
                        text(lang, "dialog.login.password", NamedTextColor.GRAY), passwordFieldLength(), INPUT_WIDTH));
        return withButtons(builder, lang, "login", allowCancel);
    }

    CompoundBinaryTag register(String lang, String playerName, boolean allowCancel) {
        int maxLength = passwordFieldLength();
        DialogNbt.DialogBuilder builder = DialogNbt
                .dialog(allowCancel ? CONFIRMATION : NOTICE, text(lang, "dialog.register.title", NamedTextColor.GOLD))
                .body(DialogNbt.plainMessage(text(lang, "dialog.register.body", NamedTextColor.WHITE, playerName), BODY_WIDTH))
                .input(DialogNbt.textInput("password",
                        text(lang, "dialog.register.password", NamedTextColor.GRAY), maxLength, INPUT_WIDTH))
                .input(DialogNbt.textInput("confirm",
                        text(lang, "dialog.register.confirm", NamedTextColor.GRAY), maxLength, INPUT_WIDTH));
        return withButtons(builder, lang, "register", allowCancel);
    }

    CompoundBinaryTag totp(String lang, boolean allowCancel) {
        DialogNbt.DialogBuilder builder = DialogNbt
                .dialog(allowCancel ? CONFIRMATION : NOTICE, text(lang, "dialog.totp.title", NamedTextColor.GOLD))
                .body(DialogNbt.plainMessage(text(lang, "dialog.totp.body", NamedTextColor.WHITE), BODY_WIDTH))
                .input(DialogNbt.textInput("code",
                        text(lang, "dialog.totp.code", NamedTextColor.GRAY), TOTP_FIELD_LENGTH, INPUT_WIDTH));
        return withButtons(builder, lang, "totp", allowCancel);
    }

    /** Single-button notice for a cracked client on a premium nickname; the button disconnects. */
    CompoundBinaryTag premiumName(String lang, String playerName) {
        Component body = Component.text()
                .append(text(lang, "dialog.premium_name.body", NamedTextColor.WHITE, playerName))
                .append(Component.newline()).append(Component.newline())
                .append(text(lang, "dialog.premium_name.hint", NamedTextColor.YELLOW))
                .build();
        DialogNbt.DialogBuilder builder = DialogNbt
                .dialog(NOTICE, text(lang, "dialog.premium_name.title", NamedTextColor.RED))
                .afterAction("close")
                .closableWithEscape(false)
                .body(bodyWithOptionalIcon("minecraft:name_tag", body));
        builder.notice(DialogNbt.customButton(text(lang, "dialog.premium_name.button", NamedTextColor.GREEN),
                "premium_name_ack", null, BUTTON_WIDTH));
        return builder.build();
    }

    CompoundBinaryTag error(String lang, Component message, Form returnTo) {
        CompoundBinaryTag additions = CompoundBinaryTag.builder()
                .putString("form", returnTo.name().toLowerCase(Locale.ROOT))
                .build();
        DialogNbt.DialogBuilder builder = DialogNbt
                .dialog(NOTICE, text(lang, "dialog.error.title", NamedTextColor.RED))
                .body(bodyWithOptionalIcon("minecraft:barrier", message));
        builder.notice(DialogNbt.customButton(
                text(lang, "dialog.button.back", NamedTextColor.YELLOW), "back", additions, BUTTON_WIDTH));
        return builder.build();
    }

    private CompoundBinaryTag withButtons(DialogNbt.DialogBuilder builder, String lang, String action,
                                          boolean allowCancel) {
        CompoundBinaryTag confirm = DialogNbt.customButton(
                text(lang, "dialog.button.confirm", NamedTextColor.GREEN), action, null, BUTTON_WIDTH);
        if (allowCancel) {
            CompoundBinaryTag exit = DialogNbt.customButton(
                    text(lang, "dialog.button.exit", NamedTextColor.RED), "exit", null, BUTTON_WIDTH);
            builder.confirmation(confirm, exit);
        } else {
            builder.notice(confirm);
        }
        return builder.build();
    }

    private CompoundBinaryTag bodyWithOptionalIcon(String item, Component body) {
        return settings.getDialogSettings().isErrorIcon()
                ? DialogNbt.itemMessage(item, body, BODY_WIDTH)
                : DialogNbt.plainMessage(body, BODY_WIDTH);
    }

    private int passwordFieldLength() {
        return Math.max(MIN_PASSWORD_FIELD_LENGTH, maxPasswordLength.getAsInt());
    }

    private Component text(String language, String key, NamedTextColor color, Object... args) {
        return messages.componentForLanguage(language, key, color, args);
    }
}
