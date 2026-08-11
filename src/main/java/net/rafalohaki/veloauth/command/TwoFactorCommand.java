package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.event.ClickEvent;
import net.kyori.adventure.text.event.HoverEvent;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.format.TextDecoration;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.auth.totp.PendingTotpState;
import net.rafalohaki.veloauth.auth.totp.TotpService;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Handles the {@code /2fa} command and all its sub-commands.
 * <p>
 * Sub-command map:
 * <ul>
 *   <li>{@code /2fa setup}      — generate a fresh secret, park it in {@link net.rafalohaki.veloauth.auth.totp.PendingTotpStore}
 *                                 as a {@link PendingTotpState.Kind#SETUP} pending state, and show the player the
 *                                 secret + otpauth URI + optional clickable QR link. Only allowed when the player has no
 *                                 active TOTP token.</li>
 *   <li>{@code /2fa verify <c>} — confirms either a setup (writes the secret to DB) or a post-BCrypt login
 *                                 (transfers the player to a backend).</li>
 *   <li>{@code /2fa disable <c>}— wipes the TOTP token from the DB after verifying the player owns the current
 *                                 authenticator (i.e. they pass a valid code).</li>
 *   <li>{@code /2fa qr}         — retained for command compatibility, but never re-displays an
 *                                 enrolled secret. Re-enrollment requires disable + setup.</li>
 *   <li>{@code /2fa status}     — prints whether the account currently has 2FA enabled.</li>
 * </ul>
 * <p>
 * Master switch: when {@code two-factor.enabled=false}, every sub-command short-circuits to a
 * "disabled by configuration" message. The shutoff also propagates to {@link LoginCommand} so
 * existing tokens stop being enforced after the restart that activates the complete two-factor
 * snapshot. Reload never changes TOTP enforcement in a running process.
 */
class TwoFactorCommand implements SimpleCommand {

    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final int CODE_DIGITS = 6;

    /**
     * QR rendering endpoint. Single hardcoded URL on purpose — there's no operator-facing
     * reason to expose this as a config knob. Format: {@code <prefix>/<base32-secret>} —
     * the worker hosts a fixed otpauth-URI template and pastes the secret into it before
     * rendering the QR. Endpoint is maintained by the VeloAuth author (pure text-to-QR,
     * no logging/storage). Operators who want fully air-gapped enrollment set
     * {@code two-factor.qr-link-enabled: false} — enrollment stays text-only (Base32
     * secret + otpauth URI for manual entry).
     */
    private static final String QR_LINK_URL = "https://qr.autarch.workers.dev/";

    private final CommandContext ctx;

    TwoFactorCommand(CommandContext ctx) {
        this.ctx = ctx;
    }

    /**
     * Hide the command from tab-completion for players who can't do anything useful with it.
     * <ul>
     *   <li>Already authorized (so {@code /2fa setup|disable|qr|status} make sense).</li>
     *   <li>Or has a pending state (post-BCrypt login waiting for verify, or pending setup).</li>
     * </ul>
     * Console always sees the command.
     */
    @Override
    public boolean hasPermission(Invocation invocation) {
        if (!(invocation.source() instanceof Player player)) {
            return true;
        }
        boolean authorized = ctx.authCache().isPlayerAuthorized(
                player.getUniqueId(), PlayerAddressUtils.getPlayerIp(player));
        boolean hasPending = ctx.pendingTotpStore().get(player.getUniqueId()).isPresent();
        return authorized || hasPending;
    }

    @Override
    public void execute(Invocation invocation) {
        CommandHelper.CommandInputs inputs = CommandHelper.requirePlayerWithAtLeastOneArg(
                invocation, ctx.messages(),
                ctx.messages().component("2fa.usage", NamedTextColor.YELLOW));
        if (inputs == null) {
            return;
        }
        Player player = inputs.player();
        String[] args = inputs.args();
        ConnectionLifecycleRegistry.Operation operation = ctx.captureConnectionOperation(player);
        if (operation == null) {
            return;
        }

        String sub = args[0].toLowerCase(java.util.Locale.ROOT);
        switch (sub) {
            case "setup" -> processSetup(player, operation);
            case "verify" -> processVerify(player, args, operation);
            case "disable" -> processDisable(player, args, operation);
            case "qr" -> processQr(player, operation);
            case "status" -> processStatus(player, operation);
            default -> sendIfCurrent(operation, () -> player.sendMessage(
                    ctx.messages().component("2fa.usage", NamedTextColor.YELLOW)));
        }
    }

    @Override
    public List<String> suggest(Invocation invocation) {
        if (invocation.arguments().length <= 1) {
            return List.of("setup", "verify", "disable", "qr", "status");
        }
        return List.of();
    }

    // ===== setup =====

    private void processSetup(Player player, ConnectionLifecycleRegistry.Operation operation) {
        if (twoFactorDisabledRejection(player, operation)) {
            return;
        }
        RegisteredPlayer dbPlayer = loadAuthorizedPlayerOrNull(player, "2fa setup", operation);
        if (dbPlayer == null) {
            return;
        }
        if (hasTotp(dbPlayer)) {
            sendIfCurrent(operation, () -> player.sendMessage(ctx.messages().component(
                    "2fa.setup.already_enabled", NamedTextColor.YELLOW)));
            return;
        }

        TotpService totp = ctx.totpService();
        Settings.TwoFactorSettings settings = ctx.settings().getTwoFactorSettings();
        String secret = totp.generateSecret();
        String otpUri = totp.otpAuthUri(settings.getIssuer(), dbPlayer.getNickname(), secret);

        ctx.runIfConnectionCurrent(operation, () -> {
            ctx.pendingTotpStore().put(PendingTotpState.forSetup(
                    player.getUniqueId(), secret, PlayerAddressUtils.getPlayerIp(player)));
            sendSetupPanel(player, dbPlayer.getNickname(), secret, otpUri, settings);
        });
    }

    private void sendSetupPanel(Player player, String nickname, String secret, String otpUri,
                                Settings.TwoFactorSettings settings) {
        player.sendMessage(ctx.messages().component("2fa.setup.generated_header", NamedTextColor.GOLD));
        player.sendMessage(ctx.messages().component("2fa.setup.scan_instruction", NamedTextColor.YELLOW));
        if (settings.isQrLinkEnabled()) {
            sendQrLink(player, secret);
        }
        player.sendMessage(ctx.messages().component(
                "2fa.setup.secret_label", NamedTextColor.YELLOW, secret));
        player.sendMessage(ctx.messages().component(
                "2fa.setup.issuer_label", NamedTextColor.YELLOW, settings.getIssuer()));
        player.sendMessage(ctx.messages().component(
                "2fa.setup.account_label", NamedTextColor.YELLOW, nickname));
        player.sendMessage(ctx.messages().component(
                "2fa.setup.uri_label", NamedTextColor.YELLOW, otpUri));
        player.sendMessage(ctx.messages().component("2fa.setup.verify_prompt", NamedTextColor.GRAY));
    }

    /**
     * Sends the clickable {@code [ Scan QR ]} line. We render it as an Adventure Component
     * with a {@code clickEvent(openUrl(...))} so the player's Minecraft client opens the URL
     * in their default browser, where the configured service draws a real PNG QR code.
     * <p>
     * URL shape: {@code <QR_LINK_URL>/<base32-secret>}. The worker hosts a fixed otpauth
     * template (issuer/account/algorithm/digits/period) and only needs the secret to render
     * a scannable QR — keeps the URL short and avoids putting the full otpauth URI in path,
     * history, and any redirect referrer.
     * <p>
     * Why a link instead of an in-chat ASCII QR: Minecraft's chat font is monospaced but
     * taller than wide, and many resource packs / client mods replace glyph metrics; in
     * practice the Unicode-block-art QR is unreadable to phone scanners on most setups.
     * A browser-rendered QR is reliable.
     */
    private void sendQrLink(Player player, String secret) {
        String resolvedUrl = QR_LINK_URL + URLEncoder.encode(secret, StandardCharsets.UTF_8);
        Component label = ctx.messages().component("2fa.setup.qr_link_label", NamedTextColor.AQUA)
                .decoration(TextDecoration.UNDERLINED, true)
                .clickEvent(ClickEvent.openUrl(resolvedUrl))
                .hoverEvent(HoverEvent.showText(
                        ctx.messages().component("2fa.setup.qr_link_hover", NamedTextColor.GRAY)));
        player.sendMessage(label);
    }

    // ===== verify =====

    private void processVerify(
            Player player, String[] args, ConnectionLifecycleRegistry.Operation operation) {
        String code = validatedCodeOrNull(
                player, args, operation,
                ctx.messages().component("2fa.verify.usage", NamedTextColor.YELLOW));
        if (code == null) {
            return;
        }

        if (rejectBlockedTotpAttempt(player, operation)) {
            return;
        }

        Optional<PendingTotpState> pendingOpt = ctx.pendingTotpStore().get(player.getUniqueId());
        if (pendingOpt.isEmpty()) {
            sendIfCurrent(operation, () -> player.sendMessage(ctx.messages().component(
                    "2fa.verify.no_pending", NamedTextColor.RED)));
            return;
        }

        PendingTotpState pending = pendingOpt.get();
        if (pending.kind() == PendingTotpState.Kind.SETUP) {
            completeSetup(player, pending, code, operation);
        } else {
            completeLogin(player, pending, code, operation);
        }
    }

    private void completeSetup(
            Player player, PendingTotpState pending, String code,
            ConnectionLifecycleRegistry.Operation operation) {
        if (twoFactorDisabledRejection(player, operation)) {
            ctx.runIfConnectionCurrent(operation,
                    () -> ctx.pendingTotpStore().invalidate(player.getUniqueId()));
            return;
        }
        RegisteredPlayer dbPlayer = loadAuthorizedPlayerOrNull(
                player, "2fa verify (setup)", operation);
        if (dbPlayer == null) {
            return;
        }
        long matchedWindow = ctx.totpService().matchedWindow(pending.newSecret(), code);
        if (!claimTotpWindow(player, dbPlayer.getNickname(), matchedWindow,
                "setup", ctx.messages().component("2fa.verify.wrong_code", NamedTextColor.RED),
                operation)) {
            return;
        }

        if (!ctx.isConnectionCurrent(operation)) {
            return;
        }
        dbPlayer.setTotpToken(pending.newSecret());
        if (!saveTotpChange(player, dbPlayer, "Save TOTP secret", operation)) {
            return;
        }

        ctx.runIfConnectionCurrent(operation, () -> {
            ctx.pendingTotpStore().invalidate(player.getUniqueId());
            emit(AuditEventType.TWO_FACTOR_ENABLED, dbPlayer.getNickname(),
                    PlayerAddressUtils.getPlayerIp(player), null);
            player.sendMessage(ctx.messages().component(
                    "2fa.verify.setup_success", NamedTextColor.GREEN));
            if (ctx.logger().isInfoEnabled()) {
                ctx.logger().info(AUTH_MARKER, "Player {} enabled 2FA from IP {}",
                        dbPlayer.getNickname(), PlayerAddressUtils.getPlayerIp(player));
            }
        });
    }

    private void completeLogin(
            Player player, PendingTotpState pending, String code,
            ConnectionLifecycleRegistry.Operation operation) {
        RegisteredPlayer dbPlayer = pending.dbPlayer();
        String storedSecret = dbPlayer.getTotpToken();
        long matchedWindow = ctx.totpService().matchedWindow(storedSecret, code);
        if (!claimTotpWindow(player, dbPlayer.getNickname(), matchedWindow,
                "login", ctx.messages().component("2fa.verify.wrong_code", NamedTextColor.RED),
                operation)) {
            return;
        }

        if (!ctx.runIfConnectionCurrent(operation,
                () -> ctx.pendingTotpStore().invalidate(player.getUniqueId()))) {
            return;
        }

        AuthenticationContext authContext = new AuthenticationContext(
                player, dbPlayer.getNickname(),
                PlayerAddressUtils.getPlayerAddress(player), dbPlayer, operation);
        if (PostAuthFlow.execute(ctx, authContext, dbPlayer, "logged in (2FA)")) {
            ctx.runIfConnectionCurrent(operation, () -> {
                emit(AuditEventType.TWO_FACTOR_VERIFY_OK, dbPlayer.getNickname(),
                        PlayerAddressUtils.getPlayerIp(player), null);
                player.sendMessage(ctx.messages().component(
                        "2fa.verify.login_success", NamedTextColor.GREEN));
            });
        }
    }

    // ===== disable =====

    private void processDisable(
            Player player, String[] args, ConnectionLifecycleRegistry.Operation operation) {
        if (twoFactorDisabledRejection(player, operation)) {
            return;
        }
        String code = validatedCodeOrNull(
                player, args, operation,
                ctx.messages().component("2fa.disable.usage", NamedTextColor.YELLOW));
        if (code == null) {
            return;
        }
        if (rejectBlockedTotpAttempt(player, operation)) {
            return;
        }
        RegisteredPlayer dbPlayer = loadAuthorizedPlayerOrNull(player, "2fa disable", operation);
        if (dbPlayer == null) {
            return;
        }
        if (!hasTotp(dbPlayer)) {
            sendIfCurrent(operation, () -> player.sendMessage(ctx.messages().component(
                    "2fa.disable.not_enabled", NamedTextColor.YELLOW)));
            return;
        }
        long matchedWindow = ctx.totpService().matchedWindow(dbPlayer.getTotpToken(), code);
        if (!claimTotpWindow(player, dbPlayer.getNickname(), matchedWindow,
                "disable", ctx.messages().component("2fa.disable.wrong_code", NamedTextColor.RED),
                operation)) {
            return;
        }

        if (!ctx.isConnectionCurrent(operation)) {
            return;
        }
        dbPlayer.setTotpToken(null);
        if (!saveTotpChange(player, dbPlayer, "Wipe TOTP secret", operation)) {
            return;
        }

        ctx.runIfConnectionCurrent(operation, () -> {
            emit(AuditEventType.TWO_FACTOR_DISABLED, dbPlayer.getNickname(),
                    PlayerAddressUtils.getPlayerIp(player), "self-disable");
            player.sendMessage(ctx.messages().component("2fa.disable.success", NamedTextColor.GREEN));
            if (ctx.logger().isInfoEnabled()) {
                ctx.logger().info(AUTH_MARKER, "Player {} disabled 2FA from IP {}",
                        dbPlayer.getNickname(), PlayerAddressUtils.getPlayerIp(player));
            }
        });
    }

    private boolean saveTotpChange(
            Player player, RegisteredPlayer dbPlayer, String operationName,
            ConnectionLifecycleRegistry.Operation operation) {
        var saveResult = ctx.databaseManager().savePlayer(dbPlayer).join();
        if (!ctx.isConnectionCurrent(operation)) {
            return false;
        }
        if (ctx.handleDatabaseError(
                saveResult, dbPlayer.getNickname(), player, operationName, operation)) {
            return false;
        }
        if (!Boolean.TRUE.equals(saveResult.getValue())) {
            sendIfCurrent(operation, () -> ctx.sendDatabaseErrorMessage(player));
            return false;
        }
        return true;
    }

    // ===== qr =====

    private void processQr(Player player, ConnectionLifecycleRegistry.Operation operation) {
        if (twoFactorDisabledRejection(player, operation)) {
            return;
        }
        RegisteredPlayer dbPlayer = loadAuthorizedPlayerOrNull(player, "2fa qr", operation);
        if (dbPlayer == null) {
            return;
        }
        if (!hasTotp(dbPlayer)) {
            sendIfCurrent(operation, () -> player.sendMessage(ctx.messages().component(
                    "2fa.qr.not_enabled", NamedTextColor.YELLOW)));
            return;
        }

        sendIfCurrent(operation, () -> player.sendMessage(
                ctx.messages().component("2fa.qr.warning", NamedTextColor.GOLD)));
    }

    // ===== status =====

    private void processStatus(Player player, ConnectionLifecycleRegistry.Operation operation) {
        RegisteredPlayer dbPlayer = loadAuthorizedPlayerOrNull(player, "2fa status", operation);
        if (dbPlayer == null) {
            return;
        }
        if (hasTotp(dbPlayer)) {
            sendIfCurrent(operation, () -> player.sendMessage(
                    ctx.messages().component("2fa.status.enabled", NamedTextColor.GREEN)));
        } else {
            sendIfCurrent(operation, () -> player.sendMessage(
                    ctx.messages().component("2fa.status.disabled", NamedTextColor.GRAY)));
        }
    }

    // ===== helpers =====

    /**
     * Returns the DB row for the currently-authorized player, or {@code null} if the
     * player is not authorized or the DB lookup fails (already handled / messaged).
     */
    private RegisteredPlayer loadAuthorizedPlayerOrNull(
            Player player, String opName, ConnectionLifecycleRegistry.Operation operation) {
        if (!ctx.authCache().isPlayerAuthorized(player.getUniqueId(), PlayerAddressUtils.getPlayerIp(player))) {
            sendIfCurrent(operation, () -> player.sendMessage(
                    ctx.messages().component("auth.must_login", NamedTextColor.RED)));
            return null;
        }
        AuthenticationContext authCtx = ctx.validateAndAuthenticatePlayer(
                player, opName, operation);
        if (authCtx == null) {
            return null;
        }
        if (authCtx.registeredPlayer() == null) {
            sendIfCurrent(operation, () -> player.sendMessage(
                    ctx.messages().component("auth.login.not_registered", NamedTextColor.RED)));
            return null;
        }
        return authCtx.registeredPlayer();
    }

    private boolean twoFactorDisabledRejection(
            Player player, ConnectionLifecycleRegistry.Operation operation) {
        if (ctx.settings().getTwoFactorSettings().isEnabled()) {
            return false;
        }
        sendIfCurrent(operation, () -> player.sendMessage(
                ctx.messages().component("2fa.disabled_in_config", NamedTextColor.YELLOW)));
        return true;
    }

    private boolean rejectBlockedTotpAttempt(
            Player player, ConnectionLifecycleRegistry.Operation operation) {
        java.net.InetAddress address = PlayerAddressUtils.getPlayerAddress(player);
        if (address == null || !ctx.authCache().isBlocked(address, player.getUsername())) {
            return false;
        }
        sendIfCurrent(operation, () -> player.sendMessage(
                ctx.messages().component("security.brute_force.blocked", NamedTextColor.RED)));
        return true;
    }

    private void sendIfCurrent(ConnectionLifecycleRegistry.Operation operation, Runnable send) {
        ctx.runIfConnectionCurrent(operation, send);
    }

    private String validatedCodeOrNull(
            Player player, String[] args, ConnectionLifecycleRegistry.Operation operation,
            Component usage) {
        if (args.length != 2) {
            sendIfCurrent(operation, () -> player.sendMessage(usage));
            return null;
        }
        String code = args[1];
        if (!isWellFormedCode(code)) {
            sendIfCurrent(operation,
                    () -> player.sendMessage(ctx.messages().component(
                            "2fa.verify.invalid_format", NamedTextColor.RED)));
            return null;
        }
        return code;
    }

    private boolean claimTotpWindow(
            Player player, String nickname, long matchedWindow, String detailsPrefix,
            Component wrongCodeMessage, ConnectionLifecycleRegistry.Operation operation) {
        if (matchedWindow == TotpService.NO_WINDOW_MATCH) {
            ctx.runIfConnectionCurrent(operation, () -> {
                recordFailedTotpAttempt(player, nickname, detailsPrefix + "-wrong-code");
                player.sendMessage(wrongCodeMessage);
            });
            return false;
        }

        // RFC 6238 §5.2: claim replay state under the same connection-generation fence. A
        // retired A must neither consume B's window nor report a replay against B.
        AtomicBoolean consumed = new AtomicBoolean();
        boolean current = ctx.runIfConnectionCurrent(operation,
                () -> consumed.set(ctx.totpReplayGuard().consume(
                        player.getUniqueId(), matchedWindow)));
        if (!current) {
            return false;
        }
        if (!consumed.get()) {
            ctx.runIfConnectionCurrent(operation, () -> {
                recordFailedTotpAttempt(player, nickname, detailsPrefix + "-replay");
                player.sendMessage(wrongCodeMessage);
            });
            return false;
        }
        return true;
    }

    private void recordFailedTotpAttempt(Player player, String nickname, String details) {
        ctx.authCache().registerFailedLogin(PlayerAddressUtils.getPlayerAddress(player), nickname);
        emit(AuditEventType.TWO_FACTOR_VERIFY_FAIL, nickname,
                PlayerAddressUtils.getPlayerIp(player), details);
    }

    private static boolean hasTotp(RegisteredPlayer player) {
        String token = player.getTotpToken();
        return token != null && !token.isBlank();
    }

    private static boolean isWellFormedCode(String code) {
        if (code == null || code.length() != CODE_DIGITS) {
            return false;
        }
        for (int i = 0; i < CODE_DIGITS; i++) {
            if (!Character.isDigit(code.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private void emit(AuditEventType type, String nickname, String ip, String details) {
        AuditLogService audit = ctx.auditLogService();
        if (audit == null) {
            return;
        }
        audit.save(type, nickname, ip, details);
    }

}
