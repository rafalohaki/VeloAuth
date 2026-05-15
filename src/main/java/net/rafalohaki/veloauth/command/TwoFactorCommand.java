package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.CommandSource;
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
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

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
 *   <li>{@code /2fa qr}         — re-shows the otpauth URI + clickable QR link for the player's existing token. Useful when
 *                                 a phone is lost and the player needs to re-enroll on a new device.</li>
 *   <li>{@code /2fa status}     — prints whether the account currently has 2FA enabled.</li>
 * </ul>
 * <p>
 * Master switch: when {@code two-factor.enabled=false}, every sub-command short-circuits to a
 * "disabled by configuration" message. The shutoff also propagates to {@link LoginCommand} so
 * existing tokens stop being enforced (operator's intended killswitch).
 */
class TwoFactorCommand implements SimpleCommand {

    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final int CODE_DIGITS = 6;

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
        CommandSource source = invocation.source();
        String[] args = invocation.arguments();

        Player player = CommandHelper.validatePlayerSource(source, ctx.messages());
        if (player == null) {
            return;
        }
        if (args.length == 0) {
            player.sendMessage(ctx.sm().twoFactorUsage());
            return;
        }

        String sub = args[0].toLowerCase(java.util.Locale.ROOT);
        switch (sub) {
            case "setup" -> processSetup(player);
            case "verify" -> processVerify(player, args);
            case "disable" -> processDisable(player, args);
            case "qr" -> processQr(player);
            case "status" -> processStatus(player);
            default -> player.sendMessage(ctx.sm().twoFactorUsage());
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

    private void processSetup(Player player) {
        if (twoFactorDisabledRejection(player)) {
            return;
        }
        RegisteredPlayer dbPlayer = loadAuthorizedPlayerOrNull(player, "2fa setup");
        if (dbPlayer == null) {
            return;
        }
        if (hasTotp(dbPlayer)) {
            player.sendMessage(ctx.sm().twoFactorSetupAlreadyEnabled());
            return;
        }

        TotpService totp = ctx.totpService();
        Settings.TwoFactorSettings settings = ctx.settings().getTwoFactorSettings();
        String secret = totp.generateSecret();
        String otpUri = totp.otpAuthUri(settings.getIssuer(), dbPlayer.getNickname(), secret);

        ctx.pendingTotpStore().put(
                PendingTotpState.forSetup(player.getUniqueId(), secret, PlayerAddressUtils.getPlayerIp(player)));

        sendSetupPanel(player, dbPlayer.getNickname(), secret, otpUri, settings);
    }

    private void sendSetupPanel(Player player, String nickname, String secret, String otpUri,
                                Settings.TwoFactorSettings settings) {
        player.sendMessage(ctx.sm().key("2fa.setup.generated_header", NamedTextColor.GOLD));
        player.sendMessage(ctx.sm().key("2fa.setup.scan_instruction", NamedTextColor.YELLOW));
        if (settings.isQrLinkEnabled()) {
            sendQrLink(player, otpUri, settings);
        }
        player.sendMessage(ctx.sm().key("2fa.setup.secret_label", NamedTextColor.YELLOW, secret));
        player.sendMessage(ctx.sm().key("2fa.setup.issuer_label", NamedTextColor.YELLOW, settings.getIssuer()));
        player.sendMessage(ctx.sm().key("2fa.setup.account_label", NamedTextColor.YELLOW, nickname));
        player.sendMessage(ctx.sm().key("2fa.setup.uri_label", NamedTextColor.YELLOW, otpUri));
        player.sendMessage(ctx.sm().key("2fa.setup.verify_prompt", NamedTextColor.GRAY));
    }

    /**
     * Sends the clickable {@code [ Scan QR ]} line. We render it as an Adventure Component
     * with a {@code clickEvent(openUrl(...))} so the player's Minecraft client opens the URL
     * in their default browser, where the configured service draws a real PNG QR code.
     * <p>
     * Why a link instead of an in-chat ASCII QR: Minecraft's chat font is monospaced but
     * taller than wide, and many resource packs / client mods replace glyph metrics; in
     * practice the Unicode-block-art QR is unreadable to phone scanners on most setups.
     * A browser-rendered QR is reliable.
     */
    private void sendQrLink(Player player, String otpUri, Settings.TwoFactorSettings settings) {
        String resolvedUrl = settings.getQrLinkUrlTemplate()
                .replace("{uri}", URLEncoder.encode(otpUri, StandardCharsets.UTF_8));
        Component label = ctx.sm().key("2fa.setup.qr_link_label", NamedTextColor.AQUA)
                .decoration(TextDecoration.UNDERLINED, true)
                .clickEvent(ClickEvent.openUrl(resolvedUrl))
                .hoverEvent(HoverEvent.showText(
                        ctx.sm().key("2fa.setup.qr_link_hover", NamedTextColor.GRAY)));
        player.sendMessage(label);
    }

    // ===== verify =====

    private void processVerify(Player player, String[] args) {
        if (args.length != 2) {
            player.sendMessage(ctx.sm().twoFactorVerifyUsage());
            return;
        }
        String code = args[1];
        if (!isWellFormedCode(code)) {
            player.sendMessage(ctx.sm().twoFactorVerifyInvalidFormat());
            return;
        }

        // Defense in depth: gate /2fa verify behind the same brute-force tracker that gates /login.
        // Otherwise an attacker holding a leaked password can park at the TOTP step and burn through
        // codes — completeLogin() increments the counter on each fail, but without this read-side
        // check the counter never converts into a block until the *next* /login attempt.
        java.net.InetAddress address = PlayerAddressUtils.getPlayerAddress(player);
        if (address != null && ctx.authCache().isBlocked(address, player.getUsername())) {
            player.sendMessage(ctx.sm().bruteForceBlocked());
            return;
        }

        Optional<PendingTotpState> pendingOpt = ctx.pendingTotpStore().get(player.getUniqueId());
        if (pendingOpt.isEmpty()) {
            player.sendMessage(ctx.sm().twoFactorVerifyNoPending());
            return;
        }

        PendingTotpState pending = pendingOpt.get();
        switch (pending.kind()) {
            case SETUP -> completeSetup(player, pending, code);
            case LOGIN -> completeLogin(player, pending, code);
        }
    }

    private void completeSetup(Player player, PendingTotpState pending, String code) {
        if (twoFactorDisabledRejection(player)) {
            ctx.pendingTotpStore().invalidate(player.getUniqueId());
            return;
        }
        RegisteredPlayer dbPlayer = loadAuthorizedPlayerOrNull(player, "2fa verify (setup)");
        if (dbPlayer == null) {
            return;
        }
        if (!ctx.totpService().verify(pending.newSecret(), code)) {
            player.sendMessage(ctx.sm().twoFactorVerifyWrongCode());
            return;
        }

        dbPlayer.setTotpToken(pending.newSecret());
        var saveResult = ctx.databaseManager().savePlayer(dbPlayer).join();
        if (ctx.handleDatabaseError(saveResult, player, "Save TOTP secret")) {
            return;
        }
        if (!Boolean.TRUE.equals(saveResult.getValue())) {
            ctx.sendDatabaseErrorMessage(player);
            return;
        }

        ctx.pendingTotpStore().invalidate(player.getUniqueId());
        emit(AuditEventType.TWO_FACTOR_ENABLED, dbPlayer.getNickname(), PlayerAddressUtils.getPlayerIp(player), null);
        player.sendMessage(ctx.sm().twoFactorVerifySetupSuccess());

        if (ctx.logger().isInfoEnabled()) {
            ctx.logger().info(AUTH_MARKER, "Player {} enabled 2FA from IP {}",
                    dbPlayer.getNickname(), PlayerAddressUtils.getPlayerIp(player));
        }
    }

    private void completeLogin(Player player, PendingTotpState pending, String code) {
        RegisteredPlayer dbPlayer = pending.dbPlayer();
        String storedSecret = dbPlayer.getTotpToken();
        if (!ctx.totpService().verify(storedSecret, code)) {
            ctx.authCache().registerFailedLogin(
                    PlayerAddressUtils.getPlayerAddress(player), dbPlayer.getNickname());
            emit(AuditEventType.TWO_FACTOR_VERIFY_FAIL, dbPlayer.getNickname(),
                    PlayerAddressUtils.getPlayerIp(player), "wrong-code");
            player.sendMessage(ctx.sm().twoFactorVerifyWrongCode());
            return;
        }

        ctx.pendingTotpStore().invalidate(player.getUniqueId());

        AuthenticationContext authContext = new AuthenticationContext(
                player, dbPlayer.getNickname(),
                PlayerAddressUtils.getPlayerAddress(player), dbPlayer);
        if (PostAuthFlow.execute(ctx, authContext, dbPlayer, "logged in (2FA)")) {
            emit(AuditEventType.TWO_FACTOR_VERIFY_OK, dbPlayer.getNickname(),
                    PlayerAddressUtils.getPlayerIp(player), null);
            player.sendMessage(ctx.sm().twoFactorVerifyLoginSuccess());
        }
    }

    // ===== disable =====

    private void processDisable(Player player, String[] args) {
        if (twoFactorDisabledRejection(player)) {
            return;
        }
        if (args.length != 2) {
            player.sendMessage(ctx.sm().twoFactorDisableUsage());
            return;
        }
        String code = args[1];
        if (!isWellFormedCode(code)) {
            player.sendMessage(ctx.sm().twoFactorVerifyInvalidFormat());
            return;
        }
        RegisteredPlayer dbPlayer = loadAuthorizedPlayerOrNull(player, "2fa disable");
        if (dbPlayer == null) {
            return;
        }
        if (!hasTotp(dbPlayer)) {
            player.sendMessage(ctx.sm().twoFactorDisableNotEnabled());
            return;
        }
        if (!ctx.totpService().verify(dbPlayer.getTotpToken(), code)) {
            player.sendMessage(ctx.sm().twoFactorDisableWrongCode());
            return;
        }

        dbPlayer.setTotpToken(null);
        var saveResult = ctx.databaseManager().savePlayer(dbPlayer).join();
        if (ctx.handleDatabaseError(saveResult, player, "Wipe TOTP secret")) {
            return;
        }
        if (!Boolean.TRUE.equals(saveResult.getValue())) {
            ctx.sendDatabaseErrorMessage(player);
            return;
        }

        emit(AuditEventType.TWO_FACTOR_DISABLED, dbPlayer.getNickname(),
                PlayerAddressUtils.getPlayerIp(player), "self-disable");
        player.sendMessage(ctx.sm().twoFactorDisableSuccess());

        if (ctx.logger().isInfoEnabled()) {
            ctx.logger().info(AUTH_MARKER, "Player {} disabled 2FA from IP {}",
                    dbPlayer.getNickname(), PlayerAddressUtils.getPlayerIp(player));
        }
    }

    // ===== qr =====

    private void processQr(Player player) {
        if (twoFactorDisabledRejection(player)) {
            return;
        }
        RegisteredPlayer dbPlayer = loadAuthorizedPlayerOrNull(player, "2fa qr");
        if (dbPlayer == null) {
            return;
        }
        if (!hasTotp(dbPlayer)) {
            player.sendMessage(ctx.sm().twoFactorQrNotEnabled());
            return;
        }

        Settings.TwoFactorSettings settings = ctx.settings().getTwoFactorSettings();
        String otpUri = ctx.totpService().otpAuthUri(settings.getIssuer(), dbPlayer.getNickname(), dbPlayer.getTotpToken());
        player.sendMessage(ctx.sm().twoFactorQrWarning());
        sendSetupPanel(player, dbPlayer.getNickname(), dbPlayer.getTotpToken(), otpUri, settings);
    }

    // ===== status =====

    private void processStatus(Player player) {
        RegisteredPlayer dbPlayer = loadAuthorizedPlayerOrNull(player, "2fa status");
        if (dbPlayer == null) {
            return;
        }
        if (hasTotp(dbPlayer)) {
            player.sendMessage(ctx.sm().twoFactorStatusEnabled());
        } else {
            player.sendMessage(ctx.sm().twoFactorStatusDisabled());
        }
    }

    // ===== helpers =====

    /**
     * Returns the DB row for the currently-authorized player, or {@code null} if the
     * player is not authorized or the DB lookup fails (already handled / messaged).
     */
    private RegisteredPlayer loadAuthorizedPlayerOrNull(Player player, String opName) {
        if (!ctx.authCache().isPlayerAuthorized(player.getUniqueId(), PlayerAddressUtils.getPlayerIp(player))) {
            player.sendMessage(ctx.sm().authMustLogin());
            return null;
        }
        AuthenticationContext authCtx = ctx.validateAndAuthenticatePlayer(player, opName);
        if (authCtx == null) {
            return null;
        }
        if (authCtx.registeredPlayer() == null) {
            player.sendMessage(ctx.sm().notRegistered());
            return null;
        }
        return authCtx.registeredPlayer();
    }

    private boolean twoFactorDisabledRejection(Player player) {
        if (ctx.settings().getTwoFactorSettings().isEnabled()) {
            return false;
        }
        player.sendMessage(ctx.sm().twoFactorDisabledInConfig());
        return true;
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
        audit.record(type, nickname, ip, details);
    }

}
