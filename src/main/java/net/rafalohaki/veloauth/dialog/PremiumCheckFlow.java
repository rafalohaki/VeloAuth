package net.rafalohaki.veloauth.dialog;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.scheduler.ScheduledTask;
import io.netty.buffer.ByteBuf;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.premium.MojangProfileKeyVerifier;
import net.rafalohaki.veloauth.premium.ProfileKeyPacket;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.concurrent.TimeUnit;

/**
 * Decides a premium-nick ownership check once the player is on the auth server: a Mojang-signed
 * profile key for the expected account admits the player, anything else ends in the localized
 * "pick another name" notice. See {@link DialogAuthService#beginPremiumCheck}.
 */
final class PremiumCheckFlow {

    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final long ACTION_BAR_REFRESH_MILLIS = 1000L;

    private final VeloAuth plugin;
    private final Settings settings;
    private final VelocityDialogTransport transport;
    private final DialogForms forms;
    private final Messages messages;
    private final Logger logger;
    private final DialogSessionHost host;

    PremiumCheckFlow(VeloAuth plugin, Settings settings, VelocityDialogTransport transport,
                     DialogForms forms, Messages messages, DialogSessionHost host) {
        this.plugin = plugin;
        this.settings = settings;
        this.transport = transport;
        this.forms = forms;
        this.messages = messages;
        this.logger = plugin.getLogger();
        this.host = host;
    }

    /** Called when the player entered PLAY on a server: shows the "checking" dialog and arms the decision. */
    void onInPlay(DialogSession session) {
        DialogSession.PremiumCheck check = session.premiumCheck;
        if (check == null || check.inPlay || !session.isActive()) {
            return;
        }
        check.inPlay = true;
        host.awaitLanguageThenShow(session);
        int checkSeconds = Math.max(1, settings.getDialogSettings().getPremiumCheckSeconds());
        check.decisionTask = plugin.getServer().getScheduler()
                .buildTask(plugin, () -> decide(session))
                .delay(checkSeconds, TimeUnit.SECONDS)
                .schedule();
    }

    void onRawPacket(DialogSession session, ByteBuf raw) {
        DialogSession.PremiumCheck check = session.premiumCheck;
        if (check == null || check.keyVerified || !session.isActive()) {
            return;
        }
        ProfileKeyPacket packet = ProfileKeyPacket.tryParse(raw,
                DialogPacketCodec.playChatSessionId(session.player.getProtocolVersion().getProtocol()));
        if (packet == null) {
            return;
        }
        boolean valid = MojangProfileKeyVerifier.verify(check.premiumUuid, packet.expiresAt(),
                packet.publicKey(), packet.signature(), System.currentTimeMillis());
        if (!valid) {
            logger.info(AUTH_MARKER, "[PREMIUM CHECK] {} sent a profile key that is NOT a Mojang certificate for {} - treating as cracked",
                    session.player.getUsername(), check.premiumUuid);
            return;
        }
        check.keyVerified = true;
        logger.info(AUTH_MARKER, "[PREMIUM CHECK] {} presented a valid Mojang profile key for {} - premium owner confirmed",
                session.player.getUsername(), check.premiumUuid);
        host.runAsync(session, () -> decide(session));
    }

    void decide(DialogSession session) {
        DialogSession.PremiumCheck check = session.premiumCheck;
        if (check == null || !session.isActive() || !check.decided.compareAndSet(false, true)) {
            return;
        }
        DialogSession.cancel(check.decisionTask);
        DialogSession.cancel(session.timeoutTask);
        Player player = session.player;
        if (!player.isActive()) {
            session.finish();
            return;
        }
        if (session.language == null || !check.inPlay) {
            host.resolveAndRememberLanguage(session);
        }
        clearActionBar(player, check);
        if (check.keyVerified) {
            admitVerifiedOwner(session, check);
        } else {
            showNotice(session);
        }
    }

    private void admitVerifiedOwner(DialogSession session, DialogSession.PremiumCheck check) {
        try {
            check.onVerified.run();
        } catch (RuntimeException e) {
            logger.warn(AUTH_MARKER, "Premium hand-over for {} failed: {}", session.player.getUsername(), e.toString());
            host.disconnect(session, "connection.premium_name.verified_reconnect");
        }
        session.finish();
    }

    /** No profile key arrived: from here on this is a plain notice session. */
    private void showNotice(DialogSession session) {
        Player player = session.player;
        logger.info(AUTH_MARKER, "[PREMIUM CHECK] No Mojang profile key from {} - cracked client on premium nick, showing notice",
                player.getUsername());
        session.premiumCheck = null;
        session.timeoutTask = plugin.getServer().getScheduler()
                .buildTask(plugin, () -> host.disconnect(session, DialogAuthService.PREMIUM_NAME_KICKED_KEY,
                        settings.getDialogSettings().getServerName()))
                .delay(DialogAuthService.NOTICE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .schedule();
        if (!transport.show(player, forms.premiumName(session.language, player.getUsername()))) {
            host.disconnect(session, DialogAuthService.PREMIUM_NAME_KICK_KEY, player.getUsername());
        }
    }

    /**
     * The check is silent: only the action bar shows "Checking your account..." in the player's
     * language (re-sent every second because the client fades it out). Nothing is written to chat.
     */
    void showActionBar(DialogSession session) {
        DialogSession.PremiumCheck check = session.premiumCheck;
        if (check == null || !session.isActive()) {
            return;
        }
        Component title = messages.componentForLanguage(session.language, "dialog.premium_check.title", NamedTextColor.GOLD);
        check.actionBarTask = plugin.getServer().getScheduler()
                .buildTask(plugin, () -> {
                    if (session.player.isActive() && !check.decided.get()) {
                        session.player.sendActionBar(title);
                    }
                })
                .repeat(ACTION_BAR_REFRESH_MILLIS, TimeUnit.MILLISECONDS)
                .schedule();
    }

    private void clearActionBar(Player player, DialogSession.PremiumCheck check) {
        ScheduledTask task = check.actionBarTask;
        if (task != null) {
            check.actionBarTask = null;
            task.cancel();
        }
        if (player.isActive()) {
            player.sendActionBar(Component.empty());
        }
    }
}
