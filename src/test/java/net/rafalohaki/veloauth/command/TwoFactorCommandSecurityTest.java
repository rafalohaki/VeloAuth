package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.auth.totp.TotpService;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.i18n.SimpleMessages;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.net.InetSocketAddress;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TwoFactorCommandSecurityTest {

    private static final PlainTextComponentSerializer PLAIN_TEXT =
            PlainTextComponentSerializer.plainText();

    @Test
    void qr_existingEnrollment_neverRedisplaysStoredSecret() {
        String storedSecret = "JBSWY3DPEHPK3PXP";
        UUID uuid = UUID.randomUUID();
        Player player = mock(Player.class);
        when(player.getUniqueId()).thenReturn(uuid);
        when(player.getUsername()).thenReturn("ProtectedPlayer");
        when(player.getRemoteAddress()).thenReturn(new InetSocketAddress("192.0.2.60", 25565));

        RegisteredPlayer registeredPlayer = new RegisteredPlayer();
        registeredPlayer.setNickname("ProtectedPlayer");
        registeredPlayer.setUuid(uuid.toString());
        registeredPlayer.setTotpToken(storedSecret);

        Messages messages = new Messages();
        messages.setLanguage("en");
        SimpleMessages simpleMessages = new SimpleMessages(messages);
        Settings settings = mock(Settings.class);
        when(settings.getTwoFactorSettings()).thenReturn(new Settings.TwoFactorSettings());
        AuthCache authCache = mock(AuthCache.class);
        when(authCache.isPlayerAuthorized(uuid, "192.0.2.60")).thenReturn(true);
        CommandContext context = mock(CommandContext.class);
        when(context.messages()).thenReturn(messages);
        when(context.sm()).thenReturn(simpleMessages);
        when(context.settings()).thenReturn(settings);
        when(context.authCache()).thenReturn(authCache);
        ConnectionLifecycleRegistry.Operation operation = allowConnection(context, player);
        java.net.InetAddress playerAddress = player.getRemoteAddress().getAddress();
        when(context.validateAndAuthenticatePlayer(player, "2fa qr", operation))
                .thenReturn(new AuthenticationContext(
                        player, "ProtectedPlayer", playerAddress, registeredPlayer, operation));

        SimpleCommand.Invocation invocation = mock(SimpleCommand.Invocation.class);
        when(invocation.source()).thenReturn(player);
        when(invocation.arguments()).thenReturn(new String[]{"qr"});

        new TwoFactorCommand(context).execute(invocation);

        ArgumentCaptor<Component> captor = ArgumentCaptor.forClass(Component.class);
        verify(player, atLeastOnce()).sendMessage(captor.capture());
        List<String> output = captor.getAllValues().stream().map(PLAIN_TEXT::serialize).toList();
        assertFalse(output.stream().anyMatch(line -> line.contains(storedSecret)),
                "An enrolled TOTP secret must never be recoverable through chat");
        assertFalse(output.stream().anyMatch(line -> line.contains("otpauth://")));
        assertTrue(output.stream().anyMatch(line -> line.contains("cannot be shown again")));
    }

    @Test
    void disable_wrongCode_countsAgainstSharedBruteForceBudget() {
        String nickname = "ProtectedPlayer";
        String storedSecret = "JBSWY3DPEHPK3PXP";
        UUID uuid = UUID.randomUUID();
        Player player = mock(Player.class);
        InetSocketAddress remoteAddress = new InetSocketAddress("192.0.2.61", 25565);
        when(player.getUniqueId()).thenReturn(uuid);
        when(player.getUsername()).thenReturn(nickname);
        when(player.getRemoteAddress()).thenReturn(remoteAddress);

        RegisteredPlayer registeredPlayer = new RegisteredPlayer();
        registeredPlayer.setNickname(nickname);
        registeredPlayer.setUuid(uuid.toString());
        registeredPlayer.setTotpToken(storedSecret);
        Messages messages = new Messages();
        messages.setLanguage("en");
        Settings settings = mock(Settings.class);
        when(settings.getTwoFactorSettings()).thenReturn(new Settings.TwoFactorSettings());
        AuthCache authCache = mock(AuthCache.class);
        when(authCache.isPlayerAuthorized(uuid, "192.0.2.61")).thenReturn(true);
        TotpService totpService = mock(TotpService.class);
        when(totpService.matchedWindow(storedSecret, "000000"))
                .thenReturn(TotpService.NO_WINDOW_MATCH);

        CommandContext context = mock(CommandContext.class);
        when(context.messages()).thenReturn(messages);
        when(context.sm()).thenReturn(new SimpleMessages(messages));
        when(context.settings()).thenReturn(settings);
        when(context.authCache()).thenReturn(authCache);
        when(context.totpService()).thenReturn(totpService);
        ConnectionLifecycleRegistry.Operation operation = allowConnection(context, player);
        when(context.validateAndAuthenticatePlayer(player, "2fa disable", operation))
                .thenReturn(new AuthenticationContext(
                        player, nickname, remoteAddress.getAddress(), registeredPlayer, operation));
        SimpleCommand.Invocation invocation = mock(SimpleCommand.Invocation.class);
        when(invocation.source()).thenReturn(player);
        when(invocation.arguments()).thenReturn(new String[]{"disable", "000000"});

        new TwoFactorCommand(context).execute(invocation);

        verify(authCache).registerFailedLogin(remoteAddress.getAddress(), nickname);
    }

    private ConnectionLifecycleRegistry.Operation allowConnection(
            CommandContext context, Player player) {
        ConnectionLifecycleRegistry.Operation operation = mock(ConnectionLifecycleRegistry.Operation.class);
        when(context.captureConnectionOperation(player)).thenReturn(operation);
        when(context.isConnectionCurrent(operation)).thenReturn(true);
        when(context.runIfConnectionCurrent(
                org.mockito.ArgumentMatchers.eq(operation),
                org.mockito.ArgumentMatchers.any(Runnable.class)))
                .thenAnswer(invocation -> {
                    invocation.<Runnable>getArgument(1).run();
                    return true;
                });
        return operation;
    }
}
