package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.i18n.SimpleMessages;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class LogoutCommandTest {

    private static final String PLAYER_NAME = "LogoutPlayer";
    private static final String PLAYER_IP = "192.0.2.90";
    private static final PlainTextComponentSerializer PLAIN_TEXT =
            PlainTextComponentSerializer.plainText();

    @Mock
    private CommandContext context;
    @Mock
    private Player player;
    @Mock
    private CommandSource console;
    @Mock
    private AuditLogService auditLogService;
    @Mock
    private ConnectionManager connectionManager;
    @Mock
    private VeloAuth plugin;

    private Messages messages;
    private LogoutCommand command;

    @BeforeEach
    void setUp() {
        messages = new Messages();
        messages.setLanguage("en");
        when(context.messages()).thenReturn(messages);
        when(context.sm()).thenReturn(new SimpleMessages(messages));
        when(context.auditLogService()).thenReturn(auditLogService);
        when(context.plugin()).thenReturn(plugin);
        when(plugin.getConnectionManager()).thenReturn(connectionManager);
        command = new LogoutCommand(context);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void execute_ActiveCrackedOrPremiumPlayer_DisconnectsWithoutAuthServerTransfer(
            boolean onlineMode) {
        when(player.isActive()).thenReturn(true);
        when(player.isOnlineMode()).thenReturn(onlineMode);
        when(player.getUsername()).thenReturn(PLAYER_NAME);
        when(player.getRemoteAddress()).thenReturn(
                new InetSocketAddress(PLAYER_IP, 25565));

        command.execute(invocation(player));

        ArgumentCaptor<Component> reason = ArgumentCaptor.forClass(Component.class);
        verify(player).disconnect(reason.capture());
        assertEquals(messages.get("auth.logged_out"), PLAIN_TEXT.serialize(reason.getValue()));
        verifyNoInteractions(connectionManager);
    }

    @Test
    void execute_ActivePlayer_CapturesIdentityBeforeDisconnectThenAuditsRequest() {
        AtomicBoolean disconnected = new AtomicBoolean();
        when(player.isActive()).thenReturn(true);
        when(player.getUsername()).thenAnswer(ignored -> {
            assertFalse(disconnected.get(), "username must be captured before disconnect");
            return PLAYER_NAME;
        });
        when(player.getRemoteAddress()).thenAnswer(ignored -> {
            assertFalse(disconnected.get(), "remote address must be captured before disconnect");
            return new InetSocketAddress(PLAYER_IP, 25565);
        });
        doAnswer(ignored -> {
            disconnected.set(true);
            return null;
        }).when(player).disconnect(any(Component.class));

        command.execute(invocation(player));

        InOrder order = inOrder(player, auditLogService);
        order.verify(player).disconnect(any(Component.class));
        order.verify(auditLogService).save(
                AuditEventType.LOGOUT, PLAYER_NAME, PLAYER_IP,
                "connection-termination-requested");
        assertTrue(disconnected.get());
    }

    @Test
    void execute_ConsoleSource_SendsLocalizedPlayerOnlyMessage() {
        command.execute(invocation(console));

        ArgumentCaptor<Component> message = ArgumentCaptor.forClass(Component.class);
        verify(console).sendMessage(message.capture());
        assertEquals(messages.get("error.player_only"), PLAIN_TEXT.serialize(message.getValue()));
        verifyNoInteractions(auditLogService, connectionManager);
    }

    @Test
    void execute_UnexpectedArguments_SendsLocalizedUsageWithoutDisconnecting() {
        command.execute(invocation(player, "unexpected"));

        ArgumentCaptor<Component> message = ArgumentCaptor.forClass(Component.class);
        verify(player).sendMessage(message.capture());
        assertEquals(messages.get("auth.logout.usage"), PLAIN_TEXT.serialize(message.getValue()));
        verify(player, never()).disconnect(any(Component.class));
        verifyNoInteractions(auditLogService, connectionManager);
    }

    @Test
    void execute_InactivePlayer_DoesNotReportOrRepeatDisconnect() {
        when(player.isActive()).thenReturn(false);

        command.execute(invocation(player));

        verify(player, never()).disconnect(any(Component.class));
        verifyNoInteractions(auditLogService, connectionManager);
    }

    @Test
    void hasPermission_PlayerOrConsole_RemainsSelfService() {
        assertTrue(command.hasPermission(invocation(player)));
        assertTrue(command.hasPermission(invocation(console)));
    }

    private SimpleCommand.Invocation invocation(CommandSource source, String... arguments) {
        SimpleCommand.Invocation invocation = org.mockito.Mockito.mock(SimpleCommand.Invocation.class);
        when(invocation.source()).thenReturn(source);
        when(invocation.arguments()).thenReturn(arguments);
        return invocation;
    }
}
