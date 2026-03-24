package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.InboundConnection;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.bstats.velocity.Metrics;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.Logger;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings({"java:S100", "java:S1450"})
class AuthListenerTest {

    private static final PlainTextComponentSerializer PLAIN_TEXT = PlainTextComponentSerializer.plainText();

    @Mock
    private AuthCache authCache;

    @Mock
    private Settings settings;

    @Mock
    private PreLoginHandler preLoginHandler;

    @Mock
    private PostLoginHandler postLoginHandler;

    @Mock
    private ConnectionManager connectionManager;

    @Mock
    private DatabaseManager databaseManager;

    @Mock
    private ProxyServer proxyServer;

    @Mock
    private Logger logger;

    private VeloAuth plugin;
    private Messages messages;
    private AuthListener authListener;

    @BeforeEach
    void setUp() throws Exception {
        messages = new Messages();
        messages.setLanguage("en");

        when(logger.isDebugEnabled()).thenReturn(false);
        when(logger.isInfoEnabled()).thenReturn(false);
        when(settings.isPremiumCheckEnabled()).thenReturn(true);
        when(settings.isFloodgateIntegrationEnabled()).thenReturn(false);
        when(settings.isFloodgateBypassAuthServerEnabled()).thenReturn(false);
        when(settings.getAuthServerName()).thenReturn("auth");
        when(preLoginHandler.isValidUsername(anyString())).thenReturn(true);
        when(preLoginHandler.isBruteForceBlocked(nullable(InetAddress.class), anyString())).thenReturn(false);
        when(databaseManager.findPlayerByUuidOrNickname(anyString(), nullable(UUID.class)))
                .thenReturn(CompletableFuture.completedFuture(DatabaseManager.DbResult.success(null)));

        Metrics.Factory metricsFactory = org.mockito.Mockito.mock(Metrics.Factory.class);
        plugin = new VeloAuth(proxyServer, logger, Path.of("."), metricsFactory);
        setPluginInitialized(true);

        authListener = new AuthListener(
                plugin,
                authCache,
                settings,
                preLoginHandler,
                postLoginHandler,
                connectionManager,
                databaseManager,
                messages
        );
    }

    @Test
    void testOnPreLogin_nullIpShouldBeBlockedFailSecure() {
        String username = "NullIpPlayer";
        InboundConnection connection = org.mockito.Mockito.mock(InboundConnection.class);
        when(connection.getRemoteAddress()).thenReturn(null);
        when(preLoginHandler.isBruteForceBlocked(null, "NullIpPlayer")).thenReturn(true);

        PreLoginEvent event = new PreLoginEvent(connection, username);

        EventTask task = authListener.onPreLogin(event);

        assertNull(task, "Null IP should be denied synchronously");
        assertFalse(event.getResult().isAllowed(), "Null IP must not fail open");
        verify(preLoginHandler).isBruteForceBlocked(null, "NullIpPlayer");
    }

    @Test
    void testOnPreLogin_sameUsernameDifferentIpsShouldNotSharePendingLoginLock() {
        String username = "SharedName";
        CompletableFuture<PreLoginHandler.PremiumResolutionResult> firstResolution = new CompletableFuture<>();
        CompletableFuture<PreLoginHandler.PremiumResolutionResult> secondResolution = new CompletableFuture<>();
        when(preLoginHandler.resolvePremiumStatusAsync(username)).thenReturn(firstResolution, secondResolution);

        PreLoginEvent firstEvent = new PreLoginEvent(createConnection("192.0.2.10"), username);
        PreLoginEvent secondEvent = new PreLoginEvent(createConnection("192.0.2.11"), username);

        EventTask firstTask = authListener.onPreLogin(firstEvent);
        EventTask secondTask = authListener.onPreLogin(secondEvent);

        assertNotNull(firstTask, "First login should enter async premium resolution");
        assertNotNull(secondTask, "Different IP should not be blocked by another pending username");

        PreLoginHandler.PremiumResolutionResult offlineResult =
                new PreLoginHandler.PremiumResolutionResult(false, null);
        firstResolution.complete(offlineResult);
        secondResolution.complete(offlineResult);

        awaitEventTask(firstTask);
        awaitEventTask(secondTask);
    }

    @Test
    void testOnPreLogin_sameUsernameSameIpShouldDenyDuplicateConnectionUntilFirstCompletes() {
        String username = "DuplicateSource";
        CompletableFuture<PreLoginHandler.PremiumResolutionResult> firstResolution = new CompletableFuture<>();
        when(preLoginHandler.resolvePremiumStatusAsync(username)).thenReturn(
                firstResolution,
                CompletableFuture.completedFuture(new PreLoginHandler.PremiumResolutionResult(false, null))
        );

        PreLoginEvent firstEvent = new PreLoginEvent(createConnection("192.0.2.20"), username);
        PreLoginEvent secondEvent = new PreLoginEvent(createConnection("192.0.2.20"), username);

        EventTask firstTask = authListener.onPreLogin(firstEvent);
        EventTask secondTask = authListener.onPreLogin(secondEvent);

        assertNotNull(firstTask, "First source should enter async premium resolution");
        assertNull(secondTask, "Duplicate source should be denied synchronously");
        assertFalse(secondEvent.getResult().isAllowed(), "Duplicate source must be denied");
        assertEquals(
                messages.get("connection.already_connecting"),
                secondEvent.getResult().getReasonComponent().map(PLAIN_TEXT::serialize).orElse(null)
        );

        firstResolution.complete(new PreLoginHandler.PremiumResolutionResult(false, null));
        awaitEventTask(firstTask);

        PreLoginEvent thirdEvent = new PreLoginEvent(createConnection("192.0.2.20"), username);
        EventTask thirdTask = authListener.onPreLogin(thirdEvent);

        assertNotNull(thirdTask, "Pending login key should be cleaned after the first attempt finishes");
        awaitEventTask(thirdTask);
        assertTrue(thirdEvent.getResult().isForceOfflineMode(), "Source lock should be released after completion");
    }

    @Test
    void testOnServerPreConnect_firstConnectionShouldUsePreviousServerInsteadOfCurrentServer() {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);

        when(player.getUsername()).thenReturn("RoutingPlayer");
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));

        ServerPreConnectEvent event = new ServerPreConnectEvent(player, backendServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNull(task, "First-connection redirect should be resolved synchronously");
        assertSame(authServer, event.getResult().getServer().orElse(null),
                "Previous server semantics should redirect first connections to auth server");
        verify(connectionManager).setForcedHostTarget(playerUuid, "backend");
    }

    @Test
    void testOnServerPreConnect_firstConnectionToAuthServerShouldBeAllowedWithoutForcedHostTarget() {
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);

        when(player.getUsername()).thenReturn("AuthRoutingPlayer");
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));

        ServerPreConnectEvent event = new ServerPreConnectEvent(player, authServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNull(task, "First connection to auth server should stay synchronous");
        assertTrue(event.getResult().isAllowed(), "Initial auth-server target should be allowed");
        assertSame(authServer, event.getResult().getServer().orElse(null));
        verify(connectionManager, never()).setForcedHostTarget(any(UUID.class), anyString());
    }

    @Test
    void testOnServerPreConnect_uuidMismatchShouldDenyAndClearCachedState() {
        String username = "MismatchPlayer";
        UUID playerUuid = UUID.randomUUID();
        String playerIp = "192.0.2.42";

        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUsername()).thenReturn(username);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.isOnlineMode()).thenReturn(false);
        when(player.isActive()).thenReturn(true);
        when(player.getRemoteAddress()).thenReturn(new InetSocketAddress(playerIp, 25565));

        RegisteredPlayer storedPlayer = new RegisteredPlayer();
        storedPlayer.setNickname(username);
        storedPlayer.setUuid(UUID.randomUUID().toString());
        when(databaseManager.findPlayerByNickname(username))
                .thenReturn(CompletableFuture.completedFuture(DatabaseManager.DbResult.success(storedPlayer)));
        when(authCache.isPlayerAuthorized(playerUuid, playerIp)).thenReturn(true);
        when(authCache.hasActiveSession(playerUuid, username, playerIp)).thenReturn(true);

        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        RegisteredServer previousServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(previousServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));

        ServerPreConnectEvent event = new ServerPreConnectEvent(player, backendServer, previousServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNotNull(task, "Backend UUID verification should be asynchronous");
        awaitEventTask(task);
        assertFalse(event.getResult().isAllowed(), "UUID mismatch must deny backend access");
        verify(authCache, atLeastOnce()).removeAuthorizedPlayer(playerUuid);
        verify(authCache, atLeastOnce()).endSession(playerUuid);
    }

    private InboundConnection createConnection(String address) {
        InboundConnection connection = org.mockito.Mockito.mock(InboundConnection.class);
        when(connection.getRemoteAddress()).thenReturn(
                new InetSocketAddress(address, 25565));
        return connection;
    }

    private void setPluginInitialized(boolean value) throws Exception {
        Field initializedField = VeloAuth.class.getDeclaredField("initialized");
        initializedField.setAccessible(true);
        initializedField.set(plugin, value);
    }

    private void awaitEventTask(EventTask task) {
        try {
            Field futureField = task.getClass().getDeclaredField("future");
            futureField.setAccessible(true);
            ((CompletableFuture<?>) futureField.get(task)).join();
        } catch (ReflectiveOperationException e) {
            try {
                Thread.sleep(200);
            } catch (InterruptedException interruptedException) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Unable to await EventTask completion", interruptedException);
            }
        }
    }
}
