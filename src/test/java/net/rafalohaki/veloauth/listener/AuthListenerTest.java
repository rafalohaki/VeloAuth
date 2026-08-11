package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.connection.LoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.player.GameProfileRequestEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.proxy.InboundConnection;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerInfo;
import com.velocitypowered.api.util.GameProfile;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import net.kyori.adventure.text.format.TextColor;
import net.kyori.adventure.text.format.TextDecoration;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.auth.totp.PendingTotpState;
import net.rafalohaki.veloauth.auth.totp.PendingTotpStore;
import net.rafalohaki.veloauth.auth.totp.TotpReplayGuard;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.connection.AuthTimeoutScheduler;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.bstats.velocity.Metrics;
import org.geysermc.floodgate.api.FloodgateApi;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.Logger;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static net.rafalohaki.veloauth.testsupport.EventTaskTestSupport.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings({"java:S100", "java:S1450", "deprecation", "unchecked"})
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
        FloodgateApi.clear();
        messages = new Messages();
        messages.setLanguage("en");

        when(logger.isDebugEnabled()).thenReturn(false);
        when(logger.isInfoEnabled()).thenReturn(false);
        when(settings.isPremiumCheckEnabled()).thenReturn(true);
        when(settings.isPremiumBypassAuthServerEnabled()).thenReturn(false);
        when(settings.isFloodgateIntegrationEnabled()).thenReturn(false);
        when(settings.isFloodgateBypassAuthServerEnabled()).thenReturn(false);
        when(settings.getAuthServerName()).thenReturn("auth");
        when(connectionManager.getAuthServerName()).thenReturn("auth");
        when(connectionManager.resolveAuthServer()).thenAnswer(ignored -> proxyServer.getServer("auth"));
        when(connectionManager.isAuthServer(any(RegisteredServer.class))).thenAnswer(invocation -> {
            RegisteredServer candidate = invocation.getArgument(0);
            return candidate.getServerInfo() != null
                    && "auth".equals(candidate.getServerInfo().getName());
        });
        when(connectionManager.prepareAuthServerConnection(any(Player.class))).thenReturn(true);
        when(preLoginHandler.isValidUsername(anyString())).thenReturn(true);
        when(preLoginHandler.isBruteForceBlocked(nullable(InetAddress.class), anyString())).thenReturn(false);
        when(databaseManager.findPlayerByNicknameOrPremiumUuidReadOnly(anyString(), nullable(UUID.class)))
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

    @AfterEach
    void tearDown() {
        FloodgateApi.clear();
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
        when(preLoginHandler.resolvePremiumStatusAsync(eq(username), any(InetAddress.class)))
                .thenReturn(firstResolution, secondResolution);

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

        await(firstTask);
        await(secondTask);
    }

    @Test
    void testOnPreLogin_sameUsernameSameIpShouldDenyDuplicateConnectionUntilFirstCompletes() {
        String username = "DuplicateSource";
        CompletableFuture<PreLoginHandler.PremiumResolutionResult> firstResolution = new CompletableFuture<>();
        when(preLoginHandler.resolvePremiumStatusAsync(eq(username), any(InetAddress.class))).thenReturn(
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
        await(firstTask);

        PreLoginEvent thirdEvent = new PreLoginEvent(createConnection("192.0.2.20"), username);
        EventTask thirdTask = authListener.onPreLogin(thirdEvent);

        assertNotNull(thirdTask, "Pending login key should be cleaned after the first attempt finishes");
        await(thirdTask);
        assertTrue(thirdEvent.getResult().isForceOfflineMode(), "Source lock should be released after completion");
    }

    @Test
    void testOnPreLogin_inactiveAttemptShouldYieldLockWithoutOldCompletionClearingReplacement() {
        String username = "ReconnectingPlayer";
        CompletableFuture<PreLoginHandler.PremiumResolutionResult> firstResolution = new CompletableFuture<>();
        CompletableFuture<PreLoginHandler.PremiumResolutionResult> replacementResolution = new CompletableFuture<>();
        when(preLoginHandler.resolvePremiumStatusAsync(eq(username), any(InetAddress.class))).thenReturn(
                firstResolution,
                replacementResolution,
                CompletableFuture.completedFuture(new PreLoginHandler.PremiumResolutionResult(false, null))
        );

        InboundConnection abandonedConnection = createConnection("192.0.2.21");
        when(abandonedConnection.isActive()).thenReturn(false);
        PreLoginEvent abandonedEvent = new PreLoginEvent(abandonedConnection, username);
        PreLoginEvent replacementEvent = new PreLoginEvent(createConnection("192.0.2.21"), username);

        EventTask abandonedTask = authListener.onPreLogin(abandonedEvent);
        EventTask replacementTask = authListener.onPreLogin(replacementEvent);

        assertNotNull(abandonedTask, "First attempt should enter async premium resolution");
        assertNotNull(replacementTask, "A dead connection must not block an immediate reconnect");

        firstResolution.complete(new PreLoginHandler.PremiumResolutionResult(false, null));
        await(abandonedTask);

        PreLoginEvent concurrentEvent = new PreLoginEvent(createConnection("192.0.2.21"), username);
        EventTask concurrentTask = authListener.onPreLogin(concurrentEvent);
        assertNull(concurrentTask, "Completion of the abandoned attempt must not release the replacement lock");
        assertFalse(concurrentEvent.getResult().isAllowed(), "A genuinely concurrent attempt must remain denied");

        replacementResolution.complete(new PreLoginHandler.PremiumResolutionResult(false, null));
        await(replacementTask);

        PreLoginEvent nextEvent = new PreLoginEvent(createConnection("192.0.2.21"), username);
        EventTask nextTask = authListener.onPreLogin(nextEvent);
        assertNotNull(nextTask, "Replacement completion should release its own lock");
        await(nextTask);
        assertTrue(nextEvent.getResult().isForceOfflineMode(), "A later reconnect should proceed normally");
    }

    @Test
    void onPreLogin_linkedFloodgatePlayer_skipsPremiumResolverAndForcesOfflineMode() {
        String linkedUsername = "LinkedJava";
        UUID floodgateUuid = UUID.randomUUID();
        FloodgateApi.install(".", Set.of(floodgateUuid), List.of(
                new FloodgateApi.PlayerView(linkedUsername, ".BedrockUser")));
        when(settings.isFloodgateIntegrationEnabled()).thenReturn(true);

        PreLoginEvent event = new PreLoginEvent(createConnection("192.0.2.25"), linkedUsername);

        Thread callingThread = Thread.currentThread();
        EventTask task = authListener.onPreLogin(event);

        assertNotNull(task, "Floodgate registry scanning must run outside the Velocity event callback");
        await(task);
        assertTrue(event.getResult().isForceOfflineMode(),
                "Linked Bedrock accounts must not be sent through Mojang's Java handshake");
        assertNotSame(callingThread, FloodgateApi.getLastGetPlayersThread(),
                "Floodgate getPlayers() is O(n) and must not run on the event thread");
        verify(preLoginHandler, never()).resolvePremiumStatusAsync(anyString(), nullable(InetAddress.class));
        verify(databaseManager, never())
                .findPlayerByNicknameOrPremiumUuidReadOnly(anyString(), nullable(UUID.class));
    }

    @Test
    void testOnServerPreConnect_firstConnectionShouldUsePreviousServerInsteadOfCurrentServer() {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);

        when(player.getUsername()).thenReturn("RoutingPlayer");
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.isOnlineMode()).thenReturn(true);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));

        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, backendServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNull(task, "First-connection redirect should be resolved synchronously");
        assertSame(authServer, event.getResult().getServer().orElse(null),
                "Previous server semantics should redirect first connections to auth server");
        verify(connectionManager).setForcedHostTarget(player, "backend");
    }

    @Test
    void onServerPreConnect_premiumBypassEnabled_allowsOriginalBackendWithoutTransferState() {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(settings.isPremiumBypassAuthServerEnabled()).thenReturn(true);
        when(player.getUsername()).thenReturn("VerifiedPremium");
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.isOnlineMode()).thenReturn(true);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, backendServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNull(task, "Direct premium backend routing should remain a synchronous fast path");
        assertSame(backendServer, event.getResult().getServer().orElse(null));
        verify(connectionManager, never()).setForcedHostTarget(any(Player.class), anyString());
        verify(connectionManager, never()).findAvailableBackendServerForInitialConnectionAsync();
        verify(postLoginHandler, never()).handlePremiumPlayer(eq(player), anyString());
    }

    @Test
    void onServerPreConnect_premiumBypassEnabled_offlinePlayerStillUsesAuthServer() {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(settings.isPremiumBypassAuthServerEnabled()).thenReturn(true);
        when(player.getUsername()).thenReturn("OfflinePlayer");
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.isOnlineMode()).thenReturn(false);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, backendServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNull(task);
        assertSame(authServer, event.getResult().getServer().orElse(null));
        verify(connectionManager).setForcedHostTarget(player, "backend");
    }

    @Test
    void onServerPreConnect_premiumBypassEnabled_initialAuthTargetSelectsBackendAsync() {
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(settings.isPremiumBypassAuthServerEnabled()).thenReturn(true);
        when(player.getUsername()).thenReturn("PremiumAuthTarget");
        when(player.getUniqueId()).thenReturn(UUID.randomUUID());
        when(player.isOnlineMode()).thenReturn(true);
        when(player.isActive()).thenReturn(true);
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(connectionManager.findAvailableBackendServerForInitialConnectionAsync())
                .thenReturn(CompletableFuture.completedFuture(Optional.of(backendServer)));
        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, authServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNotNull(task, "Selecting a backend may ping servers and must suspend the event asynchronously");
        await(task);
        assertSame(backendServer, event.getResult().getServer().orElse(null));
        verify(connectionManager, never()).setForcedHostTarget(any(Player.class), anyString());
        verify(postLoginHandler, never()).handlePremiumPlayer(eq(player), anyString());
    }

    @Test
    void onServerPreConnect_premiumBypassEnabled_withoutAvailableBackendDeniesFailSecure() {
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(settings.isPremiumBypassAuthServerEnabled()).thenReturn(true);
        when(player.getUsername()).thenReturn("PremiumWithoutBackend");
        when(player.getUniqueId()).thenReturn(UUID.randomUUID());
        when(player.isOnlineMode()).thenReturn(true);
        when(player.isActive()).thenReturn(true);
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(connectionManager.findAvailableBackendServerForInitialConnectionAsync())
                .thenReturn(CompletableFuture.completedFuture(Optional.empty()));
        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, authServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNotNull(task);
        await(task);
        assertFalse(event.getResult().isAllowed(), "Missing backend must never fall through to limbo as a fake bypass");
    }

    @Test
    void onServerPreConnect_premiumBypassEnabled_backendSelectionFailureDeniesFailSecure() {
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(settings.isPremiumBypassAuthServerEnabled()).thenReturn(true);
        when(player.getUsername()).thenReturn("PremiumSelectionFailure");
        when(player.getUniqueId()).thenReturn(UUID.randomUUID());
        when(player.isOnlineMode()).thenReturn(true);
        when(player.isActive()).thenReturn(true);
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(connectionManager.findAvailableBackendServerForInitialConnectionAsync())
                .thenReturn(CompletableFuture.failedFuture(new IllegalStateException("selection failed")));
        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, authServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNotNull(task);
        await(task);
        assertFalse(event.getResult().isAllowed(), "Selection errors must deny the connection fail-secure");
    }

    @Test
    void onServerPreConnect_premiumBypassRevokedWhileSelectingBackend_deniesFailSecure() {
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        CompletableFuture<Optional<RegisteredServer>> pendingBackend = new CompletableFuture<>();
        when(settings.isPremiumBypassAuthServerEnabled()).thenReturn(true, false);
        when(player.getUsername()).thenReturn("PremiumBypassRevoked");
        when(player.getUniqueId()).thenReturn(UUID.randomUUID());
        when(player.isOnlineMode()).thenReturn(true);
        when(player.isActive()).thenReturn(true);
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(connectionManager.findAvailableBackendServerForInitialConnectionAsync())
                .thenReturn(pendingBackend);
        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, authServer);

        EventTask task = authListener.onServerPreConnect(event);
        pendingBackend.complete(Optional.of(backendServer));

        assertNotNull(task);
        await(task);
        assertFalse(event.getResult().isAllowed(),
                "A bypass disabled during asynchronous selection must not route around auth");
    }

    @Test
    void testOnServerPreConnect_firstConnectionToAuthServerShouldBeAllowedWithoutForcedHostTarget() {
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);

        when(player.getUsername()).thenReturn("AuthRoutingPlayer");
        when(player.getUniqueId()).thenReturn(UUID.randomUUID());
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));

        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, authServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNull(task, "First connection to auth server should stay synchronous");
        assertTrue(event.getResult().isAllowed(), "Initial auth-server target should be allowed");
        assertSame(authServer, event.getResult().getServer().orElse(null));
        verify(connectionManager, never()).setForcedHostTarget(any(Player.class), anyString());
    }

    @Test
    void onServerPreConnect_embeddedPreparationFailure_ShouldDenyFailSecure() {
        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(player.getUsername()).thenReturn("RejectedEmbeddedPlayer");
        when(player.getUniqueId()).thenReturn(UUID.randomUUID());
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(connectionManager.prepareAuthServerConnection(player)).thenReturn(false);
        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, authServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNull(task);
        assertFalse(event.getResult().isAllowed(),
                "Missing protocol support, capacity or forwarding trust must fail closed");
        verify(connectionManager, never()).setForcedHostTarget(any(Player.class), anyString());
    }

    @Test
    void onServerPreConnect_floodgateConfirmedUuid_bypassesAuthServer() {
        UUID bedrockUuid = UUID.randomUUID();
        FloodgateApi.install(".", Set.of(bedrockUuid), List.of());
        when(settings.isFloodgateIntegrationEnabled()).thenReturn(true);
        when(settings.isFloodgateBypassAuthServerEnabled()).thenReturn(true);

        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUsername()).thenReturn(".BedrockUser");
        when(player.getUniqueId()).thenReturn(bedrockUuid);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, backendServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNull(task);
        assertSame(backendServer, event.getResult().getServer().orElse(null));
        verify(connectionManager, never()).setForcedHostTarget(any(Player.class), anyString());
    }

    @Test
    void onServerPreConnect_floodgateConfirmedUuid_initialAuthTargetSelectsBackendAsync() {
        UUID bedrockUuid = UUID.randomUUID();
        FloodgateApi.install(".", Set.of(bedrockUuid), List.of());
        when(settings.isFloodgateIntegrationEnabled()).thenReturn(true);
        when(settings.isFloodgateBypassAuthServerEnabled()).thenReturn(true);

        Player player = org.mockito.Mockito.mock(Player.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(player.getUsername()).thenReturn(".BedrockAuthTarget");
        when(player.getUniqueId()).thenReturn(bedrockUuid);
        when(player.isActive()).thenReturn(true);
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(connectionManager.findAvailableBackendServerForInitialConnectionAsync())
                .thenReturn(CompletableFuture.completedFuture(Optional.of(backendServer)));
        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, authServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNotNull(task, "Floodgate bypass must not leave a trusted player parked on auth");
        await(task);
        assertSame(backendServer, event.getResult().getServer().orElse(null));
        verify(connectionManager, never()).setForcedHostTarget(any(Player.class), anyString());
    }

    @Test
    void onServerPreConnect_prefixOnlyWithoutFloodgateUuid_doesNotBypassAuthServer() {
        UUID unverifiedUuid = UUID.randomUUID();
        FloodgateApi.install(".", Set.of(), List.of());
        when(settings.isFloodgateIntegrationEnabled()).thenReturn(true);
        when(settings.isFloodgateBypassAuthServerEnabled()).thenReturn(true);

        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUsername()).thenReturn(".Pretender");
        when(player.getUniqueId()).thenReturn(unverifiedUuid);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        when(proxyServer.getServer("auth")).thenReturn(Optional.of(authServer));
        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, backendServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNull(task);
        assertSame(authServer, event.getResult().getServer().orElse(null),
                "A username prefix alone must never grant Bedrock auth bypass");
        verify(connectionManager).setForcedHostTarget(player, "backend");
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

        activateConnection(player);
        ServerPreConnectEvent event = new ServerPreConnectEvent(player, backendServer, previousServer);

        EventTask task = authListener.onServerPreConnect(event);

        assertNotNull(task, "Backend UUID verification should be asynchronous");
        await(task);
        assertFalse(event.getResult().isAllowed(), "UUID mismatch must deny backend access");
        verify(authCache, atLeastOnce()).removeAuthorizedPlayer(playerUuid);
        verify(authCache, atLeastOnce()).endSession(playerUuid);
    }

    @ParameterizedTest
    @EnumSource(PendingTotpState.Kind.class)
    void onDisconnect_CurrentLogoutOwner_InvalidatesSessionAndPendingTwoFactor(
            PendingTotpState.Kind pendingKind) throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("DisconnectedPlayer");
        PendingTotpStore pendingTotpStore = new PendingTotpStore(Duration.ofMinutes(5), null);
        PendingTotpState pendingState = pendingKind == PendingTotpState.Kind.LOGIN
                ? PendingTotpState.forLogin(
                        playerUuid, org.mockito.Mockito.mock(RegisteredPlayer.class), "192.0.2.50")
                : PendingTotpState.forSetup(playerUuid, "JBSWY3DPEHPK3PXP", "192.0.2.50");
        pendingTotpStore.put(pendingState);
        TotpReplayGuard replayGuard = new TotpReplayGuard();
        assertTrue(replayGuard.consume(playerUuid, 100L));
        AuthTimeoutScheduler timeoutScheduler = org.mockito.Mockito.mock(AuthTimeoutScheduler.class);
        setPluginField("pendingTotpStore", pendingTotpStore);
        setPluginField("totpReplayGuard", replayGuard);
        setPluginField("authTimeoutScheduler", timeoutScheduler);

        authListener.onDisconnect(new DisconnectEvent(
                player, DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN));

        verify(authCache).removeAuthorizedPlayer(playerUuid);
        verify(authCache).endSession(playerUuid);
        verify(connectionManager).clearTransferState(player);
        verify(timeoutScheduler).cancel(playerUuid);
        assertTrue(pendingTotpStore.get(playerUuid).isEmpty(),
                "A disconnected connection must not leave a reusable 2FA continuation");
        assertFalse(replayGuard.consume(playerUuid, 100L),
                "Logout must not reset the one-time TOTP replay window");
    }

    @Test
    void onDisconnect_TransferCleanupFailure_StillCancelsTimeoutAndRetiresOwner()
            throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("CleanupFailurePlayer");
        AuthTimeoutScheduler timeoutScheduler = org.mockito.Mockito.mock(AuthTimeoutScheduler.class);
        setPluginField("authTimeoutScheduler", timeoutScheduler);
        activateConnection(player);
        org.mockito.Mockito.doThrow(new IllegalStateException("controlled transfer cleanup failure"))
                .when(connectionManager).clearTransferState(player);

        authListener.onDisconnect(new DisconnectEvent(
                player, DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN));

        verify(authCache).removeAuthorizedPlayer(playerUuid);
        verify(authCache).endSession(playerUuid);
        verify(timeoutScheduler).cancel(playerUuid);
        assertNull(plugin.getConnectionLifecycleRegistry().capture(player),
                "Cleanup failure must not preserve a current lifecycle owner");
    }

    @Test
    void onDisconnect_conflictingLogin_doesNotClearActivePlayersUuidState() {
        UUID sharedOfflineUuid = UUID.randomUUID();
        Player activePlayer = org.mockito.Mockito.mock(Player.class);
        Player conflictingConnection = org.mockito.Mockito.mock(Player.class);
        when(activePlayer.getUniqueId()).thenReturn(sharedOfflineUuid);
        when(conflictingConnection.getUniqueId()).thenReturn(sharedOfflineUuid);
        when(conflictingConnection.getUsername()).thenReturn("DuplicateName");
        when(proxyServer.getPlayer(sharedOfflineUuid)).thenReturn(Optional.of(activePlayer));

        authListener.onDisconnect(new DisconnectEvent(
                conflictingConnection, DisconnectEvent.LoginStatus.CONFLICTING_LOGIN));

        verify(authCache, never()).removeAuthorizedPlayer(sharedOfflineUuid);
        verify(authCache, never()).endSession(sharedOfflineUuid);
        verify(connectionManager, never()).clearTransferState(any(Player.class));
    }

    @Test
    void onPostLogin_replacementConnection_publishesNewOwnerBeforeClearingOldOwnerAndRouting() {
        UUID sharedOfflineUuid = UUID.randomUUID();
        Player oldConnection = org.mockito.Mockito.mock(Player.class);
        Player replacementConnection = org.mockito.Mockito.mock(Player.class);
        when(oldConnection.getUniqueId()).thenReturn(sharedOfflineUuid);
        when(oldConnection.getUsername()).thenReturn("ReconnectPlayer");
        when(oldConnection.getRemoteAddress()).thenReturn(
                new InetSocketAddress("192.0.2.70", 25565));
        when(replacementConnection.getUniqueId()).thenReturn(sharedOfflineUuid);
        when(replacementConnection.getUsername()).thenReturn("ReconnectPlayer");
        when(replacementConnection.getRemoteAddress()).thenReturn(
                new InetSocketAddress("192.0.2.70", 25565));

        AtomicBoolean delayedDisconnectObservedNewOwner = new AtomicBoolean();
        doAnswer(ignored -> {
            authListener.onDisconnect(new DisconnectEvent(
                    oldConnection, DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN));
            delayedDisconnectObservedNewOwner.set(true);
            return null;
        }).when(connectionManager).beginTransferSession(replacementConnection);

        authListener.onPostLogin(new PostLoginEvent(oldConnection));
        org.mockito.Mockito.clearInvocations(connectionManager, postLoginHandler, authCache);
        authListener.onPostLogin(new PostLoginEvent(replacementConnection));

        assertTrue(delayedDisconnectObservedNewOwner.get(),
                "Replacement publication hook must observe B as the active listener owner");
        verify(authCache).removeAuthorizedPlayer(sharedOfflineUuid);
        verify(authCache).endSession(sharedOfflineUuid);
        var routingOrder = inOrder(connectionManager, postLoginHandler);
        routingOrder.verify(connectionManager).beginTransferSession(replacementConnection);
        routingOrder.verify(connectionManager).clearTransferState(oldConnection);
        routingOrder.verify(postLoginHandler).handleOfflinePlayer(replacementConnection, "192.0.2.70");
    }

    @Test
    void onPostLogin_TransferPublicationFailureRetiresAndDisconnectsReplacement() {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("FailedPublicationPlayer");
        when(player.getRemoteAddress()).thenReturn(
                new InetSocketAddress("192.0.2.76", 25565));
        org.mockito.Mockito.doThrow(new IllegalStateException("controlled task cancellation failure"))
                .when(connectionManager).beginTransferSession(player);

        authListener.onPostLogin(new PostLoginEvent(player));

        assertNull(plugin.getConnectionLifecycleRegistry().capture(player),
                "A failed transfer publication must not leave a current lifecycle owner");
        verify(authCache).removeAuthorizedPlayer(playerUuid);
        verify(authCache).endSession(playerUuid);
        verify(connectionManager).clearTransferState(player);
        verify(player).disconnect(any(Component.class));
        verify(postLoginHandler, never()).handleOfflinePlayer(any(Player.class), anyString());
        verify(postLoginHandler, never()).handlePremiumPlayer(any(Player.class), anyString());
    }

    @Test
    void onPostLogin_PremiumConnectionRetiredAfterActivation_DoesNotAuthorizeAfterLogout()
            throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("RetiredPremiumPlayer");
        when(player.isOnlineMode()).thenReturn(true);
        CountDownLatch addressLookupEntered = new CountDownLatch(1);
        CountDownLatch releaseAddressLookup = new CountDownLatch(1);
        doAnswer(ignored -> {
            if (addressLookupEntered.getCount() != 0L) {
                addressLookupEntered.countDown();
                assertTrue(releaseAddressLookup.await(2, TimeUnit.SECONDS));
            }
            return new InetSocketAddress("192.0.2.75", 25565);
        }).when(player).getRemoteAddress();

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<?> postLogin = executor.submit(
                    () -> authListener.onPostLogin(new PostLoginEvent(player)));
            assertTrue(addressLookupEntered.await(2, TimeUnit.SECONDS),
                    "PostLogin must publish the lifecycle generation before logout");

            authListener.onDisconnect(new DisconnectEvent(
                    player, DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN));
            releaseAddressLookup.countDown();
            postLogin.get(2, TimeUnit.SECONDS);
        }

        verify(postLoginHandler, never()).handlePremiumPlayer(player, "192.0.2.75");
        verify(authCache, never()).authorize(eq(playerUuid), any(), anyString(), anyString());
    }

    @Test
    void conflictMessageLookup_CompletesAfterLogout_DoesNotMessageRetiredConnection()
            throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("RetiredConflictPlayer");
        CountDownLatch conflictLookupEntered = new CountDownLatch(1);
        CountDownLatch releaseConflictLookup = new CountDownLatch(1);
        doAnswer(ignored -> {
            conflictLookupEntered.countDown();
            assertTrue(releaseConflictLookup.await(2, TimeUnit.SECONDS));
            return true;
        }).when(postLoginHandler).shouldShowConflictMessage(player);
        var operation = plugin.getConnectionLifecycleRegistry().activate(player, ignored -> { });
        assertNotNull(operation);

        CompletableFuture<Void> lookup = authListener.checkConflictMessageAsync(player, operation);
        assertTrue(conflictLookupEntered.await(2, TimeUnit.SECONDS));
        authListener.onDisconnect(new DisconnectEvent(
                player, DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN));
        releaseConflictLookup.countDown();
        lookup.get(2, TimeUnit.SECONDS);

        verify(postLoginHandler, never()).showConflictResolutionMessage(player);
    }

    @Test
    void onServerPreConnect_StaleUuidMismatchCompletion_DoesNotClearReplacementAuthorization() {
        UUID sharedUuid = UUID.randomUUID();
        Player staleConnection = org.mockito.Mockito.mock(Player.class);
        Player replacementConnection = org.mockito.Mockito.mock(Player.class);
        for (Player connection : List.of(staleConnection, replacementConnection)) {
            when(connection.getUniqueId()).thenReturn(sharedUuid);
            when(connection.getUsername()).thenReturn("UuidCheckReplacement");
            when(connection.getRemoteAddress()).thenReturn(
                    new InetSocketAddress("192.0.2.78", 25565));
            when(connection.isOnlineMode()).thenReturn(false);
            when(connection.isActive()).thenReturn(true);
        }
        CompletableFuture<DatabaseManager.DbResult<RegisteredPlayer>> pendingLookup =
                new CompletableFuture<>();
        when(databaseManager.findPlayerByNickname("UuidCheckReplacement"))
                .thenReturn(pendingLookup);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        activateConnection(staleConnection);
        ServerPreConnectEvent staleEvent =
                new ServerPreConnectEvent(staleConnection, backendServer, authServer);
        EventTask staleVerification = authListener.onServerPreConnect(staleEvent);
        assertNotNull(staleVerification);

        authListener.onPostLogin(new PostLoginEvent(replacementConnection));
        org.mockito.Mockito.clearInvocations(authCache);
        RegisteredPlayer mismatchedOwner = new RegisteredPlayer();
        mismatchedOwner.setNickname("UuidCheckReplacement");
        mismatchedOwner.setUuid(UUID.randomUUID().toString());
        pendingLookup.complete(DatabaseManager.DbResult.success(mismatchedOwner));
        await(staleVerification);

        assertFalse(staleEvent.getResult().isAllowed(),
                "A stale verification completion must remain fail-closed");
        verify(authCache, never()).removeAuthorizedPlayer(sharedUuid);
        verify(authCache, never()).endSession(sharedUuid);
    }

    @Test
    void onServerPreConnect_PremiumGenerationReplacedDuringCacheRead_DeniesStaleEvent() {
        UUID sharedUuid = UUID.randomUUID();
        Player staleConnection = org.mockito.Mockito.mock(Player.class);
        Player replacementConnection = org.mockito.Mockito.mock(Player.class);
        when(staleConnection.getUniqueId()).thenReturn(sharedUuid);
        when(staleConnection.getUsername()).thenReturn("PremiumReplacement");
        when(staleConnection.getRemoteAddress()).thenReturn(
                new InetSocketAddress("192.0.2.79", 25565));
        when(staleConnection.isOnlineMode()).thenReturn(true);
        when(replacementConnection.getUniqueId()).thenReturn(sharedUuid);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        activateConnection(staleConnection);
        when(authCache.isPlayerAuthorized(sharedUuid, "192.0.2.79")).thenAnswer(ignored -> {
            assertNotNull(plugin.getConnectionLifecycleRegistry().activate(
                    replacementConnection, previous -> { }));
            return false;
        });
        ServerPreConnectEvent staleEvent =
                new ServerPreConnectEvent(staleConnection, backendServer, authServer);

        EventTask task = authListener.onServerPreConnect(staleEvent);
        if (task != null) {
            await(task);
        }

        assertFalse(staleEvent.getResult().isAllowed(),
                "A premium event replaced during its cache read must stay fail-closed");
        verify(postLoginHandler, never()).handlePremiumPlayer(staleConnection, "192.0.2.79");
    }

    @Test
    void onServerPreConnect_OfflineUuidCompletionForInactiveOwner_DeniesEvent() {
        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("InactiveUuidOwner");
        when(player.getRemoteAddress()).thenReturn(
                new InetSocketAddress("192.0.2.80", 25565));
        when(player.isOnlineMode()).thenReturn(false);
        when(player.isActive()).thenReturn(false);
        RegisteredPlayer storedPlayer = new RegisteredPlayer();
        storedPlayer.setNickname("InactiveUuidOwner");
        storedPlayer.setUuid(playerUuid.toString());
        when(databaseManager.findPlayerByNickname("InactiveUuidOwner"))
                .thenReturn(CompletableFuture.completedFuture(
                        DatabaseManager.DbResult.success(storedPlayer)));
        when(authCache.isPlayerAuthorized(playerUuid, "192.0.2.80")).thenReturn(true);
        when(authCache.hasActiveSession(
                playerUuid, "InactiveUuidOwner", "192.0.2.80")).thenReturn(true);
        RegisteredServer backendServer = org.mockito.Mockito.mock(RegisteredServer.class);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        when(backendServer.getServerInfo()).thenReturn(
                new ServerInfo("backend", InetSocketAddress.createUnresolved("127.0.0.1", 25566)));
        when(authServer.getServerInfo()).thenReturn(
                new ServerInfo("auth", InetSocketAddress.createUnresolved("127.0.0.1", 25565)));
        activateConnection(player);
        ServerPreConnectEvent event =
                new ServerPreConnectEvent(player, backendServer, authServer);

        EventTask task = authListener.onServerPreConnect(event);
        assertNotNull(task);
        await(task);

        assertFalse(event.getResult().isAllowed(),
                "An inactive concrete connection must never inherit the default allow result");
    }

    @Test
    void onServerConnected_ReplacedConnectionCannotReplaceCurrentOwnersAuthTimeout()
            throws Exception {
        UUID playerUuid = UUID.randomUUID();
        Player staleConnection = org.mockito.Mockito.mock(Player.class);
        Player currentConnection = org.mockito.Mockito.mock(Player.class);
        for (Player connection : List.of(staleConnection, currentConnection)) {
            when(connection.getUniqueId()).thenReturn(playerUuid);
            when(connection.getUsername()).thenReturn("TimeoutOwnerPlayer");
            when(connection.getRemoteAddress()).thenReturn(
                    new InetSocketAddress("192.0.2.77", 25565));
            when(connection.isOnlineMode()).thenReturn(false);
        }
        when(authCache.isPlayerAuthorized(playerUuid, "192.0.2.77")).thenReturn(false);
        when(databaseManager.findPlayerByNickname("TimeoutOwnerPlayer"))
                .thenReturn(new CompletableFuture<>());
        AuthTimeoutScheduler timeoutScheduler = org.mockito.Mockito.mock(AuthTimeoutScheduler.class);
        setPluginField("authTimeoutScheduler", timeoutScheduler);
        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerInfo authServerInfo = org.mockito.Mockito.mock(ServerInfo.class);
        when(authServer.getServerInfo()).thenReturn(authServerInfo);
        when(authServerInfo.getName()).thenReturn("auth");

        authListener.onPostLogin(new PostLoginEvent(staleConnection));
        authListener.onPostLogin(new PostLoginEvent(currentConnection));
        authListener.onServerConnected(new ServerConnectedEvent(currentConnection, authServer, null));
        authListener.onServerConnected(new ServerConnectedEvent(staleConnection, authServer, null));

        verify(timeoutScheduler).schedule(currentConnection);
        verify(timeoutScheduler, never()).schedule(staleConnection);
        verify(staleConnection, never()).sendMessage(any(Component.class));
    }

    @Test
    void onDisconnect_LogoutFromReplacedConnection_DoesNotClearReplacementState() throws Exception {
        UUID sharedOfflineUuid = UUID.randomUUID();
        Player oldConnection = org.mockito.Mockito.mock(Player.class);
        Player replacementConnection = org.mockito.Mockito.mock(Player.class);
        when(oldConnection.getUniqueId()).thenReturn(sharedOfflineUuid);
        when(oldConnection.getUsername()).thenReturn("LogoutReplacementPlayer");
        when(oldConnection.getRemoteAddress()).thenReturn(
                new InetSocketAddress("192.0.2.71", 25565));
        when(replacementConnection.getUniqueId()).thenReturn(sharedOfflineUuid);
        when(replacementConnection.getUsername()).thenReturn("LogoutReplacementPlayer");
        when(replacementConnection.getRemoteAddress()).thenReturn(
                new InetSocketAddress("192.0.2.72", 25565));

        authListener.onPostLogin(new PostLoginEvent(oldConnection));
        authListener.onPostLogin(new PostLoginEvent(replacementConnection));

        PendingTotpStore replacementPending = new PendingTotpStore(Duration.ofMinutes(5), null);
        replacementPending.put(PendingTotpState.forSetup(
                sharedOfflineUuid, "JBSWY3DPEHPK3PXP", "192.0.2.72"));
        AuthTimeoutScheduler timeoutScheduler = org.mockito.Mockito.mock(AuthTimeoutScheduler.class);
        setPluginField("pendingTotpStore", replacementPending);
        setPluginField("authTimeoutScheduler", timeoutScheduler);
        org.mockito.Mockito.clearInvocations(authCache, connectionManager, timeoutScheduler);

        authListener.onDisconnect(new DisconnectEvent(
                oldConnection, DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN));

        verify(authCache, never()).removeAuthorizedPlayer(sharedOfflineUuid);
        verify(authCache, never()).endSession(sharedOfflineUuid);
        verify(connectionManager, never()).clearTransferState(any(Player.class));
        verify(timeoutScheduler, never()).cancel(sharedOfflineUuid);
        assertTrue(replacementPending.get(sharedOfflineUuid).isPresent(),
                "A stale logout disconnect must not invalidate B's pending 2FA state");
    }

    @Test
    void onDisconnect_OwnerCleanupInterleavesWithReplacementPublication_DoesNotClearReplacement()
            throws Exception {
        UUID sharedOfflineUuid = UUID.randomUUID();
        Player oldConnection = org.mockito.Mockito.mock(Player.class);
        Player replacementConnection = org.mockito.Mockito.mock(Player.class);
        when(oldConnection.getUniqueId()).thenReturn(sharedOfflineUuid);
        when(oldConnection.getUsername()).thenReturn("InterleavedReplacementPlayer");
        when(oldConnection.getRemoteAddress()).thenReturn(
                new InetSocketAddress("192.0.2.73", 25565));
        when(replacementConnection.getUniqueId()).thenReturn(sharedOfflineUuid);
        when(replacementConnection.getUsername()).thenReturn("InterleavedReplacementPlayer");
        when(replacementConnection.getRemoteAddress()).thenReturn(
                new InetSocketAddress("192.0.2.74", 25565));

        PendingTotpStore replacementPending = new PendingTotpStore(Duration.ofMinutes(5), null);
        AuthTimeoutScheduler timeoutScheduler = org.mockito.Mockito.mock(AuthTimeoutScheduler.class);
        setPluginField("pendingTotpStore", replacementPending);
        setPluginField("authTimeoutScheduler", timeoutScheduler);

        authListener.onPostLogin(new PostLoginEvent(oldConnection));
        org.mockito.Mockito.clearInvocations(authCache, connectionManager, timeoutScheduler);

        CountDownLatch oldCleanupEntered = new CountDownLatch(1);
        CountDownLatch releaseOldCleanup = new CountDownLatch(1);
        CountDownLatch replacementAttempted = new CountDownLatch(1);
        doAnswer(ignored -> {
            oldCleanupEntered.countDown();
            assertTrue(releaseOldCleanup.await(2, TimeUnit.SECONDS));
            return null;
        }).when(authCache).removeAuthorizedPlayer(sharedOfflineUuid);
        doAnswer(ignored -> {
            replacementPending.put(PendingTotpState.forSetup(
                    sharedOfflineUuid, "JBSWY3DPEHPK3PXP", "192.0.2.74"));
            timeoutScheduler.schedule(replacementConnection);
            return null;
        }).when(connectionManager).beginTransferSession(replacementConnection);

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<?> oldDisconnect = executor.submit(() -> authListener.onDisconnect(
                    new DisconnectEvent(oldConnection, DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN)));
            assertTrue(oldCleanupEntered.await(1, TimeUnit.SECONDS),
                    "The old owner must enter cleanup before B is published");
            Future<?> replacementLogin = executor.submit(() -> {
                replacementAttempted.countDown();
                authListener.onPostLogin(new PostLoginEvent(replacementConnection));
            });
            assertTrue(replacementAttempted.await(2, TimeUnit.SECONDS));
            releaseOldCleanup.countDown();

            oldDisconnect.get(3, TimeUnit.SECONDS);
            replacementLogin.get(3, TimeUnit.SECONDS);
        }

        assertTrue(replacementPending.get(sharedOfflineUuid).isPresent(),
                "A cleanup that already claimed A must not erase B published concurrently");
        var timeoutOrder = inOrder(timeoutScheduler);
        timeoutOrder.verify(timeoutScheduler).cancel(sharedOfflineUuid);
        timeoutOrder.verify(timeoutScheduler).schedule(replacementConnection);
    }

    @Test
    void onServerConnected_authHeaderWithHexFormatting_parsesColors() throws Exception {
        messages = new Messages() {
            @Override
            public String get(String key, Object... args) {
                if ("auth.header".equals(key)) {
                    return "<#FF6700>&lSecurity";
                }
                return super.get(key, args);
            }
        };
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

        UUID playerUuid = UUID.randomUUID();
        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn("GradientPlayer");
        when(player.getRemoteAddress()).thenReturn(new InetSocketAddress("192.0.2.80", 25565));
        when(player.isOnlineMode()).thenReturn(false);
        when(authCache.isPlayerAuthorized(playerUuid, "192.0.2.80")).thenReturn(false);
        when(databaseManager.findPlayerByNickname("GradientPlayer"))
                .thenReturn(new CompletableFuture<>());

        RegisteredServer authServer = org.mockito.Mockito.mock(RegisteredServer.class);
        ServerInfo serverInfo = org.mockito.Mockito.mock(ServerInfo.class);
        when(authServer.getServerInfo()).thenReturn(serverInfo);
        when(serverInfo.getName()).thenReturn("auth");
        AuthTimeoutScheduler timeoutScheduler = org.mockito.Mockito.mock(AuthTimeoutScheduler.class);
        setPluginField("authTimeoutScheduler", timeoutScheduler);

        activateConnection(player);
        authListener.onServerConnected(new ServerConnectedEvent(player, authServer, null));

        ArgumentCaptor<net.kyori.adventure.text.Component> componentCaptor =
                ArgumentCaptor.forClass(net.kyori.adventure.text.Component.class);
        verify(player).sendMessage(componentCaptor.capture());
        net.kyori.adventure.text.Component header = componentCaptor.getValue();
        assertEquals("Security", PLAIN_TEXT.serialize(header));
        assertEquals(TextColor.color(0xFF6700), header.color());
        assertEquals(TextDecoration.State.TRUE, header.decoration(TextDecoration.BOLD));
    }

    @Test
    void onPreLogin_premiumNickWithoutDbRecord_andFlagEnabled_forcesOfflineMode() {
        String username = "CrackedOnPremium";
        UUID premiumUuid = UUID.randomUUID();
        when(settings.isAllowCrackedOnPremiumNicks()).thenReturn(true);
        when(preLoginHandler.resolvePremiumStatusAsync(eq(username), any(InetAddress.class)))
                .thenReturn(CompletableFuture.completedFuture(
                        new PreLoginHandler.PremiumResolutionResult(true, premiumUuid)));
        when(databaseManager.findPlayerByNicknameOrPremiumUuidReadOnly(username, premiumUuid))
                .thenReturn(CompletableFuture.completedFuture(DatabaseManager.DbResult.success(null)));

        PreLoginEvent event = new PreLoginEvent(createConnection("192.0.2.30"), username);

        EventTask task = authListener.onPreLogin(event);

        assertNotNull(task, "Premium resolution path must run asynchronously");
        await(task);
        assertTrue(event.getResult().isForceOfflineMode(),
                "Flag-enabled bypass must force offline mode so cracked clients can register the nick");
    }

    @Test
    void onPreLogin_premiumNickWithoutDbRecord_andFlagDisabled_forcesOnlineMode() {
        String username = "DefaultPremiumNick";
        UUID premiumUuid = UUID.randomUUID();
        when(settings.isAllowCrackedOnPremiumNicks()).thenReturn(false);
        when(preLoginHandler.resolvePremiumStatusAsync(eq(username), any(InetAddress.class)))
                .thenReturn(CompletableFuture.completedFuture(
                        new PreLoginHandler.PremiumResolutionResult(true, premiumUuid)));
        when(databaseManager.findPlayerByNicknameOrPremiumUuidReadOnly(username, premiumUuid))
                .thenReturn(CompletableFuture.completedFuture(DatabaseManager.DbResult.success(null)));

        PreLoginEvent event = new PreLoginEvent(createConnection("192.0.2.31"), username);

        EventTask task = authListener.onPreLogin(event);

        assertNotNull(task);
        await(task);
        assertTrue(event.getResult().isOnlineModeAllowed(),
                "Default (flag off) must keep nickname-theft protection: Mojang handshake forced");
    }

    @Test
    void onPreLogin_premiumNickWithExistingPremiumRecord_andFlagEnabled_stillForcesOnlineMode() {
        String username = "LegitPremiumOwner";
        UUID premiumUuid = UUID.randomUUID();
        when(settings.isAllowCrackedOnPremiumNicks()).thenReturn(true);
        when(preLoginHandler.resolvePremiumStatusAsync(eq(username), any(InetAddress.class)))
                .thenReturn(CompletableFuture.completedFuture(
                        new PreLoginHandler.PremiumResolutionResult(true, premiumUuid)));

        RegisteredPlayer storedPlayer = new RegisteredPlayer();
        storedPlayer.setNickname(username);
        storedPlayer.setUuid(premiumUuid.toString());
        storedPlayer.setPremiumUuid(premiumUuid.toString());
        when(databaseManager.findPlayerByNicknameOrPremiumUuidReadOnly(username, premiumUuid))
                .thenReturn(CompletableFuture.completedFuture(DatabaseManager.DbResult.success(storedPlayer)));
        when(databaseManager.isPlayerPremiumRuntime(storedPlayer)).thenReturn(true);
        when(preLoginHandler.isNicknameConflict(storedPlayer, true, true, premiumUuid)).thenReturn(false);

        PreLoginEvent event = new PreLoginEvent(createConnection("192.0.2.32"), username);

        EventTask task = authListener.onPreLogin(event);

        assertNotNull(task);
        await(task);
        assertTrue(event.getResult().isOnlineModeAllowed(),
                "SECURITY: returning premium owner with matching DB record must NEVER skip Mojang handshake even when the bypass flag is on");
    }

    @Test
    void onGameProfileRequest_legacyBindingShouldExposeHistoricalUuidAndCacheVerifiedUuid() {
        String username = "LegacyPremium";
        UUID verifiedPremiumUuid = UUID.randomUUID();
        UUID historicalBackendUuid = UUID.randomUUID();
        InboundConnection connection = createConnection("192.0.2.40");
        GameProfile originalProfile = new GameProfile(verifiedPremiumUuid, username, java.util.List.of());
        when(databaseManager.reconcileVerifiedPremiumProfile(username, verifiedPremiumUuid))
                .thenReturn(CompletableFuture.completedFuture(DatabaseManager.DbResult.success(
                        new DatabaseManager.PremiumProfileBinding(
                                historicalBackendUuid, verifiedPremiumUuid, true))));
        GameProfileRequestEvent event = new GameProfileRequestEvent(connection, originalProfile, true);

        EventTask task = authListener.onGameProfileRequest(event);

        assertNotNull(task);
        await(task);
        assertEquals(historicalBackendUuid, event.getGameProfile().getId());
        assertEquals(originalProfile.getProperties(), event.getGameProfile().getProperties(),
                "UUID rewrite must retain Mojang-signed profile properties");
        verify(authCache).addPremiumPlayer(username, verifiedPremiumUuid);
    }

    @Test
    void onGameProfileRequest_databaseFailureShouldDenyAtLoginEvent() {
        String username = "UnsafeBinding";
        UUID verifiedPremiumUuid = UUID.randomUUID();
        InetSocketAddress address = new InetSocketAddress("192.0.2.41", 25565);
        InboundConnection connection = org.mockito.Mockito.mock(InboundConnection.class);
        when(connection.getRemoteAddress()).thenReturn(address);
        GameProfile originalProfile = new GameProfile(verifiedPremiumUuid, username, java.util.List.of());
        when(databaseManager.reconcileVerifiedPremiumProfile(username, verifiedPremiumUuid))
                .thenReturn(CompletableFuture.completedFuture(
                        DatabaseManager.DbResult.databaseError("database.error")));
        GameProfileRequestEvent profileEvent = new GameProfileRequestEvent(connection, originalProfile, true);
        await(authListener.onGameProfileRequest(profileEvent));

        Player player = org.mockito.Mockito.mock(Player.class);
        when(player.getUsername()).thenReturn(username);
        when(player.getUniqueId()).thenReturn(verifiedPremiumUuid);
        when(player.getRemoteAddress()).thenReturn(address);
        LoginEvent loginEvent = new LoginEvent(player, "test-server-id");

        authListener.onLogin(loginEvent);

        assertFalse(loginEvent.getResult().isAllowed(),
                "A failed UUID binding must never reach PostLogin/backend routing");
    }

    @Test
    void onGameProfileRequest_linkedFloodgateUsernameWithBypassDisabled_stillSkipsMojangBinding() {
        String username = "LinkedJava";
        UUID floodgateUuid = UUID.randomUUID();
        UUID originalProfileUuid = UUID.randomUUID();
        FloodgateApi.install(".", Set.of(floodgateUuid), List.of(
                new FloodgateApi.PlayerView(username, ".BedrockUser")));
        when(settings.isFloodgateIntegrationEnabled()).thenReturn(true);
        when(settings.isFloodgateBypassAuthServerEnabled()).thenReturn(false);
        GameProfile originalProfile = new GameProfile(originalProfileUuid, username, List.of());
        GameProfileRequestEvent event = new GameProfileRequestEvent(
                createConnection("192.0.2.43"), originalProfile, true);

        Thread callingThread = Thread.currentThread();
        EventTask task = authListener.onGameProfileRequest(event);

        assertNotNull(task, "Live Floodgate username lookup must suspend the event asynchronously");
        await(task);
        assertNotSame(callingThread, FloodgateApi.getLastGetPlayersThread(),
                "GameProfile fallback must not scan Floodgate players on the event thread");
        verify(databaseManager, never()).reconcileVerifiedPremiumProfile(anyString(), any(UUID.class));
    }

    private InboundConnection createConnection(String address) {
        InboundConnection connection = org.mockito.Mockito.mock(InboundConnection.class);
        when(connection.getRemoteAddress()).thenReturn(
                new InetSocketAddress(address, 25565));
        when(connection.isActive()).thenReturn(true);
        return connection;
    }

    private void activateConnection(Player player) {
        assertNotNull(plugin.getConnectionLifecycleRegistry().activate(player,
                ignored -> connectionManager.beginTransferSession(player)));
    }

    private void setPluginInitialized(boolean value) throws Exception {
        Field initializedField = VeloAuth.class.getDeclaredField("initialized");
        initializedField.setAccessible(true);
        initializedField.set(plugin, value);
    }

    private void setPluginField(String fieldName, Object value) throws Exception {
        Field field = VeloAuth.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(plugin, value);
    }

}
