package net.rafalohaki.veloauth.command;

import at.favre.lib.crypto.bcrypt.BCrypt;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import net.rafalohaki.veloauth.database.DatabaseConfig;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.lifecycle.ConnectionLifecycleRegistry;
import net.rafalohaki.veloauth.listener.AuthListener;
import net.rafalohaki.veloauth.listener.PostLoginHandler;
import net.rafalohaki.veloauth.listener.PreLoginHandler;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
import org.bstats.velocity.Metrics;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings({"java:S100", "java:S2068", "java:S1192"})
class CommandFlowFixesTest {

    private static final String TEST_PLAYER_NAME = "TestPlayer";
    private static final String TEST_IP = "127.0.0.1";
    private static final PlainTextComponentSerializer PLAIN_TEXT = PlainTextComponentSerializer.plainText();

    @Mock
    private ProxyServer proxyServer;
    @Mock
    private org.slf4j.Logger logger;
    @Mock
    private Player player;
    @Mock
    private CommandSource commandSource;
    @Mock
    private ConnectionManager connectionManager;

    private Messages messages;
    private Settings settings;
    private AuthCache authCache;
    private StubDatabaseManager databaseManager;
    private InlineCommandContext inlineContext;
    private CommandContext asyncContext;
    private VeloAuth plugin;
    private UUID playerUuid;

    @BeforeEach
    void setUp() throws Exception {
        playerUuid = UUID.randomUUID();

        when(logger.isDebugEnabled()).thenReturn(false);
        when(logger.isInfoEnabled()).thenReturn(false);
        when(logger.isWarnEnabled()).thenReturn(false);
        when(logger.isErrorEnabled()).thenReturn(false);

        Metrics.Factory metricsFactory = mock(Metrics.Factory.class);
        plugin = new VeloAuth(proxyServer, logger, Path.of(".test-command-flow"), metricsFactory);
        setConnectionManager(connectionManager);

        messages = new Messages();
        messages.setLanguage("en");
        settings = new TestValidationSettings(Path.of(".test-command-flow"), 6, 32);
        authCache = new AuthCache(
                new AuthCache.AuthCacheConfig(60, 10000, 1000, 10000, 5, 5, 1, 60),
                settings,
                messages
        );
        databaseManager = new StubDatabaseManager(DatabaseConfig.forLocalDatabase("H2", "command-flow-test"), messages);
        inlineContext = new InlineCommandContext(plugin, databaseManager, authCache, settings, messages);
        asyncContext = new CommandContext(plugin, databaseManager, authCache, settings, messages);

        InetAddress inetAddress = InetAddress.getByName(TEST_IP);
        when(player.getUniqueId()).thenReturn(playerUuid);
        when(player.getUsername()).thenReturn(TEST_PLAYER_NAME);
        when(player.getRemoteAddress()).thenReturn(new InetSocketAddress(inetAddress, 25565));
        when(proxyServer.getPlayer(TEST_PLAYER_NAME)).thenReturn(java.util.Optional.empty());
        when(proxyServer.getAllPlayers()).thenReturn(List.of());
        plugin.getConnectionLifecycleRegistry().activate(player, ignored -> { });
    }

    @AfterEach
    void tearDown() throws Exception {
        setExecutorShutdown(false);
    }

    @Test
    void testLoginCommand_ConsoleSource_ShowsPlayerOnlyMessage() {
        LoginCommand command = new LoginCommand(inlineContext);

        command.execute(invocation(commandSource, "secret123"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(commandSource).sendMessage(messagesCaptor.capture());
        assertTrue(capturedTexts(messagesCaptor).contains(messages.get("error.player_only")));
    }

    @Test
    void testCommandInputs_toString_shouldNotExposePasswordArguments() {
        CommandHelper.CommandInputs inputs = new CommandHelper.CommandInputs(
                player, new String[]{"superSecretPassword", "123456"});

        String rendered = inputs.toString();

        assertFalse(rendered.contains("superSecretPassword"));
        assertFalse(rendered.contains("123456"));
        assertTrue(rendered.contains("argCount=2"));
    }

    @Test
    void testLoginAndRegisterPermissions_authorizedActiveSessionOnAuthServer_shouldBeHidden() {
        RegisteredPlayer registeredPlayer = createRegisteredPlayer(
                TEST_PLAYER_NAME, playerUuid, hash("secret123"));
        when(connectionManager.isPlayerOnAuthServer(player)).thenReturn(true);
        authCache.addAuthorizedPlayer(playerUuid, CachedAuthUser.fromRegisteredPlayer(registeredPlayer, false));
        authCache.startSession(playerUuid, TEST_PLAYER_NAME, TEST_IP);

        assertFalse(new LoginCommand(inlineContext).hasPermission(invocation(player)));
        assertFalse(new RegisterCommand(inlineContext).hasPermission(invocation(player)));
    }

    @Test
    void testLoginAndRegisterPermissions_authorizedButSessionExpired_shouldRemainVisible() {
        RegisteredPlayer registeredPlayer = createRegisteredPlayer(
                TEST_PLAYER_NAME, playerUuid, hash("secret123"));
        when(connectionManager.isPlayerOnAuthServer(player)).thenReturn(true);
        authCache.addAuthorizedPlayer(playerUuid, CachedAuthUser.fromRegisteredPlayer(registeredPlayer, false));

        assertTrue(new LoginCommand(inlineContext).hasPermission(invocation(player)));
        assertTrue(new RegisterCommand(inlineContext).hasPermission(invocation(player)));
    }

    @Test
    void testChangePasswordCommand_WhenLockHeld_ShowsInProgressMessage() {
        ChangePasswordCommand command = new ChangePasswordCommand(inlineContext);
        var operation = inlineContext.captureConnectionOperation(player);
        assertNotNull(operation);
        assertTrue(inlineContext.tryAcquireCommandLock(playerUuid, operation));

        command.execute(invocation(player, "oldPassword", "newPassword123"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player).sendMessage(messagesCaptor.capture());
        assertTrue(capturedTexts(messagesCaptor).contains(messages.get("auth.command.in_progress")));

        inlineContext.releaseCommandLock(playerUuid, operation);
    }

    @Test
    void testRegisterCommand_InvalidPassword_ShowsLocalizedValidationMessage() {
        RegisterCommand command = new RegisterCommand(inlineContext);

        command.execute(invocation(player, "short", "short"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        assertTrue(sentMessages.contains(messages.get("validation.password.too_short", 6)));
        assertFalse(sentMessages.contains("validation.password.too_short"));
    }

    @Test
    void testChangePasswordCommand_InvalidPassword_ShowsLocalizedValidationMessage() {
        ChangePasswordCommand command = new ChangePasswordCommand(inlineContext);

        command.execute(invocation(player, "oldPassword", "short"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        assertTrue(sentMessages.contains(messages.get("validation.password.too_short", 6)));
        assertFalse(sentMessages.contains("validation.password.too_short"));
    }

    @Test
    void testChangePasswordCommand_WhenSuccessful_DisconnectsDuplicateSessionsAndReleasesLock() {
        Player duplicateSession = mock(Player.class);
        when(duplicateSession.getUsername()).thenReturn(TEST_PLAYER_NAME.toLowerCase(Locale.ROOT));
        when(proxyServer.getAllPlayers()).thenReturn(List.of(player, duplicateSession));

        RegisteredPlayer registeredPlayer = createRegisteredPlayer(TEST_PLAYER_NAME, playerUuid, hash("oldPassword"));
        databaseManager.setFindResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(registeredPlayer)));
        databaseManager.enqueueSavePlayerResult(DatabaseManager.DbResult.success(true));
        databaseManager.setPremiumResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(false)));
        authCache.addAuthorizedPlayer(playerUuid, CachedAuthUser.fromRegisteredPlayer(registeredPlayer, false));
        authCache.startSession(playerUuid, TEST_PLAYER_NAME, TEST_IP);

        ChangePasswordCommand command = new ChangePasswordCommand(inlineContext);
        command.execute(invocation(player, "oldPassword", "newPassword123"));

        ArgumentCaptor<Component> disconnectCaptor = ArgumentCaptor.forClass(Component.class);
        verify(duplicateSession).disconnect(disconnectCaptor.capture());
        assertTrue(PLAIN_TEXT.serialize(disconnectCaptor.getValue()).contains(messages.get("general.kick.message")));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player, atLeastOnce()).sendMessage(messagesCaptor.capture());
        assertTrue(capturedTexts(messagesCaptor).contains(messages.get("auth.changepassword.success")));
        assertFalse(authCache.hasActiveSession(playerUuid, TEST_PLAYER_NAME, TEST_IP));
        assertFalse(authCache.isPlayerAuthorized(playerUuid, TEST_IP));
        var operation = inlineContext.captureConnectionOperation(player);
        assertNotNull(operation);
        assertTrue(inlineContext.tryAcquireCommandLock(playerUuid, operation));
        inlineContext.releaseCommandLock(playerUuid, operation);
    }

    @Test
    void changePassword_CommittedAfterReplacement_RevokesAccountWithoutReadingRetiredPlayer()
            throws Exception {
        AtomicBoolean retiredPlayer = new AtomicBoolean();
        when(player.getUniqueId()).thenAnswer(ignored -> {
            if (retiredPlayer.get()) {
                throw new IllegalStateException("retired Player#getUniqueId access");
            }
            return playerUuid;
        });
        when(player.getUsername()).thenAnswer(ignored -> {
            if (retiredPlayer.get()) {
                throw new IllegalStateException("retired Player#getUsername access");
            }
            return TEST_PLAYER_NAME;
        });
        when(player.getRemoteAddress()).thenAnswer(ignored -> {
            if (retiredPlayer.get()) {
                throw new IllegalStateException("retired Player#getRemoteAddress access");
            }
            return new InetSocketAddress(InetAddress.getByName(TEST_IP), 25565);
        });

        RegisteredPlayer registeredPlayer = createRegisteredPlayer(
                TEST_PLAYER_NAME, playerUuid, hash("oldPassword"));
        databaseManager.setFindResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(registeredPlayer)));
        CompletableFuture<DatabaseManager.DbResult<Boolean>> committedSave =
                new CompletableFuture<>();
        CountDownLatch saveEntered = new CountDownLatch(1);
        databaseManager.enqueueSavePlayerFuture(committedSave);
        databaseManager.setSaveEnteredLatch(saveEntered);
        CompletableFuture<DatabaseManager.DbResult<Boolean>> pendingPremiumLookup =
                new CompletableFuture<>();
        databaseManager.setPremiumResult(TEST_PLAYER_NAME, pendingPremiumLookup);
        authCache.addAuthorizedPlayer(
                playerUuid, CachedAuthUser.fromRegisteredPlayer(registeredPlayer, false));
        authCache.startSession(playerUuid, TEST_PLAYER_NAME, TEST_IP);

        Player replacement = mock(Player.class);
        when(replacement.getUniqueId()).thenReturn(playerUuid);
        when(replacement.getUsername()).thenReturn(TEST_PLAYER_NAME);
        CountDownLatch duplicateDisconnected = new CountDownLatch(1);
        org.mockito.Mockito.doAnswer(ignored -> {
            duplicateDisconnected.countDown();
            return null;
        }).when(replacement).disconnect(org.mockito.ArgumentMatchers.any(Component.class));
        when(proxyServer.getAllPlayers()).thenReturn(List.of(player, replacement));
        AuditLogService auditLogService = mock(AuditLogService.class);
        setPluginField("auditLogService", auditLogService);

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            CapturingAsyncCommandContext context = new CapturingAsyncCommandContext(
                    plugin, databaseManager, authCache, settings, messages, executor);
            new ChangePasswordCommand(context).execute(
                    invocation(player, "oldPassword", "newPassword123"));

            assertTrue(saveEntered.await(5, TimeUnit.SECONDS),
                    "The password update must be parked at its controlled commit future");
            assertNotNull(plugin.getConnectionLifecycleRegistry().activate(
                    replacement, ignored -> { }));
            authCache.addAuthorizedPlayer(
                    playerUuid, CachedAuthUser.fromRegisteredPlayer(registeredPlayer, false));
            authCache.startSession(playerUuid, TEST_PLAYER_NAME, TEST_IP);
            retiredPlayer.set(true);

            committedSave.complete(DatabaseManager.DbResult.success(true));
            assertTrue(duplicateDisconnected.await(2, TimeUnit.SECONDS),
                    "Mandatory duplicate-session revocation must precede optional premium lookup");
            assertFalse(authCache.isPlayerAuthorized(playerUuid, TEST_IP));
            assertFalse(authCache.hasActiveSession(playerUuid, TEST_PLAYER_NAME, TEST_IP));
            verify(auditLogService).save(
                    AuditEventType.PASSWORD_CHANGE, TEST_PLAYER_NAME, TEST_IP);

            pendingPremiumLookup.complete(DatabaseManager.DbResult.success(false));
            context.submitted().get(5, TimeUnit.SECONDS);
        }

        assertFalse(authCache.isPlayerAuthorized(playerUuid, TEST_IP),
                "A committed password change must revoke replacement authorization");
        assertFalse(authCache.hasActiveSession(playerUuid, TEST_PLAYER_NAME, TEST_IP),
                "A committed password change must revoke replacement sessions");
        verify(replacement).disconnect(org.mockito.ArgumentMatchers.any(Component.class));
        verify(player, never()).sendMessage(org.mockito.ArgumentMatchers.any(Component.class));
    }

    @Test
    void commandLock_ReconnectReplacesRetiredOwnerAndLateReleaseCannotClearReplacement() {
        var staleOperation = inlineContext.captureConnectionOperation(player);
        assertNotNull(staleOperation);
        assertTrue(inlineContext.tryAcquireCommandLock(playerUuid, staleOperation));
        Player replacement = mock(Player.class);
        when(replacement.getUniqueId()).thenReturn(playerUuid);
        var replacementOperation = plugin.getConnectionLifecycleRegistry().activate(
                replacement, ignored -> { });
        assertNotNull(replacementOperation);

        assertTrue(inlineContext.tryAcquireCommandLock(playerUuid, replacementOperation),
                "B must replace the command lock owned by retired generation A");
        inlineContext.releaseCommandLock(playerUuid, staleOperation);

        assertFalse(inlineContext.tryAcquireCommandLock(playerUuid, replacementOperation),
                "A's late finally must not release B's command lock");
        inlineContext.releaseCommandLock(playerUuid, replacementOperation);
        assertTrue(inlineContext.tryAcquireCommandLock(playerUuid, replacementOperation));
        inlineContext.releaseCommandLock(playerUuid, replacementOperation);
    }

    @Test
    void registrationLock_LateExpiredLeaseReleaseCannotClearReplacementLease() throws Exception {
        InetAddress address = InetAddress.getByName(TEST_IP);
        var expiredLease = inlineContext.tryAcquireRegistrationLock(address);
        assertNotNull(expiredLease);
        inlineContext.releaseRegistrationLock(expiredLease);
        var replacementLease = inlineContext.tryAcquireRegistrationLock(address);
        assertNotNull(replacementLease);

        inlineContext.releaseRegistrationLock(expiredLease);

        assertNull(inlineContext.tryAcquireRegistrationLock(address),
                "A late release must not erase B's replacement IP lease");
        inlineContext.releaseRegistrationLock(replacementLease);
        var nextLease = inlineContext.tryAcquireRegistrationLock(address);
        assertNotNull(nextLease);
        inlineContext.releaseRegistrationLock(nextLease);
    }

    @Test
    void testLoginCommand_WhenPostAuthFlowFails_DoesNotSendSuccess() {
        databaseManager.setFindResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(
                        createRegisteredPlayer(TEST_PLAYER_NAME, playerUuid, hash("secret123")))));
        databaseManager.enqueueSavePlayerResult(DatabaseManager.DbResult.success(true));
        databaseManager.setPremiumResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.databaseError("premium lookup failed")));

        LoginCommand command = new LoginCommand(inlineContext);
        command.execute(invocation(player, "secret123"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player, atLeastOnce()).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        assertFalse(sentMessages.contains(messages.get("auth.login.success")));
        assertTrue(sentMessages.contains(messages.get("error.database.query")));
        assertFalse(authCache.isPlayerAuthorized(playerUuid, TEST_IP));
    }

    @Test
    void testRegisterCommand_WhenPostAuthFlowFails_DoesNotSendSuccess() {
        databaseManager.setFindResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(null)));
        databaseManager.enqueueRegistrationResult(DatabaseManager.DbResult.success(true));
        databaseManager.setPremiumResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.databaseError("premium lookup failed")));

        RegisterCommand command = new RegisterCommand(inlineContext);
        command.execute(invocation(player, "secret123", "secret123"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player, atLeastOnce()).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        assertFalse(sentMessages.contains(messages.get("auth.register.success")));
        assertTrue(sentMessages.contains(messages.get("error.database.query")));
        assertFalse(authCache.isPlayerAuthorized(playerUuid, TEST_IP));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void logoutDisconnect_LateLoginOrRegisterCompletion_DoesNotRestoreConnectionState(
            boolean registration) throws Exception {
        AtomicBoolean active = new AtomicBoolean(true);
        when(player.isActive()).thenAnswer(ignored -> active.get());
        org.mockito.Mockito.doAnswer(ignored -> {
            active.set(false);
            return null;
        }).when(player).disconnect(org.mockito.ArgumentMatchers.any(Component.class));
        when(player.isOnlineMode()).thenReturn(false);
        when(connectionManager.transferToBackend(player)).thenReturn(true);
        injectAuthTimeoutScheduler();

        PreLoginHandler preLoginHandler = mock(PreLoginHandler.class);
        PostLoginHandler postLoginHandler = mock(PostLoginHandler.class);
        AuthListener listener = new AuthListener(
                plugin, authCache, settings, preLoginHandler, postLoginHandler,
                connectionManager, databaseManager, messages);
        listener.onPostLogin(new PostLoginEvent(player));

        CompletableFuture<DatabaseManager.DbResult<RegisteredPlayer>> lookup = new CompletableFuture<>();
        CountDownLatch lookupEntered = new CountDownLatch(1);
        databaseManager.setFindResult(TEST_PLAYER_NAME, lookup);
        databaseManager.setFindEnteredLatch(lookupEntered);
        databaseManager.setPremiumResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(false)));
        databaseManager.enqueueSavePlayerResult(DatabaseManager.DbResult.success(true));
        databaseManager.enqueueRegistrationResult(DatabaseManager.DbResult.success(true));

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            CapturingAsyncCommandContext context = new CapturingAsyncCommandContext(
                    plugin, databaseManager, authCache, settings, messages, executor);
            if (registration) {
                new RegisterCommand(context).execute(invocation(player, "secret123", "secret123"));
            } else {
                new LoginCommand(context).execute(invocation(player, "secret123"));
            }

            assertTrue(lookupEntered.await(2, TimeUnit.SECONDS),
                    "The command must be parked inside its controlled DAO lookup before logout");
            new LogoutCommand(context).execute(invocation(player));
            listener.onDisconnect(new DisconnectEvent(
                    player, DisconnectEvent.LoginStatus.SUCCESSFUL_LOGIN));

            RegisteredPlayer stored = registration
                    ? null
                    : createRegisteredPlayer(TEST_PLAYER_NAME, playerUuid, hash("secret123"));
            lookup.complete(DatabaseManager.DbResult.success(stored));
            context.submitted().get(5, TimeUnit.SECONDS);
        }

        assertFalse(authCache.isPlayerAuthorized(playerUuid, TEST_IP),
                "A retired concrete connection must not be re-authorized by late command work");
        assertFalse(authCache.hasActiveSession(playerUuid, TEST_PLAYER_NAME, TEST_IP),
                "A retired concrete connection must not recreate its session");
        verify(connectionManager, never()).transferToBackend(player);
        verify(player, never()).sendMessage(org.mockito.ArgumentMatchers.any(Component.class));
    }

    @Test
    void testRegisterCommand_ConcurrentNicknameOwnerCreated_ShowsAlreadyRegistered() {
        databaseManager.setFindResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(null)));
        databaseManager.enqueueRegistrationResult(DatabaseManager.DbResult.success(false));

        RegisterCommand command = new RegisterCommand(inlineContext);
        command.execute(invocation(player, "secret123", "secret123"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player, atLeastOnce()).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        assertTrue(sentMessages.contains(messages.get("auth.register.already_registered")));
        assertFalse(sentMessages.contains(messages.get("auth.register.success")));
        assertFalse(authCache.isPlayerAuthorized(playerUuid, TEST_IP));
    }

    @Test
    void registrationTimeout_TimeoutWinsBeforeCommit_ShowsRetrySafeTimeoutAndCancelsPermit() {
        DatabaseManager.RegistrationCommitPermit permit =
                new DatabaseManager.RegistrationCommitPermit();
        ConnectionLifecycleRegistry.Operation operation =
                plugin.getConnectionLifecycleRegistry().capture(player);

        DatabaseManager.RegistrationTimeoutDisposition disposition =
                inlineContext.handleRegistrationTimeout(player, operation, permit);

        assertEquals(DatabaseManager.RegistrationTimeoutDisposition.CANCELLED_BEFORE_COMMIT,
                disposition);
        assertTrue(permit.isCancelled());
        assertFalse(permit.tryBeginCommit());
        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player).sendMessage(messagesCaptor.capture());
        assertEquals(messages.get("auth.registration.timeout"),
                PLAIN_TEXT.serialize(messagesCaptor.getValue()));
    }

    @Test
    void registrationTimeout_CommitWinsBeforeTimeout_ShowsDoNotRetryMessage() {
        DatabaseManager.RegistrationCommitPermit permit =
                new DatabaseManager.RegistrationCommitPermit();
        assertTrue(permit.tryBeginCommit());
        ConnectionLifecycleRegistry.Operation operation =
                plugin.getConnectionLifecycleRegistry().capture(player);

        DatabaseManager.RegistrationTimeoutDisposition disposition =
                inlineContext.handleRegistrationTimeout(player, operation, permit);

        assertEquals(DatabaseManager.RegistrationTimeoutDisposition.COMMIT_IN_PROGRESS,
                disposition);
        assertFalse(permit.isCancelled());
        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player).sendMessage(messagesCaptor.capture());
        assertEquals(messages.get("auth.registration.commit_pending"),
                PLAIN_TEXT.serialize(messagesCaptor.getValue()));
        assertFalse(PLAIN_TEXT.serialize(messagesCaptor.getValue())
                .equals(messages.get("auth.registration.timeout")));
    }

    @ParameterizedTest
    @EnumSource(LateRegistrationDecision.class)
    void registrationTimeout_BlockedPreCommitDecisionCompletesLate_EmitsOnlyTimeout(
            LateRegistrationDecision lateDecision) throws Exception {
        CompletableFuture<DatabaseManager.DbResult<RegisteredPlayer>> lookup =
                new CompletableFuture<>();
        CountDownLatch lookupEntered = new CountDownLatch(1);
        databaseManager.setFindResult(TEST_PLAYER_NAME, lookup);
        databaseManager.setFindEnteredLatch(lookupEntered);
        if (lateDecision == LateRegistrationDecision.IP_LIMIT) {
            databaseManager.setRegistrationCount(
                    CompletableFuture.completedFuture(Long.MAX_VALUE));
        }

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            CapturingAsyncCommandContext context = new CapturingAsyncCommandContext(
                    plugin, databaseManager, authCache, settings, messages, executor);
            new RegisterCommand(context)
                    .execute(invocation(player, "secret123", "secret123"));

            assertTrue(lookupEntered.await(5, TimeUnit.SECONDS),
                    "Registration must be parked in the controlled lookup");
            assertEquals(
                    DatabaseManager.RegistrationTimeoutDisposition.CANCELLED_BEFORE_COMMIT,
                    context.triggerRegistrationTimeout());
            lookup.complete(lateDecision.lookupResult());
            context.submitted().get(5, TimeUnit.SECONDS);
        }

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player, atLeastOnce()).sendMessage(messagesCaptor.capture());
        assertEquals(List.of(messages.get("auth.registration.timeout")),
                capturedTexts(messagesCaptor),
                "The timeout must own the only terminal player message");
        verify(connectionManager, never()).transferToBackend(player);
        assertFalse(authCache.isPlayerAuthorized(playerUuid, TEST_IP));
    }

    @Test
    void testRegisterCommand_CommitOutcomeUnknown_ShowsConservativeMessageAndNoSuccess() {
        databaseManager.setFindResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(null)));
        databaseManager.enqueueRegistrationOutcome(
                DatabaseManager.DbResult.success(
                        DatabaseManager.RegistrationResult.COMMIT_UNKNOWN));

        new RegisterCommand(inlineContext)
                .execute(invocation(player, "secret123", "secret123"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player, atLeastOnce()).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        assertTrue(sentMessages.contains(messages.get("auth.registration.commit_unknown")));
        assertFalse(sentMessages.contains(messages.get("auth.register.success")));
        assertFalse(authCache.isPlayerAuthorized(playerUuid, TEST_IP));
        verify(connectionManager, never()).transferToBackend(player);
    }

    @Test
    void testRegisterCommand_TimeoutCancelledTransaction_DoesNotRunPostAuthFlow() {
        databaseManager.setFindResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(null)));
        databaseManager.enqueueRegistrationOutcome(
                DatabaseManager.DbResult.success(DatabaseManager.RegistrationResult.CANCELLED));

        new RegisterCommand(inlineContext)
                .execute(invocation(player, "secret123", "secret123"));

        verify(player, never()).sendMessage(org.mockito.ArgumentMatchers.any(Component.class));
        assertFalse(authCache.isPlayerAuthorized(playerUuid, TEST_IP));
        assertFalse(authCache.hasActiveSession(playerUuid, TEST_PLAYER_NAME, TEST_IP));
        verify(connectionManager, never()).transferToBackend(player);
    }

    @Test
    void testLoginCommand_AuthorizedButSessionExpired_ProceedsToPasswordCheckInsteadOfAlreadyLogged() throws Exception {
        // Regression for the authorized-but-no-session deadlock: pre-1.3.3 /login checked
        // isPlayerAuthorized alone and replied "already logged in" while ServerPreConnectEvent
        // blocked the backend (no active session). The fix makes the "already logged in"
        // short-circuit require BOTH authorization AND an active session.
        RegisteredPlayer registeredPlayer = createRegisteredPlayer(TEST_PLAYER_NAME, playerUuid, hash("secret123"));
        databaseManager.setFindResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(registeredPlayer)));
        databaseManager.enqueueSavePlayerResult(DatabaseManager.DbResult.success(true));
        databaseManager.setPremiumResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(false)));

        // Authorized in cache, but NO active session (simulates TTL/eviction-driven expiry).
        authCache.addAuthorizedPlayer(playerUuid, CachedAuthUser.fromRegisteredPlayer(registeredPlayer, false));
        assertFalse(authCache.hasActiveSession(playerUuid, TEST_PLAYER_NAME, TEST_IP),
                "Sanity: no session should exist before the command runs");

        // PostAuthFlow needs both a real ConnectionManager (transferToBackend → true) and an
        // AuthTimeoutScheduler (cancel on success). Inject a scheduler stub via reflection.
        when(connectionManager.transferToBackend(player)).thenReturn(true);
        injectAuthTimeoutScheduler();

        setExecutorShutdown(true); // run inline so assertions see the post-command state
        try {
            LoginCommand command = new LoginCommand(inlineContext);
            command.execute(invocation(player, "secret123"));
        } finally {
            setExecutorShutdown(false);
        }

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player, atLeastOnce()).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        assertFalse(sentMessages.contains(messages.get("auth.login.already_logged_in")),
                "Authorized-but-no-session must NOT short-circuit to 'already logged in'");
        assertTrue(sentMessages.contains(messages.get("auth.login.success")),
                "Password verification should succeed and re-establish both caches");
        // After successful re-login both authorization and session are present again.
        assertTrue(authCache.hasActiveSession(playerUuid, TEST_PLAYER_NAME, TEST_IP),
                "Successful re-login must re-establish the session");
    }

    @Test
    void testLoginCommand_AuthorizedAndSessionActive_ShortCircuitsToAlreadyLogged() {
        // Counter-regression: when BOTH authorization and session are valid, /login must
        // still short-circuit. The fix must not weaken the normal "already logged in" path.
        RegisteredPlayer registeredPlayer = createRegisteredPlayer(TEST_PLAYER_NAME, playerUuid, hash("secret123"));
        databaseManager.setFindResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(registeredPlayer)));

        authCache.addAuthorizedPlayer(playerUuid, CachedAuthUser.fromRegisteredPlayer(registeredPlayer, false));
        authCache.startSession(playerUuid, TEST_PLAYER_NAME, TEST_IP);

        LoginCommand command = new LoginCommand(inlineContext);
        command.execute(invocation(player, "secret123"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(player, atLeastOnce()).sendMessage(messagesCaptor.capture());
        assertTrue(capturedTexts(messagesCaptor).contains(messages.get("auth.login.already_logged_in")),
                "Fully authorized player (auth + session) must see 'already logged in'");
    }

    @Test
    void testPostAuthFlow_DoesNotPersistResolverSourcedPremiumUuidFromOfflinePath() throws Exception {
        UUID premiumUuid = UUID.randomUUID();
        RegisteredPlayer registeredPlayer = createRegisteredPlayer(TEST_PLAYER_NAME, playerUuid, hash("secret123"));
        AuthenticationContext authContext = new AuthenticationContext(
                player,
                TEST_PLAYER_NAME,
                player.getRemoteAddress().getAddress(),
                registeredPlayer,
                plugin.getConnectionLifecycleRegistry().capture(player)
        );

        authCache.addPremiumPlayer(TEST_PLAYER_NAME, premiumUuid);
        databaseManager.setPremiumResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(true)));
        databaseManager.setSavePremiumUuidResult(
                CompletableFuture.completedFuture(DatabaseManager.DbResult.databaseError("must not be called")));
        when(connectionManager.transferToBackend(player)).thenReturn(true);
        injectAuthTimeoutScheduler();

        boolean result = PostAuthFlow.execute(inlineContext, authContext, registeredPlayer, "logged in");

        assertTrue(result);
        assertNull(registeredPlayer.getPremiumUuid(),
                "Offline auth must not promote resolver-sourced UUIDs into AUTH.PREMIUMUUID");
        assertTrue(authCache.findAuthorizedPlayer(playerUuid).isPresent());
        assertNull(authCache.findAuthorizedPlayer(playerUuid).orElseThrow().getPremiumUuid(),
                "Offline auth cache must not store resolver-sourced UUIDs");
        verify(connectionManager).transferToBackend(player);
        assertFalse(databaseManager.wasSavePremiumUuidCalled(),
                "PREMIUM_UUIDS sync must be reserved for Mojang-verified profile reconciliation");
    }

    @Test
    void testPostAuthFlow_PreservesStoredVerifiedPremiumUuidInCache() throws Exception {
        UUID storedPremiumUuid = UUID.randomUUID();
        UUID resolverPremiumUuid = UUID.randomUUID();
        RegisteredPlayer registeredPlayer = createRegisteredPlayer(TEST_PLAYER_NAME, playerUuid, hash("secret123"));
        registeredPlayer.setPremiumUuid(storedPremiumUuid.toString());
        AuthenticationContext authContext = new AuthenticationContext(
                player,
                TEST_PLAYER_NAME,
                player.getRemoteAddress().getAddress(),
                registeredPlayer,
                plugin.getConnectionLifecycleRegistry().capture(player)
        );

        authCache.addPremiumPlayer(TEST_PLAYER_NAME, resolverPremiumUuid);
        databaseManager.setPremiumResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(true)));
        databaseManager.setSavePremiumUuidResult(
                CompletableFuture.completedFuture(DatabaseManager.DbResult.databaseError("must not be called")));
        when(connectionManager.transferToBackend(player)).thenReturn(true);
        injectAuthTimeoutScheduler();

        boolean result = PostAuthFlow.execute(inlineContext, authContext, registeredPlayer, "logged in");

        CachedAuthUser cachedUser = authCache.findAuthorizedPlayer(playerUuid).orElseThrow();
        assertTrue(result);
        assertEquals(storedPremiumUuid, cachedUser.getPremiumUuid(),
                "Offline auth may cache the verified premium UUID already stored in AUTH");
        verify(connectionManager).transferToBackend(player);
        assertFalse(databaseManager.wasSavePremiumUuidCalled(),
                "Preserving stored AUTH.PREMIUMUUID must not trigger a new premium UUID sync");
    }

    private void injectAuthTimeoutScheduler() throws Exception {
        net.rafalohaki.veloauth.connection.AuthTimeoutScheduler scheduler =
                mock(net.rafalohaki.veloauth.connection.AuthTimeoutScheduler.class);
        Field schedulerField = VeloAuth.class.getDeclaredField("authTimeoutScheduler");
        schedulerField.setAccessible(true);
        schedulerField.set(plugin, scheduler);
    }

    @Test
    void testVAuthCommand_StatsWhenQueryFails_ShowsDatabaseError() {
        when(commandSource.hasPermission("veloauth.admin")).thenReturn(true);
        databaseManager.setTotalRegisteredAccounts(CompletableFuture.completedFuture(3));
        databaseManager.setTotalPremiumAccounts(
                CompletableFuture.failedFuture(new IllegalStateException("stats query failed")));
        databaseManager.setTotalNonPremiumAccounts(CompletableFuture.completedFuture(1));

        VAuthCommand command = new VAuthCommand(asyncContext);
        command.execute(invocation(commandSource, "stats"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(commandSource, timeout(1_000).atLeastOnce()).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        assertTrue(sentMessages.contains(messages.get("error.database.query")));
        assertFalse(sentMessages.contains(messages.get("admin.stats.header")));
    }

    @Test
    void testVAuthCommand_StatsWhenDatabaseDisconnected_ShowsDatabaseError() {
        when(commandSource.hasPermission("veloauth.admin")).thenReturn(true);
        databaseManager.setConnected(false);

        VAuthCommand command = new VAuthCommand(inlineContext);
        command.execute(invocation(commandSource, "stats"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(commandSource).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        assertTrue(sentMessages.contains(messages.get("error.database.query")));
        assertFalse(sentMessages.contains(messages.get("admin.stats.header")));
    }

    @Test
    void testVAuthCommand_ConflictsWhenQueryFails_ShowsDatabaseError() {
        when(commandSource.hasPermission("veloauth.admin")).thenReturn(true);
        databaseManager.setConflicts(
                CompletableFuture.failedFuture(new IllegalStateException("conflicts query failed")));

        VAuthCommand command = new VAuthCommand(asyncContext);
        command.execute(invocation(commandSource, "conflicts"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(commandSource, timeout(1_000).atLeastOnce()).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        assertTrue(sentMessages.contains(messages.get("error.database.query")));
        assertFalse(sentMessages.contains(messages.get("admin.conflicts.header")));
    }

    @Test
    void testVAuthCommand_ConflictsWhenDatabaseDisconnected_ShowsDatabaseError() {
        when(commandSource.hasPermission("veloauth.admin")).thenReturn(true);
        databaseManager.setConnected(false);

        VAuthCommand command = new VAuthCommand(inlineContext);
        command.execute(invocation(commandSource, "conflicts"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(commandSource).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        assertTrue(sentMessages.contains(messages.get("error.database.query")));
        assertFalse(sentMessages.contains(messages.get("admin.conflicts.none")));
    }

    @Test
    void testVAuthCommand_CacheResetOfflineAuthorizedPlayer_UsesCacheLookup() {
        UUID offlinePlayerUuid = UUID.randomUUID();
        RegisteredPlayer registeredPlayer = createRegisteredPlayer(TEST_PLAYER_NAME, offlinePlayerUuid, hash("secret123"));
        databaseManager.setFindResult(TEST_PLAYER_NAME,
                CompletableFuture.completedFuture(DatabaseManager.DbResult.success(registeredPlayer)));
        authCache.addAuthorizedPlayer(offlinePlayerUuid,
                new CachedAuthUser(offlinePlayerUuid, TEST_PLAYER_NAME, TEST_IP, System.currentTimeMillis(), false, null));
        when(commandSource.hasPermission("veloauth.admin")).thenReturn(true);

        VAuthCommand command = new VAuthCommand(inlineContext);
        command.execute(invocation(commandSource, "cache-reset", TEST_PLAYER_NAME));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(commandSource).sendMessage(messagesCaptor.capture());
        assertTrue(capturedTexts(messagesCaptor).contains(messages.get("admin.cache_reset.player", TEST_PLAYER_NAME)));
        assertTrue(authCache.findAuthorizedPlayer(offlinePlayerUuid).isEmpty());
    }

    @Test
    void testVAuthCommand_WhenExecutorIsShuttingDown_ShowsFailureForStatsAndConflicts() throws Exception {
        when(commandSource.hasPermission("veloauth.admin")).thenReturn(true);
        setExecutorShutdown(true);

        VAuthCommand command = new VAuthCommand(asyncContext);
        command.execute(invocation(commandSource, "stats"));
        command.execute(invocation(commandSource, "conflicts"));

        ArgumentCaptor<Component> messagesCaptor = ArgumentCaptor.forClass(Component.class);
        verify(commandSource, atLeastOnce()).sendMessage(messagesCaptor.capture());
        List<String> sentMessages = capturedTexts(messagesCaptor);
        long shuttingDownMessages = sentMessages.stream()
                .filter(messages.get("system.shutting_down")::equals)
                .count();
        assertTrue(shuttingDownMessages >= 2);
    }

    private RegisteredPlayer createRegisteredPlayer(String nickname, UUID uuid, String hash) {
        return new RegisteredPlayer(nickname, hash, TEST_IP, uuid.toString());
    }

    private String hash(String password) {
        return BCrypt.with(BCrypt.Version.VERSION_2Y)
                .hashToString(settings.getBcryptCost(), password.toCharArray());
    }

    private SimpleCommand.Invocation invocation(CommandSource source, String... args) {
        SimpleCommand.Invocation invocation = mock(SimpleCommand.Invocation.class);
        when(invocation.source()).thenReturn(source);
        when(invocation.arguments()).thenReturn(args);
        return invocation;
    }

    private List<String> capturedTexts(ArgumentCaptor<Component> captor) {
        return captor.getAllValues().stream()
                .map(PLAIN_TEXT::serialize)
                .toList();
    }

    private enum LateRegistrationDecision {
        ALREADY_REGISTERED,
        IP_LIMIT,
        DATABASE_ERROR;

        private DatabaseManager.DbResult<RegisteredPlayer> lookupResult() {
            return switch (this) {
                case ALREADY_REGISTERED -> DatabaseManager.DbResult.success(
                        new RegisteredPlayer(
                                TEST_PLAYER_NAME,
                                "$2a$10$offlinehashvalueofflinehashvalueofflinehashval",
                                TEST_IP,
                                UUID.randomUUID().toString()));
                case IP_LIMIT -> DatabaseManager.DbResult.success(null);
                case DATABASE_ERROR -> DatabaseManager.DbResult.databaseError(
                        "controlled lookup failure");
            };
        }
    }

    private void setConnectionManager(ConnectionManager manager) throws Exception {
        Field connectionManagerField = VeloAuth.class.getDeclaredField("connectionManager");
        connectionManagerField.setAccessible(true);
        connectionManagerField.set(plugin, manager);
    }

    private void setPluginField(String fieldName, Object value) throws Exception {
        Field field = VeloAuth.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(plugin, value);
    }

    private void setExecutorShutdown(boolean shutdown) throws Exception {
        Field shutdownField = VirtualThreadExecutorProvider.class.getDeclaredField("SHUTDOWN_INITIATED");
        shutdownField.setAccessible(true);
        AtomicBoolean shutdownFlag = (AtomicBoolean) shutdownField.get(null);
        shutdownFlag.set(shutdown);
    }

    private static final class InlineCommandContext extends CommandContext {

        private InlineCommandContext(VeloAuth plugin, DatabaseManager databaseManager,
                                     AuthCache authCache, Settings settings, Messages messages) {
            super(plugin, databaseManager, authCache, settings, messages);
        }

        @Override
        void runAsyncCommand(CommandSource source, Runnable task, String errorKey) {
            task.run();
        }

        @Override
        void runAsyncCommand(
                Player player, ConnectionLifecycleRegistry.Operation operation,
                Runnable task, String errorKey) {
            task.run();
        }

        @Override
        void runAsyncCommandWithTimeout(CommandSource source, Runnable task, String errorKey, String timeoutKey) {
            task.run();
        }

        @Override
        void runAsyncCommandWithTimeout(
                Player player, ConnectionLifecycleRegistry.Operation operation, Runnable task,
                String errorKey, String timeoutKey) {
            task.run();
        }

        @Override
        void runRegistrationCommandWithTimeout(
                Player player, ConnectionLifecycleRegistry.Operation operation,
                DatabaseManager.RegistrationCommitPermit permit, Runnable task,
                String errorKey) {
            task.run();
        }
    }

    private static final class CapturingAsyncCommandContext extends CommandContext {
        private final ExecutorService executor;
        private volatile Future<?> submitted;
        private volatile Player registrationPlayer;
        private volatile ConnectionLifecycleRegistry.Operation registrationOperation;
        private volatile DatabaseManager.RegistrationCommitPermit registrationPermit;

        private CapturingAsyncCommandContext(
                VeloAuth plugin, DatabaseManager databaseManager, AuthCache authCache,
                Settings settings, Messages messages, ExecutorService executor) {
            super(plugin, databaseManager, authCache, settings, messages);
            this.executor = executor;
        }

        @Override
        void runAsyncCommand(CommandSource source, Runnable task, String errorKey) {
            submitted = executor.submit(task);
        }

        @Override
        void runAsyncCommand(
                Player player, ConnectionLifecycleRegistry.Operation operation,
                Runnable task, String errorKey) {
            submitted = executor.submit(task);
        }

        @Override
        void runAsyncCommandWithTimeout(
                CommandSource source, Runnable task, String errorKey, String timeoutKey) {
            submitted = executor.submit(task);
        }

        @Override
        void runAsyncCommandWithTimeout(
                Player player, ConnectionLifecycleRegistry.Operation operation, Runnable task,
                String errorKey, String timeoutKey) {
            submitted = executor.submit(task);
        }

        @Override
        void runRegistrationCommandWithTimeout(
                Player player, ConnectionLifecycleRegistry.Operation operation,
                DatabaseManager.RegistrationCommitPermit permit, Runnable task,
                String errorKey) {
            registrationPlayer = player;
            registrationOperation = operation;
            registrationPermit = permit;
            submitted = executor.submit(task);
        }

        private DatabaseManager.RegistrationTimeoutDisposition triggerRegistrationTimeout() {
            if (registrationPlayer == null || registrationOperation == null
                    || registrationPermit == null) {
                throw new IllegalStateException("Registration timeout state was not captured");
            }
            return handleRegistrationTimeout(
                    registrationPlayer, registrationOperation, registrationPermit);
        }

        private Future<?> submitted() {
            if (submitted == null) {
                throw new IllegalStateException("Command task was not submitted");
            }
            return submitted;
        }
    }

    private static final class StubDatabaseManager extends DatabaseManager {
        private final Map<String, CompletableFuture<DbResult<RegisteredPlayer>>> findResults = new ConcurrentHashMap<>();
        private final Map<String, CompletableFuture<DbResult<Boolean>>> premiumResults = new ConcurrentHashMap<>();
        private final ConcurrentLinkedDeque<CompletableFuture<DbResult<Boolean>>> savePlayerResults =
                new ConcurrentLinkedDeque<>();
        private final ConcurrentLinkedDeque<CompletableFuture<DbResult<Boolean>>> registrationResults =
                new ConcurrentLinkedDeque<>();
        private final ConcurrentLinkedDeque<CompletableFuture<DbResult<RegistrationResult>>>
                registrationOutcomes = new ConcurrentLinkedDeque<>();
        private CompletableFuture<DbResult<Boolean>> defaultSavePlayerResult =
                CompletableFuture.completedFuture(DbResult.success(true));
        private CompletableFuture<DbResult<Boolean>> savePremiumUuidResult =
                CompletableFuture.completedFuture(DbResult.success(true));
        private boolean savePremiumUuidCalled;
        private CompletableFuture<Integer> totalRegisteredAccounts =
                CompletableFuture.completedFuture(0);
        private CompletableFuture<Integer> totalPremiumAccounts =
                CompletableFuture.completedFuture(0);
        private CompletableFuture<Integer> totalNonPremiumAccounts =
                CompletableFuture.completedFuture(0);
        private CompletableFuture<Long> registrationCount =
                CompletableFuture.completedFuture(0L);
        private CompletableFuture<List<RegisteredPlayer>> conflicts =
                CompletableFuture.completedFuture(List.of());
        private boolean connected = true;
        private volatile CountDownLatch findEnteredLatch;
        private volatile CountDownLatch saveEnteredLatch;

        private StubDatabaseManager(DatabaseConfig config, Messages messages) {
            super(config, messages);
        }

        void setConnected(boolean connected) {
            this.connected = connected;
        }

        void setFindResult(String nickname, CompletableFuture<DbResult<RegisteredPlayer>> result) {
            findResults.put(nickname.toLowerCase(Locale.ROOT), result);
        }

        void setFindEnteredLatch(CountDownLatch latch) {
            findEnteredLatch = latch;
        }

        void setRegistrationCount(CompletableFuture<Long> result) {
            registrationCount = result;
        }

        void setPremiumResult(String username, CompletableFuture<DbResult<Boolean>> result) {
            premiumResults.put(username, result);
        }

        void enqueueSavePlayerResult(DbResult<Boolean> result) {
            savePlayerResults.add(CompletableFuture.completedFuture(result));
        }

        void enqueueSavePlayerFuture(CompletableFuture<DbResult<Boolean>> result) {
            savePlayerResults.add(result);
        }

        void setSaveEnteredLatch(CountDownLatch latch) {
            saveEnteredLatch = latch;
        }

        void enqueueRegistrationResult(DbResult<Boolean> result) {
            registrationResults.add(CompletableFuture.completedFuture(result));
        }

        void enqueueRegistrationOutcome(DbResult<RegistrationResult> result) {
            registrationOutcomes.add(CompletableFuture.completedFuture(result));
        }

        void setSavePremiumUuidResult(CompletableFuture<DbResult<Boolean>> result) {
            savePremiumUuidResult = result;
        }

        boolean wasSavePremiumUuidCalled() {
            return savePremiumUuidCalled;
        }

        void setTotalRegisteredAccounts(CompletableFuture<Integer> result) {
            totalRegisteredAccounts = result;
        }

        void setTotalPremiumAccounts(CompletableFuture<Integer> result) {
            totalPremiumAccounts = result;
        }

        void setTotalNonPremiumAccounts(CompletableFuture<Integer> result) {
            totalNonPremiumAccounts = result;
        }

        void setConflicts(CompletableFuture<List<RegisteredPlayer>> result) {
            conflicts = result;
        }

        @Override
        public CompletableFuture<DbResult<RegisteredPlayer>> findPlayerByNickname(String nickname) {
            CountDownLatch entered = findEnteredLatch;
            if (entered != null) {
                entered.countDown();
            }
            if (nickname == null || nickname.isBlank()) {
                return CompletableFuture.completedFuture(DbResult.success(null));
            }
            return findResults.getOrDefault(
                    nickname.toLowerCase(Locale.ROOT),
                    CompletableFuture.completedFuture(DbResult.success(null)));
        }

        @Override
        public CompletableFuture<DbResult<Boolean>> savePlayer(RegisteredPlayer player) {
            CountDownLatch entered = saveEnteredLatch;
            if (entered != null) {
                entered.countDown();
            }
            CompletableFuture<DbResult<Boolean>> queuedResult = savePlayerResults.poll();
            return queuedResult != null ? queuedResult : defaultSavePlayerResult;
        }

        @Override
        public CompletableFuture<DbResult<Boolean>> registerPlayerIfAbsent(RegisteredPlayer player) {
            CompletableFuture<DbResult<Boolean>> queuedResult = registrationResults.poll();
            return queuedResult != null
                    ? queuedResult
                    : CompletableFuture.completedFuture(DbResult.success(true));
        }

        @Override
        public CompletableFuture<DbResult<RegistrationResult>> registerPlayerIfAbsent(
                RegisteredPlayer player, RegistrationCommitPermit permit) {
            CompletableFuture<DbResult<RegistrationResult>> queuedOutcome =
                    registrationOutcomes.poll();
            if (queuedOutcome != null) {
                return queuedOutcome;
            }
            CompletableFuture<DbResult<Boolean>> queuedResult = registrationResults.poll();
            if (queuedResult == null) {
                return CompletableFuture.completedFuture(
                        DbResult.success(RegistrationResult.CREATED));
            }
            return queuedResult.thenApply(result -> {
                if (result.isDatabaseError()) {
                    return DbResult.databaseError(result.getErrorMessage());
                }
                return DbResult.success(Boolean.TRUE.equals(result.getValue())
                        ? RegistrationResult.CREATED
                        : RegistrationResult.DUPLICATE);
            });
        }

        @Override
        public CompletableFuture<DbResult<Boolean>> isPremium(String username) {
            return premiumResults.getOrDefault(
                    username,
                    CompletableFuture.completedFuture(DbResult.success(false)));
        }

        @Override
        public CompletableFuture<Long> countRegistrationsByIp(String ip) {
            return registrationCount;
        }

        @Override
        public CompletableFuture<DbResult<Boolean>> savePremiumUuid(String username, UUID premiumUuid) {
            savePremiumUuidCalled = true;
            return savePremiumUuidResult;
        }

        @Override
        public CompletableFuture<Integer> getTotalRegisteredAccounts() {
            return totalRegisteredAccounts;
        }

        @Override
        public CompletableFuture<Integer> getTotalPremiumAccounts() {
            return totalPremiumAccounts;
        }

        @Override
        public CompletableFuture<Integer> getTotalNonPremiumAccounts() {
            return totalNonPremiumAccounts;
        }

        @Override
        public CompletableFuture<List<RegisteredPlayer>> findPlayersInConflictMode() {
            return conflicts;
        }

        @Override
        public boolean isConnected() {
            return connected;
        }
    }
}
