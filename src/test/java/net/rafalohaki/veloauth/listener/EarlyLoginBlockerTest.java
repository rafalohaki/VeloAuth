package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.proxy.InboundConnection;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import net.rafalohaki.veloauth.VeloAuth;
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
import java.net.InetSocketAddress;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;

import static net.rafalohaki.veloauth.testsupport.EventTaskTestSupport.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings({"java:S100", "deprecation"})
class EarlyLoginBlockerTest {

    private static final PlainTextComponentSerializer PLAIN_TEXT = PlainTextComponentSerializer.plainText();

    @Mock
    private ProxyServer proxyServer;

    @Mock
    private Logger logger;

    private VeloAuth plugin;
    private EarlyLoginBlocker blocker;

    @BeforeEach
    void setUp() throws Exception {
        Metrics.Factory metricsFactory = org.mockito.Mockito.mock(Metrics.Factory.class);
        plugin = new VeloAuth(proxyServer, logger, Path.of("."), metricsFactory);
        setPluginInitialized(false);
        blocker = new EarlyLoginBlocker(plugin);
    }

    @Test
    void testOnPreLogin_WhenInitializationCompletes_RunsQueuedEventThroughAuthPipeline() throws Exception {
        AuthListener authListener = org.mockito.Mockito.mock(AuthListener.class);
        org.mockito.Mockito.when(authListener.onPreLogin(org.mockito.Mockito.any(PreLoginEvent.class)))
                .thenAnswer(invocation -> {
                    PreLoginEvent delegated = invocation.getArgument(0);
                    delegated.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
                    return null;
                });
        setAuthListener(authListener);
        PreLoginEvent event = new PreLoginEvent(createConnection("192.0.2.50"), "QueuedPremium");

        EventTask task = blocker.onPreLogin(event);

        assertNotNull(task, "Connections during initialization should be queued");
        setPluginInitialized(true);
        getInitializationFuture().complete(null);
        await(task);
        org.mockito.Mockito.verify(authListener).onPreLogin(event);
        assertTrue(event.getResult().isAllowed(),
                "The released event must carry the auth pipeline's verdict");
        assertEquals(PreLoginEvent.PreLoginComponentResult.forceOnlineMode().toString(),
                event.getResult().toString(),
                "A queued premium player must resume with forced online mode, not the default result");
    }

    @Test
    void testOnPreLogin_DelegatedEventTask_IsAwaitedBeforeRelease() throws Exception {
        CompletableFuture<Void> pipelineWork = new CompletableFuture<>();
        AuthListener authListener = org.mockito.Mockito.mock(AuthListener.class);
        org.mockito.Mockito.when(authListener.onPreLogin(org.mockito.Mockito.any(PreLoginEvent.class)))
                .thenReturn(EventTask.resumeWhenComplete(pipelineWork));
        setAuthListener(authListener);
        PreLoginEvent event = new PreLoginEvent(createConnection("192.0.2.52"), "QueuedAsync");

        EventTask task = blocker.onPreLogin(event);
        assertNotNull(task);
        setPluginInitialized(true);
        getInitializationFuture().complete(null);

        CompletableFuture<Void> release = new CompletableFuture<>();
        task.execute(new com.velocitypowered.api.event.Continuation() {
            @Override
            public void resume() {
                release.complete(null);
            }

            @Override
            public void resumeWithException(Throwable exception) {
                release.completeExceptionally(exception);
            }
        });
        assertFalse(release.isDone(),
                "The queued event must stay suspended until the auth pipeline finishes");
        pipelineWork.complete(null);
        release.orTimeout(5, java.util.concurrent.TimeUnit.SECONDS).join();
    }

    @Test
    void testOnPreLogin_AuthListenerMissingAfterInitialization_DeniesFailClosed() throws Exception {
        // Initialization future completed but phase 8 never registered the listener.
        PreLoginEvent event = new PreLoginEvent(createConnection("192.0.2.53"), "Orphaned");

        EventTask task = blocker.onPreLogin(event);

        assertNotNull(task);
        setPluginInitialized(true);
        getInitializationFuture().complete(null);
        await(task);
        assertFalse(event.getResult().isAllowed(),
                "A queued event with no auth pipeline to run must be denied, never released unchecked");
    }

    @Test
    void testOnPreLogin_WhenInitializationFails_DeniesQueuedConnection() throws Exception {
        PreLoginEvent event = new PreLoginEvent(createConnection("192.0.2.51"), "FailedPlayer");

        EventTask task = blocker.onPreLogin(event);

        assertNotNull(task, "Connections during initialization should still return an EventTask");
        getInitializationFuture().completeExceptionally(new IllegalStateException("init failed"));
        await(task);
        assertFalse(event.getResult().isAllowed(), "Initialization failure should deny queued connections");
        assertEquals("VeloAuth ⏳",
                event.getResult().getReasonComponent().map(PLAIN_TEXT::serialize).orElse(null));
    }

    private InboundConnection createConnection(String address) {
        InboundConnection connection = org.mockito.Mockito.mock(InboundConnection.class);
        org.mockito.Mockito.when(connection.getRemoteAddress()).thenReturn(new InetSocketAddress(address, 25565));
        return connection;
    }

    @SuppressWarnings("unchecked")
    private CompletableFuture<Void> getInitializationFuture() throws Exception {
        Field futureField = VeloAuth.class.getDeclaredField("initializationFuture");
        futureField.setAccessible(true);
        return (CompletableFuture<Void>) futureField.get(plugin);
    }

    private void setAuthListener(AuthListener authListener) throws Exception {
        Field listenerField = VeloAuth.class.getDeclaredField("authListener");
        listenerField.setAccessible(true);
        listenerField.set(plugin, authListener);
    }

    private void setPluginInitialized(boolean value) throws Exception {
        Field initializedField = VeloAuth.class.getDeclaredField("initialized");
        initializedField.setAccessible(true);
        initializedField.set(plugin, value);
    }

}
