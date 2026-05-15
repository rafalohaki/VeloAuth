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
    void testOnPreLogin_WhenInitializationCompletes_ReleasesQueuedConnection() throws Exception {
        PreLoginEvent event = new PreLoginEvent(createConnection("192.0.2.50"), "QueuedPlayer");

        EventTask task = blocker.onPreLogin(event);

        assertNotNull(task, "Connections during initialization should be queued");
        setPluginInitialized(true);
        getInitializationFuture().complete(null);
        awaitEventTask(task);
        assertTrue(event.getResult().isAllowed(), "Queued connection should resume after initialization completes");
    }

    @Test
    void testOnPreLogin_WhenInitializationFails_DeniesQueuedConnection() throws Exception {
        PreLoginEvent event = new PreLoginEvent(createConnection("192.0.2.51"), "FailedPlayer");

        EventTask task = blocker.onPreLogin(event);

        assertNotNull(task, "Connections during initialization should still return an EventTask");
        getInitializationFuture().completeExceptionally(new IllegalStateException("init failed"));
        awaitEventTask(task);
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

    private void setPluginInitialized(boolean value) throws Exception {
        Field initializedField = VeloAuth.class.getDeclaredField("initialized");
        initializedField.setAccessible(true);
        initializedField.set(plugin, value);
    }

    private void awaitEventTask(EventTask task) throws Exception {
        try {
            Field futureField = task.getClass().getDeclaredField("future");
            futureField.setAccessible(true);
            ((CompletableFuture<?>) futureField.get(task)).join();
        } catch (ReflectiveOperationException e) {
            Thread.sleep(100);
        }
    }
}
