package net.rafalohaki.veloauth.integration;

import net.kyori.adventure.text.serializer.plain.PlainTextComponentSerializer;
import org.geysermc.mcprotocollib.auth.GameProfile;
import org.geysermc.mcprotocollib.network.ClientSession;
import org.geysermc.mcprotocollib.network.Session;
import org.geysermc.mcprotocollib.network.event.session.ConnectedEvent;
import org.geysermc.mcprotocollib.network.event.session.DisconnectedEvent;
import org.geysermc.mcprotocollib.network.event.session.PacketErrorEvent;
import org.geysermc.mcprotocollib.network.event.session.SessionAdapter;
import org.geysermc.mcprotocollib.network.factory.ClientNetworkSessionFactory;
import org.geysermc.mcprotocollib.network.packet.Packet;
import org.geysermc.mcprotocollib.protocol.MinecraftProtocol;
import org.geysermc.mcprotocollib.protocol.packet.ingame.clientbound.ClientboundSystemChatPacket;
import org.geysermc.mcprotocollib.protocol.packet.ingame.serverbound.ServerboundChatCommandPacket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Opt-in real external-mode journey. The owning shell script starts Velocity plus two
 * checksum-pinned NanoLimbo processes so auth and backend connections are distinguishable.
 */
class VelocityExternalJourneyIT {

    private static final PlainTextComponentSerializer PLAIN = PlainTextComponentSerializer.plainText();
    private static final int CONNECT_TIMEOUT_SECONDS = 20;
    private static final int TRANSFER_TIMEOUT_SECONDS = 30;

    private ClientSession client;

    @AfterEach
    void disconnectClient() {
        if (client != null && client.isConnected()) {
            client.disconnect("external journey complete");
        }
    }

    @Test
    @SuppressWarnings("PMD.UnitTestShouldIncludeAssert") // Phase helpers own the journey assertions.
    void crackedPlayerCompletesRegisterLogoutLoginAndSessionReconnectJourney() throws Exception {
        String host = System.getProperty("veloauth.external.host");
        Assumptions.assumeTrue(host != null && !host.isBlank(),
                "Run through scripts/test-velocity-external.sh");
        int port = Integer.getInteger("veloauth.external.port", 25565);
        String username = requiredProperty("veloauth.external.username");
        String password = requiredProperty("veloauth.external.password");
        String authMarker = requiredProperty("veloauth.external.auth-marker");
        String backendMarker = requiredProperty("veloauth.external.backend-marker");
        String phase = requiredProperty("veloauth.external.phase");
        UUID playerId = UUID.nameUUIDFromBytes(("OfflinePlayer:" + username)
                .getBytes(java.nio.charset.StandardCharsets.UTF_8));

        JourneyConnection connection = connect(host, port, playerId, username, authMarker, backendMarker);
        switch (phase) {
            case "register" -> exerciseRegistration(connection, password);
            case "login" -> exerciseLogin(connection, password);
            case "reconnect" -> exerciseReconnect(connection, password);
            default -> throw new IllegalArgumentException("Unsupported external journey phase: " + phase);
        }
    }

    private void exerciseRegistration(JourneyConnection connection, String password) throws InterruptedException {
        assertTrue(connection.authReached().await(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                () -> "A new cracked player must reach auth; state=" + connection.connectionFailure().get());
        assertFalse(connection.backendBeforeCredentials().get(),
                "An unauthenticated cracked player must never reach a backend first");
        connection.credentialsSent().set(true);
        client.send(new ServerboundChatCommandPacket("register " + password + " " + password));
        assertTrue(connection.backendReached().await(TRANSFER_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                "Successful /register must transfer the same real connection to a backend");
        assertTrue(client.isConnected(), "The registered player must remain connected on the backend");
        client.send(new ServerboundChatCommandPacket("logout"));
        assertTrue(connection.disconnected().await(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                "/logout must terminate the concrete proxy connection");
    }

    private void exerciseLogin(JourneyConnection connection, String password) throws InterruptedException {
        assertTrue(connection.authReached().await(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                () -> "Reconnect after /logout must reach auth; state=" + connection.connectionFailure().get());
        assertFalse(connection.backendBeforeCredentials().get(),
                "Logout must prevent session resurrection before /login");
        connection.credentialsSent().set(true);
        client.send(new ServerboundChatCommandPacket("login " + password));
        assertTrue(connection.backendReached().await(TRANSFER_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                "Successful /login must transfer the player to a backend");
        assertTrue(client.isConnected(), "The logged-in player must remain connected on the backend");
        client.disconnect("exercise connection-bound session cleanup");
        assertTrue(connection.disconnected().await(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                "The proxy must observe the deliberate reconnect boundary");
    }

    private void exerciseReconnect(JourneyConnection connection, String password) throws InterruptedException {
        assertTrue(connection.authReached().await(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                () -> "A normal reconnect must return to auth; state=" + connection.connectionFailure().get());
        assertFalse(connection.backendBeforeCredentials().get(),
                "Connection-bound authorization must not survive disconnect");
        connection.credentialsSent().set(true);
        client.send(new ServerboundChatCommandPacket("login " + password));
        assertTrue(connection.backendReached().await(TRANSFER_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                "A fresh /login after reconnect must return the player to the backend");
        assertTrue(client.isConnected(), "The reauthenticated player must remain connected");
    }

    private JourneyConnection connect(String host, int port, UUID playerId, String username,
            String authMarker, String backendMarker) {
        CountDownLatch authReached = new CountDownLatch(1);
        CountDownLatch backendReached = new CountDownLatch(1);
        CountDownLatch connected = new CountDownLatch(1);
        CountDownLatch disconnected = new CountDownLatch(1);
        AtomicBoolean credentialsSent = new AtomicBoolean();
        AtomicBoolean backendBeforeCredentials = new AtomicBoolean();
        AtomicReference<String> connectionFailure = new AtomicReference<>("no connection event received");
        MinecraftProtocol protocol = new MinecraftProtocol(new GameProfile(playerId, username), null);
        client = ClientNetworkSessionFactory.factory()
                .setAddress(host, port)
                .setProtocol(protocol)
                .setPacketHandlerExecutor(Runnable::run)
                .create();
        client.addListener(new SessionAdapter() {
            @Override
            public void connected(ConnectedEvent event) {
                connected.countDown();
            }

            @Override
            public void packetReceived(Session session, Packet packet) {
                if (!(packet instanceof ClientboundSystemChatPacket chat)) {
                    return;
                }
                String message = PLAIN.serialize(chat.getContent());
                if (message.contains(authMarker)) {
                    authReached.countDown();
                }
                if (message.contains(backendMarker)) {
                    if (!credentialsSent.get()) {
                        backendBeforeCredentials.set(true);
                    }
                    backendReached.countDown();
                }
            }

            @Override
            public void disconnected(DisconnectedEvent event) {
                String reason = PLAIN.serialize(event.getReason());
                Throwable cause = event.getCause();
                connectionFailure.set(cause == null ? reason : reason + ": " + cause);
                disconnected.countDown();
            }

            @Override
            public void packetError(PacketErrorEvent event) {
                connectionFailure.set("packet error: " + event.getCause());
            }
        });
        client.connect(true);
        try {
            assertTrue(connected.await(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS),
                    () -> "External journey client did not connect: " + connectionFailure.get());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while connecting external journey client", interrupted);
        }
        return new JourneyConnection(authReached, backendReached, disconnected,
                credentialsSent, backendBeforeCredentials, connectionFailure);
    }

    private static String requiredProperty(String name) {
        String value = System.getProperty(name);
        assertTrue(value != null && !value.isBlank(), "Missing required external journey property: " + name);
        return value;
    }

    private record JourneyConnection(
            CountDownLatch authReached,
            CountDownLatch backendReached,
            CountDownLatch disconnected,
            AtomicBoolean credentialsSent,
            AtomicBoolean backendBeforeCredentials,
            AtomicReference<String> connectionFailure) {
    }
}
