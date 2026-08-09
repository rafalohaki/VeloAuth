package net.rafalohaki.veloauth.authserver;

import io.netty.channel.Channel;

/**
 * Narrow boundary between the embedded Minecraft server and its protocol translator.
 *
 * <p>MCProtocolLib owns the listener, sessions and native protocol-47 codec. Implementations of
 * this contract only advertise a verified translation matrix and insert translation handlers into
 * an already-created MCProtocolLib channel.</p>
 */
interface ProtocolRuntime extends AutoCloseable {

    boolean supportsProtocol(int protocol);

    int minimumProtocol();

    int maximumProtocol();

    String minimumVersionName();

    String maximumVersionName();

    String runtimeVersion();

    void inject(Channel channel);

    /**
     * Sends Velocity's standard login forwarding query when the connected protocol supports it,
     * then resumes the base-protocol login in wire order.
     *
     * <p>The managed runtime owns the client protocol details. A protocol-47-only test runtime
     * has no login-query packet and therefore resumes immediately.</p>
     */
    default void sendVelocityForwardingRequest(
            Channel channel, int transactionId, Runnable loginContinuation) {
        java.util.Objects.requireNonNull(channel, "channel");
        java.util.Objects.requireNonNull(loginContinuation, "loginContinuation").run();
    }

    @Override
    void close();
}
