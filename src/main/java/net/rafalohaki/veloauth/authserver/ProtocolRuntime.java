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

    @Override
    void close();
}
