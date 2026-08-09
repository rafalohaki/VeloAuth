package net.rafalohaki.veloauth.authserver;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

/** Supplies a deterministic IPv4 loopback address without DNS or host configuration. */
final class LoopbackAddress {

    private static final byte[] IPV4_BYTES = {127, 0, 0, 1};
    private static final InetAddress IPV4 = createIpv4();

    private LoopbackAddress() {
    }

    static InetSocketAddress socket(int port) {
        return new InetSocketAddress(IPV4, port);
    }

    private static InetAddress createIpv4() {
        try {
            return InetAddress.getByAddress(IPV4_BYTES);
        } catch (UnknownHostException impossible) {
            throw new ExceptionInInitializerError(impossible);
        }
    }
}
