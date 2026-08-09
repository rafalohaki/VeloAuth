package net.rafalohaki.veloauth.authserver;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFactory;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.ServerSocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.ByteToMessageCodec;
import io.netty.handler.codec.CorruptedFrameException;
import io.netty.handler.codec.TooLongFrameException;
import org.geysermc.mcprotocollib.network.NetworkConstants;
import org.geysermc.mcprotocollib.network.Session;
import org.geysermc.mcprotocollib.network.event.server.SessionAddedEvent;
import org.geysermc.mcprotocollib.network.event.server.SessionRemovedEvent;
import org.geysermc.mcprotocollib.network.netty.MinecraftChannelInitializer;
import org.geysermc.mcprotocollib.network.packet.PacketHeader;
import org.geysermc.mcprotocollib.network.server.NetworkServer;
import org.geysermc.mcprotocollib.network.session.ServerNetworkSession;
import org.geysermc.mcprotocollib.protocol.MinecraftProtocol;

import java.net.SocketAddress;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * MCProtocolLib server with an owned NIO transport, concurrent session registry and a declared
 * frame-size limit enforced before the payload is buffered.
 */
final class BoundedNetworkServer extends NetworkServer {

    private static final String FRAME_SIZER_NAME = "veloauth-bounded-sizer";
    private static final AtomicInteger SERVER_SEQUENCE = new AtomicInteger();

    private final Set<Session> concurrentSessions = ConcurrentHashMap.newKeySet();
    private final ProtocolRuntime protocolRuntime;
    private final int maximumFrameBytes;
    private final int backlog;
    private final int serverSequence = SERVER_SEQUENCE.incrementAndGet();
    private final CountDownLatch localAddressReady = new CountDownLatch(1);
    private volatile EventLoopGroup bossGroup;
    private volatile EventLoopGroup workerGroup;
    private volatile SocketAddress localAddress;

    BoundedNetworkServer(
            SocketAddress bindAddress,
            Supplier<? extends MinecraftProtocol> protocolSupplier,
            ProtocolRuntime protocolRuntime,
            int maximumFrameBytes,
            int backlog) {
        // Packet callbacks remain ordered on the owning Netty event loop. Embedded handlers do
        // bounded CPU only; they never perform database, filesystem or HTTP work.
        super(bindAddress, protocolSupplier, () -> Runnable::run);
        if (maximumFrameBytes <= 0) {
            throw new IllegalArgumentException("maximumFrameBytes must be positive");
        }
        if (backlog <= 0) {
            throw new IllegalArgumentException("backlog must be positive");
        }
        this.protocolRuntime = java.util.Objects.requireNonNull(protocolRuntime, "protocolRuntime");
        this.maximumFrameBytes = maximumFrameBytes;
        this.backlog = backlog;
    }

    @Override
    protected ChannelFactory<? extends ServerSocketChannel> getChannelFactory() {
        return NioServerSocketChannel::new;
    }

    @Override
    protected EventLoopGroup createBossEventLoopGroup() {
        EventLoopGroup group = new MultiThreadIoEventLoopGroup(
                1, threadFactory("boss"), NioIoHandler.newFactory());
        bossGroup = group;
        return group;
    }

    @Override
    protected EventLoopGroup createWorkerEventLoopGroup() {
        int workerThreads = Math.max(2, Math.min(4, Runtime.getRuntime().availableProcessors()));
        EventLoopGroup group = new MultiThreadIoEventLoopGroup(
                workerThreads, threadFactory("worker"), NioIoHandler.newFactory());
        workerGroup = group;
        return group;
    }

    @Override
    protected void setOptions(ServerBootstrap bootstrap) {
        super.setOptions(bootstrap);
        bootstrap.option(ChannelOption.SO_BACKLOG, backlog);
        bootstrap.childOption(ChannelOption.SO_KEEPALIVE, true);
        bootstrap.handler(new ChannelInboundHandlerAdapter() {
            @Override
            public void channelActive(ChannelHandlerContext context) throws Exception {
                localAddress = context.channel().localAddress();
                localAddressReady.countDown();
                super.channelActive(context);
            }
        });
    }

    @Override
    protected ChannelHandler getChannelHandler() {
        return new MinecraftChannelInitializer<>(this::createSession, false) {
            @Override
            protected void addHandlers(ServerNetworkSession session, Channel channel) {
                super.addHandlers(session, channel);
                channel.pipeline().replace(
                        NetworkConstants.SIZER_NAME,
                        FRAME_SIZER_NAME,
                        new BoundedPacketSizerCodec(
                                session.getPacketProtocol().getPacketHeader(), maximumFrameBytes));
                protocolRuntime.inject(channel);
            }
        };
    }

    SocketAddress localAddress() {
        return localAddress;
    }

    SocketAddress awaitLocalAddress(Duration timeout) {
        try {
            if (!localAddressReady.await(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
                throw new IllegalStateException("Timed out waiting for the embedded listener address");
            }
            return localAddress;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for the embedded listener address", e);
        }
    }

    private ServerNetworkSession createSession(Channel channel) {
        MinecraftProtocol protocol = createPacketProtocol();
        ServerNetworkSession session = new ServerNetworkSession(
                channel.remoteAddress(), protocol, this, Runnable::run);
        protocol.newServerSession(this, session);
        return session;
    }

    @Override
    public List<Session> getSessions() {
        return new ArrayList<>(concurrentSessions);
    }

    @Override
    public void addSession(Session session) {
        if (concurrentSessions.add(session)) {
            callEvent(new SessionAddedEvent(this, session));
        }
    }

    @Override
    public void removeSession(Session session) {
        if (concurrentSessions.remove(session)) {
            callEvent(new SessionRemovedEvent(this, session));
        }
    }

    boolean closeAndAwait(Duration timeout) {
        close(false);
        long deadline = System.nanoTime() + timeout.toNanos();
        boolean workersStopped = awaitGroup(workerGroup, deadline);
        boolean bossStopped = awaitGroup(bossGroup, deadline);
        return workersStopped && bossStopped;
    }

    private boolean awaitGroup(EventLoopGroup group, long deadlineNanos) {
        if (group == null) {
            return true;
        }
        long remaining = deadlineNanos - System.nanoTime();
        if (remaining <= 0) {
            return group.isTerminated();
        }
        return group.terminationFuture().awaitUninterruptibly(remaining, TimeUnit.NANOSECONDS);
    }

    private ThreadFactory threadFactory(String role) {
        AtomicInteger sequence = new AtomicInteger();
        return runnable -> {
            Thread thread = new Thread(runnable,
                    "VeloAuth-EmbeddedLimbo-" + serverSequence + '-' + role + '-' + sequence.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }

    /**
     * Minecraft VarInt frame codec with an early declared-size guard. This mirrors the public wire
     * framing contract used by MCProtocolLib, while adding the missing maximum before waiting for
     * or allocating the full payload.
     */
    private static final class BoundedPacketSizerCodec extends ByteToMessageCodec<ByteBuf> {
        private final PacketHeader header;
        private final int maximumFrameBytes;

        private BoundedPacketSizerCodec(PacketHeader header, int maximumFrameBytes) {
            this.header = header;
            this.maximumFrameBytes = maximumFrameBytes;
        }

        @Override
        protected void encode(ChannelHandlerContext context, ByteBuf input, ByteBuf output) {
            int length = input.readableBytes();
            if (length > maximumFrameBytes) {
                throw new TooLongFrameException("Outbound Minecraft frame exceeds configured limit");
            }
            output.ensureWritable(header.getLengthSize(length) + length);
            header.writeLength(output, length);
            output.writeBytes(input);
        }

        @Override
        protected void decode(ChannelHandlerContext context, ByteBuf input, List<Object> output) {
            input.markReaderIndex();
            int maximumLengthBytes = header.getLengthSize();
            byte[] lengthBytes = new byte[maximumLengthBytes];
            for (int index = 0; index < maximumLengthBytes; index++) {
                if (!input.isReadable()) {
                    input.resetReaderIndex();
                    return;
                }
                lengthBytes[index] = input.readByte();
                if ((header.isLengthVariable() && lengthBytes[index] >= 0)
                        || index == maximumLengthBytes - 1) {
                    int length = header.readLength(Unpooled.wrappedBuffer(lengthBytes), input.readableBytes());
                    if (length < 0) {
                        throw new CorruptedFrameException("Negative Minecraft frame length");
                    }
                    if (length > maximumFrameBytes) {
                        throw new TooLongFrameException("Minecraft frame exceeds configured limit");
                    }
                    if (input.readableBytes() < length) {
                        input.resetReaderIndex();
                        return;
                    }
                    output.add(input.readRetainedSlice(length));
                    return;
                }
            }
            throw new CorruptedFrameException("Minecraft frame length VarInt is too long");
        }
    }
}
