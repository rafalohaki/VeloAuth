package net.rafalohaki.veloauth.authserver;

import com.sun.management.ThreadMXBean;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandler;
import io.netty.channel.embedded.EmbeddedChannel;
import org.geysermc.mcprotocollib.network.packet.DefaultPacketHeader;
import org.geysermc.mcprotocollib.network.packet.PacketHeader;
import org.junit.jupiter.api.Test;

import java.lang.management.ManagementFactory;
import java.lang.reflect.Constructor;

import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Manual allocation and throughput benchmark for the embedded frame-size guard. */
class BoundedNetworkServerPerformanceTest {

    private static final byte[] KEEP_ALIVE_FRAME = {2, 0, 1};
    private static final int DEFAULT_WARMUP_OPERATIONS = 100_000;
    private static final int DEFAULT_MEASURED_OPERATIONS = 500_000;

    @Test
    void benchmarkBoundedFrameDecoder() throws Exception {
        assumeTrue(Boolean.getBoolean("veloauth.benchmark"),
                "Manual benchmark disabled. Run with -Dveloauth.benchmark=true");

        int warmupOperations = Integer.getInteger(
                "veloauth.benchmark.warmup", DEFAULT_WARMUP_OPERATIONS);
        int measuredOperations = Integer.getInteger(
                "veloauth.benchmark.operations", DEFAULT_MEASURED_OPERATIONS);
        assumeTrue(warmupOperations > 0 && measuredOperations > 0,
                "Benchmark operation counts must be positive");

        EmbeddedChannel channel = new EmbeddedChannel(newFrameDecoder());
        try {
            runFrames(channel, warmupOperations);

            ThreadMXBean threadBean = (ThreadMXBean) ManagementFactory.getThreadMXBean();
            assumeTrue(threadBean.isThreadAllocatedMemorySupported(),
                    "Thread allocation measurement is unavailable on this JVM");
            threadBean.setThreadAllocatedMemoryEnabled(true);

            long threadId = Thread.currentThread().threadId();
            long allocatedBefore = threadBean.getThreadAllocatedBytes(threadId);
            long startedAt = System.nanoTime();
            runFrames(channel, measuredOperations);
            long elapsedNanos = System.nanoTime() - startedAt;
            long allocatedBytes = threadBean.getThreadAllocatedBytes(threadId) - allocatedBefore;

            double nanosecondsPerFrame = (double) elapsedNanos / measuredOperations;
            double bytesPerFrame = (double) allocatedBytes / measuredOperations;
            System.out.printf(
                    "Embedded frame decoder: %,d frames, %.1f ns/frame, %.1f allocated bytes/frame%n",
                    measuredOperations, nanosecondsPerFrame, bytesPerFrame);
        } finally {
            channel.finishAndReleaseAll();
        }
    }

    private static ChannelHandler newFrameDecoder() throws Exception {
        Class<?> codecClass = Class.forName(
                "net.rafalohaki.veloauth.authserver.BoundedNetworkServer$BoundedPacketSizerCodec");
        Constructor<?> constructor = codecClass.getDeclaredConstructor(PacketHeader.class, int.class);
        constructor.setAccessible(true);
        return (ChannelHandler) constructor.newInstance(
                new DefaultPacketHeader(), EmbeddedLimboServer.MAX_FRAME_BYTES);
    }

    private static void runFrames(EmbeddedChannel channel, int operations) {
        for (int index = 0; index < operations; index++) {
            if (!channel.writeInbound(Unpooled.wrappedBuffer(KEEP_ALIVE_FRAME))) {
                throw new IllegalStateException("Frame decoder produced no payload");
            }
            ByteBuf payload = channel.readInbound();
            if (payload.readableBytes() != KEEP_ALIVE_FRAME.length - 1) {
                payload.release();
                throw new IllegalStateException("Frame decoder produced an invalid payload");
            }
            payload.release();
        }
    }
}
