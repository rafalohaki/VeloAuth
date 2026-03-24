package net.rafalohaki.veloauth.cache;

import net.rafalohaki.veloauth.i18n.Messages;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"java:S100", "java:S3011"})
class BruteForceTrackerTest {

    private Messages messages;

    @BeforeEach
    void setUp() {
        messages = new Messages();
        messages.setLanguage("en");
    }

    @Test
    void testResetLoginAttempts_ConcurrentRegister_WaitsForRegisterLock() throws Exception {
        BruteForceTracker tracker = new BruteForceTracker(3, 60, messages);
        InetAddress address = InetAddress.getByName("127.0.0.10");
        BlockingIncrementEntry entry = new BlockingIncrementEntry();
        getEntries(tracker).put(address, entry);

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> registerFuture = executor.submit(() -> tracker.registerFailedLogin(address, null));

            assertTrue(entry.awaitIncrementStarted());

            Future<?> resetFuture = executor.submit(() -> {
                tracker.resetLoginAttempts(address, null);
                return null;
            });

            assertThrows(TimeoutException.class, () -> resetFuture.get(200, TimeUnit.MILLISECONDS));

            entry.release();

            assertFalse(registerFuture.get(5, TimeUnit.SECONDS));
            resetFuture.get(5, TimeUnit.SECONDS);
        }

        assertEquals(0, tracker.size());
        assertFalse(tracker.isBlocked(address, null));
    }

    @Test
    void testCleanupExpired_ConcurrentCheck_WaitsForCheckLock() throws Exception {
        BruteForceTracker tracker = new BruteForceTracker(3, 60, messages);
        InetAddress address = InetAddress.getByName("127.0.0.11");
        BlockingExpiryEntry entry = new BlockingExpiryEntry();
        entry.incrementAttempts();
        getEntries(tracker).put(address, entry);

        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> blockedFuture = executor.submit(() -> tracker.isBlocked(address, null));

            assertTrue(entry.awaitExpiryCheckStarted());

            Future<Integer> cleanupFuture = executor.submit(tracker::cleanupExpired);

            assertThrows(TimeoutException.class, () -> cleanupFuture.get(200, TimeUnit.MILLISECONDS));

            entry.release();

            assertFalse(blockedFuture.get(5, TimeUnit.SECONDS));
            assertEquals(0, cleanupFuture.get(5, TimeUnit.SECONDS));
        }

        assertEquals(1, tracker.size());
        assertFalse(tracker.isBlocked(address, null));
    }

    @SuppressWarnings("unchecked")
    private static ConcurrentHashMap<InetAddress, BruteForceTracker.BruteForceEntry> getEntries(
            BruteForceTracker tracker
    ) throws Exception {
        Field field = BruteForceTracker.class.getDeclaredField("bruteForceAttempts");
        field.setAccessible(true);
        return (ConcurrentHashMap<InetAddress, BruteForceTracker.BruteForceEntry>) field.get(tracker);
    }

    private static final class BlockingIncrementEntry extends BruteForceTracker.BruteForceEntry {

        private final CountDownLatch incrementStarted = new CountDownLatch(1);
        private final CountDownLatch releaseIncrement = new CountDownLatch(1);

        @Override
        void incrementAttempts() {
            incrementStarted.countDown();
            await(releaseIncrement);
            super.incrementAttempts();
        }

        private boolean awaitIncrementStarted() throws InterruptedException {
            return incrementStarted.await(5, TimeUnit.SECONDS);
        }

        private void release() {
            releaseIncrement.countDown();
        }
    }

    private static final class BlockingExpiryEntry extends BruteForceTracker.BruteForceEntry {

        private final CountDownLatch expiryCheckStarted = new CountDownLatch(1);
        private final CountDownLatch releaseExpiryCheck = new CountDownLatch(1);

        @Override
        boolean isExpired(int timeoutMinutes) {
            expiryCheckStarted.countDown();
            await(releaseExpiryCheck);
            return false;
        }

        private boolean awaitExpiryCheckStarted() throws InterruptedException {
            return expiryCheckStarted.await(5, TimeUnit.SECONDS);
        }

        private void release() {
            releaseExpiryCheck.countDown();
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(5, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting for latch");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for latch", e);
        }
    }
}
