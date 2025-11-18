package net.rafalohaki.veloauth.command;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for IPRateLimiter.
 * Tests rate limiting behavior, thread safety, and cleanup logic.
 */
class IPRateLimiterTest {

    private IPRateLimiter rateLimiter;
    private InetAddress testAddress1;
    private InetAddress testAddress2;

    @BeforeEach
    void setUp() throws UnknownHostException {
        rateLimiter = new IPRateLimiter(5, 5); // 5 attempts, 5 minutes timeout
        testAddress1 = InetAddress.getByName("192.168.1.1");
        testAddress2 = InetAddress.getByName("192.168.1.2");
    }

    @Test
    void testIsRateLimit_NewAddress_ReturnsFalse() {
        boolean result = rateLimiter.isRateLimited(testAddress1);

        assertFalse(result);
    }

    @Test
    void testIncrementAttempts_NewAddress_ReturnsOne() {
        rateLimiter.incrementAttempts(testAddress1);

        int attempts = rateLimiter.getAttempts(testAddress1);

        assertEquals(1, attempts);
    }

    @Test
    void testIncrementAttempts_MultipleCalls_ReturnsCorrectCount() {
        rateLimiter.incrementAttempts(testAddress1);
        rateLimiter.incrementAttempts(testAddress1);
        rateLimiter.incrementAttempts(testAddress1);

        int attempts = rateLimiter.getAttempts(testAddress1);

        assertEquals(3, attempts);
    }

    @Test
    void testIsRateLimit_AfterThreshold_ReturnsTrue() {
        // Increment attempts beyond the threshold (5)
        for (int i = 0; i < 5; i++) {
            rateLimiter.incrementAttempts(testAddress1);
        }

        boolean result = rateLimiter.isRateLimited(testAddress1);

        assertTrue(result);
    }

    @Test
    void testIsRateLimit_BeforeThreshold_ReturnsFalse() {
        // Increment attempts but stay below threshold (5)
        for (int i = 0; i < 4; i++) {
            rateLimiter.incrementAttempts(testAddress1);
        }

        boolean result = rateLimiter.isRateLimited(testAddress1);

        assertFalse(result);
    }

    @Test
    void testGetAttempts_NonExistentAddress_ReturnsZero() {
        int attempts = rateLimiter.getAttempts(testAddress1);

        assertEquals(0, attempts);
    }

    @Test
    void testMultipleAddresses_IndependentCounting() {
        rateLimiter.incrementAttempts(testAddress1);
        rateLimiter.incrementAttempts(testAddress1);
        rateLimiter.incrementAttempts(testAddress2);

        int attempts1 = rateLimiter.getAttempts(testAddress1);
        int attempts2 = rateLimiter.getAttempts(testAddress2);

        assertEquals(2, attempts1);
        assertEquals(1, attempts2);
    }

    @Test
    void testThreadSafety_ConcurrentIncrementAttempts() throws InterruptedException {
        int threadCount = 10;
        int incrementsPerThread = 100;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);

        // Launch multiple threads to increment attempts concurrently
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threadCount; i++) {
            futures.add(executor.submit(() -> {
                try {
                    for (int j = 0; j < incrementsPerThread; j++) {
                        rateLimiter.incrementAttempts(testAddress1);
                    }
                } finally {
                    latch.countDown();
                }
            }));
        }

        // Wait for all threads to complete
        assertTrue(latch.await(10, TimeUnit.SECONDS));
        executor.shutdown();
        assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));

        // Verify all futures completed successfully
        assertEquals(threadCount, futures.size());
        for (Future<?> future : futures) {
            try {
                future.get(10, TimeUnit.SECONDS);
            } catch (ExecutionException | TimeoutException e) {
                fail("Future should complete without exceptions: " + e.getMessage());
            }
        }

        // Verify final count is correct
        int finalAttempts = rateLimiter.getAttempts(testAddress1);
        assertEquals(threadCount * incrementsPerThread, finalAttempts);
    }

    @Test
    void testThreadSafety_ConcurrentIsRateLimited() throws InterruptedException {
        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        CountDownLatch latch = new CountDownLatch(threadCount);

        // Launch multiple threads to check rate limiting concurrently
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < threadCount; i++) {
            futures.add(executor.submit(() -> {
                try {
                    // Each thread increments and checks rate limiting
                    rateLimiter.incrementAttempts(testAddress1);
                    rateLimiter.isRateLimited(testAddress1);
                } finally {
                    latch.countDown();
                }
            }));
        }

        // Wait for all threads to complete
        assertTrue(latch.await(5, TimeUnit.SECONDS));

        // Wait for all futures to complete with timeout
        for (Future<?> future : futures) {
            try {
                future.get(5, TimeUnit.SECONDS); // This should complete without exception
                assertTrue(true, "Future should complete within 5 seconds");
            } catch (ExecutionException | TimeoutException e) {
                fail("Future should complete without exceptions: " + e.getMessage());
            }
        }

        executor.shutdown();
    }

    @Test
    void testResetAttempts_ClearsCount() {
        // Add some attempts
        rateLimiter.incrementAttempts(testAddress1);
        rateLimiter.incrementAttempts(testAddress1);
        assertEquals(2, rateLimiter.getAttempts(testAddress1));

        // Reset attempts
        rateLimiter.reset(testAddress1);

        // Verify attempts are cleared
        assertEquals(0, rateLimiter.getAttempts(testAddress1));
        assertFalse(rateLimiter.isRateLimited(testAddress1));
    }

    @Test
    void testResetAttempts_NonExistentAddress_NoException() {
        // Should not throw exception for non-existent address
        assertDoesNotThrow(() -> rateLimiter.reset(testAddress1));

        assertEquals(0, rateLimiter.getAttempts(testAddress1));
    }

    @Test
    void testGetSize_ReturnsCorrectInformation() {
        // Add some attempts for different addresses
        rateLimiter.incrementAttempts(testAddress1);
        rateLimiter.incrementAttempts(testAddress2);

        int size = rateLimiter.size();

        assertEquals(2, size);
    }

    @Test
    void testClearAll_RemovesAllEntries() {
        // Add some attempts
        rateLimiter.incrementAttempts(testAddress1);
        rateLimiter.incrementAttempts(testAddress2);

        assertEquals(2, rateLimiter.size());

        // Clear all entries
        rateLimiter.clearAll();

        // Verify all entries are removed
        assertEquals(0, rateLimiter.size());
        assertEquals(0, rateLimiter.getAttempts(testAddress1));
        assertEquals(0, rateLimiter.getAttempts(testAddress2));
    }
}
