package net.rafalohaki.veloauth.premium;

import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Budget accounting is driven by an injected clock so the tests cost no wall-clock time and
 * cannot flake on a loaded CI machine.
 */
class UpstreamRateLimiterTest {

    private static final long ONE_SECOND_NANOS = TimeUnit.SECONDS.toNanos(1);

    private final AtomicLong clockNanos = new AtomicLong(TimeUnit.HOURS.toNanos(3));
    private final AtomicLong sleptNanos = new AtomicLong();

    /** 60 requests/minute — one permit per second, burst of 15. */
    private UpstreamRateLimiter limiterPerSecond(int maxWaitMillis) {
        return new UpstreamRateLimiter("mojang", 60, maxWaitMillis, clockNanos::get, nanos -> {
            sleptNanos.addAndGet(nanos);
            clockNanos.addAndGet(nanos);
            return true;
        });
    }

    @Test
    void tryAcquire_freshLimiter_grantsFullBurstWithoutWaiting() {
        UpstreamRateLimiter limiter = limiterPerSecond(0);

        for (int i = 0; i < 15; i++) {
            assertTrue(limiter.tryAcquire(true), "Burst permit " + i + " must be granted immediately");
        }

        assertEquals(0L, sleptNanos.get(), "Burst permits must not wait");
        assertFalse(limiter.tryAcquire(true), "The 16th request exceeds the burst and must be refused");
    }

    @Test
    void tryAcquire_budgetExhaustedAndNoWaitAllowed_refusesWithoutReserving() {
        UpstreamRateLimiter limiter = limiterPerSecond(0);
        for (int i = 0; i < 15; i++) {
            limiter.tryAcquire(true);
        }

        assertFalse(limiter.tryAcquire(true));
        assertFalse(limiter.tryAcquire(true));

        // A refusal must not consume budget, so one interval later exactly one permit is due.
        clockNanos.addAndGet(ONE_SECOND_NANOS);
        assertTrue(limiter.tryAcquire(true), "Refusals must not push the schedule forward");
        assertFalse(limiter.tryAcquire(true));
    }

    @Test
    void tryAcquire_budgetExhaustedButWaitAllowed_pacesInsteadOfRefusing() {
        UpstreamRateLimiter limiter = limiterPerSecond(1500);
        for (int i = 0; i < 15; i++) {
            limiter.tryAcquire(true);
        }

        assertTrue(limiter.tryAcquire(true), "A caller willing to wait must get the next permit");
        assertEquals(ONE_SECOND_NANOS, sleptNanos.get(), "Pacing must be one interval, not more");
    }

    @Test
    void tryAcquire_retryAttempt_isRefusedRatherThanWaitingAgain() {
        UpstreamRateLimiter limiter = limiterPerSecond(1500);
        for (int i = 0; i < 15; i++) {
            limiter.tryAcquire(true);
        }

        assertFalse(limiter.tryAcquire(false), "A retry must not spend the lookup's wait budget twice");
        assertEquals(0L, sleptNanos.get(), "A refused retry must not delay the login at all");
        assertTrue(limiter.tryAcquire(true), "Refusing the retry must leave the permit available");
    }

    @Test
    void tryAcquire_waitLongerThanConfiguredMaximum_refuses() {
        // Two permits per minute: the second permit is 30s away, far beyond the 1s allowance.
        UpstreamRateLimiter limiter = new UpstreamRateLimiter(
                "mojang", 2, 1000, clockNanos::get, nanos -> true);

        assertTrue(limiter.tryAcquire(true));
        assertFalse(limiter.tryAcquire(true), "A 30s wait must fail closed rather than stall the login");
    }

    @Test
    void tryAcquire_idleLimiter_reaccumulatesAtMostOneBurst() {
        UpstreamRateLimiter limiter = limiterPerSecond(0);
        for (int i = 0; i < 15; i++) {
            limiter.tryAcquire(true);
        }

        // Idle for an hour — credit is capped at the burst, never the whole idle period.
        clockNanos.addAndGet(TimeUnit.HOURS.toNanos(1));

        int granted = 0;
        while (limiter.tryAcquire(true)) {
            granted++;
        }
        assertEquals(15, granted, "Idle credit must be capped at the burst allowance");
    }

    @Test
    void tryAcquire_zeroRequestsPerMinute_disablesTheCeiling() {
        UpstreamRateLimiter limiter = new UpstreamRateLimiter(
                "mojang", 0, 0, clockNanos::get, nanos -> true);

        for (int i = 0; i < 1000; i++) {
            assertTrue(limiter.tryAcquire(true), "A disabled ceiling must never refuse");
        }
    }

    @Test
    void tryAcquire_waitInterrupted_refusesTheRequest() {
        UpstreamRateLimiter limiter = new UpstreamRateLimiter(
                "mojang", 60, 1500, clockNanos::get, nanos -> false);
        for (int i = 0; i < 15; i++) {
            limiter.tryAcquire(true);
        }

        assertFalse(limiter.tryAcquire(true), "An interrupted wait must not send the request");
    }

    @Test
    void tryAcquire_concurrentCallers_neverExceedTheBurst() throws Exception {
        UpstreamRateLimiter limiter = limiterPerSecond(0);
        int threads = 8;
        AtomicInteger granted = new AtomicInteger();
        CountDownLatch start = new CountDownLatch(1);
        CountDownLatch done = new CountDownLatch(threads);

        try (ExecutorService pool = Executors.newFixedThreadPool(threads)) {
            for (int i = 0; i < threads; i++) {
                pool.execute(() -> {
                    try {
                        assertTrue(start.await(2, TimeUnit.SECONDS));
                        for (int call = 0; call < 50; call++) {
                            if (limiter.tryAcquire(true)) {
                                granted.incrementAndGet();
                            }
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        done.countDown();
                    }
                });
            }
            start.countDown();
            assertTrue(done.await(10, TimeUnit.SECONDS));
        }

        assertEquals(15, granted.get(), "The frozen clock allows exactly the burst, whatever the thread count");
    }

    @Test
    void constructor_negativeBudget_isRejected() {
        assertThrows(IllegalArgumentException.class, () -> new UpstreamRateLimiter(
                "mojang", -1, 0, clockNanos::get, nanos -> true));
        assertThrows(IllegalArgumentException.class, () -> new UpstreamRateLimiter(
                "mojang", 60, -1, clockNanos::get, nanos -> true));
    }
}
