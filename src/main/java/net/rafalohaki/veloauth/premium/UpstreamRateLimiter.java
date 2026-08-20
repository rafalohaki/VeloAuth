package net.rafalohaki.veloauth.premium;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;

/**
 * Outbound request budget for a single upstream premium API.
 * <p>
 * The per-source admission controller and the global concurrency semaphore both bound
 * <em>lookups</em>; neither bounds the <em>rate</em> of HTTP requests VeloAuth sends to
 * Mojang or its mirrors. One cold lookup fans out to every enabled resolver and each
 * resolver may retry, so a join wave translates into a multiple of itself in upstream
 * traffic. This limiter is the ceiling on that traffic: it is enforced per attempt, so
 * retries consume budget exactly like first attempts.
 * <p>
 * Pacing uses the reserve-and-wait scheme: each permit is stamped one interval after the
 * previous one, and the caller waits until its stamp comes due. Callers that would have to
 * wait longer than {@code maxWaitMillis} are refused without reserving, which turns upstream
 * saturation into a bounded login delay for some players instead of an unbounded queue for
 * everyone. The budget starts full and an idle limiter re-accumulates credit for up to a
 * quarter of the minute budget, so ordinary bursts pass without waiting.
 * <p>
 * Thread-safe. Waiting happens off-lock and only on the virtual threads that run resolver
 * I/O — never on a Velocity event thread.
 */
final class UpstreamRateLimiter {

    private static final Logger logger = LoggerFactory.getLogger(UpstreamRateLimiter.class);
    private static final Marker PREMIUM_MARKER = MarkerFactory.getMarker("PREMIUM");
    private static final long NANOS_PER_MINUTE = TimeUnit.MINUTES.toNanos(1);

    /** Idle credit, as a fraction of the per-minute budget. */
    private static final int BURST_DIVISOR = 4;

    /** Wait hook. Replaced in tests so an exhausted budget costs no wall-clock time. */
    @FunctionalInterface
    interface NanoSleeper {
        /** @return false if the wait was interrupted and the request must be abandoned. */
        boolean sleep(long nanos);
    }

    private final String upstreamId;
    private final long intervalNanos;
    private final long burstNanos;
    private final long maxWaitNanos;
    private final LongSupplier nanoClock;
    private final NanoSleeper sleeper;
    private final ReentrantLock lock = new ReentrantLock();

    /** Instant the next permit comes due. Guarded by {@link #lock}. */
    private long nextPermitNanos;

    /**
     * @param requestsPerMinute upstream ceiling; {@code 0} disables the limiter
     * @param maxWaitMillis     longest a caller may wait for a permit before being refused
     */
    static UpstreamRateLimiter perMinute(String upstreamId, int requestsPerMinute, int maxWaitMillis) {
        return new UpstreamRateLimiter(upstreamId, requestsPerMinute, maxWaitMillis,
                System::nanoTime, UpstreamRateLimiter::sleepNanos);
    }

    UpstreamRateLimiter(String upstreamId, int requestsPerMinute, int maxWaitMillis,
                        LongSupplier nanoClock, NanoSleeper sleeper) {
        this.upstreamId = Objects.requireNonNull(upstreamId, "upstreamId");
        this.nanoClock = Objects.requireNonNull(nanoClock, "nanoClock");
        this.sleeper = Objects.requireNonNull(sleeper, "sleeper");
        if (requestsPerMinute < 0) {
            throw new IllegalArgumentException("requestsPerMinute must be >= 0");
        }
        if (maxWaitMillis < 0) {
            throw new IllegalArgumentException("maxWaitMillis must be >= 0");
        }
        this.intervalNanos = requestsPerMinute == 0 ? 0L : NANOS_PER_MINUTE / requestsPerMinute;
        // One of the burst permits is the one due now, so only the rest is backdated credit.
        int burstPermits = Math.max(1, requestsPerMinute / BURST_DIVISOR);
        this.burstNanos = this.intervalNanos * (burstPermits - 1L);
        this.maxWaitNanos = TimeUnit.MILLISECONDS.toNanos(maxWaitMillis);
        // nanoTime() has an arbitrary origin, so anchor the schedule instead of starting at 0.
        // Anchoring a full burst in the past starts the budget full: at construction VeloAuth
        // has sent nothing yet, so the upstream's own window is untouched too.
        this.nextPermitNanos = nanoClock.getAsLong() - this.burstNanos;
    }

    /**
     * Claims budget for one outbound request.
     * <p>
     * Waiting is offered to first attempts only. A retry already sits inside a degraded
     * lookup, and Velocity closes the connection when the whole PreLogin phase outlasts
     * {@code connection-timeout} (5s by default), so the wait must be spent at most once
     * per lookup rather than once per attempt.
     *
     * @param mayWait whether this caller may wait for the next permit
     * @return false when the request must not be sent — the budget is exhausted or the wait
     *         was interrupted
     */
    boolean tryAcquire(boolean mayWait) {
        if (intervalNanos == 0L) {
            return true;
        }

        long waitNanos = reserve(mayWait ? maxWaitNanos : 0L);
        if (waitNanos < 0L) {
            if (logger.isDebugEnabled()) {
                logger.debug(PREMIUM_MARKER,
                        "[RateLimit] {} budget exhausted — request not sent", upstreamId);
            }
            return false;
        }
        if (waitNanos == 0L) {
            return true;
        }

        if (logger.isDebugEnabled()) {
            logger.debug(PREMIUM_MARKER, "[RateLimit] {} pacing request by {}ms",
                    upstreamId, TimeUnit.NANOSECONDS.toMillis(waitNanos));
        }
        return sleeper.sleep(waitNanos);
    }

    /**
     * Reserves the next permit.
     *
     * @return nanos the caller must wait, or {@code -1} when that wait would exceed the
     *         configured maximum — in which case nothing is reserved and the permit stays
     *         available for a caller that can use it sooner
     */
    private long reserve(long allowedWaitNanos) {
        lock.lock();
        try {
            long now = nanoClock.getAsLong();
            long earliestPermit = now - burstNanos;
            // Subtraction, not <, so the comparison survives nanoTime() wrapping.
            if (nextPermitNanos - earliestPermit < 0L) {
                nextPermitNanos = earliestPermit;
            }

            long waitNanos = nextPermitNanos - now;
            if (waitNanos > allowedWaitNanos) {
                return -1L;
            }
            nextPermitNanos += intervalNanos;
            return Math.max(0L, waitNanos);
        } finally {
            lock.unlock();
        }
    }

    private static boolean sleepNanos(long nanos) {
        try {
            TimeUnit.NANOSECONDS.sleep(nanos);
            return true;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }
}
