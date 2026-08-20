package net.rafalohaki.veloauth.premium;

import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers the interaction between the retry loop and the upstream budget. The stub resolver
 * counts endpoint reads, which happen only on the code path that performs an HTTP request —
 * so a count of zero proves nothing was sent.
 */
class AbstractPremiumResolverTest {

    private static final Logger logger = LoggerFactory.getLogger(AbstractPremiumResolverTest.class);

    private static final class StubResolver extends AbstractPremiumResolver {

        private final AtomicInteger endpointReads = new AtomicInteger();

        StubResolver(boolean enabled, UpstreamRateLimiter rateLimiter) {
            super(logger, enabled, 100, rateLimiter);
        }

        @Override
        public String id() {
            return "stub";
        }

        @Override
        protected String getEndpoint() {
            endpointReads.incrementAndGet();
            // Discard port — reaching this would fail the test long before any network use.
            return "http://127.0.0.1:9/";
        }

        @Override
        protected boolean isNotFoundResponse(int code) {
            return code == 404;
        }

        @Override
        protected String extractUuidField(String responseBody) {
            return null;
        }

        @Override
        protected String extractUsernameField(String responseBody) {
            return null;
        }
    }

    /** One permit per minute, no waiting: the single burst permit is the whole budget. */
    private static UpstreamRateLimiter exhaustibleLimiter() {
        return new UpstreamRateLimiter("stub", 1, 0, System::nanoTime, nanos -> true);
    }

    @Test
    void resolve_upstreamBudgetExhausted_returnsUnknownWithoutSendingRequest() {
        UpstreamRateLimiter limiter = exhaustibleLimiter();
        assertTrue(limiter.tryAcquire(true), "Test setup must consume the only permit");
        StubResolver resolver = new StubResolver(true, limiter);

        PremiumResolution resolution = resolver.resolve("RateLimited");

        assertTrue(resolution.isUnknown(), "An unsent lookup must not claim a premium verdict");
        assertEquals("upstream rate limit", resolution.message());
        assertEquals(0, resolver.endpointReads.get(), "No request may reach the upstream");
    }

    @Test
    void resolve_disabledResolver_doesNotConsumeUpstreamBudget() {
        UpstreamRateLimiter limiter = exhaustibleLimiter();
        StubResolver resolver = new StubResolver(false, limiter);

        PremiumResolution resolution = resolver.resolve("Disabled");

        assertTrue(resolution.isUnknown());
        assertEquals("disabled", resolution.message());
        assertTrue(limiter.tryAcquire(true), "A disabled resolver must leave the budget untouched");
    }
}
