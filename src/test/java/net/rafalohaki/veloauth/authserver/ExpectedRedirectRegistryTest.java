package net.rafalohaki.veloauth.authserver;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ExpectedRedirectRegistryTest {

    private static final Instant NOW = Instant.parse("2026-08-09T12:00:00Z");

    @Test
    void consume_MatchingRedirect_ShouldReturnIdentityExactlyOnce() {
        ExpectedRedirectRegistry registry = registry(2, NOW);
        UUID id = UUID.randomUUID();
        registry.expect(id, "Player");

        ExpectedRedirectRegistry.ExpectedPlayer expected = registry.consume("Player").orElseThrow();

        assertEquals(id, expected.uniqueId());
        assertEquals("Player", expected.username());
        assertTrue(registry.consume("Player").isEmpty());
    }

    @Test
    void consume_ExpiredRedirect_ShouldRejectAndReleaseCapacity() {
        MutableClock clock = new MutableClock(NOW);
        ExpectedRedirectRegistry registry = new ExpectedRedirectRegistry(
                1, Duration.ofSeconds(15), clock);
        registry.expect(UUID.randomUUID(), "Player");
        clock.now = NOW.plusSeconds(16);

        assertTrue(registry.consume("Player").isEmpty());
        registry.expect(UUID.randomUUID(), "Replacement");
        assertEquals(1, registry.size());
    }

    @Test
    void expect_ExpiredRedirectBelowCapacity_ShouldCleanItProactively() {
        MutableClock clock = new MutableClock(NOW);
        ExpectedRedirectRegistry registry = new ExpectedRedirectRegistry(
                4, Duration.ofSeconds(15), clock);
        registry.expect(UUID.randomUUID(), "Expired");
        clock.now = NOW.plusSeconds(16);

        registry.expect(UUID.randomUUID(), "Current");

        assertEquals(1, registry.size(),
                "Moderate traffic should not retain expired redirects until capacity is exhausted");
    }

    @Test
    void expect_AtCapacity_ShouldRejectNewIdentityButAllowAtomicRefresh() {
        ExpectedRedirectRegistry registry = registry(1, NOW);
        UUID first = UUID.randomUUID();
        UUID refreshed = UUID.randomUUID();
        registry.expect(first, "Player");

        registry.expect(refreshed, "Player");

        assertThrows(ExpectedRedirectRegistry.CapacityExceededException.class,
                () -> registry.expect(UUID.randomUUID(), "Second"));
        assertEquals(refreshed, registry.consume("Player").orElseThrow().uniqueId());
    }

    @Test
    void consume_CaseMismatch_ShouldBurnOneTimeEntry() {
        ExpectedRedirectRegistry registry = registry(2, NOW);
        registry.expect(UUID.randomUUID(), "Player");

        assertTrue(registry.consume("player").isEmpty());
        assertTrue(registry.consume("Player").isEmpty());
    }

    @Test
    void expect_InvalidUsername_ShouldRejectWithoutConsumingCapacity() {
        ExpectedRedirectRegistry registry = registry(1, NOW);

        assertThrows(IllegalArgumentException.class,
                () -> registry.expect(UUID.randomUUID(), "invalid name".repeat(2)));
        registry.expect(UUID.randomUUID(), "Valid");
        assertEquals(1, registry.size());
    }

    private static ExpectedRedirectRegistry registry(int capacity, Instant now) {
        return new ExpectedRedirectRegistry(
                capacity, Duration.ofSeconds(15), Clock.fixed(now, ZoneOffset.UTC));
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        private MutableClock(Instant now) {
            this.now = now;
        }

        @Override
        public ZoneOffset getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
