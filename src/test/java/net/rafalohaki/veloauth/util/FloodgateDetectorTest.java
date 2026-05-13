package net.rafalohaki.veloauth.util;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertFalse;

/**
 * Unit tests for {@link FloodgateDetector}.
 * <p>
 * Floodgate is not present on the test classpath, so the static initializer
 * leaves {@code FLOODGATE_AVAILABLE = false}. These tests verify the
 * fail-secure path: every public method returns {@code false} when Floodgate
 * is absent, never throwing.
 * <p>
 * The "Floodgate present" path is exercised in real-proxy integration testing
 * (cannot be cleanly mocked because the static initializer runs once per JVM).
 */
class FloodgateDetectorTest {

    @Test
    void isFloodgateAvailable_floodgateAbsent_returnsFalse() {
        assertFalse(FloodgateDetector.isFloodgateAvailable());
    }

    @Test
    void isBedrockPlayer_floodgateAbsent_returnsFalseForAnyUuid() {
        UUID someUuid = UUID.fromString("12345678-1234-1234-1234-123456789abc");
        assertFalse(FloodgateDetector.isBedrockPlayer(someUuid));
    }

    @Test
    void isBedrockPlayer_floodgateAbsent_returnsFalseForNullUuidWithoutThrowing() {
        // FloodgateDetector swallows reflection exceptions and returns false.
        // When FG is absent the early-return short-circuits before any null check on UUID.
        assertFalse(FloodgateDetector.isBedrockPlayer(null));
    }

    @Test
    void isBedrockPlayer_calledRepeatedly_remainsStable() {
        UUID uuid = UUID.randomUUID();
        for (int i = 0; i < 100; i++) {
            assertFalse(FloodgateDetector.isBedrockPlayer(uuid));
        }
    }
}
