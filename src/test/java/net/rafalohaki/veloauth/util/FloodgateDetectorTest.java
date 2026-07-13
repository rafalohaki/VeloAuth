package net.rafalohaki.veloauth.util;

import org.geysermc.floodgate.api.FloodgateApi;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for {@link FloodgateDetector}.
 * <p>
 * Uses a minimal test API with a replaceable instance to verify both fail-secure behavior and
 * late Floodgate initialization.
 */
class FloodgateDetectorTest {

    @BeforeEach
    void setUp() {
        FloodgateApi.clear();
    }

    @AfterEach
    void tearDown() {
        FloodgateApi.clear();
    }

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

    @Test
    void isFloodgateAvailable_apiInitializesLate_recoversWithoutRestart() {
        assertFalse(FloodgateDetector.isFloodgateAvailable());

        FloodgateApi.install(".", Set.of(), List.of());

        assertTrue(FloodgateDetector.isFloodgateAvailable());
    }

    @Test
    void isBedrockPlayer_uuidRegisteredByFloodgate_returnsTrue() {
        UUID bedrockUuid = UUID.randomUUID();
        FloodgateApi.install(".", Set.of(bedrockUuid), List.of());

        assertTrue(FloodgateDetector.isBedrockPlayer(bedrockUuid));
        assertFalse(FloodgateDetector.isBedrockPlayer(UUID.randomUUID()));
    }

    @Test
    void isBedrockPlayer_linkedUsernameRegisteredBeforePreLogin_returnsTrue() {
        FloodgateApi.PlayerView linkedPlayer = new FloodgateApi.PlayerView(
                "LinkedJava", ".BedrockUser", "Bedrock User");
        FloodgateApi.install(".", Set.of(), List.of(linkedPlayer));

        assertTrue(FloodgateDetector.isBedrockUsername("linkedjava"));
        assertTrue(FloodgateDetector.isBedrockUsername(".bedrockuser"));
        assertTrue(FloodgateDetector.isBedrockUsername("bedrock user"));
        assertFalse(FloodgateDetector.isBedrockUsername("DifferentPlayer"));
    }

    @Test
    void getPlayerPrefix_liveApiAvailable_returnsEffectivePrefix() {
        FloodgateApi.install("+", Set.of(), List.of());

        assertEquals("+", FloodgateDetector.getPlayerPrefix().orElseThrow());
    }
}
