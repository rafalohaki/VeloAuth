package net.rafalohaki.veloauth.authserver;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class VelocityEmbeddedCapacityProfileTest {

    @Test
    void parseTargets_AscendingProductionPlateaus_ShouldPreserveOrder() {
        assertEquals(List.of(1_000, 5_000, 10_000),
                VelocityEmbeddedCapacityProfile.parseTargets("1000,5000,10000"));
    }

    @Test
    void parseTargets_DuplicateDescendingOrOutOfRange_ShouldReject() {
        assertThrows(IllegalArgumentException.class,
                () -> VelocityEmbeddedCapacityProfile.parseTargets("1000,1000"));
        assertThrows(IllegalArgumentException.class,
                () -> VelocityEmbeddedCapacityProfile.parseTargets("5000,1000"));
        assertThrows(IllegalArgumentException.class,
                () -> VelocityEmbeddedCapacityProfile.parseTargets("10001"));
        assertThrows(IllegalArgumentException.class,
                () -> VelocityEmbeddedCapacityProfile.parseTargets("0"));
        assertThrows(IllegalArgumentException.class,
                () -> VelocityEmbeddedCapacityProfile.parseTargets("1000,not-a-number"));
    }
}
