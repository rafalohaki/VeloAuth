package net.rafalohaki.veloauth.authserver;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RuntimeArtifactDescriptorTest {

    @ParameterizedTest(name = "candidate {0} newer than {1} should be {2}")
    @CsvSource({
            "5.12.0-20260805.155110-1, 5.11.0, true",
            "5.12.0-20260805.155110-1, 5.12.0-20260805.155110-1, false",
            "5.11.9-20260805.155110-9, 5.12.0-20260805.155110-1, false",
            "5.12.0-20260805.155110-2, 5.12.0-20260805.155110-1, true",
            "5.12.0-20260804.235959-99, 5.12.0-20260805.155110-1, false",
            "5.12.0-20260805.155110-1, 5.12.0, false",
            "5.12.0.0, 5.12.0, false",
            "5.12.0.1, 5.12.0, true",
            "unsafe-version, 5.12.0, false",
            "999999999999999999999.0.0, 5.12.0, false"
    })
    void isNewerVersion_RecognizedOrdering_ShouldRemainMonotonic(
            String candidate, String current, boolean expected) {
        assertEquals(expected, RuntimeArtifactDescriptor.isNewerVersion(candidate, current));
    }

    @Test
    void isNewerVersion_FourPartSnapshotRollback_ShouldRejectOlderBuild() {
        assertFalse(RuntimeArtifactDescriptor.isNewerVersion(
                "6.0.0.1-20270102.040506-6",
                "6.0.0.1-20270102.040506-7"));
    }

    @Test
    void isNewerVersion_FourPartSnapshotAdvance_ShouldAcceptNewerBuild() {
        assertTrue(RuntimeArtifactDescriptor.isNewerVersion(
                "6.0.0.1-20270102.040506-8",
                "6.0.0.1-20270102.040506-7"));
    }

    @Test
    void isNewerVersion_UnrecognizedCurrentVersion_ShouldFailClosed() {
        assertFalse(RuntimeArtifactDescriptor.isNewerVersion(
                "7.0.0-20280102.040506-1",
                "operator-managed-version"));
    }

    @Test
    void isNewerVersion_StableReleaseForSameLine_ShouldSupersedeSnapshot() {
        assertTrue(RuntimeArtifactDescriptor.isNewerVersion(
                "6.0.0",
                "6.0.0-20270102.040506-7"));
    }
}
