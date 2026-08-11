package net.rafalohaki.veloauth.connection;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BackendTransferOutcomeTest {

    @Test
    void accepted_DeferredAndCoalescedOutcomes_PreserveLegacySuccessContract() {
        assertTrue(BackendTransferOutcome.CONNECTED.accepted());
        assertTrue(BackendTransferOutcome.COALESCED.accepted());
        assertTrue(BackendTransferOutcome.WAITING_FOR_BACKEND.accepted());
        assertTrue(BackendTransferOutcome.FALLBACK_TO_AUTH.accepted());
        assertTrue(BackendTransferOutcome.RETRYING_TIMEOUT.accepted());
        assertFalse(BackendTransferOutcome.REJECTED.accepted());
    }
}
