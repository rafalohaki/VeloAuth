package net.rafalohaki.veloauth.premium;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class PremiumNameAttemptTrackerTest {

    private static final UUID NOTCH = UUID.fromString("069a79f4-44e9-4726-a5be-fca90e38aaf5");
    private final AtomicLong now = new AtomicLong(1_000_000L);
    private final PremiumNameAttemptTracker tracker = new PremiumNameAttemptTracker(now::get);

    @Test
    void checkMarkIsConsumedExactlyOnce() {
        tracker.markCheck("1.2.3.4", "Notch", NOTCH);
        assertEquals(NOTCH, tracker.consumeCheck("1.2.3.4", "notch"));
        assertNull(tracker.consumeCheck("1.2.3.4", "Notch"));
        assertEquals(0, tracker.size());
    }

    @Test
    void marksAreIndependentPerIpAndNick() {
        tracker.markCheck("1.2.3.4", "Notch", NOTCH);
        assertNull(tracker.consumeCheck("5.6.7.8", "Notch"));
        assertNull(tracker.consumeCheck("1.2.3.4", "Jeb_"));
        assertEquals(NOTCH, tracker.peekCheck("1.2.3.4", "Notch"));
    }

    @Test
    void expiredMarksAreIgnored() {
        tracker.markCheck("1.2.3.4", "Notch", NOTCH);
        now.addAndGet(PremiumNameAttemptTracker.CHECK_TTL_MILLIS + 1);
        assertNull(tracker.peekCheck("1.2.3.4", "Notch"));
        assertNull(tracker.consumeCheck("1.2.3.4", "Notch"));
    }

    @Test
    void clearRemovesEverything() {
        tracker.markCheck("1.2.3.4", "Notch", NOTCH);
        tracker.clear("1.2.3.4", "Notch");
        assertEquals(0, tracker.size());
    }

    @Test
    void nullsAreIgnored() {
        tracker.markCheck(null, "Notch", NOTCH);
        tracker.markCheck("1.2.3.4", null, NOTCH);
        tracker.markCheck("1.2.3.4", "Notch", null);
        assertEquals(0, tracker.size());
        assertNull(tracker.consumeCheck(null, null));
    }
}
