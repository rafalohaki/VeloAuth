package net.rafalohaki.veloauth.premium;

import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import javax.annotation.Nullable;

/**
 * Short-lived hand-over mark for the premium-nick ownership check, keyed by {@code ip|nick}:
 * {@link #markCheck} (PreLogin → PostLogin of the <b>same</b> connection) tells PostLogin that this
 * offline connection must run the ownership check on the auth server instead of the login dialog.
 * A verified owner is admitted in place (premium record + authorization), so nothing has to be
 * remembered across connections. Marks are consumed exactly once and expire quickly.
 */
public final class PremiumNameAttemptTracker {

    private static final int MAX_ENTRIES = 10_000;
    /** A check mark only has to survive the login handshake of its own connection. */
    static final long CHECK_TTL_MILLIS = 60_000L;

    private record Mark(UUID premiumUuid, long createdAt) { }

    private final Map<String, Mark> checks = new ConcurrentHashMap<>();
    private final LongSupplier clock;

    public PremiumNameAttemptTracker() {
        this(System::currentTimeMillis);
    }

    PremiumNameAttemptTracker(LongSupplier clock) {
        this.clock = clock;
    }

    /** Marks the pending offline connection for the ownership check. */
    public void markCheck(String ip, String nickname, UUID premiumUuid) {
        put(checks, ip, nickname, premiumUuid, CHECK_TTL_MILLIS);
    }

    /** Premium UUID of a pending check for ip/nick, without consuming it; {@code null} if none. */
    @Nullable
    public UUID peekCheck(String ip, String nickname) {
        if (ip == null || nickname == null) {
            return null;
        }
        Mark mark = checks.get(key(ip, nickname));
        if (mark == null || clock.getAsLong() - mark.createdAt() > CHECK_TTL_MILLIS) {
            return null;
        }
        return mark.premiumUuid();
    }

    /** Returns (once) the premium UUID of a connection marked for the check, or {@code null}. */
    @Nullable
    public UUID consumeCheck(String ip, String nickname) {
        return take(checks, ip, nickname, CHECK_TTL_MILLIS);
    }

    /** Removes every mark for the pair. */
    public void clear(String ip, String nickname) {
        if (ip != null && nickname != null) {
            checks.remove(key(ip, nickname));
        }
    }

    public int size() {
        return checks.size();
    }

    private void put(Map<String, Mark> map, String ip, String nickname, UUID premiumUuid, long ttl) {
        if (ip == null || nickname == null || premiumUuid == null) {
            return;
        }
        long now = clock.getAsLong();
        if (map.size() >= MAX_ENTRIES) {
            evictExpired(map, now, ttl);
        }
        if (map.size() < MAX_ENTRIES) {
            map.put(key(ip, nickname), new Mark(premiumUuid, now));
        }
    }

    @Nullable
    private UUID take(Map<String, Mark> map, String ip, String nickname, long ttl) {
        if (ip == null || nickname == null) {
            return null;
        }
        Mark mark = map.remove(key(ip, nickname));
        if (mark == null || clock.getAsLong() - mark.createdAt() > ttl) {
            return null;
        }
        return mark.premiumUuid();
    }

    private static void evictExpired(Map<String, Mark> map, long now, long ttl) {
        Iterator<Map.Entry<String, Mark>> it = map.entrySet().iterator();
        while (it.hasNext()) {
            if (now - it.next().getValue().createdAt() > ttl) {
                it.remove();
            }
        }
    }

    private static String key(String ip, String nickname) {
        return ip + '|' + nickname.toLowerCase(Locale.ROOT);
    }
}
