package net.rafalohaki.veloauth.authserver;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Semaphore;

/** Bounded one-time correlation between a Velocity redirect and loopback login start. */
final class ExpectedRedirectRegistry {

    private final Map<String, ExpectedRedirect> redirects = new ConcurrentHashMap<>();
    private final Semaphore capacity;
    private final Duration timeToLive;
    private static final String UNIQUE_ID_PARAM = "uniqueId";

    private final Clock clock;

    ExpectedRedirectRegistry(int maximumSize, Duration timeToLive, Clock clock) {
        if (maximumSize <= 0) {
            throw new IllegalArgumentException("maximumSize must be positive");
        }
        if (timeToLive == null || timeToLive.isNegative() || timeToLive.isZero()) {
            throw new IllegalArgumentException("timeToLive must be positive");
        }
        capacity = new Semaphore(maximumSize);
        this.timeToLive = timeToLive;
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    void expect(UUID uniqueId, String username) {
        Objects.requireNonNull(uniqueId, UNIQUE_ID_PARAM);
        String key = normalizedUsername(username);
        removeExpired();
        ExpectedRedirect replacement = new ExpectedRedirect(
                uniqueId, username, clock.instant().plus(timeToLive));
        while (true) {
            ExpectedRedirect existing = redirects.get(key);
            if (existing != null) {
                if (redirects.replace(key, existing, replacement)) {
                    return;
                }
                continue;
            }

            if (!tryAcquireCapacity()) {
                throw new CapacityExceededException();
            }
            if (redirects.putIfAbsent(key, replacement) == null) {
                return;
            }
            capacity.release();
        }
    }

    Optional<ExpectedPlayer> consume(String username) {
        String key = normalizedUsername(username);
        ExpectedRedirect expected = redirects.remove(key);
        if (expected == null) {
            return Optional.empty();
        }
        capacity.release();
        if (!clock.instant().isBefore(expected.expiresAt())
                || !expected.username().equals(username)) {
            return Optional.empty();
        }
        return Optional.of(new ExpectedPlayer(expected.uniqueId(), expected.username()));
    }

    void removeExpired() {
        Instant now = clock.instant();
        for (Map.Entry<String, ExpectedRedirect> entry : redirects.entrySet()) {
            if (!now.isBefore(entry.getValue().expiresAt())
                    && redirects.remove(entry.getKey(), entry.getValue())) {
                capacity.release();
            }
        }
    }

    void clear() {
        for (Map.Entry<String, ExpectedRedirect> entry : redirects.entrySet()) {
            if (redirects.remove(entry.getKey(), entry.getValue())) {
                capacity.release();
            }
        }
    }

    int size() {
        return redirects.size();
    }

    private boolean tryAcquireCapacity() {
        if (capacity.tryAcquire()) {
            return true;
        }
        removeExpired();
        return capacity.tryAcquire();
    }

    private static String normalizedUsername(String username) {
        if (username == null || username.isBlank() || username.length() > 16) {
            throw new IllegalArgumentException("username must contain 1-16 characters");
        }
        return username.toLowerCase(Locale.ROOT);
    }

    record ExpectedPlayer(UUID uniqueId, String username) {
        ExpectedPlayer {
            Objects.requireNonNull(uniqueId, UNIQUE_ID_PARAM);
            Objects.requireNonNull(username, "username");
        }
    }

    private record ExpectedRedirect(UUID uniqueId, String username, Instant expiresAt) {
        private ExpectedRedirect {
            Objects.requireNonNull(uniqueId, UNIQUE_ID_PARAM);
            Objects.requireNonNull(username, "username");
            Objects.requireNonNull(expiresAt, "expiresAt");
        }
    }

    static final class CapacityExceededException extends IllegalStateException {
        private CapacityExceededException() {
            super("Embedded auth-server pending redirect capacity reached");
        }
    }
}
