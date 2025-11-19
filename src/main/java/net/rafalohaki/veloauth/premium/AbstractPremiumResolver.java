package net.rafalohaki.veloauth.premium;

import org.slf4j.Logger;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Abstract base class for premium resolvers using HTTP APIs.
 * Implements template method pattern to reduce code duplication.
 */
abstract class AbstractPremiumResolver implements PremiumResolver {

    private static final int REQUESTS_PER_MINUTE = 60; // Max 60 requests per minute
    private static final long MINUTE_IN_MILLIS = 60_000L;
    private final Logger logger;
    private final boolean enabled;
    private final int timeoutMs;
    // Rate limiting protection
    private final ConcurrentHashMap<String, AtomicInteger> requestCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicLong> lastResetTime = new ConcurrentHashMap<>();

    protected AbstractPremiumResolver(Logger logger, boolean enabled, int timeoutMs) {
        this.logger = Objects.requireNonNull(logger, "logger");
        this.enabled = enabled;
        this.timeoutMs = timeoutMs;
    }

    @Override
    public boolean enabled() {
        return enabled;
    }

    @Override
    public PremiumResolution resolve(String username) {
        PremiumResolution pre = preResolve(username);
        if (pre != null) {
            return pre;
        }
        try {
            HttpJsonClient.HttpJsonResponse response = HttpJsonClient.get(getEndpoint(), username, timeoutMs);
            return resolveFromResponse(response, username);
        } catch (IOException ex) {
            logger.debug("[{}] IO error for {}: {}", getClass().getSimpleName(), username, ex.getMessage());
            return PremiumResolution.unknown(id(), "io error");
        } catch (Exception ex) {
            logger.warn("[{}] Unexpected error for {}", getClass().getSimpleName(), username, ex);
            return PremiumResolution.unknown(id(), "unexpected");
        }
    }

    /**
     * Returns the API endpoint for this resolver.
     */
    protected abstract String getEndpoint();

    /**
     * Determines if the HTTP response code indicates "not found".
     * Most APIs use HTTP_NOT_FOUND, but Mojang uses HTTP_NO_CONTENT.
     */
    protected abstract boolean isNotFoundResponse(int code);

    /**
     * Extracts the UUID field from the JSON response.
     * Most APIs use "uuid", but Mojang uses "id".
     */
    protected abstract String extractUuidField(String responseBody);

    /**
     * Extracts the username field from the JSON response.
     * Most APIs use "username", but Mojang uses "name".
     */
    protected abstract String extractUsernameField(String responseBody);

    /**
     * Parses the UUID string into a UUID object.
     * Most APIs use standard UUID format, but Mojang uses raw 32-char format.
     */
    protected UUID parseUuid(String uuidStr) {
        try {
            return UUID.fromString(uuidStr);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    /**
     * Checks if the resolver is currently rate limited.
     * Uses per-resolver rate limiting with sliding window.
     */
    private boolean isRateLimited() {
        String resolverId = id();
        long currentTime = System.currentTimeMillis();

        // Get or initialize request count and last reset time
        AtomicInteger count = requestCounts.computeIfAbsent(resolverId, k -> new AtomicInteger(0));
        AtomicLong lastReset = lastResetTime.computeIfAbsent(resolverId, k -> new AtomicLong(currentTime));

        // Reset counter if more than a minute has passed using atomic compute to avoid Virtual Thread pinning
        long timeSinceReset = currentTime - lastReset.get();
        if (timeSinceReset > MINUTE_IN_MILLIS) {
            // Use atomic compute on ConcurrentHashMap to avoid synchronization that pins Virtual Threads
            lastResetTime.compute(resolverId, (key, existingValue) -> {
                if (existingValue == null || currentTime - existingValue.get() > MINUTE_IN_MILLIS) {
                    // Reset counter atomically
                    count.set(0);
                    return new AtomicLong(currentTime);
                }
                return existingValue; // No reset needed
            });
        }

        // Check if rate limit exceeded
        return count.incrementAndGet() > REQUESTS_PER_MINUTE;
    }

    private PremiumResolution preResolve(String username) {
        if (!enabled) {
            return PremiumResolution.unknown(id(), "disabled");
        }
        if (isRateLimited()) {
            logger.debug("[{}] Rate limited for {}", getClass().getSimpleName(), username);
            return PremiumResolution.unknown(id(), "rate limited");
        }
        return null;
    }

    private PremiumResolution resolveFromResponse(HttpJsonClient.HttpJsonResponse response, String username) {
        int code = response.statusCode();
        if (isNotFoundResponse(code)) {
            return PremiumResolution.offline(username, id(), "not found");
        }
        if (code != HttpURLConnection.HTTP_OK) {
            logger.debug("[{}] HTTP {} for {}", getClass().getSimpleName(), code, username);
            return PremiumResolution.unknown(id(), "http " + code);
        }
        String body = response.body();
        String uuidStr = extractUuidField(body);
        String canonical = extractUsernameField(body);
        if (uuidStr == null || canonical == null) {
            logger.debug("[{}] Missing fields for {}", getClass().getSimpleName(), username);
            return PremiumResolution.unknown(id(), "missing fields");
        }
        UUID uuid = parseUuid(uuidStr);
        if (uuid == null || (uuid.getMostSignificantBits() == 0L && uuid.getLeastSignificantBits() == 0L)) {
            logger.debug("[{}] Invalid uuid {} for {}", getClass().getSimpleName(), uuidStr, username);
            return PremiumResolution.unknown(id(), "uuid parse error");
        }
        return PremiumResolution.premium(uuid, canonical, id());
    }
}
