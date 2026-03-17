package net.rafalohaki.veloauth.premium;

import org.slf4j.Logger;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Objects;
import java.util.UUID;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
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
    private final Map<String, AtomicInteger> requestCounts = new java.util.concurrent.ConcurrentHashMap<>();
    private final Map<String, AtomicLong> lastResetTime = new java.util.concurrent.ConcurrentHashMap<>();

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
        return executeWithRetriesAsync(username, 0, 2, 100).join();
    }

    private CompletableFuture<PremiumResolution> executeWithRetriesAsync(
            String username, int attempt, int maxRetries, int baseDelayMs) {
        return CompletableFuture.supplyAsync(
                () -> tryResolveAttempt(username, attempt, maxRetries),
                net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider.getVirtualExecutor()
        ).thenCompose(result -> {
            if (result != null) {
                return CompletableFuture.completedFuture(result);
            }

            int nextAttempt = attempt + 1;
            if (nextAttempt > maxRetries) {
                return CompletableFuture.completedFuture(PremiumResolution.unknown(id(), "max retries exceeded"));
            }

            return delayBeforeRetry(username, attempt, baseDelayMs)
                    .thenCompose(ignored -> executeWithRetriesAsync(username, nextAttempt, maxRetries, baseDelayMs));
        });
    }

    private PremiumResolution tryResolveAttempt(String username, int attempt, int maxRetries) {
        try {
            HttpJsonClient.HttpJsonResponse response = HttpJsonClient.get(getEndpoint(), username, timeoutMs);
            PremiumResolution result = resolveFromResponse(response, username);

            if (!result.isUnknown() || attempt == maxRetries) {
                logSuccessOnRetry(username, attempt);
                return result;
            }

            return null; // Signal to continue loop

        } catch (IOException ex) {
            return handleIOException(username, attempt, maxRetries, ex);
        } catch (Exception ex) {
            return handleUnexpectedException(username, ex);
        }
    }

    private void logSuccessOnRetry(String username, int attempt) {
        if (attempt > 0 && logger.isDebugEnabled()) {
            logger.debug("[{}] Succeeded on retry {} for {}", getClass().getSimpleName(), attempt, username);
        }
    }

    private CompletableFuture<Void> delayBeforeRetry(String username, int attempt, int baseDelayMs) {
        int delayMs = baseDelayMs * (1 << attempt);
        if (logger.isDebugEnabled()) {
            logger.debug("[{}] Retry {} after {}ms for {}", getClass().getSimpleName(), attempt + 1, delayMs, username);
        }
        return CompletableFuture.runAsync(
                () -> { },
                CompletableFuture.delayedExecutor(
                        delayMs,
                        TimeUnit.MILLISECONDS,
                        net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider.getVirtualExecutor()
                )
        );
    }

    private PremiumResolution handleIOException(String username, int attempt, int maxRetries, IOException ex) {
        if (attempt == maxRetries) {
            if (logger.isDebugEnabled()) {
                logger.debug("[{}] IO error after {} retries for {}: {}",
                        getClass().getSimpleName(), maxRetries, username, ex.getMessage());
            }
            return PremiumResolution.unknown(id(), "io error after retries");
        }
        if (logger.isDebugEnabled()) {
            logger.debug("[{}] IO error on attempt {} for {}, retrying...",
                    getClass().getSimpleName(), attempt, username);
        }
        return null; // Signal to continue loop
    }

    private PremiumResolution handleUnexpectedException(String username, Exception ex) {
        if (logger.isWarnEnabled()) {
            logger.warn("[{}] Unexpected error for {}", getClass().getSimpleName(), username, ex);
        }
        return PremiumResolution.unknown(id(), "unexpected");
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
            if (logger.isDebugEnabled()) {
                logger.debug("[{}] Rate limited for {}", getClass().getSimpleName(), username);
            }
            return PremiumResolution.unknown(id(), "rate limited");
        }
        return null;
    }

    private PremiumResolution resolveFromResponse(HttpJsonClient.HttpJsonResponse response, String username) {
        int code = response.statusCode();
        
        PremiumResolution statusResult = validateHttpStatus(code, username);
        if (statusResult != null) {
            return statusResult;
        }
        
        return parseResponseBody(response.body(), username);
    }

    private PremiumResolution validateHttpStatus(int code, String username) {
        if (isNotFoundResponse(code)) {
            return PremiumResolution.offline(username, id(), "not found");
        }
        if (code != HttpURLConnection.HTTP_OK) {
            if (logger.isDebugEnabled()) {
                logger.debug("[{}] HTTP {} for {}", getClass().getSimpleName(), code, username);
            }
            return PremiumResolution.unknown(id(), "http " + code);
        }
        return null; // Status OK, continue processing
    }

    private PremiumResolution parseResponseBody(String body, String username) {
        String uuidStr = extractUuidField(body);
        String canonical = extractUsernameField(body);
        
        if (uuidStr == null || canonical == null) {
            return logAndReturnMissingFields(username);
        }
        
        return validateAndCreateResolution(uuidStr, canonical, username);
    }

    private PremiumResolution logAndReturnMissingFields(String username) {
        if (logger.isDebugEnabled()) {
            logger.debug("[{}] Missing fields for {}", getClass().getSimpleName(), username);
        }
        return PremiumResolution.unknown(id(), "missing fields");
    }

    private PremiumResolution validateAndCreateResolution(String uuidStr, String canonical, String username) {
        UUID uuid = parseUuid(uuidStr);
        
        if (isInvalidUuid(uuid)) {
            if (logger.isDebugEnabled()) {
                logger.debug("[{}] Invalid uuid {} for {}", getClass().getSimpleName(), uuidStr, username);
            }
            return PremiumResolution.unknown(id(), "uuid parse error");
        }
        
        return PremiumResolution.premium(uuid, canonical, id());
    }

    private boolean isInvalidUuid(UUID uuid) {
        return uuid == null || (uuid.getMostSignificantBits() == 0L && uuid.getLeastSignificantBits() == 0L);
    }
}
