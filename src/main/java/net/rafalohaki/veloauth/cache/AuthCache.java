package net.rafalohaki.veloauth.cache;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Expiry;
import net.rafalohaki.veloauth.command.IPRateLimiter;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Thread-safe authentication cache for VeloAuth.
 * <p>
 * Storage is delegated to Caffeine (W-TinyLFU eviction, lock-striped concurrency,
 * scheduled time-based expiration). The hand-rolled {@code ReentrantLock} +
 * {@code ConcurrentHashMap} + per-insert O(N) eviction this class used to ship
 * has been removed entirely; Caffeine subsumes all three responsibilities.
 *
 * <h2>Stored Caches</h2>
 * <ul>
 *   <li>{@code authorizedPlayers} — UUID → {@link CachedAuthUser}, bounded by
 *       {@code maxSize}, evicted by access-TTL ({@code ttlMinutes}).</li>
 *   <li>{@code premiumCache} — nickname (lowercase) → {@link PremiumCacheEntry},
 *       bounded by {@code maxPremiumCache}, evicted per-entry TTL (positive entries
 *       use the configured premium hit-ttl, negative entries use {@link #NEGATIVE_PREMIUM_TTL_MINUTES}).</li>
 *   <li>{@link BruteForceTracker} — brute-force counters (delegated).</li>
 *   <li>{@link SessionManager} — active sessions (delegated).</li>
 * </ul>
 *
 * <h2>Invalidation</h2>
 * <ul>
 *   <li>{@code authorizedPlayers} — on player data update, TTL expiration, manual removal, or logout.</li>
 *   <li>{@code premiumCache} — on per-entry TTL expiration, manual removal, or W-TinyLFU eviction.</li>
 *   <li>{@code bruteForceAttempts} — on timeout expiration, successful login, or manual reset.</li>
 *   <li>{@code activeSessions} — on player disconnect, session hijacking detection, or inactivity.</li>
 * </ul>
 */
public class AuthCache {

    private static final Logger logger = LoggerFactory.getLogger(AuthCache.class);

    /** Negative-result TTL (player resolved as non-premium). Short on purpose so the cache can
     *  recover quickly when a player upgrades to a premium account. */
    private static final long NEGATIVE_PREMIUM_TTL_MINUTES = 5;

    /** Per-entry expiry for {@link PremiumCacheEntry} — reads the TTL the entry was constructed
     *  with so positive vs negative hits can coexist with different lifetimes. */
    private static final Expiry<String, PremiumCacheEntry> PREMIUM_EXPIRY =
            new Expiry<>() {
                @Override
                public long expireAfterCreate(String key, PremiumCacheEntry value, long currentTime) {
                    return TimeUnit.MILLISECONDS.toNanos(value.getTtlMillis());
                }

                @Override
                public long expireAfterUpdate(String key, PremiumCacheEntry value, long currentTime, long currentDuration) {
                    return TimeUnit.MILLISECONDS.toNanos(value.getTtlMillis());
                }

                @Override
                public long expireAfterRead(String key, PremiumCacheEntry value, long currentTime, long currentDuration) {
                    return currentDuration;
                }
            };

    private final Cache<UUID, CachedAuthUser> authorizedPlayers;
    private final Cache<String, PremiumCacheEntry> premiumCache;
    private final BruteForceTracker bruteForceTracker;
    private final SessionManager sessionManager;

    private final int ttlMinutes;
    private final int maxSize;
    private final int premiumTtlHours;
    private final double premiumRefreshThreshold;

    private final ScheduledExecutorService scheduler;
    private final CacheMetrics authMetrics = new CacheMetrics();

    private final Settings settings;
    private final Messages messages;

    /** Optional IP rate limiter for periodic cleanup. Set after construction because
     *  {@link IPRateLimiter} is created later by {@code CommandContext}. */
    private volatile IPRateLimiter ipRateLimiter;

    /** Configuration parameters for AuthCache. */
    public record AuthCacheConfig(
            int ttlMinutes,
            int maxSize,
            int maxSessions,
            int maxPremiumCache,
            int maxLoginAttempts,
            int bruteForceTimeoutMinutes,
            int cleanupIntervalMinutes,
            int sessionTimeoutMinutes
    ) {}

    public AuthCache(AuthCacheConfig config, Settings settings, Messages messages) {
        String error = validateParams(
                config.ttlMinutes(), config.maxSize(), config.maxSessions(), config.maxPremiumCache(),
                config.maxLoginAttempts(), config.bruteForceTimeoutMinutes(), messages
        );
        if (error != null) {
            throw new IllegalArgumentException(error);
        }

        this.ttlMinutes = config.ttlMinutes();
        this.maxSize = config.maxSize();
        this.premiumTtlHours = settings.getPremiumTtlHours();
        this.premiumRefreshThreshold = settings.getPremiumRefreshThreshold();
        this.settings = settings;
        this.messages = messages;

        this.authorizedPlayers = VeloAuthCaches.accessTtl(
                config.maxSize(), Duration.ofMinutes(Math.max(1L, config.ttlMinutes())));
        this.premiumCache = VeloAuthCaches.variableTtl(
                config.maxPremiumCache(), PREMIUM_EXPIRY);

        this.bruteForceTracker = new BruteForceTracker(
                config.maxLoginAttempts(), config.bruteForceTimeoutMinutes(), messages);
        this.sessionManager = new SessionManager(
                config.maxSessions(),
                config.sessionTimeoutMinutes() > 0 ? config.sessionTimeoutMinutes() : 60,
                messages);

        this.scheduler = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "AuthCache-Scheduler");
            t.setDaemon(true);
            return t;
        });

        if (config.cleanupIntervalMinutes() > 0) {
            // skipcq: JAVA-W1087 - Periodic scheduled task, fire-and-forget.
            scheduler.scheduleAtFixedRate(
                    this::cleanupExpiredEntries,
                    config.cleanupIntervalMinutes(),
                    config.cleanupIntervalMinutes(),
                    TimeUnit.MINUTES
            );
        }

        // skipcq: JAVA-W1087 - Periodic scheduled task, fire-and-forget.
        scheduler.scheduleAtFixedRate(
                this::logPeriodicCacheMetrics,
                5, 5, TimeUnit.MINUTES
        );

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.auth.created"),
                    this.ttlMinutes, this.maxSize, config.maxLoginAttempts(), config.bruteForceTimeoutMinutes());
        }
    }

    /**
     * Sets the IP rate limiter for periodic cleanup integration.
     * Called after CommandContext creates the IPRateLimiter instance.
     */
    public void setIpRateLimiter(IPRateLimiter ipRateLimiter) {
        this.ipRateLimiter = ipRateLimiter;
    }

    private static String validateParams(int ttlMinutes, int maxSize, int maxSessions, int maxPremiumCache,
                                         int maxLoginAttempts, int bruteForceTimeoutMinutes, Messages messages) {
        if (ttlMinutes < 0) return messages.get("validation.ttl.negative");
        if (maxSize <= 0) return messages.get("validation.maxsize.gt_zero");
        if (maxSessions <= 0) return messages.get("validation.maxsessions.gt_zero");
        if (maxPremiumCache <= 0) return messages.get("validation.maxpremiumcache.gt_zero");
        if (maxLoginAttempts <= 0) return messages.get("validation.maxloginattempts.gt_zero");
        if (bruteForceTimeoutMinutes <= 0) return messages.get("validation.bruteforcetimeout.gt_zero");
        return null;
    }

    // ===== Authorized Players =====

    /**
     * Convenience helper: atomically marks the player as authorized and starts a session.
     * Equivalent to {@link #addAuthorizedPlayer(UUID, CachedAuthUser)} followed by
     * {@link #startSession(UUID, String, String)}, kept as one call so the two-step
     * cache update is not accidentally split across paths.
     * <p>
     * Does NOT handle:
     * <ul>
     *   <li>premium UUID resolution — callers must build {@code CachedAuthUser} themselves
     *       to keep the premium/offline decision explicit at the call site;</li>
     *   <li>brute-force counter reset — that lives in {@code SecurityUtils} / command flow;</li>
     *   <li>auth-server timeout cancellation — handled by {@code AuthTimeoutScheduler} in
     *       PostAuthFlow only (timeouts are only armed in the auth-server path).</li>
     * </ul>
     */
    public void authorize(UUID uuid, CachedAuthUser user, String nickname, String ip) {
        addAuthorizedPlayer(uuid, user);
        startSession(uuid, nickname, ip);
    }

    public void addAuthorizedPlayer(UUID uuid, CachedAuthUser user) {
        if (uuid == null || user == null) {
            throw new IllegalArgumentException("UUID and user must not be null");
        }
        authorizedPlayers.put(uuid, user);
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.auth.added"), user.getNickname(), uuid);
        }
    }

    @javax.annotation.Nullable
    public CachedAuthUser getAuthorizedPlayer(@javax.annotation.Nullable UUID uuid) {
        if (uuid == null) {
            return null;
        }
        // Caffeine handles TTL: an expired entry is invisible to getIfPresent(),
        // which collapses the previous "missing OR expired" branches into one path.
        CachedAuthUser user = authorizedPlayers.getIfPresent(uuid);
        if (user == null) {
            authMetrics.recordMiss();
            logCacheAccessMetric("cache.debug.uuid.miss", uuid);
            return null;
        }
        authMetrics.recordHit();
        logCacheAccessMetric("cache.debug.hit.rate");
        return user;
    }

    public java.util.Optional<CachedAuthUser> findAuthorizedPlayer(@javax.annotation.Nullable UUID uuid) {
        return java.util.Optional.ofNullable(getAuthorizedPlayer(uuid));
    }

    public void removeAuthorizedPlayer(UUID uuid) {
        if (uuid == null) {
            return;
        }
        CachedAuthUser removed = authorizedPlayers.asMap().remove(uuid);
        if (removed != null && logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.player.removed"),
                    removed.getNickname(), uuid);
        }
    }

    public boolean isPlayerAuthorized(UUID uuid, String currentIp) {
        CachedAuthUser user = getAuthorizedPlayer(uuid);
        return user != null && user.matchesIp(currentIp);
    }

    public void invalidatePlayerData(UUID playerUuid) {
        if (playerUuid == null) {
            return;
        }
        CachedAuthUser removed = authorizedPlayers.asMap().remove(playerUuid);
        if (removed != null && logger.isDebugEnabled()) {
            logger.debug("Invalidated cached data for player UUID: {} (nickname: {})",
                    playerUuid, removed.getNickname());
        }
    }

    // ===== Premium Cache =====

    public void removePremiumPlayer(String nickname) {
        if (nickname == null || nickname.isEmpty()) {
            return;
        }
        PremiumCacheEntry removed = premiumCache.asMap().remove(nickname.toLowerCase(java.util.Locale.ROOT));
        if (removed != null && logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.premium.removed"),
                    nickname, removed.isPremium());
        }
    }

    public void addPremiumPlayer(String nickname, UUID premiumUuid) {
        if (nickname == null || nickname.isEmpty()) {
            return;
        }
        String key = nickname.toLowerCase(java.util.Locale.ROOT);
        long ttlMillis = (premiumUuid == null)
                ? TimeUnit.MINUTES.toMillis(NEGATIVE_PREMIUM_TTL_MINUTES)
                : TimeUnit.HOURS.toMillis(premiumTtlHours);
        premiumCache.put(key,
                new PremiumCacheEntry(premiumUuid != null, premiumUuid, ttlMillis, premiumRefreshThreshold));

        if (logger.isDebugEnabled()) {
            logger.debug("{} | nickname: {}, premium entry: {}, TTL: {}h, threshold: {}",
                    messages.get("cache.debug.premium.added"),
                    nickname,
                    premiumUuid != null,
                    premiumTtlHours,
                    premiumRefreshThreshold);
        }
    }

    @javax.annotation.Nullable
    public PremiumCacheEntry getPremiumStatus(@javax.annotation.Nullable String nickname) {
        if (nickname == null || nickname.isEmpty()) {
            return null;
        }
        // Per-entry TTL is enforced by Caffeine's Expiry — an expired entry is invisible here.
        return premiumCache.getIfPresent(nickname.toLowerCase(java.util.Locale.ROOT));
    }

    public java.util.Optional<PremiumCacheEntry> findPremiumStatus(@javax.annotation.Nullable String nickname) {
        return java.util.Optional.ofNullable(getPremiumStatus(nickname));
    }

    // ===== Brute Force Delegation =====

    public boolean registerFailedLogin(InetAddress address, String username) {
        return bruteForceTracker.registerFailedLogin(address, username);
    }

    public boolean isBlocked(InetAddress address, String username) {
        return bruteForceTracker.isBlocked(address, username);
    }

    public void resetLoginAttempts(InetAddress address, String username) {
        bruteForceTracker.resetLoginAttempts(address, username);
    }

    // ===== Session Delegation =====

    public void startSession(UUID uuid, String nickname, String ip) {
        sessionManager.startSession(uuid, nickname, ip);
    }

    public void endSession(UUID uuid) {
        sessionManager.endSession(uuid);
    }

    public boolean hasActiveSession(UUID uuid, String nickname, String currentIp) {
        return sessionManager.hasActiveSession(uuid, nickname, currentIp);
    }

    // ===== Clear / Cleanup =====

    public void clearAll() {
        try {
            authorizedPlayers.invalidateAll();
            premiumCache.invalidateAll();
            bruteForceTracker.clear();
            sessionManager.clear();
            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.all_cleared"));
            }
        } catch (IllegalStateException e) {
            logger.error(messages.get("cache.error.state.clear"), e);
        }
    }

    /**
     * Forces Caffeine to run its pending maintenance (expired-entry eviction, size cap
     * enforcement) for every cache we own. Caffeine schedules this work proactively via
     * {@code Scheduler.systemScheduler()} but the periodic kick keeps the cleanup deterministic
     * on idle proxies and matches the legacy {@code cacheCleanupInterval} expectation.
     */
    public void cleanupExpiredEntries() {
        try {
            authorizedPlayers.cleanUp();
            premiumCache.cleanUp();
            bruteForceTracker.cleanUp();
            sessionManager.cleanUp();
            IPRateLimiter limiter = this.ipRateLimiter;
            if (limiter != null) {
                limiter.cleanupExpired();
            }
        } catch (RuntimeException e) {
            logger.error("Error during cache cleanup", e);
        }
    }

    /**
     * Premium-cache-only maintenance kick. Scheduled independently from
     * {@link #cleanupExpiredEntries} so the premium cache can be tuned on a different
     * cadence (premium TTL is hours, the other caches are minutes).
     */
    public void cleanExpiredPremiumEntries() {
        try {
            premiumCache.cleanUp();
        } catch (RuntimeException e) {
            logger.error("Error during premium cache cleanup", e);
        }
    }

    // ===== Metrics & Shutdown =====

    private void logCacheAccessMetric(String messageKey, Object... args) {
        if (!logger.isDebugEnabled()) {
            return;
        }
        Object[] logArgs = new Object[args.length + 1];
        System.arraycopy(args, 0, logArgs, 0, args.length);
        logArgs[args.length] = authMetrics.formatHitRate();
        logger.debug(messages.get(messageKey), logArgs);
    }

    private void logPeriodicCacheMetrics() {
        try {
            if (!settings.isDebugEnabled()) {
                return;
            }

            CacheStats stats = getStats();
            double hitRate = stats.getHitRate();
            long totalRequests = stats.getTotalRequests();
            String hitRateStr = String.format(java.util.Locale.US, "%.2f", hitRate);

            logger.debug("=== CACHE METRICS ===");
            logger.debug("Authorized Players: {}/{} ({}% full)",
                    stats.authorizedPlayersCount(), stats.maxSize(),
                    (double) stats.authorizedPlayersCount() / Math.max(1, stats.maxSize()) * 100);
            logger.debug("Brute Force Entries: {}", stats.bruteForceEntriesCount());
            logger.debug("Premium Cache Entries: {}", stats.premiumCacheCount());
            logger.debug("Cache Performance: {} hits, {} misses, {}% hit rate",
                    stats.cacheHits(), stats.cacheMisses(), hitRateStr);
            logger.debug("Total Requests: {}", totalRequests);

            if (hitRate < 80.0 && totalRequests > 100) {
                logger.warn("Low cache hit rate ({}%) - consider increasing TTL or cache size", hitRateStr);
            }

            if (stats.authorizedPlayersCount() >= stats.maxSize() * 0.9) {
                logger.warn("Cache approaching capacity ({}/{} entries) - consider increasing maxSize",
                        stats.authorizedPlayersCount(), stats.maxSize());
            }

            logger.debug("====================");
        } catch (RuntimeException e) {
            logger.error("Error logging cache metrics", e);
        }
    }

    public void shutdown() {
        try {
            if (authMetrics.getTotalRequests() > 0 && logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.stats_final"),
                        authMetrics.getHits(), authMetrics.getMisses(), authMetrics.formatHitRate());
            }

            scheduler.shutdown();
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }

            clearAll();
            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.shutdown"));
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            scheduler.shutdownNow();
            if (logger.isWarnEnabled()) {
                logger.warn(messages.get("cache.interrupted_shutdown"));
            }
        }
    }

    // ===== Stats =====

    public CacheStats getStats() {
        // cleanUp() forces Caffeine to converge to its size cap before we read the count.
        // Otherwise size assertions in tests (and the approaching-capacity warning at
        // runtime) can momentarily see entries that the async maintenance hasn't evicted yet.
        authorizedPlayers.cleanUp();
        premiumCache.cleanUp();
        return new CacheStats(
                (int) Math.min(Integer.MAX_VALUE, authorizedPlayers.estimatedSize()),
                bruteForceTracker.size(),
                (int) Math.min(Integer.MAX_VALUE, premiumCache.estimatedSize()),
                authMetrics.getHits(),
                authMetrics.getMisses(),
                maxSize,
                ttlMinutes
        );
    }

    public record CacheStats(
            int authorizedPlayersCount,
            int bruteForceEntriesCount,
            int premiumCacheCount,
            long cacheHits,
            long cacheMisses,
            int maxSize,
            int ttlMinutes
    ) {
        public double getHitRate() {
            long total = cacheHits + cacheMisses;
            return total == 0 ? 0 : (double) cacheHits / total * 100;
        }

        public long getTotalRequests() {
            return cacheHits + cacheMisses;
        }
    }

    // ===== Inner Data Classes (kept public for external usage) =====

    /**
     * Premium cache entry with TTL.
     * <p>
     * {@code isExpired()} / {@code isStale()} were the only mechanism the legacy
     * {@code ConcurrentHashMap}-backed implementation had to honor per-entry TTL. With
     * Caffeine handling expiration via {@link AuthCache#PREMIUM_EXPIRY}, those methods
     * survive only for external callers ({@code getStale()} is still used to decide
     * whether to refresh a premium entry proactively).
     */
    public static class PremiumCacheEntry {
        private final boolean isPremium;
        private final UUID premiumUuid;
        private final long timestamp;
        private final long ttlMillis;
        private final double refreshThreshold;

        public PremiumCacheEntry(boolean isPremium, UUID premiumUuid, long ttlMillis, double refreshThreshold) {
            this.isPremium = isPremium;
            this.premiumUuid = premiumUuid;
            this.timestamp = System.currentTimeMillis();
            this.ttlMillis = ttlMillis;
            this.refreshThreshold = refreshThreshold;
        }

        public boolean isPremium() { return isPremium; }
        public UUID getPremiumUuid() { return premiumUuid; }
        public long getTimestamp() { return timestamp; }
        public long getTtlMillis() { return ttlMillis; }

        public boolean isExpired() {
            return System.currentTimeMillis() - timestamp > ttlMillis;
        }

        public boolean isStale() {
            return System.currentTimeMillis() - timestamp > (ttlMillis * refreshThreshold);
        }

        public long getAgeMillis() {
            return System.currentTimeMillis() - timestamp;
        }
    }

    /**
     * Active player session — anti-hijacking record managed by {@link SessionManager}.
     */
    public static class ActiveSession {
        private final UUID uuid;
        private final String nickname;
        private final String ip;
        private final long sessionStartTime;
        private volatile long lastActivityTime;

        public ActiveSession(UUID uuid, String nickname, String ip) {
            this.uuid = uuid;
            this.nickname = nickname;
            this.ip = ip;
            this.sessionStartTime = System.currentTimeMillis();
            this.lastActivityTime = System.currentTimeMillis();
        }

        public boolean isActive(long timeoutMinutes) {
            long timeoutMillis = timeoutMinutes * 60L * 1000L;
            return (System.currentTimeMillis() - lastActivityTime) < timeoutMillis;
        }

        public void updateActivity() {
            this.lastActivityTime = System.currentTimeMillis();
        }

        public UUID getUuid() { return uuid; }
        public String getNickname() { return nickname; }
        public String getIp() { return ip; }
        public long getSessionStartTime() { return sessionStartTime; }
        public long getLastActivityTime() { return lastActivityTime; }
    }
}
