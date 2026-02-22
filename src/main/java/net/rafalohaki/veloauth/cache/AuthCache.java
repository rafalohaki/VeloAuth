package net.rafalohaki.veloauth.cache;

import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Thread-safe cache autoryzacji dla VeloAuth.
 * Używa ConcurrentHashMap dla bezpiecznego dostępu wielowątkowego i ReentrantLock.
 * <p>
 * <h2>Extracted Components</h2>
 * <ul>
 *   <li>{@link BruteForceTracker} - brute-force attempt tracking and IP blocking</li>
 *   <li>{@link SessionManager} - active session management with anti-hijacking</li>
 * </ul>
 * <p>
 * Cache przechowuje:
 * - Autoryzowanych graczy (UUID -> CachedAuthUser)
 * - Próby brute force (delegated to BruteForceTracker)
 * - Premium graczy (nickname -> premium status)
 * - Aktywne sesje (delegated to SessionManager)
 * 
 * <h2>Cache Invalidation Strategy</h2>
 * <ul>
 *   <li><b>authorizedPlayers</b> - On player data update, TTL expiration, manual removal, or logout</li>
 *   <li><b>premiumCache</b> - On TTL expiration (24h), manual removal, or LRU eviction</li>
 *   <li><b>bruteForceAttempts</b> - On timeout expiration, successful login, or manual reset</li>
 *   <li><b>activeSessions</b> - On player disconnect, session hijacking detection, or inactivity</li>
 * </ul>
 */
public class AuthCache {

    private static final Logger logger = LoggerFactory.getLogger(AuthCache.class);

    /**
     * Cache autoryzowanych graczy.
     */
    private final ConcurrentHashMap<UUID, CachedAuthUser> authorizedPlayers;

    /**
     * Cache premium graczy.
     */
    private final ConcurrentHashMap<String, PremiumCacheEntry> premiumCache;

    /**
     * Delegated brute-force tracking.
     */
    private final BruteForceTracker bruteForceTracker;

    /**
     * Delegated session management.
     */
    private final SessionManager sessionManager;

    /**
     * Lock dla operacji krytycznych.
     */
    private final ReentrantLock cacheLock;

    private final int ttlMinutes;
    private final int maxSize;
    private final int maxPremiumCache;
    private final int premiumTtlHours;
    private final double premiumRefreshThreshold;

    private final ScheduledExecutorService cleanupScheduler;
    private final ScheduledExecutorService metricsScheduler;

    private final AtomicLong cacheHits = new AtomicLong(0);
    private final AtomicLong cacheMisses = new AtomicLong(0);

    private final Settings settings;
    private final Messages messages;

    /**
     * Configuration parameters for AuthCache.
     */
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

    /**
     * Tworzy nowy AuthCache.
     */
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
        this.maxPremiumCache = config.maxPremiumCache();
        this.premiumTtlHours = settings.getPremiumTtlHours();
        this.premiumRefreshThreshold = settings.getPremiumRefreshThreshold();
        this.settings = settings;
        this.messages = messages;

        this.authorizedPlayers = new ConcurrentHashMap<>();
        this.premiumCache = new ConcurrentHashMap<>();
        this.cacheLock = new ReentrantLock();

        // Delegated components
        this.bruteForceTracker = new BruteForceTracker(
                config.maxLoginAttempts(), config.bruteForceTimeoutMinutes(), messages);
        this.sessionManager = new SessionManager(
                config.maxSessions(), config.sessionTimeoutMinutes() > 0 ? config.sessionTimeoutMinutes() : 60, messages);

        this.cleanupScheduler = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "AuthCache-Cleanup");
            t.setDaemon(true);
            return t;
        });

        this.metricsScheduler = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "AuthCache-Metrics");
            t.setDaemon(true);
            return t;
        });

        if (config.cleanupIntervalMinutes() > 0) {
            // skipcq: JAVA-W1087 - Periodic scheduled task, fire-and-forget
            cleanupScheduler.scheduleAtFixedRate(
                    this::cleanupExpiredEntries,
                    config.cleanupIntervalMinutes(),
                    config.cleanupIntervalMinutes(),
                    TimeUnit.MINUTES
            );
        }

        // skipcq: JAVA-W1087 - Periodic scheduled task, fire-and-forget
        metricsScheduler.scheduleAtFixedRate(
                this::logPeriodicCacheMetrics,
                5, 5, TimeUnit.MINUTES
        );

        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.auth.created"),
                    this.ttlMinutes, this.maxSize, config.maxLoginAttempts(), config.bruteForceTimeoutMinutes());
        }
    }

    private static final class ParamCheck {
        final boolean invalid;
        final String message;
        ParamCheck(boolean invalid, String message) {
            this.invalid = invalid;
            this.message = message;
        }
    }

    private static String validateParams(int ttlMinutes, int maxSize, int maxSessions, int maxPremiumCache,
                                         int maxLoginAttempts, int bruteForceTimeoutMinutes, Messages messages) {
        ParamCheck[] checks = new ParamCheck[] {
                new ParamCheck(ttlMinutes < 0, messages.get("validation.ttl.negative")),
                new ParamCheck(maxSize <= 0, messages.get("validation.maxsize.gt_zero")),
                new ParamCheck(maxSessions <= 0, messages.get("validation.maxsessions.gt_zero")),
                new ParamCheck(maxPremiumCache <= 0, messages.get("validation.maxpremiumcache.gt_zero")),
                new ParamCheck(maxLoginAttempts <= 0, messages.get("validation.maxloginattempts.gt_zero")),
                new ParamCheck(bruteForceTimeoutMinutes <= 0, messages.get("validation.bruteforcetimeout.gt_zero"))
        };
        for (ParamCheck c : checks) {
            if (c.invalid) {
                return c.message;
            }
        }
        return null;
    }

    // ===== Authorized Players =====

    public void addAuthorizedPlayer(UUID uuid, CachedAuthUser user) {
        if (uuid == null || user == null) {
            throw new IllegalArgumentException("UUID and user must not be null");
        }

        if (authorizedPlayers.size() >= maxSize && !authorizedPlayers.containsKey(uuid)) {
            evictOldestAuthorizedEntryAtomic();
        }

        authorizedPlayers.put(uuid, user);
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.auth.added"), user.getNickname(), uuid);
        }
    }

    private void logCacheAccessMetric(String messageKey, Object... args) {
        double rate = (double) cacheHits.get() / Math.max(1, cacheHits.get() + cacheMisses.get()) * 100;
        String rateStr = String.format(java.util.Locale.US, "%.1f", rate);
        if (logger.isDebugEnabled()) {
            Object[] logArgs = new Object[args.length + 1];
            System.arraycopy(args, 0, logArgs, 0, args.length);
            logArgs[args.length] = rateStr;
            logger.debug(messages.get(messageKey), logArgs);
        }
    }

    @javax.annotation.Nullable
    public CachedAuthUser getAuthorizedPlayer(@javax.annotation.Nullable UUID uuid) {
        if (uuid == null) {
            return null;
        }

        CachedAuthUser user = authorizedPlayers.get(uuid);
        if (user == null) {
            cacheMisses.incrementAndGet();
            logCacheAccessMetric("cache.debug.uuid.miss", uuid);
            return null;
        }

        if (!user.isValid(ttlMinutes)) {
            removeAuthorizedPlayer(uuid);
            cacheMisses.incrementAndGet();
            logCacheAccessMetric("cache.debug.uuid.expired", uuid);
            return null;
        }

        user.touch();
        cacheHits.incrementAndGet();
        logCacheAccessMetric("cache.debug.hit.rate");
        return user;
    }

    @javax.annotation.Nonnull
    public java.util.Optional<CachedAuthUser> findAuthorizedPlayer(@javax.annotation.Nullable UUID uuid) {
        return java.util.Objects.requireNonNull(java.util.Optional.ofNullable(getAuthorizedPlayer(uuid)), "Optional cannot be null");
    }

    public void removeAuthorizedPlayer(UUID uuid) {
        if (uuid != null) {
            CachedAuthUser removed = authorizedPlayers.remove(uuid);
            if (removed != null && logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.debug.player.removed"),
                        removed.getNickname(), uuid);
            }
        }
    }

    public boolean isPlayerAuthorized(UUID uuid, String currentIp) {
        CachedAuthUser user = getAuthorizedPlayer(uuid);
        if (user == null) {
            return false;
        }
        return user.matchesIp(currentIp);
    }
    
    public void invalidatePlayerData(UUID playerUuid) {
        if (playerUuid == null) {
            return;
        }
        
        CachedAuthUser user = authorizedPlayers.get(playerUuid);
        if (user != null) {
            authorizedPlayers.remove(playerUuid);
            if (logger.isDebugEnabled()) {
                logger.debug("Invalidated cached data for player UUID: {} (nickname: {})", 
                        playerUuid, user.getNickname());
            }
        }
    }

    // ===== Premium Cache =====

    public void removePremiumPlayer(String nickname) {
        if (nickname == null || nickname.isEmpty()) {
            return;
        }

        PremiumCacheEntry removed = premiumCache.remove(nickname.toLowerCase());
        if (removed != null && logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.premium.removed"),
                    nickname, removed.isPremium());
        }
    }

    public void addPremiumPlayer(String nickname, UUID premiumUuid) {
        if (nickname == null || nickname.isEmpty()) {
            return;
        }

        String key = nickname.toLowerCase();
        if (premiumCache.size() >= maxPremiumCache && !premiumCache.containsKey(key)) {
            evictOldestPremiumEntryAtomic();
        }

        long ttl = TimeUnit.HOURS.toMillis(premiumTtlHours);
        PremiumCacheEntry entry = new PremiumCacheEntry(premiumUuid != null, premiumUuid, ttl, premiumRefreshThreshold);
        premiumCache.put(key, entry);

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

        String key = nickname.toLowerCase();
        PremiumCacheEntry entry = premiumCache.get(key);
        if (entry == null) {
            return null;
        }

        if (entry.isExpired()) {
            premiumCache.remove(key);
            if (logger.isDebugEnabled()) {
                logger.debug("Premium cache entry expired for {} (age: {}ms, TTL: {}ms)", 
                        nickname, entry.getAgeMillis(), entry.getTtlMillis());
            }
            return null;
        }

        return entry;
    }

    @javax.annotation.Nonnull
    public java.util.Optional<PremiumCacheEntry> findPremiumStatus(@javax.annotation.Nullable String nickname) {
        return java.util.Objects.requireNonNull(java.util.Optional.ofNullable(getPremiumStatus(nickname)), "Optional cannot be null");
    }

    // ===== Brute Force Delegation =====

    public boolean registerFailedLogin(InetAddress address) {
        return bruteForceTracker.registerFailedLogin(address);
    }

    public boolean isBlocked(InetAddress address) {
        return bruteForceTracker.isBlocked(address);
    }

    public void resetLoginAttempts(InetAddress address) {
        bruteForceTracker.resetLoginAttempts(address);
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
            cacheLock.lock();
            try {
                authorizedPlayers.clear();
                bruteForceTracker.clear();
                premiumCache.clear();
                sessionManager.clear();
                if (logger.isDebugEnabled()) {
                    logger.debug(messages.get("cache.all_cleared"));
                }
            } finally {
                cacheLock.unlock();
            }
        } catch (IllegalStateException e) {
            logger.error(messages.get("cache.error.state.clear"), e);
        }
    }

    public void cleanupExpiredEntries() {
        try {
            cacheLock.lock();
            try {
                int removedAuth = cleanupAuthorized();
                int removedBrute = bruteForceTracker.cleanupExpired();
                int removedPremium = cleanupPremium();
                int removedSessions = sessionManager.cleanupExpired();

                if (removedAuth > 0 || removedBrute > 0 || removedPremium > 0 || removedSessions > 0) {
                    logger.debug("Cleanup: usunięto {} auth, {} brute force, {} premium, {} sessions",
                            removedAuth, removedBrute, removedPremium, removedSessions);
                }
            } finally {
                cacheLock.unlock();
            }
        } catch (Exception e) {
            logger.error("Błąd podczas czyszczenia cache", e);
        }
    }

    private int cleanupAuthorized() {
        int removed = 0;
        var iterator = authorizedPlayers.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (!entry.getValue().isValid(ttlMinutes)) {
                iterator.remove();
                removed++;
            }
        }
        return removed;
    }

    private int cleanupPremium() {
        int removed = 0;
        var iterator = premiumCache.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (entry.getValue().isExpired()) {
                iterator.remove();
                removed++;
            }
        }
        return removed;
    }

    // ===== Eviction =====

    private void evictOldestAuthorizedEntryAtomic() {
        var lru = authorizedPlayers.entrySet().stream()
                .min(java.util.Comparator.comparingLong(e -> e.getValue().getLastAccessTime()))
                .orElse(null);
        if (lru != null) {
            authorizedPlayers.remove(lru.getKey(), lru.getValue());
        }
    }

    private void evictOldestPremiumEntryAtomic() {
        var oldest = premiumCache.entrySet().stream()
                .min(java.util.Comparator.comparingLong(e -> e.getValue().getTimestamp()))
                .orElse(null);
        if (oldest != null) {
            String evictedKey = oldest.getKey();
            PremiumCacheEntry evictedEntry = oldest.getValue();
            premiumCache.remove(evictedKey, evictedEntry);
            
            if (logger.isDebugEnabled()) {
                logger.debug("Premium cache LRU eviction: {} (age: {}ms, was premium: {})", 
                        evictedKey, evictedEntry.getAgeMillis(), evictedEntry.isPremium());
            }
        }
    }

    // ===== Metrics & Shutdown =====

    private void logPeriodicCacheMetrics() {
        try {
            if (!settings.isDebugEnabled()) {
                return;
            }

            CacheStats stats = getStats();
            double hitRate = stats.getHitRate();
            long totalRequests = stats.getTotalRequests();

            logger.debug("=== CACHE METRICS ===");
            logger.debug("Authorized Players: {}/{} ({}% full)",
                    stats.authorizedPlayersCount(), stats.maxSize(),
                    (double) stats.authorizedPlayersCount() / stats.maxSize() * 100);
            logger.debug("Brute Force Entries: {}", stats.bruteForceEntriesCount());
            logger.debug("Premium Cache Entries: {}", stats.premiumCacheCount());
            String hitRateStr = String.format(java.util.Locale.US, "%.2f", hitRate);
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
        } catch (Exception e) {
            logger.error("Error logging cache metrics", e);
        }
    }

    public void shutdown() {
        try {
            if (cacheHits.get() + cacheMisses.get() > 0) {
                double rate = (double) cacheHits.get() / (cacheHits.get() + cacheMisses.get()) * 100;
                String rateStr = String.format(java.util.Locale.US, "%.1f", rate);
                if (logger.isDebugEnabled()) {
                    logger.debug(messages.get("cache.stats_final"),
                            cacheHits.get(), cacheMisses.get(), rateStr);
                }
            }

            cleanupScheduler.shutdown();
            if (!cleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupScheduler.shutdownNow();
            }

            metricsScheduler.shutdown();
            if (!metricsScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                metricsScheduler.shutdownNow();
            }

            clearAll();
            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.shutdown"));
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            cleanupScheduler.shutdownNow();
            metricsScheduler.shutdownNow();
            if (logger.isWarnEnabled()) {
                logger.warn(messages.get("cache.interrupted_shutdown"));
            }
        }
    }

    // ===== Stats =====

    public CacheStats getStats() {
        return new CacheStats(
                authorizedPlayers.size(),
                bruteForceTracker.size(),
                premiumCache.size(),
                cacheHits.get(),
                cacheMisses.get(),
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
     * Wpis premium cache z TTL.
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
     * Aktywna sesja gracza - zapobiega session hijacking.
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
