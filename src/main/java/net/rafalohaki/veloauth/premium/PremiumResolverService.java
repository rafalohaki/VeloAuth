package net.rafalohaki.veloauth.premium;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Expiry;
import net.rafalohaki.veloauth.alert.PremiumResolverAlertService;
import net.rafalohaki.veloauth.cache.VeloAuthCaches;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.config.Settings.PremiumResolverSettings;
import net.rafalohaki.veloauth.database.PremiumUuidDao;
import net.rafalohaki.veloauth.model.PremiumUuid;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * Aggregates premium resolvers with caching and priority fallback.
 * <p>
 * In-memory caching is delegated to Caffeine ({@link VeloAuthCaches#variableTtl}) so
 * positive hits use the configured {@code hit-ttl-minutes} while negative results
 * (player not premium) use the much shorter {@code miss-ttl-minutes}. Capacity is
 * bounded by {@code memory-cache-max-size}; W-TinyLFU handles eviction in O(1).
 * <p>
 * No explicit lock or hand-rolled LRU sweep is needed any more — Caffeine's per-node
 * synchronization covers both the size cap and the per-entry TTL.
 */
public class PremiumResolverService {

    private static final Pattern VALID_USERNAME = Pattern.compile("^\\w{3,16}$");
    private static final String RESOLVER_SERVICE = "resolver-service";
    private static final Marker PREMIUM_MARKER = MarkerFactory.getMarker("PREMIUM");

    private final Logger logger;
    private final PremiumUuidDao dao; // Renamed to avoid conflict with class name
    private final List<PremiumResolver> resolvers;
    private final Cache<String, PremiumResolution> cache;
    private final long premiumTtlMillis;
    private final long missTtlMillis;
    private final int maxCacheSize;
    private final PremiumResolverAlertService alertService;

    public PremiumResolverService(Logger logger, Settings settings, PremiumUuidDao premiumUuidDao) {
        this(logger, settings, premiumUuidDao, null);
    }

    public PremiumResolverService(Logger logger, Settings settings, PremiumUuidDao premiumUuidDao,
                                  PremiumResolverAlertService alertService) {
        this.logger = Objects.requireNonNull(logger, "logger");
        PremiumResolverSettings rs = Objects.requireNonNull(settings, "settings").getPremiumResolverSettings();
        this.dao = Objects.requireNonNull(premiumUuidDao, "premiumUuidDao");
        this.alertService = alertService;

        if (logger.isInfoEnabled()) {
            logger.info(PREMIUM_MARKER, "[PremiumResolver] Config - Mojang: {}, Ashcon: {}, Wpme: {}",
                    rs.isMojangEnabled(),
                    rs.isAshconEnabled(),
                    rs.isWpmeEnabled());
        }

        this.resolvers = createDefaultResolvers(logger, rs);

        this.premiumTtlMillis = Math.max(0L, rs.getHitTtlMinutes()) * 60_000L;
        this.missTtlMillis = Math.max(0L, rs.getMissTtlMinutes()) * 60_000L;
        int configuredMaxSize = rs.getMemoryCacheMaxSize();
        this.maxCacheSize = configuredMaxSize > 0 ? configuredMaxSize : 10_000;
        this.cache = VeloAuthCaches.variableTtl(this.maxCacheSize, perEntryExpiry());

        if (premiumTtlMillis == 0 && logger.isWarnEnabled()) {
            logger.warn(PREMIUM_MARKER, "[PremiumResolver] hitTtlMinutes = 0 — premium cache disabled, every login will query API!");
        }
        if (missTtlMillis == 0 && logger.isWarnEnabled()) {
            logger.warn(PREMIUM_MARKER, "[PremiumResolver] missTtlMinutes = 0 — miss cache disabled, every unknown player will query API!");
        }
    }

    PremiumResolverService(Logger logger,
                           PremiumUuidDao premiumUuidDao,
                           List<PremiumResolver> resolvers,
                           long premiumTtlMillis,
                           long missTtlMillis) {
        this.logger = Objects.requireNonNull(logger, "logger");
        this.dao = Objects.requireNonNull(premiumUuidDao, "premiumUuidDao");
        this.resolvers = List.copyOf(Objects.requireNonNull(resolvers, "resolvers"));
        this.premiumTtlMillis = Math.max(0L, premiumTtlMillis);
        this.missTtlMillis = Math.max(0L, missTtlMillis);
        this.maxCacheSize = 10_000;
        this.alertService = null;
        this.cache = VeloAuthCaches.variableTtl(this.maxCacheSize, perEntryExpiry());
    }

    /**
     * Builds the per-entry expiry policy. Captured premium / miss TTLs are final
     * by the time this is called, so the returned {@link Expiry} can read them
     * via the enclosing instance fields without any mutation hazard.
     */
    private Expiry<String, PremiumResolution> perEntryExpiry() {
        return new Expiry<>() {
            @Override
            public long expireAfterCreate(String key, PremiumResolution value, long currentTime) {
                return computeTtlNanos(value);
            }

            @Override
            public long expireAfterUpdate(String key, PremiumResolution value, long currentTime, long currentDuration) {
                return computeTtlNanos(value);
            }

            @Override
            public long expireAfterRead(String key, PremiumResolution value, long currentTime, long currentDuration) {
                return currentDuration;
            }
        };
    }

    /**
     * TTL conversion helper. Cache-skip semantics (TTL ≤ 0 = "do not cache this kind of result")
     * live in {@link #cacheResult}; here we only handle the positive case so the Expiry never
     * has to think about disabled tiers.
     */
    private long computeTtlNanos(PremiumResolution value) {
        long ttlMillis = value.isPremium() ? premiumTtlMillis : missTtlMillis;
        return ttlMillis <= 0L ? 1L : TimeUnit.MILLISECONDS.toNanos(ttlMillis);
    }

    private static List<PremiumResolver> createDefaultResolvers(Logger logger, PremiumResolverSettings settings) {
        int timeoutMs = Math.max(100, settings.getRequestTimeoutMs());
        List<PremiumResolver> resolverList = new ArrayList<>();
        resolverList.add(new ConfigurablePremiumResolver(logger, settings.isMojangEnabled(), timeoutMs, ResolverConfig.MOJANG));
        resolverList.add(new ConfigurablePremiumResolver(logger, settings.isAshconEnabled(), timeoutMs, ResolverConfig.ASHCON));
        resolverList.add(new ConfigurablePremiumResolver(logger, settings.isWpmeEnabled(), timeoutMs, ResolverConfig.WPME));
        return Collections.unmodifiableList(resolverList);
    }

    /**
     * Rozwiązuje status premium przez API resolvers.
     *
     * @param trimmed  Nazwa gracza (trimmed)
     * @param cacheKey Klucz do cache
     * @return PremiumResolution z API lub offline
     */
    private PremiumResolution resolveFromApi(String trimmed, String cacheKey) {
        PremiumResolution offlineCandidate = tryApiResolvers(trimmed);

        if (offlineCandidate != null) {
            cacheResult(cacheKey, offlineCandidate);
            return offlineCandidate;
        }

        if (logger.isWarnEnabled()) {
            logger.warn(PREMIUM_MARKER, "[PremiumResolver] No premium resolvers enabled - defaulting offline");
        }
        PremiumResolution disabled = PremiumResolution.offline(trimmed, RESOLVER_SERVICE, "no resolvers enabled");
        cacheResult(cacheKey, disabled);
        return disabled;
    }

    /**
     * Próbuje wszystkie API resolvers RÓWNOLEGLE.
     * Zwraca pierwszy wynik PREMIUM lub pierwszy OFFLINE jeśli żaden nie jest premium.
     * Używa Virtual Threads dla maksymalnej wydajności.
     *
     * @param trimmed Nazwa gracza
     * @return PremiumResolution lub null jeśli żaden resolver nie włączony
     */
    private PremiumResolution tryApiResolvers(String trimmed) {
        List<PremiumResolver> enabledResolvers = resolvers.stream()
                .filter(PremiumResolver::enabled)
                .toList();

        if (enabledResolvers.isEmpty()) {
            return null;
        }

        ResolverResults results = executeResolversInParallel(enabledResolvers, trimmed);
        return selectBestResult(results, trimmed);
    }

    private ResolverResults executeResolversInParallel(List<PremiumResolver> enabledResolvers, String trimmed) {
        AtomicReference<PremiumResolution> premiumResult = new AtomicReference<>();
        AtomicReference<PremiumResolution> offlineCandidate = new AtomicReference<>();
        java.util.concurrent.atomic.AtomicInteger unknownCount = new java.util.concurrent.atomic.AtomicInteger(0);

        List<CompletableFuture<PremiumResolution>> futures = enabledResolvers.stream()
                .map(resolver -> createResolverFuture(resolver, trimmed, premiumResult, offlineCandidate, unknownCount))
                .toList();

        awaitResolverFutures(futures);
        return new ResolverResults(premiumResult.get(), offlineCandidate.get(), unknownCount.get() > 0);
    }

    private CompletableFuture<PremiumResolution> createResolverFuture(
            PremiumResolver resolver, String trimmed,
            AtomicReference<PremiumResolution> premiumResult,
            AtomicReference<PremiumResolution> offlineCandidate,
            java.util.concurrent.atomic.AtomicInteger unknownCount) {
        return CompletableFuture.supplyAsync(
                () -> executeResolver(resolver, trimmed, premiumResult, offlineCandidate, unknownCount),
                net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider.getVirtualExecutor()
        );
    }

    private PremiumResolution executeResolver(
            PremiumResolver resolver, String trimmed,
            AtomicReference<PremiumResolution> premiumResult,
            AtomicReference<PremiumResolution> offlineCandidate,
            java.util.concurrent.atomic.AtomicInteger unknownCount) {
        try {
            PremiumResolution rawResolution = resolver.resolve(trimmed);
            PremiumResolution resolution = normalizeResolution(resolver, rawResolution, trimmed);
            categorizeResolution(resolver, resolution, trimmed, premiumResult, offlineCandidate, unknownCount);
            // API responded (premium or offline) = success; unknown = treated as failure for alerting
            recordAlertMetric(resolver.id(), !resolution.isUnknown());
            return resolution;
        } catch (Exception e) {
            logResolverFailure(resolver, trimmed, e);
            recordAlertMetric(resolver.id(), false);
            return PremiumResolution.unknown(resolver.id(), e.getMessage());
        }
    }

    private void recordAlertMetric(String resolverId, boolean success) {
        if (alertService != null) {
            alertService.recordResolution(resolverId, success);
        }
    }

    private void categorizeResolution(
            PremiumResolver resolver, PremiumResolution resolution, String trimmed,
            AtomicReference<PremiumResolution> premiumResult,
            AtomicReference<PremiumResolution> offlineCandidate,
            java.util.concurrent.atomic.AtomicInteger unknownCount) {
        if (resolution.isPremium()) {
            premiumResult.compareAndSet(null, resolution);
            logResolutionResult(resolver, trimmed, "PREMIUM");
        } else if (resolution.isOffline()) {
            offlineCandidate.compareAndSet(null, resolution);
            logResolutionResult(resolver, trimmed, "OFFLINE");
        } else {
            unknownCount.incrementAndGet();
            if (logger.isDebugEnabled()) {
                logger.debug(PREMIUM_MARKER, "[PARALLEL] {} returned UNKNOWN for {}: {}", resolver.id(), trimmed, resolution.message());
            }
        }
    }

    private void logResolutionResult(PremiumResolver resolver, String trimmed, String status) {
        if (logger.isDebugEnabled()) {
            logger.debug(PREMIUM_MARKER, "[PARALLEL] {} returned {} for {}", resolver.id(), status, trimmed);
        }
    }

    private void logResolverFailure(PremiumResolver resolver, String trimmed, Exception e) {
        if (logger.isWarnEnabled()) {
            logger.warn(PREMIUM_MARKER, "[PARALLEL] {} failed for {}: {}", resolver.id(), trimmed, e.getMessage());
        }
    }

    private void awaitResolverFutures(List<CompletableFuture<PremiumResolution>> futures) {
        try {
            CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                    .orTimeout(5, TimeUnit.SECONDS)
                    .exceptionally(ex -> null)
                    .join();
        } catch (Exception e) {
            if (logger.isDebugEnabled()) {
                logger.debug(PREMIUM_MARKER, "[PARALLEL] Timeout or error waiting for resolvers: {}", e.getMessage());
            }
        }
    }

    private PremiumResolution selectBestResult(ResolverResults results, String trimmed) {
        if (results.premium() != null) {
            savePremiumToCache(results.premium(), trimmed);
            if (logger.isInfoEnabled()) {
                logger.info(PREMIUM_MARKER, "[PARALLEL] Premium confirmed for {} from {}", trimmed, results.premium().source());
            }
            return results.premium();
        }

        if (results.offline() != null) {
            // At least one resolver explicitly confirmed "player not found" (API responded correctly).
            // Trust that result — UNKNOWN from other resolvers means timeout/rate-limit/error,
            // NOT that the player might be premium. A premium player would be found by at least
            // one working resolver. Blocking offline players due to API failures is too strict.
            if (results.hasUnknown() && logger.isDebugEnabled()) {
                logger.debug(PREMIUM_MARKER, "[PARALLEL] OFFLINE confirmed for {} (some resolvers returned unknown, but at least one confirmed offline)", trimmed);
            }
            if (logger.isDebugEnabled()) {
                logger.debug(PREMIUM_MARKER, "[PARALLEL] Player {} resolved as offline", trimmed);
            }
            return results.offline();
        }

        if (logger.isWarnEnabled()) {
            logger.warn(PREMIUM_MARKER, "[PARALLEL] All resolvers returned unknown for {} - possible API issues", trimmed);
        }
        return PremiumResolution.unknown(RESOLVER_SERVICE, "all resolvers failed");
    }

    private record ResolverResults(PremiumResolution premium, PremiumResolution offline, boolean hasUnknown) {}

    /**
     * Saves premium resolution to database cache.
     *
     * @param resolution Premium resolution
     * @param trimmed    Username
     */
    private void savePremiumToCache(PremiumResolution resolution, String trimmed) {
        if (resolution.uuid() != null) {
            boolean saved = dao.saveOrUpdate(resolution.uuid(), trimmed);
            if (saved && logger.isDebugEnabled()) {
                logger.debug(PREMIUM_MARKER, "[PremiumResolver] zapisano do DB cache: {} -> {}", trimmed, resolution.uuid());
            }
        }
    }


    public PremiumResolution resolve(String username) {
        if (username == null || username.isBlank()) {
            return PremiumResolution.offline(username, RESOLVER_SERVICE, "empty username");
        }

        String trimmed = username.trim();
        if (!VALID_USERNAME.matcher(trimmed).matches()) {
            return PremiumResolution.offline(trimmed, RESOLVER_SERVICE, "invalid characters");
        }

        String cacheKey = trimmed.toLowerCase(Locale.ROOT);

        // 1. Sprawdź memory cache (najszybsze)
        PremiumResolution cached = getFromCache(cacheKey);
        if (cached != null) {
            if (logger.isDebugEnabled()) {
                logger.debug(PREMIUM_MARKER, "[PremiumResolver] memory cache hit {} -> {}", trimmed, cached.status());
            }
            return cached;
        }

        // 2. Sprawdź database cache (persistency)
        Optional<PremiumUuid> dbResult = dao.findByNickname(trimmed);
        if (dbResult.isPresent() && isDbCacheEntryFresh(dbResult.get())) {
            PremiumUuid premiumUuid = dbResult.get();
            PremiumResolution result = PremiumResolution.premium(
                    premiumUuid.getUuid(),
                    trimmed,
                    RESOLVER_SERVICE + "-db-cache"
            );

            // Zapisz do memory cache
            cacheResult(cacheKey, result);
            if (logger.isInfoEnabled()) {
                logger.info(PREMIUM_MARKER, "[PremiumResolver] database cache hit {} -> {} (UUID: {})",
                        trimmed, result.status(), premiumUuid.getUuid());
            }
            return result;
        }

        if (dbResult.isPresent() && logger.isDebugEnabled()) {
            logger.debug(PREMIUM_MARKER,
                    "[PremiumResolver] DB cache entry for {} stale (lastSeen age > hit-ttl) — refreshing from API",
                    trimmed);
        }

        // 3. Cache miss (or stale DB entry) - wywołaj API
        return resolveFromApi(trimmed, cacheKey);
    }

    /**
     * Treats a DB cache entry as fresh only if its last-seen timestamp is within the
     * configured hit-ttl. Without this guard a stale {@code PREMIUM_UUIDS} row could
     * trigger an erroneous account migration in {@code findAndMigrateByPremiumUuid}
     * when the player's actual Mojang UUID has since changed.
     * <p>
     * Compatibility note: legacy rows imported from LimboAuth via
     * {@code DatabaseMigrationService} have {@code LAST_SEEN=0} (the {@code DEFAULT 0}
     * we set on ALTER TABLE). Treating those as stale would force an API refetch on
     * every login until the next successful resolution rewrites the timestamp — a
     * potential API storm right after upgrade. So {@code lastSeen <= 0} is treated
     * as "unknown but trusted"; only entries with a real positive timestamp are
     * subject to the TTL check.
     */
    private boolean isDbCacheEntryFresh(PremiumUuid entry) {
        long lastSeen = entry.getLastSeen();
        if (lastSeen <= 0L) {
            return true;
        }
        if (premiumTtlMillis <= 0L) {
            return true;
        }
        long age = System.currentTimeMillis() - lastSeen;
        return age >= 0 && age <= premiumTtlMillis;
    }

    private PremiumResolution normalizeResolution(PremiumResolver resolver, PremiumResolution resolution, String requestName) {
        String source = resolver.id();
        if (resolution == null) {
            return PremiumResolution.unknown(source, "null resolution");
        }

        source = resolution.source() != null ? resolution.source() : source;
        String canonical = resolution.canonicalUsername() != null ? resolution.canonicalUsername() : requestName;

        if (resolution.status() == PremiumResolution.PremiumStatus.PREMIUM) {
            return validatePremiumResolution(resolution, source, canonical, requestName);
        } else if (resolution.status() == PremiumResolution.PremiumStatus.OFFLINE) {
            return PremiumResolution.offline(requestName, source, resolution.message());
        } else {
            return PremiumResolution.unknown(source, resolution.message());
        }
    }

    private PremiumResolution validatePremiumResolution(PremiumResolution resolution, String source, String canonical, String requestName) {
        if (resolution.uuid() == null) {
            return PremiumResolution.unknown(source, "missing uuid");
        }
        if (!canonical.equalsIgnoreCase(requestName)) {
            if (logger.isDebugEnabled()) {
                logger.debug(PREMIUM_MARKER, "[PremiumResolver] username mismatch {} vs {} from {}", canonical, requestName, source);
            }
            return PremiumResolution.offline(requestName, source, "username mismatch with canonical name");
        }
        return PremiumResolution.premium(resolution.uuid(), canonical, source);
    }

    /**
     * Cache read. Caffeine's per-entry TTL hides expired entries from {@code getIfPresent},
     * collapsing the previous "lookup → expiry check → conditional remove" branch into a
     * single call.
     */
    private PremiumResolution getFromCache(String key) {
        return cache.getIfPresent(key);
    }

    /**
     * Cache write. When the matching TTL tier is disabled (configured to {@code 0}) we
     * intentionally drop any existing entry instead of putting one with a phantom TTL —
     * matches the legacy semantics where {@code hit-ttl-minutes=0} or {@code miss-ttl-minutes=0}
     * meant "every login queries the API for this kind of result".
     */
    private void cacheResult(String key, PremiumResolution resolution) {
        long ttl = resolution.isPremium() ? premiumTtlMillis : missTtlMillis;
        if (ttl <= 0L) {
            cache.invalidate(key);
            return;
        }
        cache.put(key, resolution);
    }

    /**
     * Clears the in-memory premium resolution cache and releases resources.
     * Must be called during plugin shutdown before DatabaseManager is closed.
     */
    public void shutdown() {
        long size = cache.estimatedSize();
        cache.invalidateAll();
        cache.cleanUp();
        if (logger.isDebugEnabled()) {
            logger.debug(PREMIUM_MARKER, "[PremiumResolver] Shutdown complete — cleared {} cached entries", size);
        }
    }
}
