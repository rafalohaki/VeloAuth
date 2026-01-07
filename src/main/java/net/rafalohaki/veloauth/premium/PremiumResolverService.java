package net.rafalohaki.veloauth.premium;

import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.config.Settings.PremiumResolverSettings;
import net.rafalohaki.veloauth.database.PremiumUuidDao;
import net.rafalohaki.veloauth.model.PremiumUuid;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

/**
 * Aggregates premium resolvers with caching and priority fallback.
 */
public class PremiumResolverService {

    private static final Pattern VALID_USERNAME = Pattern.compile("^\\w{3,16}$");
    private static final String RESOLVER_SERVICE = "resolver-service";

    private final Logger logger;
    private final PremiumUuidDao dao; // Renamed to avoid conflict with class name
    private final List<PremiumResolver> resolvers;
    private final Map<String, CachedEntry> cache = new java.util.concurrent.ConcurrentHashMap<>();
    private final long premiumTtlMillis;
    private final long missTtlMillis;
    private final int maxCacheSize;
    // ReentrantLock prevents virtual thread pinning (Java 21 synchronized issue)
    private final ReentrantLock cacheSizeLock = new ReentrantLock();

    public PremiumResolverService(Logger logger, Settings settings, PremiumUuidDao premiumUuidDao) {
        this.logger = Objects.requireNonNull(logger, "logger");
        PremiumResolverSettings rs = Objects.requireNonNull(settings, "settings").getPremiumResolverSettings();
        this.dao = Objects.requireNonNull(premiumUuidDao, "premiumUuidDao");

        if (logger.isInfoEnabled()) {
            logger.info("[PremiumResolver] Config - Mojang: {}, Ashcon: {}, Wpme: {}",
                    rs.isMojangEnabled(),
                    rs.isAshconEnabled(),
                    rs.isWpmeEnabled());
        }

        int timeoutMs = Math.max(100, rs.getRequestTimeoutMs());
        List<PremiumResolver> resolverList = new ArrayList<>();
        resolverList.add(new ConfigurablePremiumResolver(logger, rs.isMojangEnabled(), timeoutMs, ResolverConfig.MOJANG));
        resolverList.add(new ConfigurablePremiumResolver(logger, rs.isAshconEnabled(), timeoutMs, ResolverConfig.ASHCON));
        resolverList.add(new ConfigurablePremiumResolver(logger, rs.isWpmeEnabled(), timeoutMs, ResolverConfig.WPME));
        this.resolvers = Collections.unmodifiableList(resolverList);

        this.premiumTtlMillis = Math.max(0L, rs.getHitTtlMinutes()) * 60_000L;
        this.missTtlMillis = Math.max(0L, rs.getMissTtlMinutes()) * 60_000L;
        this.maxCacheSize = 10_000;
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
            logger.warn("[PremiumResolver] No premium resolvers enabled - defaulting offline");
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

        List<CompletableFuture<PremiumResolution>> futures = enabledResolvers.stream()
                .map(resolver -> createResolverFuture(resolver, trimmed, premiumResult, offlineCandidate))
                .toList();

        awaitResolverFutures(futures);
        return new ResolverResults(premiumResult.get(), offlineCandidate.get());
    }

    private CompletableFuture<PremiumResolution> createResolverFuture(
            PremiumResolver resolver, String trimmed,
            AtomicReference<PremiumResolution> premiumResult,
            AtomicReference<PremiumResolution> offlineCandidate) {
        return CompletableFuture.supplyAsync(
                () -> executeResolver(resolver, trimmed, premiumResult, offlineCandidate),
                net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider.getVirtualExecutor()
        );
    }

    private PremiumResolution executeResolver(
            PremiumResolver resolver, String trimmed,
            AtomicReference<PremiumResolution> premiumResult,
            AtomicReference<PremiumResolution> offlineCandidate) {
        try {
            PremiumResolution rawResolution = resolver.resolve(trimmed);
            PremiumResolution resolution = normalizeResolution(resolver, rawResolution, trimmed);
            categorizeResolution(resolver, resolution, trimmed, premiumResult, offlineCandidate);
            return resolution;
        } catch (Exception e) {
            logResolverFailure(resolver, trimmed, e);
            return PremiumResolution.unknown(resolver.id(), e.getMessage());
        }
    }

    private void categorizeResolution(
            PremiumResolver resolver, PremiumResolution resolution, String trimmed,
            AtomicReference<PremiumResolution> premiumResult,
            AtomicReference<PremiumResolution> offlineCandidate) {
        if (resolution.isPremium()) {
            premiumResult.compareAndSet(null, resolution);
            logResolutionResult(resolver, trimmed, "PREMIUM");
        } else if (resolution.isOffline()) {
            offlineCandidate.compareAndSet(null, resolution);
            logResolutionResult(resolver, trimmed, "OFFLINE");
        } else if (logger.isDebugEnabled()) {
            logger.debug("[PARALLEL] {} returned UNKNOWN for {}: {}", resolver.id(), trimmed, resolution.message());
        }
    }

    private void logResolutionResult(PremiumResolver resolver, String trimmed, String status) {
        if (logger.isDebugEnabled()) {
            logger.debug("[PARALLEL] {} returned {} for {}", resolver.id(), status, trimmed);
        }
    }

    private void logResolverFailure(PremiumResolver resolver, String trimmed, Exception e) {
        if (logger.isWarnEnabled()) {
            logger.warn("[PARALLEL] {} failed for {}: {}", resolver.id(), trimmed, e.getMessage());
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
                logger.debug("[PARALLEL] Timeout or error waiting for resolvers: {}", e.getMessage());
            }
        }
    }

    private PremiumResolution selectBestResult(ResolverResults results, String trimmed) {
        if (results.premium() != null) {
            savePremiumToCache(results.premium(), trimmed);
            if (logger.isInfoEnabled()) {
                logger.info("[PARALLEL] Premium confirmed for {} from {}", trimmed, results.premium().source());
            }
            return results.premium();
        }

        if (results.offline() != null) {
            if (logger.isDebugEnabled()) {
                logger.debug("[PARALLEL] All resolvers returned offline for {}", trimmed);
            }
            return results.offline();
        }

        if (logger.isWarnEnabled()) {
            logger.warn("[PARALLEL] All resolvers returned unknown for {} - possible API issues", trimmed);
        }
        return PremiumResolution.unknown(RESOLVER_SERVICE, "all resolvers failed");
    }

    private record ResolverResults(PremiumResolution premium, PremiumResolution offline) {}

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
                logger.debug("[PremiumResolver] zapisano do DB cache: {} -> {}", trimmed, resolution.uuid());
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
                logger.debug("[PremiumResolver] memory cache hit {} -> {}", trimmed, cached.status());
            }
            return cached;
        }

        // 2. Sprawdź database cache (persistency)
        Optional<PremiumUuid> dbResult = dao.findByNickname(trimmed);
        if (dbResult.isPresent()) {
            PremiumUuid premiumUuid = dbResult.get();
            PremiumResolution result = PremiumResolution.premium(
                    premiumUuid.getUuid(),
                    trimmed,
                    RESOLVER_SERVICE + "-db-cache"
            );

            // Zapisz do memory cache
            cacheResult(cacheKey, result);
            if (logger.isInfoEnabled()) {
                logger.info("[PremiumResolver] database cache hit {} -> {} (UUID: {})",
                        trimmed, result.status(), premiumUuid.getUuid());
            }
            return result;
        }

        // 3. Cache miss - wywołaj API
        return resolveFromApi(trimmed, cacheKey);
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
                logger.debug("[PremiumResolver] username mismatch {} vs {} from {}", canonical, requestName, source);
            }
            return PremiumResolution.offline(requestName, source, "username mismatch with canonical name");
        }
        return PremiumResolution.premium(resolution.uuid(), canonical, source);
    }

    private PremiumResolution getFromCache(String key) {
        CachedEntry entry = cache.get(key);
        if (entry == null) {
            return null;
        }
        if (entry.isExpired(premiumTtlMillis, missTtlMillis)) {
            cache.remove(key);
            return null;
        }
        return entry.resolution();
    }

    private void cacheResult(String key, PremiumResolution resolution) {
        long ttl = resolution.isPremium() ? premiumTtlMillis : missTtlMillis;
        if (ttl <= 0L) {
            cache.remove(key);
            return;
        }

        // Check cache size and implement LRU eviction if needed
        // Using ReentrantLock prevents virtual thread pinning (Java 21)
        cacheSizeLock.lock();
        try {
            if (cache.size() >= maxCacheSize) {
                // Remove oldest entries (simple LRU - remove first 10% of entries)
                int entriesToRemove = Math.max(1, maxCacheSize / 10);
                cache.entrySet().stream()
                        .sorted((e1, e2) -> Long.compare(e1.getValue().timestamp(), e2.getValue().timestamp()))
                        .limit(entriesToRemove)
                        .forEach(entry -> cache.remove(entry.getKey()));

                if (logger.isDebugEnabled()) {
                    logger.debug("[PremiumResolver] Cache eviction: removed {} entries, new size: {}",
                            entriesToRemove, cache.size());
                }
            }

            cache.put(key, new CachedEntry(resolution, System.currentTimeMillis()));
        } finally {
            cacheSizeLock.unlock();
        }
    }

    private record CachedEntry(PremiumResolution resolution, long timestamp) {
        boolean isExpired(long premiumTtlMillis, long missTtlMillis) {
            long ttl = resolution.isPremium() ? premiumTtlMillis : missTtlMillis;
            return ttl <= 0L || System.currentTimeMillis() - timestamp > ttl;
        }
    }
}
