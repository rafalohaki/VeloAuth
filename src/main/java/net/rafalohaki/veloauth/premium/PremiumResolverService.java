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
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
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

    /** Resolver ID treated as authoritative for OFFLINE classification. Must match
     *  {@link ResolverConfig#MOJANG}{@code .id()} — that resolver is the single source of
     *  truth for "this name exists / does not exist as a premium account". Other resolvers
     *  (Ashcon, wpme) are mirrors and can be stale or partial, so their OFFLINE alone is
     *  weaker evidence. See {@link #selectBestResult} for the decision rule. */
    static final String AUTHORITATIVE_RESOLVER_ID = "mojang";

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
        ConcurrentHashMap<String, PremiumResolution> byResolver = new ConcurrentHashMap<>();

        List<CompletableFuture<Void>> futures = enabledResolvers.stream()
                .map(resolver -> createResolverFuture(resolver, trimmed, byResolver))
                .toList();

        awaitResolverFutures(futures);
        return new ResolverResults(Map.copyOf(byResolver));
    }

    private CompletableFuture<Void> createResolverFuture(
            PremiumResolver resolver, String trimmed,
            ConcurrentHashMap<String, PremiumResolution> byResolver) {
        return CompletableFuture.runAsync(
                () -> {
                    PremiumResolution resolution = executeResolver(resolver, trimmed);
                    byResolver.put(resolver.id(), resolution);
                },
                net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider.getVirtualExecutor()
        );
    }

    private PremiumResolution executeResolver(PremiumResolver resolver, String trimmed) {
        try {
            PremiumResolution rawResolution = resolver.resolve(trimmed);
            PremiumResolution resolution = normalizeResolution(resolver, rawResolution, trimmed);
            logResolution(resolver, trimmed, resolution);
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

    private void logResolution(PremiumResolver resolver, String trimmed, PremiumResolution resolution) {
        if (!logger.isDebugEnabled()) {
            return;
        }
        if (resolution.isPremium()) {
            logger.debug(PREMIUM_MARKER, "[PARALLEL] {} returned PREMIUM for {}", resolver.id(), trimmed);
        } else if (resolution.isOffline()) {
            logger.debug(PREMIUM_MARKER, "[PARALLEL] {} returned OFFLINE for {}", resolver.id(), trimmed);
        } else {
            logger.debug(PREMIUM_MARKER, "[PARALLEL] {} returned UNKNOWN for {}: {}",
                    resolver.id(), trimmed, resolution.message());
        }
    }

    private void logResolverFailure(PremiumResolver resolver, String trimmed, Exception e) {
        if (logger.isWarnEnabled()) {
            logger.warn(PREMIUM_MARKER, "[PARALLEL] {} failed for {}: {}", resolver.id(), trimmed, e.getMessage());
        }
    }

    private void awaitResolverFutures(List<CompletableFuture<Void>> futures) {
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

    /**
     * Picks the final answer from per-resolver results using a tiered trust policy.
     *
     * <h2>Decision rule (in order)</h2>
     * <ol>
     *   <li><b>PREMIUM answers</b> → all positive answers must agree on UUID. Mojang wins
     *       deterministically when present; conflicting UUIDs return UNKNOWN (fail-closed).</li>
     *   <li><b>Mojang OFFLINE</b> → trust immediately. Mojang is the authoritative source for
     *       "this name does not have a premium account"; other resolvers are mirrors.</li>
     *   <li><b>Mojang silent (UNKNOWN or disabled) + all non-Mojang enabled resolvers OFFLINE</b>
     *       → trust OFFLINE. Strong consensus from independent mirrors is treated as a quorum
     *       substitute for Mojang's word.</li>
     *   <li><b>Mojang silent + any non-Mojang UNKNOWN</b> → return UNKNOWN. Mixing OFFLINE with
     *       UNKNOWN from another mirror is insufficient evidence; the listener will deny the
     *       login (fail-closed). This is the case the previous "any OFFLINE wins" logic got
     *       wrong — it could classify a premium account as OFFLINE when Mojang timed out and
     *       Ashcon's mirror was stale, opening a name-sniping window.</li>
     *   <li><b>All resolvers UNKNOWN</b> → return UNKNOWN.</li>
     * </ol>
     */
    private PremiumResolution selectBestResult(ResolverResults results, String trimmed) {
        PremiumResolution premium = selectConsistentPremium(results, trimmed);
        if (premium != null) {
            if (premium.isUnknown()) {
                return premium;
            }
            if (logger.isInfoEnabled()) {
                logger.info(PREMIUM_MARKER, "[PARALLEL] Premium confirmed for {} from {}",
                        trimmed, premium.source());
            }
            return premium;
        }

        PremiumResolution mojang = results.byId(AUTHORITATIVE_RESOLVER_ID);
        if (mojang != null && mojang.isOffline()) {
            if (logger.isDebugEnabled()) {
                logger.debug(PREMIUM_MARKER,
                        "[PARALLEL] {} resolved as OFFLINE by authoritative resolver ({})",
                        trimmed, AUTHORITATIVE_RESOLVER_ID);
            }
            return mojang;
        }

        // Mojang silent (UNKNOWN or disabled). Quorum fallback: trust OFFLINE only if every
        // non-Mojang enabled resolver also said OFFLINE. Any UNKNOWN from a mirror voids the
        // quorum because a stale/down mirror cannot disprove premium status on its own.
        List<PremiumResolution> nonMojang = results.nonAuthoritativeResults();
        boolean haveQuorum = !nonMojang.isEmpty()
                && nonMojang.stream().allMatch(PremiumResolution::isOffline);
        if (haveQuorum) {
            PremiumResolution offline = nonMojang.get(0);
            if (logger.isDebugEnabled()) {
                logger.debug(PREMIUM_MARKER,
                        "[PARALLEL] {} resolved as OFFLINE by mirror quorum ({} resolvers agreed)",
                        trimmed, nonMojang.size());
            }
            return offline;
        }

        logQuorumFailure(results, trimmed);
        return PremiumResolution.unknown(RESOLVER_SERVICE,
                "no quorum: mojang=" + statusLabel(mojang)
                        + ", non-mojang=" + nonMojangSummary(nonMojang));
    }

    private PremiumResolution selectConsistentPremium(ResolverResults results, String trimmed) {
        List<PremiumResolution> premiumResults = results.premiumResultsByPriority();
        if (premiumResults.isEmpty()) {
            return null;
        }

        PremiumResolution selected = premiumResults.get(0);
        for (int i = 1; i < premiumResults.size(); i++) {
            PremiumResolution candidate = premiumResults.get(i);
            if (!selected.uuid().equals(candidate.uuid())) {
                logger.error(PREMIUM_MARKER,
                        "[PARALLEL] Conflicting premium UUIDs for {} from {} and {} - denying login",
                        trimmed, selected.source(), candidate.source());
                return PremiumResolution.unknown(RESOLVER_SERVICE,
                        "premium resolver UUID disagreement");
            }
        }
        return selected;
    }

    private void logQuorumFailure(ResolverResults results, String trimmed) {
        if (!logger.isWarnEnabled()) {
            return;
        }
        PremiumResolution mojang = results.byId(AUTHORITATIVE_RESOLVER_ID);
        List<PremiumResolution> nonMojang = results.nonAuthoritativeResults();
        logger.warn(PREMIUM_MARKER,
                "[PARALLEL] {} UNKNOWN: mojang={} non-mojang={} — login will be denied (fail-closed)",
                trimmed, statusLabel(mojang), nonMojangSummary(nonMojang));
    }

    private static String statusLabel(PremiumResolution resolution) {
        if (resolution == null) {
            return "absent";
        }
        if (resolution.isPremium()) {
            return "PREMIUM";
        }
        if (resolution.isOffline()) {
            return "OFFLINE";
        }
        return "UNKNOWN";
    }

    private static String nonMojangSummary(List<PremiumResolution> nonMojang) {
        if (nonMojang.isEmpty()) {
            return "[]";
        }
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < nonMojang.size(); i++) {
            PremiumResolution r = nonMojang.get(i);
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(r.source()).append('=').append(statusLabel(r));
        }
        return sb.append(']').toString();
    }

    /**
     * Per-resolver result bag returned by {@link #executeResolversInParallel}.
     * Keyed by {@link PremiumResolver#id()} so {@link #selectBestResult} can apply
     * resolver-specific trust (e.g. Mojang is authoritative for OFFLINE).
     */
    private record ResolverResults(Map<String, PremiumResolution> byResolver) {

        List<PremiumResolution> premiumResultsByPriority() {
            List<Map.Entry<String, PremiumResolution>> entries = byResolver.entrySet().stream()
                    .filter(entry -> entry.getValue() != null && entry.getValue().isPremium())
                    .sorted(Comparator
                            .comparing((Map.Entry<String, PremiumResolution> entry) ->
                                    !AUTHORITATIVE_RESOLVER_ID.equals(entry.getKey()))
                            .thenComparing(Map.Entry::getKey))
                    .toList();
            return entries.stream().map(Map.Entry::getValue).toList();
        }

        PremiumResolution byId(String id) {
            return byResolver.get(id);
        }

        List<PremiumResolution> nonAuthoritativeResults() {
            List<PremiumResolution> out = new ArrayList<>(byResolver.size());
            List<Map.Entry<String, PremiumResolution>> entries = byResolver.entrySet().stream()
                    .sorted(Map.Entry.comparingByKey())
                    .toList();
            for (Map.Entry<String, PremiumResolution> entry : entries) {
                if (!AUTHORITATIVE_RESOLVER_ID.equals(entry.getKey()) && entry.getValue() != null) {
                    out.add(entry.getValue());
                }
            }
            return out;
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
     * Entries without a positive verification timestamp are stale. LimboAuth premium
     * accounts are recovered from the authoritative AUTH table by PreLoginHandler;
     * PREMIUM_UUIDS is only a cache and must never manufacture migration authority.
     */
    private boolean isDbCacheEntryFresh(PremiumUuid entry) {
        long lastSeen = entry.getLastSeen();
        if (lastSeen <= 0L) {
            return false;
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
