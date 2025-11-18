package net.rafalohaki.veloauth.cache;

import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.CachedAuthUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Thread-safe cache autoryzacji dla VeloAuth.
 * Używa ConcurrentHashMap dla bezpiecznego dostępu wielowątkowego i ReentrantLock
 * dla operacji krytycznych zgodnie z wzorcami z Neo4j Memory.
 * <p>
 * Cache przechowuje:
 * - Autoryzowanych graczy (UUID -> CachedAuthUser)
 * - Próby brute force (IP -> liczba prób)
 * - Premium graczy (nickname -> premium status)
 * - Aktywne sesje (UUID -> ActiveSession)
 * <p>
 * UWAGA: 757 linii jest uzasadnione - zarządzanie 4 różnymi typami cache
 * z odrębnymi wymaganiami (różne TTL, harmonogramy czyszczenia, metryki)
 * wymaga znaczącej ilości kodu. Nie jest to overengineering.
 */
public class AuthCache {

    private static final Logger logger = LoggerFactory.getLogger(AuthCache.class);
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    /**
     * Cache autoryzowanych graczy - ZAWSZE ConcurrentHashMap dla thread-safety.
     */
    private final ConcurrentHashMap<UUID, CachedAuthUser> authorizedPlayers;

    /**
     * Cache prób brute force - ZAWSZE ConcurrentHashMap.
     */
    private final ConcurrentHashMap<InetAddress, BruteForceEntry> bruteForceAttempts;

    /**
     * Cache premium graczy - ZAWSZE ConcurrentHashMap.
     */
    private final ConcurrentHashMap<String, PremiumCacheEntry> premiumCache;

    /**
     * Aktywne sesje graczy - zapobiega session hijacking.
     */
    private final ConcurrentHashMap<UUID, ActiveSession> activeSessions;

    /**
     * Lock dla operacji krytycznych - używaj ReentrantLock zamiast synchronized.
     */
    private final ReentrantLock cacheLock;

    /**
     * TTL cache w minutach.
     */
    private final int ttlMinutes;

    /**
     * Maksymalny rozmiar cache.
     */
    private final int maxSize;

    /**
     * Maksymalna liczba aktywnych sesji.
     */
    private final int maxSessions;

    /**
     * Maksymalny rozmiar premium cache.
     */
    private final int maxPremiumCache;

    /**
     * Maksymalna liczba prób logowania.
     */
    private final int maxLoginAttempts;

    /**
     * Timeout brute force w minutach.
     */
    private final int bruteForceTimeoutMinutes;

    /**
     * Scheduler dla czyszczenia cache.
     */
    private final ScheduledExecutorService cleanupScheduler;

    /**
     * Scheduler dla logowania metryk cache.
     */
    private final ScheduledExecutorService metricsScheduler;

    /**
     * Metryki cache - thread-safe AtomicLong dla atomowych operacji.
     */
    private final AtomicLong cacheHits = new AtomicLong(0);
    private final AtomicLong cacheMisses = new AtomicLong(0);

    /**
     * Settings dla konfiguracji debug mode.
     */
    private final Settings settings;
    /**
     * System wiadomości i18n.
     */
    private final Messages messages;

    /**
     * Tworzy nowy AuthCache.
     *
     * @param ttlMinutes               TTL cache w minutach
     * @param maxSize                  Maksymalny rozmiar cache
     * @param maxSessions              Maksymalna liczba aktywnych sesji
     * @param maxPremiumCache          Maksymalny rozmiar premium cache
     * @param maxLoginAttempts         Maksymalna liczba prób logowania
     * @param bruteForceTimeoutMinutes Timeout brute force w minutach
     * @param cleanupIntervalMinutes   Interwał czyszczenia cache w minutach
     * @param settings                 Ustawienia pluginu
     * @param messages                 System wiadomości i18n
     */
    @SuppressWarnings("java:S107") // SonarCloud false positive: all 9 parameters required for cache configuration
    public AuthCache(int ttlMinutes, int maxSize, int maxSessions, int maxPremiumCache,
                     int maxLoginAttempts, int bruteForceTimeoutMinutes, int cleanupIntervalMinutes,
                     Settings settings, Messages messages) {

        if (ttlMinutes < 0) {
            throw new IllegalArgumentException(messages.get("validation.ttl.negative"));
        }
        if (maxSize <= 0) {
            throw new IllegalArgumentException(messages.get("validation.maxsize.gt_zero"));
        }
        if (maxSessions <= 0) {
            throw new IllegalArgumentException(messages.get("validation.maxsessions.gt_zero"));
        }
        if (maxPremiumCache <= 0) {
            throw new IllegalArgumentException(messages.get("validation.maxpremiumcache.gt_zero"));
        }
        if (maxLoginAttempts <= 0) {
            throw new IllegalArgumentException(messages.get("validation.maxloginattempts.gt_zero"));
        }
        if (bruteForceTimeoutMinutes <= 0) {
            throw new IllegalArgumentException(messages.get("validation.bruteforcetimeout.gt_zero"));
        }

        this.ttlMinutes = ttlMinutes;
        this.maxSize = maxSize;
        this.maxSessions = maxSessions;
        this.maxPremiumCache = maxPremiumCache;
        this.maxLoginAttempts = maxLoginAttempts;
        this.bruteForceTimeoutMinutes = bruteForceTimeoutMinutes;
        this.settings = settings;
        this.messages = messages;

        // ZAWSZE ConcurrentHashMap dla thread-safety
        this.authorizedPlayers = new ConcurrentHashMap<>();
        this.bruteForceAttempts = new ConcurrentHashMap<>();
        this.premiumCache = new ConcurrentHashMap<>();
        this.activeSessions = new ConcurrentHashMap<>();

        // ReentrantLock zamiast synchronized (nie pina virtual threads)
        this.cacheLock = new ReentrantLock();

        // Scheduler dla automatycznego czyszczenia
        this.cleanupScheduler = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "AuthCache-Cleanup");
            t.setDaemon(true);
            return t;
        });

        // Scheduler dla logowania metryk cache
        this.metricsScheduler = Executors.newScheduledThreadPool(1, r -> {
            Thread t = new Thread(r, "AuthCache-Metrics");
            t.setDaemon(true);
            return t;
        });

        // Uruchom czyszczenie co określony interwał
        if (cleanupIntervalMinutes > 0) {
            // skipcq: JAVA-W1087 - Periodic scheduled task, fire-and-forget
            cleanupScheduler.scheduleAtFixedRate(
                    this::cleanupExpiredEntries,
                    cleanupIntervalMinutes,
                    cleanupIntervalMinutes,
                    TimeUnit.MINUTES
            );
        }

        // Loguj metryki co 5 minut
        // skipcq: JAVA-W1087 - Periodic scheduled task, fire-and-forget
        metricsScheduler.scheduleAtFixedRate(
                this::logCacheMetrics,
                5, 5, TimeUnit.MINUTES
        );

        logger.info(messages.get("cache.auth.created"),
                ttlMinutes, maxSize, maxLoginAttempts, bruteForceTimeoutMinutes);
    }

    /**
     * Dodaje autoryzowanego gracza do cache.
     *
     * @param uuid UUID gracza
     * @param user Dane gracza
     */
    public void addAuthorizedPlayer(UUID uuid, CachedAuthUser user) {
        if (uuid == null || user == null) {
            throw new IllegalArgumentException("UUID i user nie mogą być null");
        }

        try {
            cacheLock.lock();
            try {
                // Sprawdź limit rozmiaru cache
                if (authorizedPlayers.size() >= maxSize && !authorizedPlayers.containsKey(uuid)) {
                    // Usuń najstarszy wpis
                    removeOldestAuthorizedPlayer();
                }

                authorizedPlayers.put(uuid, user);
                if (logger.isDebugEnabled()) {
                    logger.debug(messages.get("cache.debug.auth.added"),
                            user.getNickname(), uuid);
                }

            } finally {
                cacheLock.unlock();
            }

        } catch (IllegalStateException e) {
            logger.error(messages.get("cache.error.state.add_player") + uuid, e);
        }
    }

    /**
     * Pobiera autoryzowanego gracza z cache.
     *
     * @param uuid UUID gracza
     * @return CachedAuthUser lub null jeśli nie znaleziono lub wygasł
     */
    public CachedAuthUser getAuthorizedPlayer(UUID uuid) {
        if (uuid == null) {
            return null;
        }

        CachedAuthUser user = authorizedPlayers.get(uuid);
        if (user == null) {
            cacheMisses.incrementAndGet();
            double rate = (double) cacheHits.get() / Math.max(1, cacheHits.get() + cacheMisses.get()) * 100;
            String rateStr = String.format(java.util.Locale.US, "%.1f", rate);
            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.debug.uuid.miss"),
                        uuid, rateStr);
            }
            return null;
        }

        // Sprawdź TTL
        if (!user.isValid(ttlMinutes)) {
            removeAuthorizedPlayer(uuid);
            cacheMisses.incrementAndGet();
            double rate = (double) cacheHits.get() / Math.max(1, cacheHits.get() + cacheMisses.get()) * 100;
            String rateStr = String.format(java.util.Locale.US, "%.1f", rate);
            if (logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.debug.uuid.expired"),
                        uuid, rateStr);
            }
            return null;
        }

        cacheHits.incrementAndGet();
        double rate = (double) cacheHits.get() / Math.max(1, cacheHits.get() + cacheMisses.get()) * 100;
        String rateStr = String.format(java.util.Locale.US, "%.1f", rate);
        if (logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.hit.rate"), rateStr);
        }
        return user;
    }

    /**
     * Usuwa autoryzowanego gracza z cache.
     *
     * @param uuid UUID gracza
     */
    public void removeAuthorizedPlayer(UUID uuid) {
        if (uuid != null) {
            CachedAuthUser removed = authorizedPlayers.remove(uuid);
            if (removed != null) {
                if (logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.debug.player.removed"),
                        removed.getNickname(), uuid);
            }
            }
        }
    }

    /**
     * Sprawdza czy gracz jest autoryzowany i IP się zgadza.
     *
     * @param uuid      UUID gracza
     * @param currentIp Aktualny IP gracza
     * @return true jeśli autoryzowany i IP się zgadza
     */
    public boolean isPlayerAuthorized(UUID uuid, String currentIp) {
        CachedAuthUser user = getAuthorizedPlayer(uuid);
        if (user == null) {
            return false;
        }

        return user.matchesIp(currentIp);
    }

    /**
     * Usuwa gracza premium z cache.
     * Używane przy zmianie hasła lub usunięciu konta premium.
     *
     * @param nickname Nickname gracza (case-insensitive)
     */
    public void removePremiumPlayer(String nickname) {
        if (nickname == null || nickname.isEmpty()) {
            return;
        }

        PremiumCacheEntry removed = premiumCache.remove(nickname.toLowerCase());
        if (removed != null) {
            if (logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.premium.removed"),
                    nickname, removed.isPremium());
        }
        }
    }

    /**
     * Dodaje gracza premium do cache.
     * Używane po weryfikacji premium status z Mojang API.
     *
     * @param nickname    Nickname gracza (case-insensitive)
     * @param premiumUuid Premium UUID gracza lub null jeśli nie premium
     */
    public void addPremiumPlayer(String nickname, UUID premiumUuid) {
        if (nickname == null || nickname.isEmpty()) {
            return;
        }

        try {
            cacheLock.lock();
            try {
                // Sprawdź limit rozmiaru premium cache
                if (premiumCache.size() >= maxPremiumCache && !premiumCache.containsKey(nickname.toLowerCase())) {
                    // Usuń najstarszy wpis premium
                    removeOldestPremiumEntry();
                }

                PremiumCacheEntry entry = new PremiumCacheEntry(premiumUuid != null, premiumUuid);
                premiumCache.put(nickname.toLowerCase(), entry);

                if (logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.debug.premium.added"),
                        nickname, premiumUuid != null);
            }

            } finally {
                cacheLock.unlock();
            }

        } catch (IllegalStateException e) {
            logger.error(messages.get("cache.error.state.add_premium") + nickname, e);
        }
    }

    /**
     * Rejestruje nieudaną próbę logowania.
     *
     * @param address IP adres
     * @return true jeśli przekroczono limit prób
     */
    public boolean registerFailedLogin(InetAddress address) {
        if (address == null) {
            return false;
        }

        try {
            cacheLock.lock();
            try {
                BruteForceEntry entry = bruteForceAttempts.computeIfAbsent(
                        address,
                        k -> new BruteForceEntry()
                );

                // Sprawdź czy timeout już minął
                if (entry.isExpired(bruteForceTimeoutMinutes)) {
                    entry.reset();
                }

                entry.incrementAttempts();

                boolean blocked = entry.getAttempts() >= maxLoginAttempts;
                if (blocked) {
                    logger.warn(messages.get("cache.warn.ip.blocked"),
                            address.getHostAddress(), entry.getAttempts());
                } else {
                    if (logger.isDebugEnabled()) {
                        logger.debug(messages.get("cache.debug.failed.login"),
                                address.getHostAddress(), entry.getAttempts(), maxLoginAttempts);
                    }
                }

                return blocked;

            } finally {
                cacheLock.unlock();
            }

        } catch (IllegalStateException e) {
            logger.error(messages.get("cache.error.state.register_failed") + address, e);
            return false;
        } catch (IllegalArgumentException e) {
            logger.error(messages.get("cache.error.args.register_failed") + address, e);
            return false;
        }
    }

    /**
     * Sprawdza czy IP jest zablokowany za brute force.
     *
     * @param address IP adres
     * @return true jeśli zablokowany
     */
    public boolean isBlocked(InetAddress address) {
        if (address == null) {
            return false;
        }

        BruteForceEntry entry = bruteForceAttempts.get(address);
        if (entry == null) {
            return false;
        }

        // Sprawdź czy timeout już minął
        if (entry.isExpired(bruteForceTimeoutMinutes)) {
            bruteForceAttempts.remove(address);
            return false;
        }

        return entry.getAttempts() >= maxLoginAttempts;
    }

    /**
     * Resetuje próby logowania dla IP.
     *
     * @param address IP adres
     */
    public void resetLoginAttempts(InetAddress address) {
        if (address != null) {
            BruteForceEntry removed = bruteForceAttempts.remove(address);
            if (removed != null) {
                if (logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.debug.reset.attempts"), address.getHostAddress());
            }
            }
        }
    }

    /**
     * Sprawdza czy gracz ma premium (z cache).
     *
     * @param nickname Nickname gracza
     * @return PremiumCacheEntry lub null jeśli nie w cache lub wygasł
     */
    public PremiumCacheEntry getPremiumStatus(String nickname) {
        if (nickname == null || nickname.isEmpty()) {
            return null;
        }

        PremiumCacheEntry entry = premiumCache.get(nickname.toLowerCase());
        if (entry == null) {
            return null;
        }

        // Premium cache ma TTL 24h
        if (entry.isExpired(24 * 60)) {
            premiumCache.remove(nickname.toLowerCase());
            return null;
        }

        return entry;
    }

    /**
     * Czyści wszystkie cache.
     */
    public void clearAll() {
        try {
            cacheLock.lock();
            try {
                authorizedPlayers.clear();
                bruteForceAttempts.clear();
                premiumCache.clear();
                activeSessions.clear();
                logger.info(messages.get("cache.all_cleared"));

            } finally {
                cacheLock.unlock();
            }

        } catch (IllegalStateException e) {
            logger.error(messages.get("cache.error.state.clear"), e);
        }
    }

    /**
     * Rozpoczyna aktywną sesję gracza - zapobiega session hijacking.
     */
    public void startSession(UUID uuid, String nickname, String ip) {
        if (uuid == null || nickname == null) {
            return;
        }

        try {
            cacheLock.lock();
            try {
                // Sprawdź limit rozmiaru sesji
                if (activeSessions.size() >= maxSessions && !activeSessions.containsKey(uuid)) {
                    // Usuń najstarszą sesję
                    removeOldestSession();
                }

                ActiveSession session = new ActiveSession(uuid, nickname, ip);
                activeSessions.put(uuid, session);
                if (logger.isDebugEnabled()) {
                logger.debug(messages.get("cache.debug.session.started"), nickname, uuid, ip);
            }

            } finally {
                cacheLock.unlock();
            }

        } catch (IllegalStateException e) {
            logger.error(messages.get("cache.error.state.start_session") + uuid, e);
        }
    }

    /**
     * Kończy aktywną sesję gracza (wylogowanie/disconnect).
     */
    public void endSession(UUID uuid) {
        if (uuid == null) {
            return;
        }

        ActiveSession removed = activeSessions.remove(uuid);
        if (removed != null) {
            if (logger.isDebugEnabled()) {
            logger.debug(messages.get("cache.debug.session.ended"), removed.getNickname(), uuid);
        }
        }
    }

    /**
     * Sprawdza czy gracz ma aktywną sesję z weryfikacją nickname i IP.
     * Zapobiega session hijacking przez zmianę nicku lub IP.
     */
    public boolean hasActiveSession(UUID uuid, String nickname, String currentIp) {
        if (uuid == null || nickname == null || currentIp == null) {
            return false;
        }

        ActiveSession session = activeSessions.get(uuid);
        if (session == null) {
            return false; // Brak sesji
        }

        // KLUCZOWE: Sprawdź czy nickname się zgadza
        if (!session.getNickname().equalsIgnoreCase(nickname)) {
            logger.warn(SECURITY_MARKER,
                    messages.get("security.session.hijack"),
                    uuid, session.getNickname(), nickname);

            // Usuń podejrzaną sesję
            activeSessions.remove(uuid);
            return false;
        }

        // NOWE: Sprawdź czy IP się zgadza
        if (!session.getIp().equals(currentIp)) {
            logger.warn(SECURITY_MARKER, messages.get("security.session.ip.mismatch"),
                    uuid, session.getIp(), currentIp);
            activeSessions.remove(uuid);
            return false;
        }

        // Sesja OK - aktualizuj aktywność
        session.updateActivity();
        return true;
    }

    /**
     * Logs cache metrics for monitoring.
     * Uses debug level for detailed diagnostics in development mode.
     */
    private void logCacheMetrics() {
        try {
            // Only log metrics if debug mode is enabled
            if (!settings.isDebugEnabled()) {
                return;
            }

            CacheStats stats = getStats();
            double hitRate = stats.getHitRate();
            long totalRequests = stats.getTotalRequests();

            // Log comprehensive metrics at debug level
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

            // Performance warnings still use info level as they're important
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

    /**
     * Czyści wygasłe wpisy z cache.
     */
    public void cleanupExpiredEntries() {
        try {
            cacheLock.lock();
            try {
                int removedAuth = cleanupCache(authorizedPlayers,
                        entry -> !entry.getValue().isValid(ttlMinutes));
                int removedBrute = cleanupCache(bruteForceAttempts,
                        entry -> entry.getValue().isExpired(bruteForceTimeoutMinutes));
                int removedPremium = cleanupCache(premiumCache,
                        entry -> entry.getValue().isExpired(24 * 60));
                int removedSessions = cleanupCache(activeSessions,
                        entry -> !entry.getValue().isActive(60));

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

    /**
     * Generic method to clean up cache entries based on a predicate.
     *
     * @param cache        The cache map to clean
     * @param shouldRemove Predicate to determine if entry should be removed
     * @param <K>          Key type
     * @param <V>          Value type
     * @return Number of removed entries
     */
    private <K, V> int cleanupCache(java.util.Map<K, V> cache,
                                    java.util.function.Predicate<java.util.Map.Entry<K, V>> shouldRemove) {
        int removed = 0;
        var iterator = cache.entrySet().iterator();
        while (iterator.hasNext()) {
            var entry = iterator.next();
            if (shouldRemove.test(entry)) {
                iterator.remove();
                removed++;
            }
        }
        return removed;
    }

    /**
     * Czyści wygasłe wpisy z cache.
     * Usuwa najstarszy wpis autoryzacji.
     */
    private void removeOldestAuthorizedPlayer() {
        if (authorizedPlayers.isEmpty()) {
            return;
        }

        // Znajdź najstarszy wpis
        UUID oldestUuid = null;
        long oldestTime = Long.MAX_VALUE;

        for (Map.Entry<UUID, CachedAuthUser> entry : authorizedPlayers.entrySet()) {
            long cacheTime = entry.getValue().getCacheTime();
            if (cacheTime < oldestTime) {
                oldestTime = cacheTime;
                oldestUuid = entry.getKey();
            }
        }

        if (oldestUuid != null) {
            CachedAuthUser removed = authorizedPlayers.remove(oldestUuid);
            if (removed != null) {
                logger.debug("Usunięto najstarszy wpis cache: {} (UUID: {})",
                        removed.getNickname(), oldestUuid);
            }
        }
    }

    /**
     * Usuwa najstarszą aktywną sesję przy przekroczeniu limitu.
     */
    private void removeOldestSession() {
        if (activeSessions.isEmpty()) {
            return;
        }

        // Znajdź najstarszą sesję
        UUID oldestUuid = null;
        long oldestTime = Long.MAX_VALUE;

        for (Map.Entry<UUID, ActiveSession> entry : activeSessions.entrySet()) {
            long sessionTime = entry.getValue().getSessionStartTime();
            if (sessionTime < oldestTime) {
                oldestTime = sessionTime;
                oldestUuid = entry.getKey();
            }
        }

        if (oldestUuid != null) {
            ActiveSession removed = activeSessions.remove(oldestUuid);
            if (removed != null) {
                logger.debug("Usunięto najstarszą sesję: {} (UUID: {})",
                        removed.getNickname(), oldestUuid);
            }
        }
    }

    /**
     * Usuwa najstarszy wpis premium cache przy przekroczeniu limitu.
     */
    private void removeOldestPremiumEntry() {
        if (premiumCache.isEmpty()) {
            return;
        }

        // Znajdź najstarszy wpis premium
        String oldestNickname = null;
        long oldestTime = Long.MAX_VALUE;

        for (Map.Entry<String, PremiumCacheEntry> entry : premiumCache.entrySet()) {
            long cacheTime = entry.getValue().getCacheTime();
            if (cacheTime < oldestTime) {
                oldestTime = cacheTime;
                oldestNickname = entry.getKey();
            }
        }

        if (oldestNickname != null) {
            PremiumCacheEntry removed = premiumCache.remove(oldestNickname);
            if (removed != null) {
                logger.debug("Usunięto najstarszy wpis premium cache: {}", oldestNickname);
            }
        }
    }

    /**
     * Zamyka AuthCache i schedulery.
     */
    public void shutdown() {
        try {
            // Loguj finalne statystyki cache
            if (cacheHits.get() + cacheMisses.get() > 0) {
                double rate = (double) cacheHits.get() / (cacheHits.get() + cacheMisses.get()) * 100;
                String rateStr = String.format(java.util.Locale.US, "%.1f", rate);
                logger.info(messages.get("cache.stats_final"),
                        cacheHits.get(), cacheMisses.get(), rateStr);
            }

            // Zamknij cleanup scheduler
            cleanupScheduler.shutdown();
            if (!cleanupScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                cleanupScheduler.shutdownNow();
            }

            // Zamknij metrics scheduler
            metricsScheduler.shutdown();
            if (!metricsScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                metricsScheduler.shutdownNow();
            }

            clearAll();
            logger.info(messages.get("cache.shutdown"));

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            cleanupScheduler.shutdownNow();
            metricsScheduler.shutdownNow();
            logger.warn(messages.get("cache.interrupted_shutdown"));
        }
    }

    /**
     * Zwraca statystyki cache.
     *
     * @return CacheStats z metrykami HIT/MISS
     */
    public CacheStats getStats() {
        return new CacheStats(
                authorizedPlayers.size(),
                bruteForceAttempts.size(),
                premiumCache.size(),
                cacheHits.get(),
                cacheMisses.get(),
                maxSize,
                ttlMinutes
        );
    }

    /**
     * Statystyki cache z metrykami wydajności.
     */
    public record CacheStats(
            int authorizedPlayersCount,
            int bruteForceEntriesCount,
            int premiumCacheCount,
            long cacheHits,
            long cacheMisses,
            int maxSize,
            int ttlMinutes
    ) {
        /**
         * Oblicza hit rate cache.
         *
         * @return Hit rate w procentach (0-100)
         */
        public double getHitRate() {
            long total = cacheHits + cacheMisses;
            return total == 0 ? 0 : (double) cacheHits / total * 100;
        }

        /**
         * Zwraca całkowitą liczbę zapytań do cache.
         *
         * @return Suma HIT + MISS
         */
        public long getTotalRequests() {
            return cacheHits + cacheMisses;
        }
    }

    /**
     * Wpis brute force.
     */
    private static class BruteForceEntry {
        private int attempts = 0;
        private long firstAttemptTime = System.currentTimeMillis();

        public void incrementAttempts() {
            attempts++;
        }

        public int getAttempts() {
            return attempts;
        }

        public void reset() {
            attempts = 0;
            firstAttemptTime = System.currentTimeMillis();
        }

        public boolean isExpired(int timeoutMinutes) {
            long timeoutMillis = timeoutMinutes * 60L * 1000L;
            return (System.currentTimeMillis() - firstAttemptTime) > timeoutMillis;
        }
    }

    /**
     * Wpis premium cache.
     */
    public static class PremiumCacheEntry {
        private final boolean isPremium;
        private final UUID premiumUuid;
        private final long cacheTime;

        public PremiumCacheEntry(boolean isPremium, UUID premiumUuid) {
            this.isPremium = isPremium;
            this.premiumUuid = premiumUuid;
            this.cacheTime = System.currentTimeMillis();
        }

        public boolean isPremium() {
            return isPremium;
        }

        public UUID getPremiumUuid() {
            return premiumUuid;
        }

        public long getCacheTime() {
            return cacheTime;
        }

        public boolean isExpired(int ttlMinutes) {
            long ttlMillis = ttlMinutes * 60L * 1000L;
            return (System.currentTimeMillis() - cacheTime) > ttlMillis;
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

        /**
         * Sprawdza czy sesja jest aktywna (gracz online).
         */
        public boolean isActive(long timeoutMinutes) {
            long timeoutMillis = timeoutMinutes * 60L * 1000L;
            return (System.currentTimeMillis() - lastActivityTime) < timeoutMillis;
        }

        public void updateActivity() {
            this.lastActivityTime = System.currentTimeMillis();
        }

        public UUID getUuid() {
            return uuid;
        }

        public String getNickname() {
            return nickname;
        }

        public String getIp() {
            return ip;
        }

        public long getSessionStartTime() {
            return sessionStartTime;
        }

        public long getLastActivityTime() {
            return lastActivityTime;
        }
    }
}
