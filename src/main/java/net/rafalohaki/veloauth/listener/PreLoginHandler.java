package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.connection.PreLoginEvent;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.cache.AuthCache.PremiumCacheEntry;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.premium.PremiumResolution;
import net.rafalohaki.veloauth.premium.PremiumResolverService;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
import org.slf4j.Logger;

import java.net.InetAddress;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * Handles pre-login validation and conflict detection logic.
 * Extracted from AuthListener to reduce complexity and improve testability.
 */
public class PreLoginHandler {

    private final AuthCache authCache;
    private final PremiumResolverService premiumResolverService;
    private final DatabaseManager databaseManager;
    private final Messages messages;
    private final Logger logger;

    /**
     * Creates a new PreLoginHandler.
     *
     * @param authCache              Cache for authorization and premium status
     * @param premiumResolverService Service for resolving premium status
     * @param databaseManager        Manager for database operations
     * @param messages               i18n message system
     * @param logger                 Logger instance
     */
    public PreLoginHandler(AuthCache authCache,
                          PremiumResolverService premiumResolverService,
                          DatabaseManager databaseManager,
                          Messages messages,
                          Logger logger) {
        this.authCache = authCache;
        this.premiumResolverService = premiumResolverService;
        this.databaseManager = databaseManager;
        this.messages = messages;
        this.logger = logger;
    }

    /**
     * Validates username format (3-16 chars, alphanumeric + underscore).
     *
     * @param username Username to validate
     * @return true if valid, false otherwise
     */
    public boolean isValidUsername(String username) {
        if (username == null || username.isEmpty()) {
            return false;
        }

        // Minecraft username limit: 3-16 characters
        if (username.length() < 3 || username.length() > 16) {
            return false;
        }

        // Minecraft usernames: letters, numbers, underscore
        for (int i = 0; i < username.length(); i++) {
            char c = username.charAt(i);
            if (!Character.isLetterOrDigit(c) && c != '_') {
                return false;
            }
        }

        return true;
    }

    /**
     * Checks if IP address is blocked due to brute force attempts.
     *
     * @param address IP address to check
     * @return true if blocked, false otherwise
     */
    public boolean isBruteForceBlocked(InetAddress address) {
        if (address == null) {
            return false;
        }
        return authCache.isBlocked(address);
    }

    /**
     * Resolves premium status with caching, TTL, and background refresh (stale-while-revalidate).
     *
     * @param username Username to check
     * @return PremiumResolutionResult with status and UUID
     */
    public PremiumResolutionResult resolvePremiumStatus(String username) {
        PremiumCacheEntry cachedStatus = authCache.getPremiumStatus(username);
        if (cachedStatus != null) {
            logger.debug("Premium cache hit dla {} -> {} (age: {}ms, TTL: {}ms)", 
                    username, cachedStatus.isPremium(), cachedStatus.getAgeMillis(), cachedStatus.getTtlMillis());
            
            // Background refresh if stale (but still use cached value - stale-while-revalidate)
            if (cachedStatus.isStale()) {
                triggerBackgroundRefresh(username);
            }
            
            return new PremiumResolutionResult(cachedStatus.isPremium(), cachedStatus.getPremiumUuid());
        }

        // Cache miss - synchronous resolution
        PremiumResolution resolution = resolveViaServiceWithTimeout(username);
        return cacheFromResolution(username, resolution);
    }

    /**
     * Triggers asynchronous background refresh of premium status.
     * Uses stale-while-revalidate pattern to avoid blocking current request.
     *
     * @param username Username to refresh
     */
    private void triggerBackgroundRefresh(String username) {
        boolean submitted = VirtualThreadExecutorProvider.submitTask(() -> {
            logger.debug("Background refresh of premium status for {}", username);
            try {
                PremiumResolution resolution = premiumResolverService.resolve(username);
                cacheFromResolution(username, resolution);
                logger.debug("Background refresh completed for {}", username);
            } catch (Exception e) {
                logger.warn("Background refresh failed for {}: {}", username, e.getMessage());
            }
        });

        if (!submitted) {
            logger.warn("Failed to trigger background refresh for {} - executor is shutting down", username);
        }
    }

    /**
     * Checks for nickname conflicts between premium and offline players.
     *
     * @param existingPlayer    Existing player in database
     * @param isPremium         Whether current player is premium
     * @param existingIsPremium Whether existing player is premium (runtime detection)
     * @return true if conflict exists
     */
    public boolean isNicknameConflict(RegisteredPlayer existingPlayer, boolean isPremium, boolean existingIsPremium) {
        // Conflict scenarios:
        // 1. Premium player trying to use offline nickname
        // 2. Offline player trying to access account in conflict mode
        return (isPremium && !existingIsPremium) ||
                (!isPremium && existingPlayer.getConflictMode());
    }

    /**
     * Marks player as having nickname conflict (PMD CPD fix - extracted common logic).
     *
     * @param existingPlayer Existing player to mark
     * @param username Username for logging
     */
    private void markAsConflicted(RegisteredPlayer existingPlayer, String username) {
        if (!existingPlayer.getConflictMode()) {
            existingPlayer.setConflictMode(true);
            existingPlayer.setConflictTimestamp(System.currentTimeMillis());
            existingPlayer.setOriginalNickname(existingPlayer.getNickname());
            databaseManager.savePlayer(existingPlayer).join();
            logger.info("[NICKNAME CONFLICT] Premium player {} detected conflict with offline account", username);
        }
    }

    /**
     * Handles nickname conflict by forcing offline mode and tracking conflict.
     *
     * @param event          PreLoginEvent
     * @param existingPlayer Existing player in database
     * @param isPremium      Whether current player is premium
     */
    public void handleNicknameConflict(PreLoginEvent event, RegisteredPlayer existingPlayer, boolean isPremium) {
        String username = event.getUsername();

        if (isPremium && existingPlayer.getPremiumUuid() == null) {
            // Premium player trying to use offline nickname
            markAsConflicted(existingPlayer, username);

            // Force offline mode for premium player
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());

        } else if (!isPremium && existingPlayer.getConflictMode()) {
            // Offline player accessing conflicted account
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());

            logger.debug("[NICKNAME CONFLICT] Offline player {} accessing conflicted account", username);
        }
    }

    public void handleNicknameConflictNoEvent(String username, RegisteredPlayer existingPlayer, boolean isPremium) {
        if (isPremium && existingPlayer.getPremiumUuid() == null) {
            markAsConflicted(existingPlayer, username);
        } else if (!isPremium && existingPlayer.getConflictMode()) {
            logger.debug("[NICKNAME CONFLICT] Offline player {} accessing conflicted account", username);
        }
    }

    /**
     * Resolves premium status via service with timeout.
     *
     * @param username Username to resolve
     * @return PremiumResolution result
     */
    private PremiumResolution resolveViaServiceWithTimeout(String username) {
        try {
            return CompletableFuture.supplyAsync(() -> premiumResolverService.resolve(username))
                    .orTimeout(3, TimeUnit.SECONDS)
                    .exceptionally(throwable -> PremiumResolution.offline(username, "VeloAuth-Timeout",
                            "Timeout - fallback to offline"))
                    .join();
        } catch (Exception e) {
            return PremiumResolution.offline(username, "VeloAuth-Error", "Error - fallback to offline");
        }
    }

    /**
     * Caches premium resolution result.
     *
     * @param username   Username
     * @param resolution Resolution result
     * @return PremiumResolutionResult with status and UUID
     */
    private PremiumResolutionResult cacheFromResolution(String username, PremiumResolution resolution) {
        if (resolution.isPremium()) {
            UUID premiumUuid = resolution.uuid();
            String canonical = resolution.canonicalUsername() != null ? resolution.canonicalUsername() : username;
            authCache.addPremiumPlayer(canonical, premiumUuid);
            if (logger.isInfoEnabled()) {
                logger.info(messages.get("player.premium.confirmed"), username, resolution.source(), premiumUuid);
            }
            return new PremiumResolutionResult(true, premiumUuid);
        }
        if (resolution.isOffline()) {
            authCache.addPremiumPlayer(username, null);
            logger.debug("{} nie jest premium (resolver: {}, info: {})", username, resolution.source(),
                    resolution.message());
            return new PremiumResolutionResult(false, null);
        }
        logger.warn("⚠️ Nie udało się jednoznacznie potwierdzić statusu premium dla {} (resolver: {}, info: {})",
                username, resolution.source(), resolution.message());
        return new PremiumResolutionResult(false, null);
    }

    /**
     * Simple data holder for premium resolution results using Java 21 record.
     */
    public record PremiumResolutionResult(boolean premium, UUID premiumUuid) {
    }
}
