package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.event.connection.PreLoginEvent;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.cache.AuthCache.PremiumCacheEntry;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.premium.PremiumResolution;
import net.rafalohaki.veloauth.premium.PremiumResolverService;
import net.rafalohaki.veloauth.util.VirtualThreadExecutorProvider;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.net.InetAddress;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static java.util.Objects.requireNonNull;

/**
 * Handles pre-login validation and conflict detection logic.
 * Extracted from AuthListener to reduce complexity and improve testability.
 */
public class PreLoginHandler {

    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final AuthCache authCache;
    private final PremiumResolverService premiumResolverService;
    private final DatabaseManager databaseManager;
    private final Messages messages;
    private final Logger logger;
    private final Settings settings;

    /**
     * Creates a new PreLoginHandler.
     *
     * @param authCache              Cache for authorization and premium status
     * @param premiumResolverService Service for resolving premium status
         * @param settings               Plugin configuration
     * @param databaseManager        Manager for database operations
     * @param messages               i18n message system
     * @param logger                 Logger instance
     */
    PreLoginHandler(AuthCache authCache,
                   PremiumResolverService premiumResolverService,
                   Settings settings,
                   DatabaseManager databaseManager,
                   Messages messages,
                   Logger logger) {
        this.authCache = requireNonNull(authCache, "authCache");
        this.premiumResolverService = requireNonNull(premiumResolverService, "premiumResolverService");
        this.settings = requireNonNull(settings, "settings");
        this.databaseManager = requireNonNull(databaseManager, "databaseManager");
        this.messages = requireNonNull(messages, "messages");
        this.logger = requireNonNull(logger, "logger");
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

        String validatedUsername = stripConfiguredFloodgatePrefix(username);

        // Minecraft username limit: 3-16 characters
        if (validatedUsername.length() < 3 || validatedUsername.length() > 16) {
            return false;
        }

        // Minecraft usernames: letters, numbers, underscore
        for (int i = 0; i < validatedUsername.length(); i++) {
            char c = validatedUsername.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')) {
                return false;
            }
        }

        return true;
    }

    private String stripConfiguredFloodgatePrefix(String username) {
        if (!settings.isFloodgateIntegrationEnabled()) {
            return username;
        }

        String prefix = settings.getFloodgateUsernamePrefix();
        if (prefix.isEmpty() || !username.startsWith(prefix)) {
            return username;
        }

        return username.substring(prefix.length());
    }

    /**
     * Checks if IP address or username is blocked due to brute force attempts.
     *
     * @param address  IP address to check
     * @param username Username to check (nullable)
     * @return true if blocked, false otherwise
     */
    public boolean isBruteForceBlocked(InetAddress address, String username) {
        if (address == null) {
            return true; // fail-secure: block when address is unknown
        }
        return authCache.isBlocked(address, username);
    }

    /**
     * Async version of resolvePremiumStatus — returns CompletableFuture to avoid blocking Netty IO thread.
     * On cache hit, returns immediately via completedFuture.
        * On cache miss, resolves via PremiumResolverService asynchronously.
     *
     * @param username Username to check
     * @return CompletableFuture with PremiumResolutionResult (may be null on UNKNOWN/API failure)
     */
    public CompletableFuture<PremiumResolutionResult> resolvePremiumStatusAsync(String username) {
        PremiumCacheEntry cachedStatus = authCache.getPremiumStatus(username);
        if (cachedStatus != null) {
            logger.debug("Premium cache hit for {} -> {} (age: {}ms, TTL: {}ms)",
                    username, cachedStatus.isPremium(), cachedStatus.getAgeMillis(), cachedStatus.getTtlMillis());

            if (cachedStatus.isStale()) {
                triggerBackgroundRefresh(username);
            }

            return CompletableFuture.completedFuture(
                    new PremiumResolutionResult(cachedStatus.isPremium(), cachedStatus.getPremiumUuid()));
        }

        // Cache miss — async resolution (does NOT block Netty IO thread)
        return CompletableFuture.supplyAsync(() -> premiumResolverService.resolve(username),
                        VirtualThreadExecutorProvider.getVirtualExecutor())
                .exceptionally(throwable -> {
                    logger.warn(SECURITY_MARKER, "Premium resolution failed for {} - denying login: {}",
                            username, describeThrowable(throwable));
                    return PremiumResolution.unknown("VeloAuth-Error",
                            "Exception during premium resolution: " + describeThrowable(throwable));
                })
                .thenApply(resolution -> cacheFromResolution(username, resolution));
    }

    private String describeThrowable(Throwable throwable) {
        if (throwable == null) {
            return "unknown cause";
        }

        String message = throwable.getMessage();
        if (message != null && !message.isBlank()) {
            return message;
        }

        return throwable.getClass().getSimpleName();
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
            } catch (RuntimeException e) {
                logger.warn("Background refresh failed for {}: {}", username, e.getMessage());
            }
        });

        if (!submitted) {
            logger.warn("Failed to trigger background refresh for {} - executor is shutting down", username);
        }
    }

    /**
     * Checks for nickname conflicts between premium and offline players,
     * and detects name sniping (premium UUID mismatch).
     *
     * @param existingPlayer    Existing player in database
     * @param isPremium         Whether current player is premium
     * @param existingIsPremium Whether existing player is premium (runtime detection)
     * @param currentPremiumUuid UUID of the current premium player (null for offline)
     * @return true if conflict exists
     */
    public boolean isNicknameConflict(RegisteredPlayer existingPlayer, boolean isPremium,
                                      boolean existingIsPremium, UUID currentPremiumUuid) {
        if (hasBasicNicknameConflict(existingPlayer, isPremium, existingIsPremium)) {
            return true;
        }

        return isNameSnipeConflict(existingPlayer, isPremium, existingIsPremium, currentPremiumUuid);
    }

    private boolean hasBasicNicknameConflict(RegisteredPlayer existingPlayer, boolean isPremium,
                                             boolean existingIsPremium) {
        return (isPremium && !existingIsPremium) || (!isPremium && existingPlayer.getConflictMode());
    }

    private boolean isNameSnipeConflict(RegisteredPlayer existingPlayer, boolean isPremium,
                                        boolean existingIsPremium, UUID currentPremiumUuid) {
        if (!isPremium || !existingIsPremium || currentPremiumUuid == null) {
            return false;
        }

        String dbUuidStr = existingPlayer.getPremiumUuid();
        if (dbUuidStr == null || dbUuidStr.isEmpty()) {
            return false;
        }

        try {
            UUID dbUuid = UUID.fromString(dbUuidStr);
            if (!dbUuid.equals(currentPremiumUuid)) {
                logger.warn("[SECURITY] Name snipe detected for {}: DB UUID={}, Current UUID={}",
                        existingPlayer.getNickname(), dbUuid, currentPremiumUuid);
                return true;
            }
            return false;
        } catch (IllegalArgumentException e) {
            logger.error("[SECURITY] Invalid UUID in database for {}: {}",
                    existingPlayer.getNickname(), dbUuidStr);
            return true;
        }
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
            // Fire-and-forget: don't block Netty IO thread with .join()
            databaseManager.savePlayer(existingPlayer)
                    .exceptionally(throwable -> {
                        logger.error(SECURITY_MARKER, "[NICKNAME CONFLICT] Failed to save conflict state for {}: {}",
                                username, throwable.getMessage());
                        return null;
                    })
                    .thenAccept(result -> {
                        if (result != null && result.isDatabaseError()) {
                            logger.error(SECURITY_MARKER,
                                    "[NICKNAME CONFLICT] Failed to save conflict state for {} — retrying once",
                                    username);
                            databaseManager.savePlayer(existingPlayer)
                                    .thenAccept(retryResult -> {
                                        if (retryResult != null && retryResult.isDatabaseError()) {
                                            logger.error(SECURITY_MARKER,
                                                    "[NICKNAME CONFLICT] Retry also failed for {}", username);
                                        }
                                    });
                        }
                    });
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
    public void handleNicknameConflict(PreLoginEvent event, RegisteredPlayer existingPlayer,
                                       boolean isPremium, UUID currentPremiumUuid) {
        String username = event.getUsername();

        if (shouldDenyNameSnipe(existingPlayer, isPremium, currentPremiumUuid)) {
            denyNameSnipe(event, username, existingPlayer, currentPremiumUuid);
            return;
        }

        if (isPremium && existingPlayer.getPremiumUuid() == null) {
            markAsConflicted(existingPlayer, username);
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
            return;
        }

        if (!isPremium && existingPlayer.getConflictMode()) {
            event.setResult(PreLoginEvent.PreLoginComponentResult.forceOfflineMode());
            logger.debug("[NICKNAME CONFLICT] Offline player {} accessing conflicted account", username);
        }
    }

    private boolean shouldDenyNameSnipe(RegisteredPlayer existingPlayer, boolean isPremium, UUID currentPremiumUuid) {
        return isPremium && currentPremiumUuid != null && existingPlayer.getPremiumUuid() != null;
    }

    private void denyNameSnipe(PreLoginEvent event, String username, RegisteredPlayer existingPlayer,
                               UUID currentPremiumUuid) {
        try {
            UUID dbUuid = UUID.fromString(existingPlayer.getPremiumUuid());
            if (!dbUuid.equals(currentPremiumUuid)) {
                logger.error("[SECURITY BREACH] Name snipe BLOCKED for {}: DB owner UUID={}, Attacker UUID={}",
                        username, dbUuid, currentPremiumUuid);
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                        net.kyori.adventure.text.Component.text(
                                messages.get("security.name_snipe.denied"),
                                net.kyori.adventure.text.format.NamedTextColor.RED)));
            } else {
                logger.debug("Premium UUID verified for {} — forcing online mode", username);
                event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
            }
        } catch (IllegalArgumentException ex) {
            logger.error(SECURITY_MARKER, "Malformed UUID for {} in database: {}", username, ex.getMessage());
            event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    net.kyori.adventure.text.Component.text(
                            messages.get("security.name_snipe.denied"),
                            net.kyori.adventure.text.format.NamedTextColor.RED)));
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
                logger.info("Premium player {} confirmed (source: {}, UUID: {})",
                        username, resolution.source(), premiumUuid);
            }
            return new PremiumResolutionResult(true, premiumUuid);
        }
        if (resolution.isOffline()) {
            authCache.addPremiumPlayer(username, null);
            logger.debug("{} is not premium (resolver: {}, info: {})", username, resolution.source(),
                    resolution.message());
            return new PremiumResolutionResult(false, null);
        }

        // UNKNOWN: All API resolvers failed AND DB cache had no entry.
        // Hybrid approach: DB cache was already checked in PremiumResolverService.resolve(),
        // so reaching here means this is a new player with no cached premium status.
        // Deny login for security — cannot verify premium status.
        logger.error(SECURITY_MARKER, "[SECURITY] Cannot verify premium status for {} - all API resolvers failed (resolver: {}, info: {}). Login denied for safety.",
                username, resolution.source(), resolution.message());
        return null;
    }

    /**
     * Simple data holder for premium resolution results using Java 21 record.
     */
    public record PremiumResolutionResult(boolean premium, UUID premiumUuid) {
    }
}
