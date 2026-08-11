package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.audit.AuditLogService;
import net.rafalohaki.veloauth.auth.ConflictModeService;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.database.DatabaseManager.DbResult;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import net.rafalohaki.veloauth.util.AuthenticationErrorHandler;
import net.rafalohaki.veloauth.util.UuidUtils;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.time.Instant;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Handles UUID verification logic for player authentication.
 * Extracted from AuthListener to reduce complexity and improve testability.
 * 
 * <p><b>Verification Process:</b>
 * <ol>
 *   <li>Premium players (online mode) - verification skipped</li>
 *   <li>Offline players - verify against database UUID and PREMIUMUUID</li>
 *   <li>CONFLICT_MODE players - allow UUID mismatch for conflict resolution</li>
 * </ol>
 * 
 * @since 2.1.0
 */
class UuidVerificationHandler {

    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final DatabaseManager databaseManager;
    private final AuthCache authCache;
    private final Logger logger;
    private final Supplier<AuditLogService> auditLogServiceSupplier;
    private final ConflictModeService conflictModeService;

    /**
     * Legacy ctor — kept for tests that do not exercise the audit log or conflict TTL.
     */
    UuidVerificationHandler(DatabaseManager databaseManager, AuthCache authCache, Logger logger) {
        this(databaseManager, authCache, logger, () -> null, new ConflictModeService(databaseManager, 0));
    }

    /**
     * Legacy ctor — kept for tests that exercise the audit log but not conflict TTL.
     */
    UuidVerificationHandler(DatabaseManager databaseManager, AuthCache authCache, Logger logger,
                            Supplier<AuditLogService> auditLogServiceSupplier) {
        this(databaseManager, authCache, logger, auditLogServiceSupplier,
                new ConflictModeService(databaseManager, 0));
    }

    /**
     * Creates a new UuidVerificationHandler with an audit log supplier and conflict-mode service.
     *
     * @param databaseManager        Database manager for player lookup
     * @param authCache              Authorization cache
     * @param logger                 Logger instance
     * @param auditLogServiceSupplier supplies the (possibly null) audit log service. Resolved lazily so
     *                                tests can inject a stub before the plugin completes init.
     * @param conflictModeService    conflict-mode TTL + auto-clear helper
     */
    UuidVerificationHandler(DatabaseManager databaseManager, AuthCache authCache, Logger logger,
                            Supplier<AuditLogService> auditLogServiceSupplier,
                            ConflictModeService conflictModeService) {
        this.databaseManager = databaseManager;
        this.authCache = authCache;
        this.logger = logger;
        this.auditLogServiceSupplier = auditLogServiceSupplier != null ? auditLogServiceSupplier : () -> null;
        this.conflictModeService = conflictModeService != null ? conflictModeService
                : new ConflictModeService(databaseManager, 0);
    }

    /**
     * Asynchronously verifies player UUID against database.
     * Premium players skip verification as they don't need to be registered.
     *
     * <p>Returns a {@link java.util.concurrent.CompletableFuture} so that callers can use
     * {@link com.velocitypowered.api.event.EventTask#resumeWhenComplete} in
     * {@code ServerPreConnectEvent} handlers and avoid blocking Netty IO threads.
     *
     * @param player Player to verify
     * @return CompletableFuture that resolves to true if verification passes
     */
    public java.util.concurrent.CompletableFuture<Boolean> verifyPlayerUuid(Player player) {
        return verifyPlayerUuid(player, Runnable::run);
    }

    java.util.concurrent.CompletableFuture<Boolean> verifyPlayerUuid(
            Player player, Consumer<Runnable> connectionEffectGuard) {
        try {
            if (player.isOnlineMode()) {
                return java.util.concurrent.CompletableFuture.completedFuture(handlePremiumPlayer(player));
            }
            return verifyCrackedPlayerUuidAsync(player, connectionEffectGuard);
        } catch (RuntimeException e) {
            return java.util.concurrent.CompletableFuture.completedFuture(
                    handleVerificationError(player, e, connectionEffectGuard));
        }
    }

    private boolean handlePremiumPlayer(Player player) {
        if (logger.isDebugEnabled()) {
            logger.debug("Premium player {} - skipping UUID verification", player.getUsername());
        }
        return true;
    }

    private java.util.concurrent.CompletableFuture<Boolean> verifyCrackedPlayerUuidAsync(
            Player player, Consumer<Runnable> connectionEffectGuard) {
        String username = player.getUsername();
        return databaseManager.findPlayerByNickname(username)
                .thenApply(dbResult -> {
                    if (dbResult.isDatabaseError()) {
                        return handleDatabaseVerificationError(
                                player, dbResult, connectionEffectGuard);
                    }
                    return performUuidVerification(
                            player, dbResult.getValue(), connectionEffectGuard);
                })
                .exceptionally(t -> {
                    Exception e = t instanceof Exception ex ? ex : new RuntimeException(t);
                    return handleAsyncVerificationError(player, e, connectionEffectGuard);
                });
    }

    private boolean handleDatabaseVerificationError(
            Player player, DbResult<RegisteredPlayer> dbResult,
            Consumer<Runnable> connectionEffectGuard) {
        logger.error(SECURITY_MARKER, "[DATABASE ERROR] UUID verification failed for {}: {}",
                player.getUsername(), dbResult.getErrorMessage());
        connectionEffectGuard.accept(() -> AuthenticationErrorHandler.handleVerificationFailure(
                player, player.getUniqueId(), authCache, logger));
        return false;
    }

    /**
     * Performs UUID verification against database fields.
     */
    public boolean performUuidVerification(Player player, RegisteredPlayer dbPlayer) {
        return performUuidVerification(player, dbPlayer, Runnable::run);
    }

    private boolean performUuidVerification(
            Player player, RegisteredPlayer dbPlayer,
            Consumer<Runnable> connectionEffectGuard) {
        if (dbPlayer == null) {
            logMissingDbPlayer(player);
            return false;
        }

        if (dbPlayer.getConflictMode() && conflictModeService.isActive(dbPlayer)) {
            // Conflict window still open: allow despite UUID mismatch (legitimate
            // nickname-collision resolution). uuidMatches is still computed and WARN-logged
            // so a real hijack attempt leaves a trail.
            logConflictModeActive(player, dbPlayer);
            logConflictModeUuidMismatchIfAny(player, dbPlayer);
            return true;
        }
        if (dbPlayer.getConflictMode()) {
            // TTL expired: the conflict entry is stale. Fall through to full UUID verification
            // instead of unconditionally allowing. This bounds the relaxed-verification window
            // to conflict-mode-ttl-hours (default 7 days), closing the pre-1.3.3 hole where a
            // single conflict mark disabled UUID verification forever.
            logger.info(SECURITY_MARKER,
                    "[CONFLICT_MODE EXPIRED] Player {} conflict entry older than TTL ({}h) - performing full UUID verification",
                    player.getUsername(), conflictModeService.getConflictTtlHours());
        }

        return verifyUuidMatch(player, dbPlayer, connectionEffectGuard);
    }

    private void logMissingDbPlayer(Player player) {
        if (logger.isDebugEnabled()) {
            logger.debug("No UUID in database for player {}", player.getUsername());
        }
    }

    private void logConflictModeActive(Player player, RegisteredPlayer dbPlayer) {
        logger.info(SECURITY_MARKER,
                "[CONFLICT_MODE ACTIVE] Player {} (UUID: {}) is in conflict resolution mode - " +
                        "allowing access despite potential UUID mismatch. Conflict timestamp: {}",
                player.getUsername(),
                player.getUniqueId(),
                dbPlayer.getConflictTimestamp() > 0 ?
                        Instant.ofEpochMilli(dbPlayer.getConflictTimestamp()) : "not set");
    }

    /**
     * Emits a WARN trail when a connection passes through the open conflict window with a
     * UUID that matches neither the stored primary nor the stored premium UUID. The decision
     * is still "allow" (that is the point of conflict mode); the log is for forensic review.
     */
    private void logConflictModeUuidMismatchIfAny(Player player, RegisteredPlayer dbPlayer) {
        UUID playerUuid = player.getUniqueId();
        UUID storedUuid = UuidUtils.parseUuidSafely(dbPlayer.getUuid());
        UUID storedPremiumUuid = UuidUtils.parseUuidSafely(dbPlayer.getPremiumUuid());
        boolean uuidMatches = (storedUuid != null && playerUuid.equals(storedUuid))
                || (storedPremiumUuid != null && playerUuid.equals(storedPremiumUuid));
        if (uuidMatches) {
            return;
        }
        logger.warn(SECURITY_MARKER,
                "[CONFLICT_MODE] UUID mismatch for {} - player UUID: {}, stored: {}, premium: {}",
                player.getUsername(), playerUuid, storedUuid, storedPremiumUuid);
    }

    private boolean verifyUuidMatch(
            Player player, RegisteredPlayer dbPlayer,
            Consumer<Runnable> connectionEffectGuard) {
        UUID playerUuid = player.getUniqueId();
        UUID storedUuid = UuidUtils.parseUuidSafely(dbPlayer.getUuid());
        UUID storedPremiumUuid = UuidUtils.parseUuidSafely(dbPlayer.getPremiumUuid());

        if (storedUuid != null && playerUuid.equals(storedUuid)) {
            return true;
        }

        if (storedPremiumUuid != null && playerUuid.equals(storedPremiumUuid)) {
            if (logger.isDebugEnabled()) {
                logger.debug("UUID matched against PREMIUMUUID for player {}", player.getUsername());
            }
            return true;
        }

        handleUuidMismatch(player, playerUuid, storedUuid, storedPremiumUuid,
                dbPlayer, connectionEffectGuard);
        return false;
    }

    private void handleUuidMismatch(
            Player player, UUID playerUuid, UUID storedUuid,
            UUID storedPremiumUuid, RegisteredPlayer dbPlayer,
            Consumer<Runnable> connectionEffectGuard) {
        connectionEffectGuard.accept(() -> AuthenticationErrorHandler.handleUuidMismatch(
                    new AuthenticationErrorHandler.UuidMismatchContext(
                            player, playerUuid, storedUuid, storedPremiumUuid, dbPlayer),
                    authCache, logger, auditLogServiceSupplier.get()));
    }

    private boolean handleAsyncVerificationError(
            Player player, Exception exception, Consumer<Runnable> connectionEffectGuard) {
        connectionEffectGuard.accept(() -> AuthenticationErrorHandler.handleVerificationError(
                player, exception, authCache, logger));
        return false;
    }

    private boolean handleVerificationError(
            Player player, Exception exception, Consumer<Runnable> connectionEffectGuard) {
        connectionEffectGuard.accept(() -> AuthenticationErrorHandler.handleVerificationError(
                player, exception, authCache, logger));
        return false;
    }
}
