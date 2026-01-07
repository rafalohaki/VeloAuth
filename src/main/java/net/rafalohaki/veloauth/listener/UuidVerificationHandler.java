package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.proxy.Player;
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
public class UuidVerificationHandler {

    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final DatabaseManager databaseManager;
    private final AuthCache authCache;
    private final Logger logger;

    /**
     * Creates a new UuidVerificationHandler.
     *
     * @param databaseManager Database manager for player lookup
     * @param authCache       Authorization cache
     * @param logger          Logger instance
     */
    public UuidVerificationHandler(DatabaseManager databaseManager, AuthCache authCache, Logger logger) {
        this.databaseManager = databaseManager;
        this.authCache = authCache;
        this.logger = logger;
    }

    /**
     * Verifies player UUID against database.
     * Premium players skip verification as they don't need to be registered.
     *
     * @param player Player to verify
     * @return true if verification passes
     */
    public boolean verifyPlayerUuid(Player player) {
        try {
            if (player.isOnlineMode()) {
                return handlePremiumPlayer(player);
            }
            return verifyCrackedPlayerUuid(player);
        } catch (Exception e) {
            return handleVerificationError(player, e);
        }
    }

    private boolean handlePremiumPlayer(Player player) {
        if (logger.isDebugEnabled()) {
            logger.debug("Premium player {} - skipping UUID verification", player.getUsername());
        }
        return true;
    }

    private boolean verifyCrackedPlayerUuid(Player player) {
        try {
            var dbResult = databaseManager.findPlayerByNickname(player.getUsername()).join();

            if (dbResult.isDatabaseError()) {
                return handleDatabaseVerificationError(player, dbResult);
            }

            return performUuidVerification(player, dbResult.getValue());
        } catch (Exception e) {
            return handleAsyncVerificationError(player, e);
        }
    }

    private boolean handleDatabaseVerificationError(Player player, DbResult<RegisteredPlayer> dbResult) {
        logger.error(SECURITY_MARKER, "[DATABASE ERROR] UUID verification failed for {}: {}",
                player.getUsername(), dbResult.getErrorMessage());
        AuthenticationErrorHandler.handleVerificationFailure(player, player.getUniqueId(), authCache, logger);
        return false;
    }

    /**
     * Performs UUID verification against database fields.
     */
    public boolean performUuidVerification(Player player, RegisteredPlayer dbPlayer) {
        if (dbPlayer == null) {
            logMissingDbPlayer(player);
            return false;
        }

        if (dbPlayer.getConflictMode()) {
            logConflictModeActive(player, dbPlayer);
            return true;
        }

        return verifyUuidMatch(player, dbPlayer);
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

    private boolean verifyUuidMatch(Player player, RegisteredPlayer dbPlayer) {
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

        handleUuidMismatch(player, playerUuid, storedUuid, storedPremiumUuid, dbPlayer);
        return false;
    }

    private void handleUuidMismatch(Player player, UUID playerUuid, UUID storedUuid,
                                   UUID storedPremiumUuid, RegisteredPlayer dbPlayer) {
        AuthenticationErrorHandler.handleUuidMismatch(
                player, playerUuid, storedUuid, storedPremiumUuid, dbPlayer, authCache, logger);
    }

    private boolean handleAsyncVerificationError(Player player, Exception e) {
        return AuthenticationErrorHandler.handleVerificationError(player, e, authCache, logger);
    }

    private boolean handleVerificationError(Player player, Exception e) {
        return AuthenticationErrorHandler.handleVerificationError(player, e, authCache, logger);
    }
}
