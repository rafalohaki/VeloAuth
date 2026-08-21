package net.rafalohaki.veloauth.auth;

import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.LoggerFactory;
import org.slf4j.MarkerFactory;

import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * Manages CONFLICT_MODE lifecycle: TTL-based expiry and auto-clear after successful auth.
 *
 * <p>Conflict mode is set server-side by {@code PreLoginHandler.markAsConflicted} when a
 * premium player's nickname collides with an existing offline account. While in conflict
 * mode, UUID verification is relaxed so the legitimate owner can still connect. Two
 * problems existed pre-1.3.3:
 * <ol>
 *   <li>Conflict mode was <em>never</em> auto-cleared — once set, any player knowing the
 *       nickname bypassed UUID verification indefinitely.</li>
 *   <li>No TTL — {@code CONFLICT_TIMESTAMP} was recorded but never consulted.</li>
 * </ol>
 *
 * <p>This service consults {@code CONFLICT_TIMESTAMP} against a configurable TTL
 * ({@code conflict-mode-ttl-hours}; 0 disables the TTL for backward compatibility) and
 * exposes {@link #clearIfPresent(RegisteredPlayer, String)} so the auth-success paths can
 * reset conflict state. Both writes reuse the existing {@code CONFLICT_*} columns — no
 * schema change.
 */
public final class ConflictModeService {

    private static final Logger logger = LoggerFactory.getLogger(ConflictModeService.class);
    private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");

    private final DatabaseManager databaseManager;
    private final long conflictTtlMillis;
    private final int conflictTtlHours;

    /**
     * @param databaseManager   persists state changes made by {@link #clearIfPresent}
     * @param conflictTtlHours  TTL in hours; {@code 0} disables the TTL (permanent conflict —
     *                          the pre-1.3.3 behaviour). Captured once at construction into a
     *                          {@code final} field; {@code /vauth reload} does NOT pick up
     *                          changes — a full proxy restart is required (same lifecycle as
     *                          {@code brute-force-*}, which is also captured into a final holder
     *                          by {@code IPRateLimiter} at init).
     */
    public ConflictModeService(DatabaseManager databaseManager, int conflictTtlHours) {
        this.databaseManager = databaseManager;
        this.conflictTtlHours = conflictTtlHours;
        this.conflictTtlMillis = conflictTtlHours * 60L * 60L * 1000L;
    }

    /**
     * Returns the configured TTL in hours (introspection helper; used by tests).
     */
    public int getConflictTtlHours() {
        return conflictTtlHours;
    }

    /**
     * Reports whether the given player's conflict state is still active.
     *
     * <ul>
     *   <li>{@code dbPlayer == null} or not in conflict mode → {@code false}</li>
     *   <li>TTL disabled ({@code conflict-mode-ttl-hours = 0}) → {@code true} (permanent)</li>
     *   <li>TTL enabled and {@code CONFLICT_TIMESTAMP} is within the window → {@code true}</li>
     *   <li>TTL enabled and window expired → {@code false}</li>
     * </ul>
     */
    public boolean isActive(RegisteredPlayer dbPlayer) {
        if (dbPlayer == null || !dbPlayer.getConflictMode()) {
            return false;
        }
        if (conflictTtlMillis <= 0) {
            return true; // TTL disabled — permanent conflict (pre-1.3.3 behaviour)
        }
        long conflictTimestamp = dbPlayer.getConflictTimestamp();
        if (conflictTimestamp <= 0) {
            // Timestamp missing (e.g. legacy row written before CONFLICT_TIMESTAMP existed).
            // Treat as expired so the TTL still bounds the window — safer than allowing forever.
            return false;
        }
        long age = System.currentTimeMillis() - conflictTimestamp;
        return age >= 0L && age < conflictTtlMillis;
    }

    /**
     * Resets conflict state on the given player and persists it asynchronously.
     * No-op when the player is not in conflict mode. Called from the auth-success paths
     * (post-login command flow and premium-cache refresh) so a successful login clears
     * the conflict flag for the next connection.
     *
     * @param dbPlayer      the player record to clear; mutated in place
     * @param operationName human-readable name for logging (e.g. "login", "premium refresh")
     * @return future resolving to true only after the clear was persisted
     */
    public CompletableFuture<Boolean> clearIfPresent(RegisteredPlayer dbPlayer, String operationName) {
        if (dbPlayer == null || !dbPlayer.getConflictMode()) {
            return CompletableFuture.completedFuture(true);
        }
        long previousTimestamp = dbPlayer.getConflictTimestamp();
        dbPlayer.setConflictMode(false);
        dbPlayer.setConflictTimestamp(0L);
        return persistClear(dbPlayer, operationName, previousTimestamp, false);
    }

    private CompletableFuture<Boolean> persistClear(RegisteredPlayer dbPlayer, String operationName,
                                                     long previousTimestamp, boolean retry) {
        CompletableFuture<DatabaseManager.DbResult<Boolean>> saveFuture = databaseManager.savePlayer(dbPlayer);
        if (saveFuture == null) {
            restoreConflictState(dbPlayer, previousTimestamp);
            logger.error(SECURITY_MARKER,
                    "[CONFLICT_MODE] Save did not start for {} after {}", dbPlayer.getNickname(), operationName);
            return CompletableFuture.completedFuture(false);
        }

        return saveFuture.handle(this::isSuccessful)
                .thenCompose(success -> {
                    if (Boolean.TRUE.equals(success)) {
                        logger.info(SECURITY_MARKER,
                                "[CONFLICT_MODE CLEARED] Player {} conflict state persisted after successful {}",
                                dbPlayer.getNickname(), operationName);
                        return CompletableFuture.completedFuture(true);
                    }
                    if (!retry) {
                        logger.warn(SECURITY_MARKER,
                                "[CONFLICT_MODE] Failed to persist clear for {} after {} - retrying once",
                                dbPlayer.getNickname(), operationName);
                        return persistClear(dbPlayer, operationName, previousTimestamp, true);
                    }

                    restoreConflictState(dbPlayer, previousTimestamp);
                    logger.error(SECURITY_MARKER,
                            "[CONFLICT_MODE] Could not persist clear for {} after {}; conflict state restored",
                            dbPlayer.getNickname(), operationName);
                    return CompletableFuture.completedFuture(false);
                });
    }

    private boolean isSuccessful(DatabaseManager.DbResult<Boolean> result, Throwable throwable) {
        return throwable == null
                && result != null
                && !result.isDatabaseError()
                && Boolean.TRUE.equals(result.getValue());
    }

    private void restoreConflictState(RegisteredPlayer dbPlayer, long previousTimestamp) {
        // Both call sites sit behind clearIfPresent's null gate; the explicit requireNonNull
        // states that contract where the dereference happens instead of one method away.
        Objects.requireNonNull(dbPlayer, "dbPlayer");
        dbPlayer.setConflictMode(true);
        dbPlayer.setConflictTimestamp(previousTimestamp);
    }
}
