package net.rafalohaki.veloauth.auth;

import net.rafalohaki.veloauth.database.DatabaseManager;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.LoggerFactory;
import org.slf4j.MarkerFactory;

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
     * @param databaseManager   used only for fire-and-forget saves in {@link #clearIfPresent}
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
        return (System.currentTimeMillis() - conflictTimestamp) < conflictTtlMillis;
    }

    /**
     * Resets conflict state on the given player and persists it (fire-and-forget).
     * No-op when the player is not in conflict mode. Called from the auth-success paths
     * (post-login command flow and premium-cache refresh) so a successful login clears
     * the conflict flag for the next connection.
     *
     * @param dbPlayer      the player record to clear; mutated in place
     * @param operationName human-readable name for logging (e.g. "login", "premium refresh")
     */
    public void clearIfPresent(RegisteredPlayer dbPlayer, String operationName) {
        if (dbPlayer == null || !dbPlayer.getConflictMode()) {
            return;
        }
        dbPlayer.setConflictMode(false);
        dbPlayer.setConflictTimestamp(0L);
        // Fire-and-forget: this runs on the auth-success path where we have already
        // proven the player is legitimate. A save failure is logged but does not undo
        // the in-memory state — the next savePlayer call will retry the persistence.
        databaseManager.savePlayer(dbPlayer)
                .exceptionally(throwable -> {
                    logger.error(SECURITY_MARKER,
                            "[CONFLICT_MODE] Failed to clear conflict state for {} after {}: {}",
                            dbPlayer.getNickname(), operationName, throwable.getMessage());
                    return null;
                });
        logger.info(SECURITY_MARKER,
                "[CONFLICT_MODE CLEARED] Player {} conflict state cleared after successful {}",
                dbPlayer.getNickname(), operationName);
    }
}
