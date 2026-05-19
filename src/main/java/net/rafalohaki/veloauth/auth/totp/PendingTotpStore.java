package net.rafalohaki.veloauth.auth.totp;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.RemovalCause;
import com.github.benmanes.caffeine.cache.Scheduler;
import net.rafalohaki.veloauth.audit.AuditEventType;
import net.rafalohaki.veloauth.audit.AuditLogService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

/**
 * Bounded, TTL-expiring store of in-flight 2FA verification states.
 * <p>
 * Each entry tracks either a player mid-{@code /2fa setup} (waiting to confirm
 * the freshly-generated secret) or a player who just passed BCrypt and is now
 * waiting to enter their TOTP code. Entries auto-expire after
 * {@code pendingTimeoutSeconds} so that an abandoned login session does not
 * persist indefinitely; on expiration we emit the
 * {@link AuditEventType#TWO_FACTOR_PENDING_EXPIRED} audit event so operators can
 * spot stuck flows.
 * <p>
 * Storage is Caffeine to match every other cache in the plugin (W-TinyLFU,
 * per-key node lock, proactive scheduled eviction). The cache is bounded at
 * {@link #MAX_SIZE} entries — a sane upper bound for "concurrent in-flight 2FA
 * verifications" on any normal Minecraft proxy.
 */
public final class PendingTotpStore {

    private static final Logger logger = LoggerFactory.getLogger(PendingTotpStore.class);
    private static final Marker AUDIT_MARKER = MarkerFactory.getMarker("AUDIT");

    /** Generous cap; one entry per player mid-flow. 10k is overkill for any realistic proxy. */
    private static final int MAX_SIZE = 10_000;

    private final Cache<UUID, PendingTotpState> cache;

    public PendingTotpStore(Duration pendingTtl, AuditLogService auditLogService) {
        if (pendingTtl == null || pendingTtl.isZero() || pendingTtl.isNegative()) {
            throw new IllegalArgumentException("pendingTtl must be positive, got " + pendingTtl);
        }
        this.cache = Caffeine.newBuilder()
                .maximumSize(MAX_SIZE)
                .expireAfterWrite(pendingTtl)
                .scheduler(Scheduler.systemScheduler())
                .removalListener((UUID key, PendingTotpState value, RemovalCause cause) ->
                        onRemoval(key, value, cause, auditLogService))
                .build();
    }

    public void put(PendingTotpState state) {
        cache.put(state.uuid(), state);
    }

    public Optional<PendingTotpState> get(UUID uuid) {
        if (uuid == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(cache.getIfPresent(uuid));
    }

    /** Removes the entry; used after successful verify so the next check returns empty. */
    public void invalidate(UUID uuid) {
        if (uuid == null) {
            return;
        }
        cache.invalidate(uuid);
    }

    /** Forces Caffeine maintenance — emits expired entries on the audit log. */
    public void cleanUp() {
        cache.cleanUp();
    }

    public long size() {
        return cache.estimatedSize();
    }

    /** Test seam — exposes the underlying Cache to tests that need to peek state. */
    Cache<UUID, PendingTotpState> raw() {
        return cache;
    }

    /**
     * Caffeine fires this on every removal — eviction, explicit invalidate, replace,
     * expiration, GC. We only emit the audit event on {@link RemovalCause#EXPIRED}
     * so successful verifies (which call {@link #invalidate}) don't produce noise.
     */
    private static void onRemoval(UUID key, PendingTotpState state, RemovalCause cause,
                                  AuditLogService auditLogService) {
        if (cause != RemovalCause.EXPIRED || state == null || auditLogService == null) {
            return;
        }
        String nick = state.dbPlayer() != null ? state.dbPlayer().getNickname() : null;
        String details = "kind=" + state.kind();
        try {
            auditLogService.save(AuditEventType.TWO_FACTOR_PENDING_EXPIRED, nick, state.ip(), details);
        } catch (RuntimeException e) {
            logger.warn(AUDIT_MARKER,
                    "Failed to emit TWO_FACTOR_PENDING_EXPIRED audit for {} ({})", key, nick, e);
        }
    }
}
