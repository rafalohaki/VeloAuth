package net.rafalohaki.veloauth.auth.totp;

import net.rafalohaki.veloauth.model.RegisteredPlayer;

import java.util.UUID;

/**
 * Snapshot of "something is mid-2FA-flow" state, parked inside
 * {@link PendingTotpStore} until the player completes {@code /2fa verify <code>}
 * (or the entry expires).
 * <p>
 * Two discriminated cases:
 * <ul>
 *   <li>{@link Kind#LOGIN} — BCrypt already passed; the player is on the auth
 *       server waiting to enter their TOTP code. {@code dbPlayer} carries the
 *       row we already loaded so we don't re-query the database on confirm.
 *       {@code newSecret} is unused (the secret in
 *       {@code dbPlayer.getTotpToken()} is what we verify against).</li>
 *   <li>{@link Kind#SETUP} — the player ran {@code /2fa setup}; we generated a
 *       new secret but have <em>not</em> persisted it yet. The player must
 *       successfully verify a code from that {@code newSecret} before we write
 *       it to the {@code TOTPTOKEN} column. This avoids enrolling players whose
 *       authenticator app failed to scan the QR.</li>
 * </ul>
 */
public record PendingTotpState(
        UUID uuid,
        Kind kind,
        RegisteredPlayer dbPlayer,
        String newSecret,
        String ip,
        long createdAtMs
) {

    public enum Kind { LOGIN, SETUP }

    public PendingTotpState {
        if (uuid == null) {
            throw new IllegalArgumentException("uuid must not be null");
        }
        if (kind == null) {
            throw new IllegalArgumentException("kind must not be null");
        }
        if (kind == Kind.LOGIN && dbPlayer == null) {
            throw new IllegalArgumentException("LOGIN pending state requires dbPlayer");
        }
        if (kind == Kind.SETUP && (newSecret == null || newSecret.isBlank())) {
            throw new IllegalArgumentException("SETUP pending state requires newSecret");
        }
    }

    /** Convenience constructor for the post-BCrypt login branch. */
    public static PendingTotpState forLogin(UUID uuid, RegisteredPlayer dbPlayer, String ip) {
        return new PendingTotpState(uuid, Kind.LOGIN, dbPlayer, null, ip, System.currentTimeMillis());
    }

    /** Convenience constructor for the {@code /2fa setup} confirm flow. */
    public static PendingTotpState forSetup(UUID uuid, String newSecret, String ip) {
        return new PendingTotpState(uuid, Kind.SETUP, null, newSecret, ip, System.currentTimeMillis());
    }
}
