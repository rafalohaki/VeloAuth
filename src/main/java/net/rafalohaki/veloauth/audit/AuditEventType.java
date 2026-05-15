package net.rafalohaki.veloauth.audit;

/**
 * Closed enumeration of audit events VeloAuth records.
 * String values are persisted in VELOAUTH_AUDIT_LOG.EVENT_TYPE and must stay
 * stable across releases; rename a value only when changing storage schema.
 */
public enum AuditEventType {
    LOGIN_OK,
    LOGIN_FAIL,
    REGISTER,
    UNREGISTER,
    PASSWORD_CHANGE,
    PASSWORD_REHASH,
    UUID_MISMATCH,
    SESSION_TIMEOUT,
    PROFILE_MIGRATION,
    TWO_FACTOR_ENABLED,
    TWO_FACTOR_DISABLED,
    TWO_FACTOR_VERIFY_OK,
    TWO_FACTOR_VERIFY_FAIL,
    TWO_FACTOR_PENDING_EXPIRED;

    /**
     * Persistence form, e.g. {@code "LOGIN_OK"}. Equivalent to {@link #name()},
     * kept as an explicit method so callers don't accidentally rely on {@code toString()}.
     */
    public String storageValue() {
        return name();
    }
}
