package net.rafalohaki.veloauth.premium;

import java.util.Objects;
import java.util.UUID;

/**
 * Represents the outcome of a premium name lookup using external resolvers.
 */
public record PremiumResolution(
        PremiumStatus status,
        UUID uuid,
        String canonicalUsername,
        String source,
        String message
) {

    public PremiumResolution {
        Objects.requireNonNull(status, "status");
    }

    public static PremiumResolution premium(UUID uuid, String canonicalUsername, String source) {
        return new PremiumResolution(PremiumStatus.PREMIUM, uuid, canonicalUsername, source, null);
    }

    public static PremiumResolution offline(String canonicalUsername, String source, String message) {
        return new PremiumResolution(PremiumStatus.OFFLINE, null, canonicalUsername, source, message);
    }

    public static PremiumResolution unknown(String source, String message) {
        return new PremiumResolution(PremiumStatus.UNKNOWN, null, null, source, message);
    }

    public boolean isPremium() {
        return status == PremiumStatus.PREMIUM;
    }

    public boolean isOffline() {
        return status == PremiumStatus.OFFLINE;
    }

    public enum PremiumStatus {
        PREMIUM,
        OFFLINE,
        UNKNOWN
    }
}
