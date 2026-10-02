package net.rafalohaki.veloauth.premium;

import java.net.HttpURLConnection;

/**
 * Configuration for a premium resolver.
 * Eliminates code duplication by using data-driven approach.
 * Uses enum to prevent "unnecessary instantiation" warnings.
 */
public enum ResolverConfig {

    ASHCON(
            "ashcon",
            "https://api.ashcon.app/mojang/v2/user/",
            new ProfileFields(HttpURLConnection.HTTP_NOT_FOUND, "uuid", "username", false),
            new ResolverPolicy(ResolverConfig.UNKNOWN_REPORTED_LIMIT, null, false, false)
    ),

    WPME(
            "wpme",
            "https://api-mc.wpme.pl/v2/user/",
            new ProfileFields(HttpURLConnection.HTTP_NOT_FOUND, "uuid", "username", false),
            new ResolverPolicy(ResolverConfig.UNKNOWN_REPORTED_LIMIT, null, false, false)
    ),

    /**
     * Mojang API returns BOTH 204 and 404 for non-existent players.
     * wiki.vg: "Mojang likes to change what this endpoint returns somewhat frequently."
     * Using -1 as sentinel to indicate "accept both 204 AND 404".
     */
    MOJANG(
            ResolverIds.MOJANG,
            "https://api.mojang.com/users/profiles/minecraft/",
            new ProfileFields(-1, "id", "name", true),
            new ResolverPolicy(200, null, false, true)
    ),

    MINECRAFT_SERVICES(
            "minecraft-services",
            "https://api.minecraftservices.com/minecraft/profile/lookup/name/",
            new ProfileFields(HttpURLConnection.HTTP_NOT_FOUND, "id", "name", true),
            new ResolverPolicy(ResolverConfig.UNKNOWN_REPORTED_LIMIT, ResolverIds.MOJANG, true, true)
    );

    /** Sentinel for providers that do not publish a per-minute request limit. */
    static final int UNKNOWN_REPORTED_LIMIT = 0;

    private final String id;
    private final String endpoint;
    private final ProfileFields profileFields;
    private final ResolverPolicy policy;
    private final String rateLimitGroup;

    ResolverConfig(String id, String endpoint, ProfileFields profileFields, ResolverPolicy policy) {
        this.id = id;
        this.endpoint = endpoint;
        this.profileFields = profileFields;
        this.policy = policy;
        this.rateLimitGroup = policy.rateLimitGroup() == null ? id : policy.rateLimitGroup();
    }

    public String id() {
        return id;
    }

    public String endpoint() {
        return endpoint;
    }

    public int notFoundResponseCode() {
        return profileFields.notFoundResponseCode();
    }

    public String uuidField() {
        return profileFields.uuidField();
    }

    public String usernameField() {
        return profileFields.usernameField();
    }

    public boolean usesRawUuidFormat() {
        return profileFields.usesRawUuidFormat();
    }

    /**
     * Commonly reported per-minute request limit for this provider, or
     * {@link #UNKNOWN_REPORTED_LIMIT} when the provider does not publish one.
     */
    int reportedLimitPerMinute() {
        return policy.reportedLimitPerMinute();
    }

    String rateLimitGroup() {
        return rateLimitGroup;
    }

    boolean isFallbackOnly() {
        return policy.fallbackOnly();
    }

    boolean isAuthoritative() {
        return policy.authoritative();
    }

    private record ProfileFields(int notFoundResponseCode, String uuidField, String usernameField,
                                 boolean usesRawUuidFormat) {
    }

    private record ResolverPolicy(int reportedLimitPerMinute, String rateLimitGroup,
                                  boolean fallbackOnly, boolean authoritative) {
    }

    private static final class ResolverIds {
        private static final String MOJANG = "mojang";

        private ResolverIds() {
        }
    }
}
