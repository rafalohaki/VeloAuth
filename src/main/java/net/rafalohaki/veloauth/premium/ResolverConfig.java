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
            HttpURLConnection.HTTP_NOT_FOUND,
            "uuid",
            "username",
            false,
            ResolverConfig.UNKNOWN_REPORTED_LIMIT,
            "ashcon",
            false,
            false
    ),

    WPME(
            "wpme",
            "https://api-mc.wpme.pl/v2/user/",
            HttpURLConnection.HTTP_NOT_FOUND,
            "uuid",
            "username",
            false,
            ResolverConfig.UNKNOWN_REPORTED_LIMIT,
            "wpme",
            false,
            false
    ),

    /**
     * Mojang API returns BOTH 204 and 404 for non-existent players.
     * wiki.vg: "Mojang likes to change what this endpoint returns somewhat frequently."
     * Using -1 as sentinel to indicate "accept both 204 AND 404".
     */
    MOJANG(
            "mojang",
            "https://api.mojang.com/users/profiles/minecraft/",
            -1,
            "id",
            "name",
            true,
            200,
            "mojang",
            false,
            true
    ),

    MINECRAFT_SERVICES(
            "minecraft-services",
            "https://api.minecraftservices.com/minecraft/profile/lookup/name/",
            HttpURLConnection.HTTP_NOT_FOUND,
            "id",
            "name",
            true,
            ResolverConfig.UNKNOWN_REPORTED_LIMIT,
            "mojang",
            true,
            true
    );

    /** Sentinel for providers that do not publish a per-minute request limit. */
    static final int UNKNOWN_REPORTED_LIMIT = 0;

    private final String id;
    private final String endpoint;
    private final int notFoundResponseCode;
    private final String uuidField;
    private final String usernameField;
    private final boolean usesRawUuidFormat;
    private final int reportedLimitPerMinute;
    private final String rateLimitGroup;
    private final boolean fallbackOnly;
    private final boolean authoritative;

    ResolverConfig(String id, String endpoint, int notFoundResponseCode,
                   String uuidField, String usernameField, boolean usesRawUuidFormat,
                   int reportedLimitPerMinute, String rateLimitGroup,
                   boolean fallbackOnly, boolean authoritative) {
        this.id = id;
        this.endpoint = endpoint;
        this.notFoundResponseCode = notFoundResponseCode;
        this.uuidField = uuidField;
        this.usernameField = usernameField;
        this.usesRawUuidFormat = usesRawUuidFormat;
        this.reportedLimitPerMinute = reportedLimitPerMinute;
        this.rateLimitGroup = rateLimitGroup;
        this.fallbackOnly = fallbackOnly;
        this.authoritative = authoritative;
    }

    public String id() {
        return id;
    }

    public String endpoint() {
        return endpoint;
    }

    public int notFoundResponseCode() {
        return notFoundResponseCode;
    }

    public String uuidField() {
        return uuidField;
    }

    public String usernameField() {
        return usernameField;
    }

    public boolean usesRawUuidFormat() {
        return usesRawUuidFormat;
    }

    /**
     * Commonly reported per-minute request limit for this provider, or
     * {@link #UNKNOWN_REPORTED_LIMIT} when the provider does not publish one.
     */
    int reportedLimitPerMinute() {
        return reportedLimitPerMinute;
    }

    String rateLimitGroup() {
        return rateLimitGroup;
    }

    boolean isFallbackOnly() {
        return fallbackOnly;
    }

    boolean isAuthoritative() {
        return authoritative;
    }
}
