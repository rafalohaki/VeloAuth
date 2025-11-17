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
            false
    ),

    WPME(
            "wpme",
            "https://api-mc.wpme.pl/v2/user/",
            HttpURLConnection.HTTP_NOT_FOUND,
            "uuid",
            "username",
            false
    ),

    MOJANG(
            "mojang",
            "https://api.mojang.com/users/profiles/minecraft/",
            HttpURLConnection.HTTP_NO_CONTENT,
            "id",
            "name",
            true
    );

    private final String id;
    private final String endpoint;
    private final int notFoundResponseCode;
    private final String uuidField;
    private final String usernameField;
    private final boolean usesRawUuidFormat;

    ResolverConfig(String id, String endpoint, int notFoundResponseCode,
                   String uuidField, String usernameField, boolean usesRawUuidFormat) {
        this.id = id;
        this.endpoint = endpoint;
        this.notFoundResponseCode = notFoundResponseCode;
        this.uuidField = uuidField;
        this.usernameField = usernameField;
        this.usesRawUuidFormat = usesRawUuidFormat;
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
}
