package net.rafalohaki.veloauth;

public final class BuildConstants {
    private BuildConstants() {
        // Utility class
    }

    public static final String VERSION = "${project.version}";
    public static final String EMBEDDED_BUILD_CHANNEL = "${embedded.build.channel}";
    public static final String EMBEDDED_MCPROTOCOLLIB_VERSION = "${mcprotocollib.resolved-version}";
    public static final String EMBEDDED_MCPROTOCOLLIB_SHA256 = "${mcprotocollib.sha256}";
    public static final String EMBEDDED_VIAVERSION_VERSION = "${viaversion.runtime.version}";
    public static final String EMBEDDED_VIAVERSION_URL = "${viaversion.runtime.url}";
    public static final String EMBEDDED_VIAVERSION_SHA256 = "${viaversion.runtime.sha256}";
}
