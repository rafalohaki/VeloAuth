package net.rafalohaki.veloauth.util;

import java.lang.reflect.Method;
import java.util.UUID;

/**
 * Detects Bedrock players connecting via Geyser/Floodgate using reflection.
 * Uses reflection to avoid a hard compile-time dependency on the Floodgate API.
 *
 * <p>Floodgate authenticates Bedrock players via Xbox Live during the handshake phase,
 * before {@code ServerPreConnectEvent} fires. Therefore, Bedrock players do not need
 * to be redirected to the authentication server.
 *
 * <p>This class is safe to use regardless of whether Floodgate is installed.
 * If Floodgate is not available, {@link #isBedrockPlayer(UUID)} always returns false.
 */
public final class FloodgateDetector {

    private static final boolean FLOODGATE_AVAILABLE;
    private static Method isFloodgatePlayerMethod;
    private static Object floodgateApiInstance;

    static {
        boolean available = false;
        try {
            Class<?> apiClass = Class.forName("org.geysermc.floodgate.api.FloodgateApi");
            Method getInstance = apiClass.getMethod("getInstance");
            Object instance = getInstance.invoke(null);
            if (instance != null) {
                isFloodgatePlayerMethod = apiClass.getMethod("isFloodgatePlayer", UUID.class);
                floodgateApiInstance = instance;
                available = true;
            }
        } catch (Exception ignored) {
            // Floodgate not installed or not available - this is expected
        }
        FLOODGATE_AVAILABLE = available;
    }

    private FloodgateDetector() {
        // Utility class - prevent instantiation
    }

    /**
     * Checks if Floodgate API is available on the server.
     *
     * @return true if Floodgate is installed and initialized
     */
    public static boolean isFloodgateAvailable() {
        return FLOODGATE_AVAILABLE;
    }

    /**
     * Checks if the player with the given UUID is a Bedrock player (connecting via Geyser/Floodgate).
     *
     * <p>If Floodgate is not installed, this method always returns false.
     * On any reflection error, this method returns false (fail-secure).
     *
     * @param playerId UUID of the player to check
     * @return true if the player is a Bedrock/Floodgate player
     */
    public static boolean isBedrockPlayer(UUID playerId) {
        if (!FLOODGATE_AVAILABLE) {
            return false;
        }
        try {
            return Boolean.TRUE.equals(isFloodgatePlayerMethod.invoke(floodgateApiInstance, playerId));
        } catch (Exception ignored) {
            // Fail-secure: treat as non-Bedrock player on any error
            return false;
        }
    }
}
