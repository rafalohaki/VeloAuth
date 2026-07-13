package net.rafalohaki.veloauth.util;

import java.lang.reflect.Method;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Detects Bedrock players connecting through Floodgate without making Floodgate a hard runtime
 * dependency.
 *
 * <p>The API methods are resolved lazily, while the API instance itself is fetched on every call.
 * Floodgate publishes that instance during its own initialization, so caching an early
 * {@code null} result for the lifetime of the proxy would permanently disable Bedrock support.
 *
 * <p>Floodgate adds a player to its API during the encrypted-handshake phase, before Velocity's
 * {@code PreLoginEvent}. Username lookup is therefore available early enough to keep linked
 * Bedrock accounts out of the Mojang premium-resolution path. UUID lookup remains the
 * authorization boundary used before bypassing the auth server.
 */
public final class FloodgateDetector {

    private static final String API_CLASS_NAME = "org.geysermc.floodgate.api.FloodgateApi";
    private static final AtomicReference<ApiMethods> API_METHODS = new AtomicReference<>();
    private static volatile boolean apiClassMissing;

    private FloodgateDetector() {
        // Utility class
    }

    /**
     * Checks whether the Floodgate API is visible and has published an initialized instance.
     *
     * @return {@code true} when Floodgate is ready
     */
    public static boolean isFloodgateAvailable() {
        return resolveApiContext() != null;
    }

    /**
     * Checks an authenticated profile UUID against Floodgate's live player registry.
     *
     * @param playerId UUID to verify
     * @return {@code true} only when Floodgate confirms the UUID
     */
    public static boolean isBedrockPlayer(UUID playerId) {
        if (playerId == null) {
            return false;
        }

        ApiContext context = resolveApiContext();
        if (context == null) {
            return false;
        }

        try {
            return Boolean.TRUE.equals(context.methods().isFloodgatePlayer()
                    .invoke(context.instance(), playerId));
        } catch (ReflectiveOperationException | RuntimeException | LinkageError ignored) {
            return false;
        }
    }

    /**
     * Checks whether a player currently registered by Floodgate owns the supplied login name.
     * Both the Java-form username and the linked-account username are considered.
     *
     * <p>This lookup is used only to force the pre-login connection into offline mode and skip
     * Mojang resolution. It never authorizes backend access; that requires
     * {@link #isBedrockPlayer(UUID)} after Velocity has built the final profile.
     *
     * @param username username from Velocity's pre-login event
     * @return {@code true} when the live Floodgate registry contains the username
     */
    public static boolean isBedrockUsername(String username) {
        if (username == null || username.isBlank()) {
            return false;
        }

        ApiContext context = resolveApiContext();
        if (context == null) {
            return false;
        }

        try {
            Object players = context.methods().getPlayers().invoke(context.instance());
            if (!(players instanceof Iterable<?> iterable)) {
                return false;
            }
            for (Object player : iterable) {
                if (matchesUsername(player, username)) {
                    return true;
                }
            }
        } catch (ReflectiveOperationException | RuntimeException | LinkageError ignored) {
            // Optional integration: any API mismatch falls back to the standard auth flow.
        }
        return false;
    }

    /**
     * Returns Floodgate's effective username prefix when its API is ready.
     *
     * @return live Floodgate prefix, or empty when Floodgate is unavailable
     */
    public static Optional<String> getPlayerPrefix() {
        ApiContext context = resolveApiContext();
        if (context == null) {
            return Optional.empty();
        }

        try {
            Object prefix = context.methods().getPlayerPrefix().invoke(context.instance());
            return prefix instanceof String value ? Optional.of(value) : Optional.empty();
        } catch (ReflectiveOperationException | RuntimeException | LinkageError ignored) {
            return Optional.empty();
        }
    }

    private static boolean matchesUsername(Object player, String username) {
        if (player == null) {
            return false;
        }
        return matchesUsername(player, username, "getCorrectUsername")
                || matchesUsername(player, username, "getJavaUsername")
                || matchesUsername(player, username, "getUsername");
    }

    private static boolean matchesUsername(Object player, String username, String methodName) {
        try {
            Object candidate = player.getClass().getMethod(methodName).invoke(player);
            return candidate instanceof String value && value.equalsIgnoreCase(username);
        } catch (ReflectiveOperationException | RuntimeException | LinkageError ignored) {
            return false;
        }
    }

    private static ApiContext resolveApiContext() {
        ApiMethods methods = resolveApiMethods();
        if (methods == null) {
            return null;
        }

        try {
            Object instance = methods.getInstance().invoke(null);
            return instance != null ? new ApiContext(methods, instance) : null;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError ignored) {
            return null;
        }
    }

    private static ApiMethods resolveApiMethods() {
        ApiMethods cached = API_METHODS.get();
        if (cached != null || apiClassMissing) {
            return cached;
        }

        try {
            Class<?> apiClass = Class.forName(API_CLASS_NAME);
            ApiMethods discovered = new ApiMethods(
                    apiClass.getMethod("getInstance"),
                    apiClass.getMethod("isFloodgatePlayer", UUID.class),
                    apiClass.getMethod("getPlayers"),
                    apiClass.getMethod("getPlayerPrefix")
            );
            API_METHODS.compareAndSet(null, discovered);
            return API_METHODS.get();
        } catch (ClassNotFoundException e) {
            apiClassMissing = true;
            return null;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError ignored) {
            return null;
        }
    }

    private record ApiMethods(Method getInstance, Method isFloodgatePlayer,
                              Method getPlayers, Method getPlayerPrefix) {
    }

    private record ApiContext(ApiMethods methods, Object instance) {
    }
}
