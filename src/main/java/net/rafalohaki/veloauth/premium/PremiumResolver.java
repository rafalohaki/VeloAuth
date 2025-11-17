package net.rafalohaki.veloauth.premium;

/**
 * Contract for resolving Mojang premium accounts by username.
 */
public interface PremiumResolver {

    /**
     * Identifier for logging/configuration.
     */
    String id();

    /**
     * @return true if this resolver should participate.
     */
    boolean enabled();

    /**
     * Attempts to resolve the supplied username.
     *
     * @param username case-sensitive username as provided by the player
     * @return resolution status (never {@code null})
     */
    PremiumResolution resolve(String username);
}
