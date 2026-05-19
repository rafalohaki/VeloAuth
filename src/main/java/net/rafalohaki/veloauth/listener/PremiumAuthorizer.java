package net.rafalohaki.veloauth.listener;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.cache.AuthCache.PremiumCacheEntry;
import net.rafalohaki.veloauth.model.CachedAuthUser;

import java.util.Optional;
import java.util.UUID;

/**
 * Shared logic for authorizing a Mojang-verified premium player. Used by both
 * {@link AuthListener} (cache-expiry refresh path) and {@link PostLoginHandler}
 * (initial PostLogin path) — keeping them in lockstep so a premium player always
 * ends up with the same {@link CachedAuthUser} shape regardless of which path
 * created the entry.
 */
final class PremiumAuthorizer {

    private PremiumAuthorizer() { }

    /**
     * Builds the {@link CachedAuthUser} for a premium player and registers it with the cache.
     * The premium UUID is taken from the cached premium-status entry when present, otherwise
     * falls back to the connection UUID (which Velocity itself supplies after a successful
     * Mojang handshake, so it is the authoritative premium UUID for that session).
     */
    static void authorize(Player player, String playerIp, AuthCache authCache) {
        UUID playerUuid = player.getUniqueId();
        UUID premiumUuid = Optional.ofNullable(authCache.getPremiumStatus(player.getUsername()))
                .map(PremiumCacheEntry::getPremiumUuid)
                .orElse(playerUuid);

        CachedAuthUser cachedUser = new CachedAuthUser(
                playerUuid,
                player.getUsername(),
                playerIp,
                System.currentTimeMillis(),
                true,
                premiumUuid);

        authCache.authorize(playerUuid, cachedUser, player.getUsername(), playerIp);
    }
}
