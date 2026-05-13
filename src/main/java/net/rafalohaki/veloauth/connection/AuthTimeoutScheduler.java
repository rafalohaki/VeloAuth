package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.scheduler.ScheduledTask;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

/**
 * Disconnects players who linger on the auth server without authenticating within
 * {@code auth-server.timeout-seconds}.
 * <p>
 * Lifecycle:
 * <ul>
 *   <li>{@link #schedule(Player)} — called from {@code AuthListener.handleAuthServerConnection}
 *       when an unauthenticated player lands on the auth server.</li>
 *   <li>{@link #cancel(UUID)} — called on successful auth (PostAuthFlow) and on disconnect.</li>
 *   <li>{@link #shutdown()} — called from {@code VeloAuth.shutdown()}; cancels all pending tasks.</li>
 * </ul>
 * <p>
 * Thread-safe: state held in {@link ConcurrentHashMap}; scheduled tasks run on Velocity's
 * scheduler thread, so {@code player.disconnect(...)} is invoked on a safe thread.
 */
public final class AuthTimeoutScheduler {

    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");

    private final VeloAuth plugin;
    private final Settings settings;
    private final Messages messages;
    private final AuthCache authCache;
    private final ConnectionManager connectionManager;
    private final Logger logger;
    private final Map<UUID, ScheduledTask> pending = new ConcurrentHashMap<>();

    public AuthTimeoutScheduler(VeloAuth plugin, Settings settings, Messages messages,
                                AuthCache authCache, ConnectionManager connectionManager) {
        this.plugin = plugin;
        this.settings = settings;
        this.messages = messages;
        this.authCache = authCache;
        this.connectionManager = connectionManager;
        this.logger = plugin.getLogger();
    }

    /**
     * Schedules a kick for the given player after {@code auth-server.timeout-seconds}.
     * No-op when timeout is configured to zero or negative.
     * Any previously scheduled timeout for the same UUID is cancelled first.
     */
    public void schedule(Player player) {
        int seconds = settings.getAuthServerTimeoutSeconds();
        if (seconds <= 0) {
            return;
        }
        UUID uuid = player.getUniqueId();
        cancel(uuid);

        ScheduledTask task = plugin.getServer().getScheduler().buildTask(plugin, () -> {
            pending.remove(uuid);
            if (!player.isActive()) {
                return;
            }
            // Re-check: maybe player authenticated in the meantime but cancel() didn't fire
            // (e.g. external session restore). Verify against cache + current server.
            if (isAuthorizedAndStillOnAuthServer(player)) {
                return;
            }
            if (!connectionManager.isPlayerOnAuthServer(player)) {
                return; // already moved on, nothing to do
            }

            String kickMessage = messages.get("auth.timeout.kick", seconds);
            player.disconnect(Component.text(kickMessage, NamedTextColor.RED));
            if (logger.isInfoEnabled()) {
                logger.info(AUTH_MARKER,
                        "Kicked player {} after {}s auth timeout (no login/register)",
                        player.getUsername(), seconds);
            }
        }).delay(seconds, TimeUnit.SECONDS).schedule();

        pending.put(uuid, task);
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "Auth timeout scheduled for {} ({}s)",
                    player.getUsername(), seconds);
        }
    }

    private boolean isAuthorizedAndStillOnAuthServer(Player player) {
        // If the cache says the player is authorized for their current IP, they have authenticated
        // — the cancel() call must have raced with the scheduler. Skip the kick.
        return authCache.isPlayerAuthorized(player.getUniqueId(), PlayerAddressUtils.getPlayerIp(player));
    }

    /**
     * Cancels a scheduled timeout. Called on successful authentication or disconnect.
     */
    public void cancel(UUID uuid) {
        ScheduledTask task = pending.remove(uuid);
        if (task != null) {
            task.cancel();
        }
    }

    /**
     * Cancels every pending timeout. Called during plugin shutdown.
     */
    public void shutdown() {
        pending.values().forEach(ScheduledTask::cancel);
        pending.clear();
    }
}
