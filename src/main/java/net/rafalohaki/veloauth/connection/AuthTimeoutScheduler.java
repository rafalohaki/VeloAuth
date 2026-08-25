package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.scheduler.ScheduledTask;
import net.kyori.adventure.text.format.NamedTextColor;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.config.Settings;
import net.rafalohaki.veloauth.i18n.Messages;
import net.rafalohaki.veloauth.util.PlayerAddressUtils;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;

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

    /**
     * How often the login/register reminder repeats. The one-shot prompt from
     * {@code AuthListener.sendAuthInstructions} can be lost on the initial join
     * (see issue #48); this cadence keeps the player informed without spamming
     * within the default 300s auth timeout window.
     */
    private static final int REMINDER_INTERVAL_SECONDS = 10;

    private final VeloAuth plugin;
    private final Settings settings;
    private final Messages messages;
    private final AuthCache authCache;
    private final ConnectionManager connectionManager;
    private final Logger logger;
    private final ConcurrentMap<UUID, ScheduledTask> pending = new ConcurrentHashMap<>();
    private final ConcurrentMap<UUID, ScheduledTask> reminders = new ConcurrentHashMap<>();
    private final ReentrantLock lifecycleLock = new ReentrantLock();
    private final AtomicBoolean closed = new AtomicBoolean();

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
     * Schedules the repeating login/register reminder and (when enabled) a kick for the given
     * player after {@code auth-server.timeout-seconds}. The reminder is the safety net for a
     * lost one-shot auth prompt: it repeats until the player authenticates, leaves the auth
     * server, or disconnects. Any previously scheduled tasks for the same UUID are cancelled
     * first.
     */
    public void schedule(Player player) {
        int seconds = settings.getAuthServerTimeoutSeconds();
        UUID uuid = player.getUniqueId();

        lifecycleLock.lock();
        try {
            if (closed.get()) {
                return;
            }
            scheduleReminderLocked(player, uuid);
            if (seconds > 0) {
                scheduleKickLocked(player, uuid, seconds);
            }
        } finally {
            lifecycleLock.unlock();
        }
        if (logger.isDebugEnabled()) {
            logger.debug(AUTH_MARKER, "Auth timeout scheduled for {} ({}s)",
                    player.getUsername(), seconds);
        }
    }

    private void scheduleKickLocked(Player player, UUID uuid, int seconds) {
        ScheduledTaskRegistry.replace(pending, uuid, callback ->
                plugin.getServer().getScheduler().buildTask(plugin, callback)
                        .delay(seconds, TimeUnit.SECONDS)
                        .schedule(), () -> {
            if (closed.get() || !player.isActive()) {
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

            player.disconnect(messages.component("auth.timeout.kick", NamedTextColor.RED, seconds));
            if (logger.isInfoEnabled()) {
                logger.info(AUTH_MARKER,
                        "Kicked player {} after {}s auth timeout (no login/register)",
                        player.getUsername(), seconds);
            }
        });
    }

    private void scheduleReminderLocked(Player player, UUID uuid) {
        ScheduledTask task = plugin.getServer().getScheduler()
                .buildTask(plugin, (Consumer<ScheduledTask>) self -> runReminder(player, self))
                .delay(REMINDER_INTERVAL_SECONDS, TimeUnit.SECONDS)
                .repeat(REMINDER_INTERVAL_SECONDS, TimeUnit.SECONDS)
                .schedule();
        ScheduledTask previous = reminders.put(uuid, task);
        if (previous != null) {
            previous.cancel();
        }
    }

    private void runReminder(Player player, ScheduledTask self) {
        if (closed.get() || !player.isActive()
                || isAuthorizedAndStillOnAuthServer(player)
                || !connectionManager.isPlayerOnAuthServer(player)) {
            reminders.remove(player.getUniqueId(), self);
            self.cancel();
            return;
        }
        player.sendMessage(messages.component("auth.prompt.generic", NamedTextColor.YELLOW));
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
        ScheduledTaskRegistry.cancel(pending, uuid);
        ScheduledTaskRegistry.cancel(reminders, uuid);
    }

    /**
     * Cancels every pending timeout. Called during plugin shutdown.
     */
    public void shutdown() {
        lifecycleLock.lock();
        try {
            if (closed.compareAndSet(false, true)) {
                ScheduledTaskRegistry.cancelAll(pending);
                ScheduledTaskRegistry.cancelAll(reminders);
            }
        } finally {
            lifecycleLock.unlock();
        }
    }
}
