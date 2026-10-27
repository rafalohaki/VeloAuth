package net.rafalohaki.veloauth.dialog;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import net.rafalohaki.veloauth.VeloAuth;
import net.rafalohaki.veloauth.connection.ConnectionManager;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Predicate;

/**
 * Safety net after a successful dialog login. Velocity resumes the suspended PostLoginEvent and
 * picks the initial server itself; a few seconds later this guard verifies that the player really
 * left the configuration phase. A player still on no server is connected to a backend explicitly,
 * a player that landed on the auth server is handed to VeloAuth's regular auto-transfer.
 */
final class DialogForwardingGuard {

    private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
    private static final int[] CHECK_DELAYS_SECONDS = {3, 8, 15};

    private final VeloAuth plugin;
    private final Logger logger;
    private final Predicate<Player> authenticated;
    private final BooleanSupplier closed;

    DialogForwardingGuard(VeloAuth plugin, Predicate<Player> authenticated, BooleanSupplier closed) {
        this.plugin = plugin;
        this.logger = plugin.getLogger();
        this.authenticated = authenticated;
        this.closed = closed;
    }

    void watch(Player player) {
        schedule(player, 1);
    }

    private void schedule(Player player, int attempt) {
        if (attempt > CHECK_DELAYS_SECONDS.length) {
            return;
        }
        plugin.getServer().getScheduler()
                .buildTask(plugin, () -> check(player, attempt))
                .delay(CHECK_DELAYS_SECONDS[attempt - 1], TimeUnit.SECONDS)
                .schedule();
    }

    private void check(Player player, int attempt) {
        ConnectionManager connections = plugin.getConnectionManager();
        if (!stillWaiting(player) || connections == null) {
            return;
        }
        Optional<ServerConnection> current = player.getCurrentServer();
        if (current.isPresent()) {
            if (connections.isAuthServer(current.get().getServer())) {
                logger.info(AUTH_MARKER, "Dialog-authenticated player {} is on the auth server - auto-transferring to backend",
                        player.getUsername());
                connections.autoTransferFromAuthServerToBackend(player);
            }
            return;
        }
        connections.findAvailableBackendServerForInitialConnectionAsync()
                .thenAccept(backend -> connectExplicitly(player, attempt, backend));
    }

    private void connectExplicitly(Player player, int attempt, Optional<RegisteredServer> backend) {
        if (!stillWaiting(player) || player.getCurrentServer().isPresent()) {
            return;
        }
        int waited = CHECK_DELAYS_SECONDS[attempt - 1];
        if (backend.isEmpty()) {
            logger.warn(AUTH_MARKER, "Player {} is still not on any server {}s after dialog login and no backend is available",
                    player.getUsername(), waited);
            schedule(player, attempt + 1);
            return;
        }
        logger.warn(AUTH_MARKER, "Player {} is still not on any server {}s after dialog login - connecting to {} explicitly",
                player.getUsername(), waited, backend.get().getServerInfo().getName());
        player.createConnectionRequest(backend.get()).connect().whenComplete((result, throwable) -> {
            if (throwable != null || result == null || !result.isSuccessful()) {
                schedule(player, attempt + 1);
            }
        });
    }

    private boolean stillWaiting(Player player) {
        return !closed.getAsBoolean() && player.isActive() && authenticated.test(player);
    }
}
