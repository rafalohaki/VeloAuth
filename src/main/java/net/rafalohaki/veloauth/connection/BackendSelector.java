package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.proxy.server.ServerPing;
import net.rafalohaki.veloauth.authserver.AuthServerProvider;
import org.slf4j.Logger;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.locks.ReentrantLock;

/** Selects reachable non-auth backends while preserving Velocity routing priority. */
final class BackendSelector {

    private static final long BACKEND_FALLBACK_WARN_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(30);

    private final ProxyServer proxyServer;
    private final AuthServerProvider authServerProvider;
    private final Logger logger;
    private final ConnectionManager lifecycle;
    private final AtomicLong backendFallbackWarnAfterNanos = new AtomicLong(System.nanoTime());
    private final AtomicInteger suppressedBackendFallbackWarnings = new AtomicInteger();

    BackendSelector(
            ProxyServer proxyServer,
            AuthServerProvider authServerProvider,
            Logger logger,
            ConnectionManager lifecycle) {
        this.proxyServer = proxyServer;
        this.authServerProvider = authServerProvider;
        this.logger = logger;
        this.lifecycle = lifecycle;
    }

    Optional<RegisteredServer> findAvailableBackendServer(PlayerTransferState state) {
        return findAvailableBackendServerAsync(state).join();
    }

    CompletableFuture<Optional<RegisteredServer>> findAvailableBackendServerForInitialConnectionAsync() {
        return findAvailableBackendServerAsync(null);
    }

    private CompletableFuture<Optional<RegisteredServer>> findAvailableBackendServerAsync(
            @javax.annotation.Nullable PlayerTransferState state) {
        if (lifecycle.isIoOwnerUnavailable(state)) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        String authServerName = authServerProvider.serverName();
        List<String> tryServers = proxyServer.getConfiguration().getAttemptConnectionOrder();
        if (logger.isDebugEnabled()) {
            logger.debug("Velocity try servers: {}", tryServers);
        }

        List<RegisteredServer> tryCandidates = tryServers.stream()
                .filter(name -> !name.equals(authServerName))
                .flatMap(name -> proxyServer.getServer(name).stream())
                .toList();

        CompletableFuture<Optional<RegisteredServer>> selection =
                pickFirstAvailable(tryCandidates, state).thenCompose(found -> {
                    if (lifecycle.isIoOwnerUnavailable(state)) {
                        return CompletableFuture.completedFuture(Optional.empty());
                    }
                    if (found.isPresent()) {
                        return CompletableFuture.completedFuture(found);
                    }
                    logBackendFallbackWarning();
                    Set<String> alreadyChecked = tryCandidates.stream()
                            .map(server -> server.getServerInfo().getName())
                            .collect(java.util.stream.Collectors.toUnmodifiableSet());
                    List<RegisteredServer> fallbackCandidates = proxyServer.getAllServers().stream()
                            .filter(server -> !authServerProvider.isAuthServer(server))
                            .filter(server -> !alreadyChecked.contains(server.getServerInfo().getName()))
                            .toList();
                    return pickFirstAvailable(fallbackCandidates, state);
                });
        return rejectUnavailableSelection(state, selection);
    }

    private CompletableFuture<Optional<RegisteredServer>> rejectUnavailableSelection(
            @javax.annotation.Nullable PlayerTransferState state,
            CompletableFuture<Optional<RegisteredServer>> selection) {
        return selection.thenApply(found ->
                lifecycle.isIoOwnerUnavailable(state) ? Optional.empty() : found);
    }

    private void logBackendFallbackWarning() {
        long now = System.nanoTime();
        long warnAfter = backendFallbackWarnAfterNanos.get();
        if (now >= warnAfter && backendFallbackWarnAfterNanos.compareAndSet(
                warnAfter, now + BACKEND_FALLBACK_WARN_INTERVAL_NANOS)) {
            int suppressed = suppressedBackendFallbackWarnings.getAndSet(0);
            if (suppressed == 0) {
                logger.warn("No reachable server from the Velocity try list; attempting fallback");
            } else {
                logger.warn(
                        "No reachable server from the Velocity try list; attempting fallback"
                                + " ({} repeated checks suppressed)",
                        suppressed);
            }
            return;
        }
        suppressedBackendFallbackWarnings.incrementAndGet();
        if (logger.isDebugEnabled()) {
            logger.debug("No reachable server from the Velocity try list; fallback check suppressed");
        }
    }

    CompletableFuture<Optional<RegisteredServer>> findAvailableBackendServerForRetryAsync(
            Player player, PlayerTransferState state) {
        if (lifecycle.isStale(state)) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        return resolveForcedHostTargetAsync(player, state).thenCompose(forcedTarget -> {
            if (lifecycle.isStale(state)) {
                return CompletableFuture.completedFuture(Optional.empty());
            }
            if (forcedTarget.isPresent()) {
                return CompletableFuture.completedFuture(forcedTarget);
            }
            return findAvailableBackendServerAsync(state);
        });
    }

    private CompletableFuture<Optional<RegisteredServer>> pickFirstAvailable(
            List<RegisteredServer> candidates,
            @javax.annotation.Nullable PlayerTransferState state) {
        if (candidates.isEmpty()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        OrderedPingSelection selection = new OrderedPingSelection(candidates);
        for (int index = 0; index < candidates.size() && !selection.future().isDone(); index++) {
            final int candidateIndex = index;
            try {
                CompletableFuture<ServerPing> ping =
                        lifecycle.startPingIfAllowed(state, candidates.get(index));
                if (ping == null) {
                    selection.record(candidateIndex, false);
                } else {
                    ping.whenComplete((ignored, failure) ->
                            selection.record(candidateIndex, failure == null));
                }
            } catch (RuntimeException failure) {
                selection.record(candidateIndex, false);
            }
        }
        return selection.future();
    }

    Optional<RegisteredServer> resolveForcedHostTarget(Player player, PlayerTransferState state) {
        if (lifecycle.isStale(state)) {
            return Optional.empty();
        }
        Optional<ForcedHostTarget> resolvedTarget = findStoredForcedHostTarget(player, state);
        if (resolvedTarget.isEmpty()) {
            return Optional.empty();
        }
        ForcedHostTarget target = resolvedTarget.get();
        if (isServerAvailable(state, target.server(), target.name())) {
            if (lifecycle.isStale(state)) {
                return Optional.empty();
            }
            logger.debug("Forced host target '{}' for {} is available - using it",
                    target.name(), player.getUsername());
            return Optional.of(target.server());
        }

        if (!lifecycle.isStale(state)) {
            logger.warn("Forced host target '{}' for {} is offline - falling back to try list (will retry forced host on next attempt)",
                    target.name(), player.getUsername());
        }
        return Optional.empty();
    }

    private CompletableFuture<Optional<RegisteredServer>> resolveForcedHostTargetAsync(
            Player player, PlayerTransferState state) {
        if (lifecycle.isStale(state)) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        Optional<ForcedHostTarget> resolvedTarget = findStoredForcedHostTarget(player, state);
        if (resolvedTarget.isEmpty()) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        ForcedHostTarget target = resolvedTarget.get();
        CompletableFuture<ServerPing> ping = lifecycle.startPingIfAllowed(state, target.server());
        if (ping == null) {
            return CompletableFuture.completedFuture(Optional.empty());
        }
        return ping.handle((ignored, throwable) ->
                handleForcedHostPingResult(player, state, target, throwable));
    }

    private Optional<ForcedHostTarget> findStoredForcedHostTarget(
            Player player, PlayerTransferState state) {
        if (lifecycle.isStale(state)) {
            return Optional.empty();
        }
        String targetName = state.forcedHostTarget().get();
        if (targetName == null) {
            return Optional.empty();
        }

        String authServerName = authServerProvider.serverName();
        if (targetName.equals(authServerName)) {
            logger.debug("Forced host target for {} is auth server '{}' - ignoring",
                    player.getUsername(), targetName);
            if (!lifecycle.isStale(state)) {
                state.forcedHostTarget().compareAndSet(targetName, null);
            }
            return Optional.empty();
        }

        Optional<RegisteredServer> server = proxyServer.getServer(targetName);
        if (server.isEmpty()) {
            logger.warn("Forced host target '{}' for {} is not registered - falling back to try list",
                    targetName, player.getUsername());
            if (!lifecycle.isStale(state)) {
                state.forcedHostTarget().compareAndSet(targetName, null);
            }
            return Optional.empty();
        }
        return Optional.of(new ForcedHostTarget(targetName, server.get()));
    }

    private Optional<RegisteredServer> handleForcedHostPingResult(
            Player player, PlayerTransferState state, ForcedHostTarget target, Throwable throwable) {
        if (lifecycle.isStale(state)) {
            return Optional.empty();
        }
        if (throwable == null) {
            logger.debug("Forced host target '{}' for {} is available - using it",
                    target.name(), player.getUsername());
            return Optional.of(target.server());
        }
        logger.warn("Forced host target '{}' for {} is offline - falling back to try list "
                        + "(will retry forced host on next attempt)",
                target.name(), player.getUsername());
        return Optional.empty();
    }

    private boolean isServerAvailable(
            PlayerTransferState state, RegisteredServer server, String serverName) {
        try {
            CompletableFuture<ServerPing> ping = lifecycle.startPingIfAllowed(state, server);
            if (ping == null) {
                return false;
            }
            Boolean available = ping.handle((ignored, failure) -> failure == null).join();
            if (Boolean.TRUE.equals(available)) {
                logger.debug("Found available server: {}", serverName);
                return true;
            }
        } catch (RuntimeException failure) {
            logger.debug("Server {} unavailable: {}", serverName, failure.getMessage());
        }
        return false;
    }

    private final class OrderedPingSelection {
        private final List<RegisteredServer> candidates;
        private final AtomicReferenceArray<Boolean> results;
        private final CompletableFuture<Optional<RegisteredServer>> future = new CompletableFuture<>();
        private final ReentrantLock lock = new ReentrantLock();
        private int nextResult;

        private OrderedPingSelection(List<RegisteredServer> candidates) {
            this.candidates = candidates;
            results = new AtomicReferenceArray<>(candidates.size());
        }

        private void record(int index, boolean available) {
            RegisteredServer selected = null;
            boolean shouldComplete = false;
            lock.lock();
            try {
                if (future.isDone() || results.get(index) != null) {
                    return;
                }
                results.set(index, available);
                while (nextResult < candidates.size()) {
                    Boolean result = results.get(nextResult);
                    if (result == null) {
                        break;
                    }
                    if (result) {
                        selected = candidates.get(nextResult);
                        shouldComplete = true;
                        break;
                    }
                    nextResult++;
                }
                if (nextResult == candidates.size()) {
                    shouldComplete = true;
                }
            } finally {
                lock.unlock();
            }
            if (shouldComplete && future.complete(Optional.ofNullable(selected)) && selected != null) {
                logger.debug("Found available server: {}", selected.getServerInfo().getName());
            }
        }

        private CompletableFuture<Optional<RegisteredServer>> future() {
            return future;
        }
    }

    private record ForcedHostTarget(String name, RegisteredServer server) {
    }
}
