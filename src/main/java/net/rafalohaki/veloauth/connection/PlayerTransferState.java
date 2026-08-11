package net.rafalohaki.veloauth.connection;

import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.scheduler.ScheduledTask;

import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Connection-owned mutable transfer state for one concrete player generation. */
final class PlayerTransferState {
    private final UUID playerId;
    private final Player owner;
    private final long generation;
    private final AtomicInteger retryAttempts = new AtomicInteger();
    private final AtomicBoolean backendConnectionActive = new AtomicBoolean();
    private final AtomicBoolean timeoutRetryActive = new AtomicBoolean();
    private final AtomicReference<String> forcedHostTarget = new AtomicReference<>();
    private final AtomicReference<ScheduledTask> pendingTransfer = new AtomicReference<>();
    private final AtomicReference<ScheduledTask> backendWait = new AtomicReference<>();
    private final AtomicReference<ScheduledTask> timeoutRetry = new AtomicReference<>();

    PlayerTransferState(UUID playerId, Player owner, long generation) {
        this.playerId = Objects.requireNonNull(playerId, "playerId");
        this.owner = Objects.requireNonNull(owner, "owner");
        this.generation = generation;
    }

    UUID playerId() {
        return playerId;
    }

    Player owner() {
        return owner;
    }

    long generation() {
        return generation;
    }

    AtomicInteger retryAttempts() {
        return retryAttempts;
    }

    AtomicBoolean backendConnectionActive() {
        return backendConnectionActive;
    }

    AtomicBoolean timeoutRetryActive() {
        return timeoutRetryActive;
    }

    AtomicReference<String> forcedHostTarget() {
        return forcedHostTarget;
    }

    AtomicReference<ScheduledTask> pendingTransfer() {
        return pendingTransfer;
    }

    AtomicReference<ScheduledTask> backendWait() {
        return backendWait;
    }

    AtomicReference<ScheduledTask> timeoutRetry() {
        return timeoutRetry;
    }
}
