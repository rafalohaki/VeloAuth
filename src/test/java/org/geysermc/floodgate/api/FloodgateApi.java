package org.geysermc.floodgate.api;

import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Minimal test double for the optional Floodgate API loaded through reflection. */
public final class FloodgateApi {

    private static volatile FloodgateApi instance;
    private static volatile Thread lastGetPlayersThread;

    private final String playerPrefix;
    private final Set<UUID> playerIds;
    private final List<PlayerView> players;

    private FloodgateApi(String playerPrefix, Collection<UUID> playerIds, Collection<PlayerView> players) {
        this.playerPrefix = playerPrefix;
        this.playerIds = Set.copyOf(playerIds);
        this.players = List.copyOf(players);
    }

    public static FloodgateApi getInstance() {
        return instance;
    }

    public static void install(String playerPrefix, Collection<UUID> playerIds,
                               Collection<PlayerView> players) {
        instance = new FloodgateApi(playerPrefix, playerIds, players);
    }

    public static void clear() {
        instance = null;
        lastGetPlayersThread = null;
    }

    public static Thread getLastGetPlayersThread() {
        return lastGetPlayersThread;
    }

    public boolean isFloodgatePlayer(UUID playerId) {
        return playerIds.contains(playerId);
    }

    public Collection<PlayerView> getPlayers() {
        lastGetPlayersThread = Thread.currentThread();
        return players;
    }

    public String getPlayerPrefix() {
        return playerPrefix;
    }

    public record PlayerView(String correctUsername, String javaUsername, String username) {

        public PlayerView(String correctUsername, String javaUsername) {
            this(correctUsername, javaUsername, javaUsername);
        }

        public String getCorrectUsername() {
            return correctUsername;
        }

        public String getJavaUsername() {
            return javaUsername;
        }

        public String getUsername() {
            return username;
        }
    }
}
