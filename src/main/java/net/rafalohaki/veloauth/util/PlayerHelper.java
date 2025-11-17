package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.proxy.Player;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.UUID;

/**
 * Utility class for common player operations.
 * Centralizes frequently used player-related functionality to reduce code duplication.
 */
public final class PlayerHelper {

    private PlayerHelper() {
        // Utility class - prevent instantiation
    }

    /**
     * Safely extracts player's IP address as string.
     *
     * @param player The player to extract IP from
     * @return IP address string or "unknown" if not available
     */
    public static String getPlayerIp(Player player) {
        if (player == null) {
            return StringConstants.UNKNOWN;
        }

        var address = player.getRemoteAddress();
        if (address instanceof InetSocketAddress inetAddress) {
            return inetAddress.getAddress().getHostAddress();
        }
        return StringConstants.UNKNOWN;
    }

    /**
     * Safely extracts player's InetAddress.
     *
     * @param player The player to extract address from
     * @return InetAddress or null if not available
     */
    public static InetAddress getPlayerAddress(Player player) {
        if (player == null) {
            return null;
        }

        var address = player.getRemoteAddress();
        if (address instanceof InetSocketAddress inetAddress) {
            return inetAddress.getAddress();
        }
        return null;
    }

    /**
     * Checks if the given CommandSource is a Player.
     *
     * @param source The command source to check
     * @return true if it's a player, false otherwise
     */
    public static boolean isPlayer(CommandSource source) {
        return source instanceof Player;
    }

    /**
     * Safely gets player's UUID.
     *
     * @param player The player to get UUID from
     * @return UUID or null if player is null
     */
    public static UUID getPlayerUuid(Player player) {
        return player != null ? player.getUniqueId() : null;
    }

    /**
     * Safely gets player's username.
     *
     * @param player The player to get username from
     * @return username or "unknown" if player is null
     */
    public static String getPlayerUsername(Player player) {
        return player != null ? player.getUsername() : StringConstants.UNKNOWN;
    }

    /**
     * Sends an error message to a player.
     *
     * @param player  The player to send message to
     * @param message The error message to send
     */
    public static void sendErrorMessage(Player player, String message) {
        if (player != null && message != null) {
            player.sendMessage(Component.text(message, NamedTextColor.RED));
        }
    }

    /**
     * Sends a success message to a player.
     *
     * @param player  The player to send message to
     * @param message The success message to send
     */
    public static void sendSuccessMessage(Player player, String message) {
        if (player != null && message != null) {
            player.sendMessage(Component.text(message, NamedTextColor.GREEN));
        }
    }

    /**
     * Sends a warning message to a player.
     *
     * @param player  The player to send message to
     * @param message The warning message to send
     */
    public static void sendWarningMessage(Player player, String message) {
        if (player != null && message != null) {
            player.sendMessage(Component.text(message, NamedTextColor.YELLOW));
        }
    }

    /**
     * Disconnects a player with an error message.
     *
     * @param player The player to disconnect
     * @param reason The disconnect reason
     */
    public static void disconnectWithError(Player player, String reason) {
        if (player != null && reason != null) {
            player.disconnect(Component.text(reason, NamedTextColor.RED));
        }
    }

    /**
     * Creates a player info string for logging purposes.
     *
     * @param player The player to create info for
     * @return Formatted string with player info
     */
    public static String createPlayerInfo(Player player) {
        if (player == null) {
            return "Player[null]";
        }

        return String.format("Player[%s/%s/%s]",
                player.getUsername(),
                getPlayerIp(player),
                player.getUniqueId());
    }
}
