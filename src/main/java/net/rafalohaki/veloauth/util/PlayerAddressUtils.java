package net.rafalohaki.veloauth.util;

import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.proxy.Player;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.InetSocketAddress;

/**
 * Utility class for extracting IP addresses from players and connection events.
 * Provides consistent address extraction across different event types.
 * <p>
 * Thread-safe: stateless utility methods.
 */
public final class PlayerAddressUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(PlayerAddressUtils.class);

    private PlayerAddressUtils() {
        // Utility class - prevent instantiation
    }

    /**
     * Extracts IP address from player as string.
     * Handles null addresses gracefully by returning "unknown".
     *
     * @param player Player to extract IP from
     * @return IP address string or "unknown" if unavailable
     */
    @javax.annotation.Nonnull
    public static String getPlayerIp(@javax.annotation.Nullable Player player) {
        InetAddress address = getPlayerAddress(player);
        if (address == null) {
            return StringConstants.UNKNOWN;
        }
        String hostAddress = address.getHostAddress();
        return hostAddress != null ? hostAddress : StringConstants.UNKNOWN;
    }

    /**
     * Extracts InetAddress from player.
     * Handles null addresses gracefully by returning null.
     *
     * @param player Player to extract InetAddress from
     * @return InetAddress or null if unavailable
     */
    @javax.annotation.Nullable
    public static InetAddress getPlayerAddress(@javax.annotation.Nullable Player player) {
        if (player == null) {
            return null;
        }
        return extractAddressFromRemote(player.getRemoteAddress(), player.getUsername());
    }

    /**
     * Extracts InetAddress from remote socket address with logging.
     * Shared logic for both Player and PreLoginEvent address extraction.
     *
     * @param address   Remote socket address
     * @param identifier Identifier for logging (username)
     * @return InetAddress or null if unavailable
     */
    @javax.annotation.Nullable
    private static InetAddress extractAddressFromRemote(
            @javax.annotation.Nullable InetSocketAddress address,
            String identifier) {
        if (address == null) {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn("Player {} has null remote address", identifier);
            }
            return null;
        }
        return address.getAddress();
    }

    /**
     * Extracts InetAddress from PreLoginEvent.
     * PreLoginEvent doesn't have a Player object yet, so we extract from connection data.
     * Handles null addresses gracefully by returning null.
     *
     * @param event PreLoginEvent to extract address from
     * @return InetAddress or null if unavailable
     */
    @javax.annotation.Nullable
    public static InetAddress getAddressFromPreLogin(@javax.annotation.Nullable PreLoginEvent event) {
        if (event == null) {
            return null;
        }
        
        try {
            return extractAddressFromConnection(event);
        } catch (Exception e) { // NOSONAR - defensive catch for connection edge cases
            if (LOGGER.isErrorEnabled()) {
                LOGGER.error("Error extracting address from PreLoginEvent", e);
            }
            return null;
        }
    }

    /**
     * Extracts InetAddress from event connection.
     *
     * @param event PreLoginEvent with connection data
     * @return InetAddress or null if unavailable
     */
    @javax.annotation.Nullable
    private static InetAddress extractAddressFromConnection(PreLoginEvent event) {
        com.velocitypowered.api.proxy.InboundConnection connection = event.getConnection();
        if (connection == null) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("PreLoginEvent has null connection");
            }
            return null;
        }
        
        java.net.SocketAddress socketAddress = connection.getRemoteAddress();
        if (socketAddress instanceof InetSocketAddress inetSocketAddress) {
            return extractAddressFromRemote(inetSocketAddress, event.getUsername());
        }
        return null;
    }

    /**
     * Checks if player has a valid remote address.
     * Handles null player and null address gracefully.
     *
     * @param player Player to check
     * @return true if player has valid address, false otherwise
     */
    public static boolean hasValidAddress(@javax.annotation.Nullable Player player) {
        if (player == null) {
            return false;
        }
        
        InetSocketAddress address = player.getRemoteAddress();
        return address != null;
    }
}
