package net.rafalohaki.veloauth.command;

import com.velocitypowered.api.proxy.Player;
import net.rafalohaki.veloauth.model.RegisteredPlayer;

import java.net.InetAddress;

/**
 * Immutable context for authentication operations.
 * Carries validated player data through the command pipeline,
 * reducing parameter passing between methods.
 */
record AuthenticationContext(
        Player player,
        String username,
        InetAddress playerAddress,
        RegisteredPlayer registeredPlayer
) {
}
