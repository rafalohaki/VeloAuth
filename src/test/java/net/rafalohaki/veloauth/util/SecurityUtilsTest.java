package net.rafalohaki.veloauth.util;

import net.rafalohaki.veloauth.cache.AuthCache;
import net.rafalohaki.veloauth.command.IPRateLimiter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.InetAddress;
import java.net.UnknownHostException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SecurityUtils}.
 * Verifies brute-force counter resets, block checks, and failed-login registration
 * delegate to AuthCache + IPRateLimiter and behave safely on null addresses.
 */
@ExtendWith(MockitoExtension.class)
class SecurityUtilsTest {

    @Mock
    private AuthCache authCache;

    @Mock
    private IPRateLimiter rateLimiter;

    private InetAddress address() throws UnknownHostException {
        return InetAddress.getByName("203.0.113.42");
    }

    @Test
    void resetSecurityCounters_withAddress_delegatesToCacheAndLimiter() throws UnknownHostException {
        InetAddress addr = address();

        SecurityUtils.resetSecurityCounters(addr, "alice", authCache, rateLimiter);

        verify(authCache).resetLoginAttempts(addr, "alice");
        verify(rateLimiter).reset(addr);
    }

    @Test
    void resetSecurityCounters_nullAddress_noInteractions() {
        SecurityUtils.resetSecurityCounters(null, "alice", authCache, rateLimiter);

        verify(authCache, never()).resetLoginAttempts(any(), any());
        verify(rateLimiter, never()).reset(any());
    }

    @Test
    void isBruteForceBlocked_blockedAddress_returnsTrue() throws UnknownHostException {
        InetAddress addr = address();
        when(authCache.isBlocked(addr, "alice")).thenReturn(true);

        assertTrue(SecurityUtils.isBruteForceBlocked(addr, "alice", authCache));
    }

    @Test
    void isBruteForceBlocked_notBlocked_returnsFalse() throws UnknownHostException {
        InetAddress addr = address();
        when(authCache.isBlocked(addr, "alice")).thenReturn(false);

        assertFalse(SecurityUtils.isBruteForceBlocked(addr, "alice", authCache));
    }

    @Test
    void isBruteForceBlocked_nullAddress_returnsFalseWithoutInteraction() {
        assertFalse(SecurityUtils.isBruteForceBlocked(null, "alice", authCache));

        verify(authCache, never()).isBlocked(any(), any());
    }

    @Test
    void registerFailedLogin_belowThreshold_returnsFalse() throws UnknownHostException {
        InetAddress addr = address();
        when(authCache.registerFailedLogin(addr, "alice")).thenReturn(false);

        assertFalse(SecurityUtils.registerFailedLogin(addr, "alice", authCache));
        verify(authCache).registerFailedLogin(addr, "alice");
    }

    @Test
    void registerFailedLogin_thresholdReached_returnsTrue() throws UnknownHostException {
        InetAddress addr = address();
        when(authCache.registerFailedLogin(addr, "alice")).thenReturn(true);

        assertTrue(SecurityUtils.registerFailedLogin(addr, "alice", authCache));
    }

    @Test
    void registerFailedLogin_nullAddress_returnsFalseWithoutInteraction() {
        assertFalse(SecurityUtils.registerFailedLogin(null, "alice", authCache));

        verify(authCache, never()).registerFailedLogin(any(), any());
    }

    private static <T> T any() {
        return org.mockito.ArgumentMatchers.any();
    }
}
