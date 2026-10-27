package net.rafalohaki.veloauth.premium;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.nio.ByteBuffer;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class MojangProfileKeyVerifierTest {

    private static final UUID PROFILE = UUID.fromString("069a79f4-44e9-4726-a5be-fca90e38aaf5");

    @Test
    void mojangSessionKeyIsBundled() {
        assertTrue(MojangProfileKeyVerifier.isAvailable());
    }

    @Test
    void rejectsNullsAndExpiredKeys() throws Exception {
        byte[] key = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic().getEncoded();
        long now = 1_700_000_000_000L;
        assertFalse(MojangProfileKeyVerifier.verify(null, now + 1000, key, new byte[256], now));
        assertFalse(MojangProfileKeyVerifier.verify(PROFILE, now + 1000, null, new byte[256], now));
        assertFalse(MojangProfileKeyVerifier.verify(PROFILE, now + 1000, key, null, now));
        assertFalse(MojangProfileKeyVerifier.verify(PROFILE, now - 1, key, new byte[256], now));
    }

    @Test
    void rejectsSignatureFromAnyKeyOtherThanMojang() throws Exception {
        // A perfectly well-formed signature produced by a non-Mojang key must fail: this is the
        // exact trick a modified launcher would try.
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair forger = generator.generateKeyPair();
        byte[] playerKey = generator.generateKeyPair().getPublic().getEncoded();
        long expiry = 1_700_000_000_000L;
        ByteBuffer payload = ByteBuffer.allocate(24 + playerKey.length);
        payload.putLong(PROFILE.getMostSignificantBits()).putLong(PROFILE.getLeastSignificantBits())
                .putLong(expiry).put(playerKey);
        // Same algorithm Mojang uses for profile keys; this test forges a signature with the wrong key.
        Signature signer = Signature.getInstance("SHA1withRSA"); // nosemgrep: java.lang.security.audit.crypto.weak-hash
        signer.initSign(forger.getPrivate());
        signer.update(payload.array());
        byte[] forged = signer.sign();
        assertFalse(MojangProfileKeyVerifier.verify(PROFILE, expiry, playerKey, forged, expiry - 1000));
    }

    @Test
    void garbageSignatureDoesNotThrow() {
        assertFalse(MojangProfileKeyVerifier.verify(PROFILE, Long.MAX_VALUE, new byte[] {1, 2, 3},
                new byte[] {4, 5, 6}, 0L));
    }
}
