package net.rafalohaki.veloauth.premium;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.UUID;
import javax.annotation.Nullable;

/**
 * Verifies Mojang-issued player profile keys ("chat session" certificates).
 * <p>
 * Right after joining a world every client signed in with a real Microsoft/Mojang account sends
 * its profile key ({@code chat_session_update}): an RSA public key, its expiry and a signature
 * made by Mojang over {@code profileUUID + expiry + key}. A client without a paid account (any
 * cracked launcher) cannot obtain such a certificate, so a signature that verifies for a given
 * profile UUID is cryptographic proof that the connection belongs to the owner of that Mojang
 * profile - without ever sending an encryption request.
 */
public final class MojangProfileKeyVerifier {

    private static final String RESOURCE = "/yggdrasil_session_pubkey.der";
    private static final String ALGORITHM = "SHA1withRSA";
    private static final int MAX_KEY_BYTES = 512;
    private static final int MAX_SIGNATURE_BYTES = 4096;

    private static final PublicKey YGGDRASIL_SESSION_KEY = loadKey();

    private MojangProfileKeyVerifier() {
    }

    /** Whether the Mojang session public key could be loaded. */
    public static boolean isAvailable() {
        return YGGDRASIL_SESSION_KEY != null;
    }

    /**
     * Verifies a profile key for the given profile.
     *
     * @param profile   Mojang profile UUID the key must be bound to
     * @param expiresAt key expiry (epoch millis) as sent by the client
     * @param keyBytes  X.509 encoded RSA public key as sent by the client
     * @param signature Mojang signature as sent by the client
     * @param nowMillis current time
     * @return {@code true} only when the signature is valid for exactly this profile and not expired
     */
    public static boolean verify(@Nullable UUID profile, long expiresAt, @Nullable byte[] keyBytes,
                                 @Nullable byte[] signature, long nowMillis) {
        if (YGGDRASIL_SESSION_KEY == null || profile == null || expiresAt <= nowMillis
                || !withinLimit(keyBytes, MAX_KEY_BYTES) || !withinLimit(signature, MAX_SIGNATURE_BYTES)) {
            return false;
        }
        try {
            // The client sends the X.509 encoding; Mojang signed exactly these bytes.
            KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));
            ByteBuffer data = ByteBuffer.allocate(Long.BYTES * 3 + keyBytes.length);
            data.putLong(profile.getMostSignificantBits());
            data.putLong(profile.getLeastSignificantBits());
            data.putLong(expiresAt);
            data.put(keyBytes);
            // SHA1withRSA is the algorithm Mojang's session server signs profile keys with; the
            // vanilla client and server verify with the same algorithm. It cannot be upgraded
            // on the receiving side, and it is only used to verify, never to sign.
            Signature verifier = Signature.getInstance(ALGORITHM); // nosemgrep: java.lang.security.audit.crypto.weak-hash
            verifier.initVerify(YGGDRASIL_SESSION_KEY);
            verifier.update(data.array());
            return verifier.verify(signature);
        } catch (GeneralSecurityException | RuntimeException e) {
            return false;
        }
    }

    private static boolean withinLimit(@Nullable byte[] bytes, int max) {
        return bytes != null && bytes.length > 0 && bytes.length <= max;
    }

    @Nullable
    private static PublicKey loadKey() {
        try (InputStream in = MojangProfileKeyVerifier.class.getResourceAsStream(RESOURCE)) {
            if (in == null) {
                return null;
            }
            byte[] bytes = in.readAllBytes();
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(bytes));
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            return null;
        }
    }
}
