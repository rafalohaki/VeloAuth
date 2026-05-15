package net.rafalohaki.veloauth.auth.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * RFC 6238 Time-based One-Time Password generator and verifier.
 * <p>
 * Hardcoded to the parameter set every authenticator app speaks by default
 * (HMAC-SHA1, 30-second time step, 6-digit codes, 160-bit secret). Deviating from
 * those values would break compatibility with Google Authenticator / Authy /
 * Aegis / FreeOTP and with the existing LimboAuth tokens that operators may be
 * migrating in — none of which is worth exposing as a config knob.
 * <p>
 * Verification accepts codes from the current window ± {@code windowTolerance}
 * (default ±1, = ±30 seconds) to tolerate clock skew between the server and the
 * player's phone. Brute-force protection lives at the call site — this class
 * does no rate-limiting on its own.
 */
public final class TotpService {

    /** RFC 6238: 6 decimal digits per code. */
    private static final int CODE_DIGITS = 6;
    /** RFC 6238 §5.2: 30-second window is the universal default. */
    private static final long TIME_STEP_SECONDS = 30L;
    /** RFC 6238 §3.B: 160-bit shared secret (HMAC-SHA1 block size). */
    private static final int SECRET_BYTES = 20;
    /** 10⁶ — modulus for the 6-digit truncation. */
    private static final int CODE_MODULUS = 1_000_000;
    /** Maximum ±tolerance in windows, to keep the verify loop bounded. */
    private static final int MAX_TOLERANCE = 5;

    private final int windowTolerance;
    private final SecureRandom random;

    /** Builds a service with the default ±1 window (= ±30s) drift tolerance. */
    public TotpService() {
        this(1);
    }

    public TotpService(int windowTolerance) {
        if (windowTolerance < 0 || windowTolerance > MAX_TOLERANCE) {
            throw new IllegalArgumentException(
                "windowTolerance must be in [0, " + MAX_TOLERANCE + "], got " + windowTolerance);
        }
        this.windowTolerance = windowTolerance;
        this.random = new SecureRandom();
    }

    /**
     * Generates a fresh 160-bit shared secret, Base32-encoded — ready to drop into
     * the {@code TOTPTOKEN} column and into an {@code otpauth://} URI.
     */
    public String generateSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        random.nextBytes(bytes);
        return Base32.encode(bytes);
    }

    /**
     * Verifies a 6-digit code against the given Base32 secret. Rejects malformed
     * input ({@code null}, non-digit, wrong length) without leaking the reason.
     * <p>
     * The accept-window is ±{@link #windowTolerance} steps around the current
     * 30-second slot, which makes the verification reliable for phones whose
     * clock drifts by up to {@code tolerance × 30s}.
     */
    public boolean verify(String secretBase32, String code) {
        if (secretBase32 == null || secretBase32.isBlank() || code == null) {
            return false;
        }
        if (code.length() != CODE_DIGITS) {
            return false;
        }
        int input;
        try {
            input = Integer.parseInt(code);
        } catch (NumberFormatException e) {
            return false;
        }
        byte[] key;
        try {
            key = Base32.decode(secretBase32);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (key.length == 0) {
            return false;
        }
        long window = currentWindow();
        for (int offset = -windowTolerance; offset <= windowTolerance; offset++) {
            if (input == generateCode(key, window + offset)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Builds the {@code otpauth://} URI consumed by every modern authenticator app
     * for QR-code enrollment. Format follows Google Authenticator's
     * <a href="https://github.com/google/google-authenticator/wiki/Key-Uri-Format">key-uri-format</a>:
     * <pre>otpauth://totp/{issuer}:{account}?secret={base32}&issuer={issuer}&algorithm=SHA1&digits=6&period=30</pre>
     */
    public String otpAuthUri(String issuer, String account, String secretBase32) {
        if (issuer == null || account == null || secretBase32 == null) {
            throw new IllegalArgumentException("issuer/account/secret must not be null");
        }
        String encodedIssuer = urlEncode(issuer);
        String encodedAccount = urlEncode(account);
        return "otpauth://totp/" + encodedIssuer + ":" + encodedAccount
                + "?secret=" + secretBase32
                + "&issuer=" + encodedIssuer
                + "&algorithm=SHA1&digits=" + CODE_DIGITS
                + "&period=" + TIME_STEP_SECONDS;
    }

    /** Public for tests that need to inject a fixed timestamp. */
    long currentWindow() {
        return System.currentTimeMillis() / 1000L / TIME_STEP_SECONDS;
    }

    /**
     * Single-window code generator — RFC 6238 algorithm step.
     * Package-private so {@code TotpServiceTest} can pin the RFC test vectors.
     */
    static int generateCode(byte[] key, long window) {
        byte[] msg = ByteBuffer.allocate(Long.BYTES).putLong(window).array();
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(msg);
            int offset = hash[hash.length - 1] & 0x0f;
            int binary = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);
            return binary % CODE_MODULUS;
        } catch (GeneralSecurityException e) {
            // HmacSHA1 is mandatory in every JDK since 1.4 — if it's missing the JVM is broken.
            throw new IllegalStateException("HmacSHA1 algorithm not available in JDK", e);
        }
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
