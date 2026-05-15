package net.rafalohaki.veloauth.auth.totp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class TotpServiceTest {

    /**
     * RFC 6238 Appendix B test vectors. The seed is the ASCII string {@code "12345678901234567890"}
     * (20 bytes), and the published codes are for SHA-1 at specific Unix timestamps. We assert
     * that {@link TotpService#generateCode} reproduces the published codes exactly.
     */
    @ParameterizedTest(name = "RFC 6238 §B vector @ t={0}s → {1}")
    @CsvSource({
            "59,           94287082",   // RFC truncates to 8 digits in §B; we keep last 6 below
            "1111111109,   07081804",
            "1111111111,   14050471",
            "1234567890,   89005924",
            "2000000000,   69279037",
            "20000000000,  65353130"
    })
    void generateCode_matchesRfc6238Vectors(long timestamp, String expected8Digits) {
        byte[] key = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        long window = timestamp / 30L;
        int code = TotpService.generateCode(key, window);
        // We emit 6 digits → take the last 6 chars of the published 8-digit code.
        int expected6 = Integer.parseInt(expected8Digits.substring(expected8Digits.length() - 6));
        assertEquals(expected6, code,
                "RFC 6238 vector mismatch at t=" + timestamp);
    }

    @Test
    void generateSecret_produces32CharsBase32() {
        TotpService svc = new TotpService();
        String secret = svc.generateSecret();
        assertEquals(32, secret.length(),
                "20-byte secret must encode to exactly 32 Base32 chars");
        // All chars must be in the RFC 4648 Base32 alphabet (uppercase + 2-7).
        assertTrue(secret.chars().allMatch(c ->
                (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')));
    }

    @Test
    void generateSecret_returnsDifferentValuesEachCall() {
        TotpService svc = new TotpService();
        String a = svc.generateSecret();
        String b = svc.generateSecret();
        assertNotEquals(a, b, "Two consecutive generateSecret() calls must not collide");
    }

    @Test
    void verify_acceptsCurrentWindowCode() {
        TotpService svc = new TotpService();
        String secret = svc.generateSecret();
        long window = svc.currentWindow();
        byte[] key = Base32.decode(secret);
        int expected = TotpService.generateCode(key, window);
        String code = String.format("%06d", expected);
        assertTrue(svc.verify(secret, code), "Current-window code must verify");
    }

    @Test
    void verify_acceptsAdjacentWindowsWithinTolerance() {
        TotpService svc = new TotpService(1);
        String secret = svc.generateSecret();
        long window = svc.currentWindow();
        byte[] key = Base32.decode(secret);
        // ±1 window must verify under the default tolerance of 1.
        for (int offset = -1; offset <= 1; offset++) {
            int code = TotpService.generateCode(key, window + offset);
            assertTrue(svc.verify(secret, String.format("%06d", code)),
                    "Window offset " + offset + " must verify under tolerance=1");
        }
    }

    @Test
    void verify_rejectsCodeOutsideTolerance() {
        TotpService svc = new TotpService(1);
        String secret = svc.generateSecret();
        byte[] key = Base32.decode(secret);
        long window = svc.currentWindow();
        // ±2 windows is outside ±1 tolerance — must reject.
        int futureCode = TotpService.generateCode(key, window + 2);
        assertFalse(svc.verify(secret, String.format("%06d", futureCode)),
                "Code 2 windows ahead must NOT verify under tolerance=1");
    }

    @Test
    void verify_rejectsMalformedInput() {
        TotpService svc = new TotpService();
        String secret = svc.generateSecret();
        assertFalse(svc.verify(secret, null));
        assertFalse(svc.verify(secret, ""));
        assertFalse(svc.verify(secret, "12345"));        // 5 digits
        assertFalse(svc.verify(secret, "1234567"));      // 7 digits
        assertFalse(svc.verify(secret, "abcdef"));       // non-digit
        assertFalse(svc.verify(secret, "12345a"));       // non-digit
        assertFalse(svc.verify(null, "123456"));
        assertFalse(svc.verify("", "123456"));
        // Invalid Base32 secret must return false (not throw) — defensive on bad DB data.
        assertFalse(svc.verify("!!!invalid!!!", "123456"));
    }

    @Test
    void otpAuthUri_followsGoogleAuthenticatorFormat() {
        TotpService svc = new TotpService();
        String secret = "JBSWY3DPEHPK3PXP";
        String uri = svc.otpAuthUri("VeloAuth", "Steve", secret);
        assertTrue(uri.startsWith("otpauth://totp/VeloAuth:Steve?"), uri);
        assertTrue(uri.contains("secret=" + secret), uri);
        assertTrue(uri.contains("issuer=VeloAuth"), uri);
        assertTrue(uri.contains("algorithm=SHA1"), uri);
        assertTrue(uri.contains("digits=6"), uri);
        assertTrue(uri.contains("period=30"), uri);
    }

    @Test
    void otpAuthUri_urlEncodesIssuerAndAccount() {
        TotpService svc = new TotpService();
        // Spaces in issuer / account must be percent-encoded so the URI is RFC-valid.
        String uri = svc.otpAuthUri("My Server", "Some Player", "ABCD");
        assertTrue(uri.contains("My%20Server:Some%20Player"), uri);
        assertTrue(uri.contains("issuer=My%20Server"), uri);
    }

    @Test
    void constructor_rejectsInvalidTolerance() {
        assertThrows(IllegalArgumentException.class, () -> new TotpService(-1));
        assertThrows(IllegalArgumentException.class, () -> new TotpService(6));
    }
}
