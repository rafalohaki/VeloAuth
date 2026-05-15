package net.rafalohaki.veloauth.auth.totp;

import java.util.Arrays;

/**
 * Minimal RFC 4648 Base32 encoder / decoder.
 * <p>
 * Hand-rolled instead of pulled from Apache Commons Codec to keep the dependency
 * footprint minimal — Caffeine + Nayuki + Jackson + ORMLite is enough Java baggage
 * for one Velocity plugin. Just enough surface to serialize TOTP shared secrets:
 * <ul>
 *   <li>uppercase RFC 4648 alphabet ({@code A-Z 2-7}),</li>
 *   <li>decode accepts lowercase + ignores whitespace and {@code =} padding,</li>
 *   <li>encode omits padding (Google Authenticator + LimboAuth + most apps accept
 *       unpadded Base32; 20-byte secret yields exactly 32 chars = no padding needed).</li>
 * </ul>
 */
final class Base32 {

    private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final int[] DECODE = new int[128];
    private static final int BITS_PER_CHAR = 5;
    private static final int BITS_PER_BYTE = 8;
    private static final int LOW_FIVE = 0x1f;
    private static final int LOW_EIGHT = 0xff;

    static {
        Arrays.fill(DECODE, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            DECODE[ALPHABET[i]] = i;
            DECODE[Character.toLowerCase(ALPHABET[i])] = i;
        }
    }

    private Base32() {}

    /**
     * Encodes the given bytes as an unpadded Base32 string.
     * For a 20-byte (160-bit) TOTP secret the output is exactly 32 chars.
     */
    static String encode(byte[] data) {
        if (data == null || data.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder((data.length * BITS_PER_BYTE + BITS_PER_CHAR - 1) / BITS_PER_CHAR);
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << BITS_PER_BYTE) | (b & LOW_EIGHT);
            bits += BITS_PER_BYTE;
            while (bits >= BITS_PER_CHAR) {
                bits -= BITS_PER_CHAR;
                sb.append(ALPHABET[(buffer >>> bits) & LOW_FIVE]);
            }
        }
        if (bits > 0) {
            sb.append(ALPHABET[(buffer << (BITS_PER_CHAR - bits)) & LOW_FIVE]);
        }
        return sb.toString();
    }

    /**
     * Decodes a Base32 string into raw bytes. Tolerant of:
     * <ul>
     *   <li>lowercase letters,</li>
     *   <li>{@code =} padding (stripped),</li>
     *   <li>whitespace (stripped) — operators sometimes paste in groups like
     *       {@code "ABCD EFGH IJKL …"} for readability.</li>
     * </ul>
     *
     * @throws IllegalArgumentException on any character outside the RFC 4648 alphabet.
     */
    static byte[] decode(String s) {
        if (s == null) {
            throw new IllegalArgumentException("Base32 input must not be null");
        }
        String clean = s.replaceAll("[\\s=]", "");
        if (clean.isEmpty()) {
            return new byte[0];
        }
        int outputLen = clean.length() * BITS_PER_CHAR / BITS_PER_BYTE;
        byte[] result = new byte[outputLen];
        int buffer = 0;
        int bits = 0;
        int outIdx = 0;
        for (int i = 0; i < clean.length(); i++) {
            char c = clean.charAt(i);
            int v = (c < DECODE.length) ? DECODE[c] : -1;
            if (v < 0) {
                throw new IllegalArgumentException("Invalid Base32 character: '" + c + "' at index " + i);
            }
            buffer = (buffer << BITS_PER_CHAR) | v;
            bits += BITS_PER_CHAR;
            if (bits >= BITS_PER_BYTE) {
                bits -= BITS_PER_BYTE;
                result[outIdx++] = (byte) ((buffer >>> bits) & LOW_EIGHT);
            }
        }
        return result;
    }
}
