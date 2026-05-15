package net.rafalohaki.veloauth.auth.totp;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class Base32Test {

    /**
     * RFC 4648 §10 test vectors — these are the canonical Base32 round-trips that every
     * compliant codec must agree on. Padding is stripped in our encoder, which is why
     * the expected values below have no trailing '='.
     */
    @ParameterizedTest(name = "RFC 4648 vector: \"{0}\" → {1}")
    @CsvSource({
            "'',            ''",
            "'f',           MY",
            "'fo',          MZXQ",
            "'foo',         MZXW6",
            "'foob',        MZXW6YQ",
            "'fooba',       MZXW6YTB",
            "'foobar',      MZXW6YTBOI"
    })
    void encode_rfc4648Vectors(String input, String expected) {
        byte[] bytes = input.getBytes(StandardCharsets.US_ASCII);
        assertEquals(expected, Base32.encode(bytes));
    }

    @ParameterizedTest(name = "RFC 4648 decode: {0} → \"{1}\"")
    @CsvSource({
            "'',           ''",
            "MY,           'f'",
            "MZXQ,         'fo'",
            "MZXW6,        'foo'",
            "MZXW6YQ,      'foob'",
            "MZXW6YTB,     'fooba'",
            "MZXW6YTBOI,   'foobar'"
    })
    void decode_rfc4648Vectors(String input, String expected) {
        byte[] decoded = Base32.decode(input);
        assertEquals(expected, new String(decoded, StandardCharsets.US_ASCII));
    }

    @Test
    void roundTrip_random20Bytes_matchesInput() {
        // A 20-byte (160-bit) secret encodes to exactly 32 Base32 chars — the standard
        // TOTP layout and what fits in our VARCHAR(32) TOTPTOKEN column.
        byte[] secret = new byte[20];
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) (i * 7 + 13);
        }
        String encoded = Base32.encode(secret);
        assertEquals(32, encoded.length(), "20-byte secret should encode to exactly 32 chars");
        assertArrayEquals(secret, Base32.decode(encoded));
    }

    @Test
    void decode_acceptsLowercase() {
        assertArrayEquals(Base32.decode("MZXW6YTBOI"), Base32.decode("mzxw6ytboi"));
    }

    @Test
    void decode_ignoresWhitespaceAndPadding() {
        // Operators sometimes paste secrets in groups for readability: "ABCD EFGH ..."
        // and authenticator apps often emit the padded form: "MY======".
        assertArrayEquals(Base32.decode("MZXW6YTBOI"), Base32.decode("MZXW 6YTB OI"));
        assertArrayEquals(Base32.decode("MY"), Base32.decode("MY======"));
    }

    @Test
    void decode_rejectsInvalidChar() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> Base32.decode("MZXW0YQ"));
        assertTrue(e.getMessage().contains("0"));
    }

    @Test
    void decode_nullInputThrows() {
        assertThrows(IllegalArgumentException.class, () -> Base32.decode(null));
    }

    @Test
    void encode_nullOrEmptyReturnsEmpty() {
        assertEquals("", Base32.encode(null));
        assertEquals("", Base32.encode(new byte[0]));
    }
}
