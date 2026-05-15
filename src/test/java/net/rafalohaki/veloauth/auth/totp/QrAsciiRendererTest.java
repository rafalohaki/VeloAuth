package net.rafalohaki.veloauth.auth.totp;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class QrAsciiRendererTest {

    @Test
    void render_producesNonEmptyOutput() {
        String uri = "otpauth://totp/VeloAuth:Steve?secret=JBSWY3DPEHPK3PXP"
                + "&issuer=VeloAuth&algorithm=SHA1&digits=6&period=30";
        String qr = QrAsciiRenderer.render(uri);
        assertNotNull(qr);
        assertTrue(qr.length() > 0);
    }

    @Test
    void render_outputIsRectangularGrid() {
        // Each row should be the same width — sanity check for a properly-aligned QR matrix.
        String qr = QrAsciiRenderer.render("otpauth://totp/x:y?secret=ABCD&issuer=x");
        String[] rows = qr.split("\n");
        assertTrue(rows.length >= 5, "QR must have at least a few rows");
        int firstWidth = rows[0].length();
        for (int i = 1; i < rows.length; i++) {
            // Last row may not have a trailing space depending on render — allow ±0.
            assertEquals(firstWidth, rows[i].length(),
                    "Row " + i + " has different width than row 0");
        }
    }

    @Test
    void render_usesOnlyExpectedCharacters() {
        // Only the block + space chars we picked + newlines. Anything else would
        // mean the renderer accidentally emitted ANSI escapes or stray glyphs.
        String qr = QrAsciiRenderer.render("otpauth://totp/x:y?secret=ABCD");
        for (char c : qr.toCharArray()) {
            assertTrue(c == '█' || c == ' ' || c == '\n',
                    "Unexpected char in QR output: U+" + Integer.toHexString(c));
        }
    }

    @Test
    void render_nullOrBlankThrows() {
        assertThrows(IllegalArgumentException.class, () -> QrAsciiRenderer.render(null));
        assertThrows(IllegalArgumentException.class, () -> QrAsciiRenderer.render(""));
        assertThrows(IllegalArgumentException.class, () -> QrAsciiRenderer.render("   "));
    }
}
