package net.rafalohaki.veloauth.auth.totp;

import io.nayuki.qrcodegen.QrCode;

/**
 * Renders an {@code otpauth://} URI as a QR code drawn from Unicode block
 * characters, suitable for posting into Minecraft's monospaced chat.
 * <p>
 * Each QR module is drawn as two characters wide ({@code "██"} for dark,
 * {@code "  "} for light) so the result is roughly square in MC's chat font —
 * Minecraft uses a font where each character is taller than wide, so a single
 * char per module would render as a stretched-out rectangle that scanners
 * struggle with.
 * <p>
 * A 2-module quiet zone is drawn on all sides. RFC suggests 4 modules, but
 * 2 works reliably with modern phone cameras and saves chat real estate;
 * if scanners complain in practice the constant {@link #QUIET_ZONE} is the
 * single knob to tune.
 */
public final class QrAsciiRenderer {

    /** Two-char-wide "dark module". Two columns to compensate for MC font aspect ratio. */
    private static final String DARK = "██";
    /** Two spaces for a light module — same width as DARK. */
    private static final String LIGHT = "  ";
    /** Quiet-zone margin in modules, on every side. */
    private static final int QUIET_ZONE = 2;

    private QrAsciiRenderer() {}

    /**
     * Encodes the text into a QR with the lowest error-correction level (= largest
     * possible payload for a given QR version), then renders it. {@code Ecc.LOW}
     * is fine because the QR is read from a fully-known-clean source (a chat
     * message), not from a scratched real-world surface.
     */
    public static String render(String text) {
        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("QR text must not be null or blank");
        }
        QrCode qr = QrCode.encodeText(text, QrCode.Ecc.LOW);
        int size = qr.size;
        int totalRows = size + QUIET_ZONE * 2;
        int charsPerRow = totalRows * DARK.length();

        StringBuilder sb = new StringBuilder((totalRows + 1) * (charsPerRow + 1));
        appendQuietRows(sb, QUIET_ZONE, totalRows);
        for (int y = 0; y < size; y++) {
            appendHorizontalQuiet(sb, QUIET_ZONE);
            for (int x = 0; x < size; x++) {
                sb.append(qr.getModule(x, y) ? DARK : LIGHT);
            }
            appendHorizontalQuiet(sb, QUIET_ZONE);
            sb.append('\n');
        }
        appendQuietRows(sb, QUIET_ZONE, totalRows);
        return sb.toString();
    }

    private static void appendQuietRows(StringBuilder sb, int rows, int totalCols) {
        for (int r = 0; r < rows; r++) {
            sb.append(LIGHT.repeat(totalCols));
            sb.append('\n');
        }
    }

    private static void appendHorizontalQuiet(StringBuilder sb, int modules) {
        sb.append(LIGHT.repeat(modules));
    }
}
