package net.rafalohaki.veloauth.report;

import java.util.regex.Pattern;

/**
 * Redacts secrets from configuration text before uploading to a public paste service.
 * <p>
 * Operates on the raw text of {@code config.yml} and {@code velocity.toml}. The redaction
 * is conservative — it targets known secret-bearing keys by name and replaces their values
 * with {@code <redacted>}. Non-secret values (server names, ports, booleans, timeouts) are
 * preserved so the report stays useful for support diagnosis.
 * <p>
 * Two families of secrets are handled:
 * <ul>
 *   <li><b>YAML key/value pairs</b> — {@code password: "xxx"} → {@code password: "<redacted>"}
 *       via {@link #redactYaml(String)}.</li>
 *   <li><b>Connection URLs with embedded credentials</b> —
 *       {@code postgresql://user:pass@host:5432/db} → {@code postgresql://<redacted>@host:5432/db}
 *       via {@link #redactConnectionUrl(String)}.</li>
 * </ul>
 * The same instance handles both VeloAuth's {@code config.yml} and Velocity's
 * {@code velocity.toml} — the redacted key set is the union of both files' secret keys.
 */
final class ReportRedactor {

    private static final String REDACTED = "<redacted>";

    /**
     * YAML / TOML keys whose value is a secret and must be replaced.
     * Matched case-insensitively, value can be quoted or unquoted, single or double quoted.
     * Handles both YAML ({@code key: value}) and TOML ({@code key = value}) separators.
     * The pattern captures the key, the separator and the optional <em>opening</em> quote so
     * the replacement can mirror the quoting style.
     * <p>
     * The value is consumed by a single greedy {@code .*} anchored to end-of-line rather than
     * the old {@code (.*?)} sandwiched between two independent {@code ["']?} groups. Two adjacent
     * optional quote groups around a lazy capture are mutually ambiguous (both can match the same
     * character), which made the matcher super-linear on long values. A lone greedy {@code .*}
     * against an anchored line is linear. The closing quote is reconstructed in the replacement
     * from the captured opening quote, so an unterminated quoted secret is still redacted (and
     * even normalised to a closed quote) — it never leaks.
     */
    private static final Pattern SECRET_KEY_VALUE = Pattern.compile(
            "(?im)^\\s*(password|ssl-password|webhook-url|forwarding-secret|secret)" +
            "(\\s*[:=]\\s*)([\"']?).*$"
    );

    /**
     * Credentials embedded in a connection URL: {@code scheme://user:pass@host}.
     * Captures everything between {@code://} and the {@code @} and replaces it.
     */
    private static final Pattern URL_CREDENTIALS = Pattern.compile(
            "(://)[^@\\s]+(@)"
    );

    private static final Pattern DISCORD_WEBHOOK = Pattern.compile(
            "(?i)https://discord(?:app)?\\.com/api/webhooks/[^\\s\\\"']+"
    );

    private static final Pattern BEARER_TOKEN = Pattern.compile(
            "(?i)(\\bBearer\\s+)[A-Za-z0-9._~+/=-]+"
    );

    private static final Pattern LOG_SECRET_KEY_VALUE = Pattern.compile(
            "(?i)(\\b(?:password|passwd|token|api[-_]?key|secret|webhook-url)\\b\\s*[:=]\\s*)"
                    + "(\\\"[^\\\"]*\\\"|'[^']*'|[^\\s,;]+)"
    );

    private ReportRedactor() {
    }

    /**
     * Redacts known secret keys from YAML / TOML text.
     *
     * @param input raw config text (config.yml or velocity.toml)
     * @return text with secret values replaced by {@code <redacted>}
     */
    static String redactYaml(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        return SECRET_KEY_VALUE.matcher(input).replaceAll(m ->
                m.group(1) + m.group(2) + m.group(3) + REDACTED + m.group(3));
    }

    /**
     * Redacts credentials embedded in a connection URL.
     * Preserves the scheme and host so the DB type and endpoint remain visible for support.
     *
     * @param url raw connection URL, e.g. {@code postgresql://user:pass@host:5432/db}
     * @return URL with the credentials segment replaced by {@code <redacted>}
     */
    static String redactConnectionUrl(String url) {
        if (url == null || url.isEmpty()) {
            return url;
        }
        return URL_CREDENTIALS.matcher(url).replaceAll(m -> m.group(1) + REDACTED + m.group(2));
    }

    /**
     * Full redaction pipeline for a config file body: redacts secret keys, then redacts
     * any credentials embedded in connection-url values that survived the key pass.
     *
     * @param input raw config text
     * @return redacted config text
     */
    static String redact(String input) {
        String redacted = redactYaml(input);
        // connection-url values may contain embedded credentials even after the key pass
        // because the key name "connection-url" is not in the secret-key list — only its
        // value carries credentials. Run the URL pass on the whole file to catch them.
        return redactConnectionUrl(redacted);
    }

    /**
     * Best-effort redaction for unstructured runtime logs. Logs are excluded from reports by
     * default; this additional pass protects explicit opt-in reports from common credentials
     * emitted by VeloAuth or third-party plugins.
     *
     * @param input raw log tail
     * @return log text with common token, password, webhook and URL credentials removed
     */
    static String redactLog(String input) {
        if (input == null || input.isEmpty()) {
            return input;
        }
        String redacted = DISCORD_WEBHOOK.matcher(input).replaceAll(REDACTED);
        redacted = BEARER_TOKEN.matcher(redacted)
                .replaceAll(m -> m.group(1) + REDACTED);
        redacted = LOG_SECRET_KEY_VALUE.matcher(redacted)
                .replaceAll(m -> m.group(1) + REDACTED);
        redacted = redactYaml(redacted);
        return redactConnectionUrl(redacted);
    }
}
