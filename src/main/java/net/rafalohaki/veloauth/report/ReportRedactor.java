package net.rafalohaki.veloauth.report;

import java.util.Locale;
import java.util.Set;
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
     * Secret-bearing key names, normalized (lowercase, '-'/'_' stripped). Matching the
     * alternation inline in each regex made the union super-linear (Sonar S8786) and pushed
     * its complexity past the S5843 threshold, so keys are now captured generically and
     * filtered here — same key set, linear regexes.
     */
    private static final Set<String> SECRET_KEYS = Set.of(
            "password", "passwd", "sslpassword", "webhookurl", "forwardingsecret",
            "apikey", "accesstoken", "clientsecret", "token", "secret");

    private static boolean isSecretKey(String key) {
        return SECRET_KEYS.contains(
                key.toLowerCase(Locale.ROOT).replace("-", "").replace("_", ""));
    }

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
    private static final Pattern YAML_KEY_VALUE = Pattern.compile(
            "(?m)^[ \\t]*([A-Za-z0-9._-]+)([ \\t]*[:=][ \\t]*)([\"']?).*$"
    );

    /**
     * Credentials embedded in a connection URL: {@code scheme://user:pass@host}.
     * Captures everything between {@code://} and the {@code @} and replaces it.
     */
    private static final Pattern URL_CREDENTIALS = Pattern.compile(
            "(://)[^\\s/]*(@)"
    );

    /** Secret assignments inside JDBC/URI query strings and connection-parameters values. */
    private static final Pattern SECRET_PARAMETER = Pattern.compile(
            "((?:[?&;]|\\b)([A-Za-z0-9._-]+)=)([^&#;\\s\"']*)"
    );

    private static final Pattern DISCORD_WEBHOOK = Pattern.compile(
            "(?i)https://discord(?:app)?\\.com/api/webhooks/[^\\s\\\"']+"
    );

    private static final Pattern BEARER_TOKEN = Pattern.compile(
            "(?i)(\\bBearer\\s+)[a-z0-9._~+/=-]+"
    );

    private static final Pattern LOG_KEY_VALUE = Pattern.compile(
            "(\\b([A-Za-z0-9._-]+)\\b\\s*[:=]\\s*)"
                    + "(\\\"[^\\\"]*\\\"|'[^']*'|[^\\s,;&#]+)"
    );

    private static final Set<String> PASSWORD_COMMANDS = Set.of(
            "login", "register", "changepassword", "log", "reg", "l");
    private static final Set<String> TWO_FACTOR_COMMANDS = Set.of("2fa", "totp", "twofa");
    private static final Set<String> TWO_FACTOR_SECRET_SUBCOMMANDS = Set.of("verify", "disable");

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
        return YAML_KEY_VALUE.matcher(input).replaceAll(m ->
                isSecretKey(m.group(1))
                        ? m.group(1) + m.group(2) + m.group(3) + REDACTED + m.group(3)
                        : m.group());
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
        String redacted = URL_CREDENTIALS.matcher(url)
                .replaceAll(m -> m.group(1) + REDACTED + m.group(2));
        return redactSecretParameters(redacted);
    }

    private static String redactSecretParameters(String input) {
        return SECRET_PARAMETER.matcher(input)
                .replaceAll(m -> isSecretKey(m.group(2)) ? m.group(1) + REDACTED : m.group());
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
        redacted = redactAuthenticationCommands(redacted);
        redacted = BEARER_TOKEN.matcher(redacted)
                .replaceAll(m -> m.group(1) + REDACTED);
        redacted = LOG_KEY_VALUE.matcher(redacted)
                .replaceAll(m -> isSecretKey(m.group(2)) ? m.group(1) + REDACTED : m.group());
        redacted = redactYaml(redacted);
        return redactConnectionUrl(redacted);
    }

    /**
     * Scans instead of matching a repeated argument group. Java's regex engine recurses on
     * that shape and can overflow the stack on a long log line.
     */
    private static String redactAuthenticationCommands(String input) {
        StringBuilder redacted = new StringBuilder(input.length());
        int index = 0;
        while (index < input.length()) {
            int slash = indexOfCommandSlash(input, index);
            if (slash < 0) {
                redacted.append(input, index, input.length());
                break;
            }
            redacted.append(input, index, slash);
            int commandEnd = authCommandEnd(input, slash + 1);
            if (commandEnd < 0) {
                redacted.append('/');
                index = slash + 1;
                continue;
            }
            redacted.append(input, slash, commandEnd);
            index = appendRedactedArguments(input, commandEnd, redacted);
        }
        return redacted.toString();
    }

    private static int indexOfCommandSlash(String input, int from) {
        for (int index = from; index < input.length(); index++) {
            if (input.charAt(index) == '/' && (index == 0 || !isWord(input.charAt(index - 1)))) {
                return index;
            }
        }
        return -1;
    }

    /** Returns the end of a secret-bearing command, or {@code -1} when the slash is unrelated. */
    private static int authCommandEnd(String input, int start) {
        int cursor = start;
        int namespaceEnd = namespaceEnd(input, cursor);
        if (namespaceEnd >= 0) {
            cursor = namespaceEnd;
        }
        int nameEnd = tokenEnd(input, cursor);
        if (nameEnd == cursor) {
            return -1;
        }
        String name = input.substring(cursor, nameEnd).toLowerCase(Locale.ROOT);
        if (PASSWORD_COMMANDS.contains(name)) {
            return nameEnd;
        }
        return twoFactorCommandEnd(input, name, nameEnd);
    }

    private static int twoFactorCommandEnd(String input, String name, int nameEnd) {
        if (!TWO_FACTOR_COMMANDS.contains(name)) {
            return -1;
        }
        int subcommandStart = skipHorizontalSpace(input, nameEnd);
        if (subcommandStart == nameEnd) {
            return -1;
        }
        int subcommandEnd = tokenEnd(input, subcommandStart);
        String subcommand = input.substring(subcommandStart, subcommandEnd).toLowerCase(Locale.ROOT);
        return TWO_FACTOR_SECRET_SUBCOMMANDS.contains(subcommand) ? subcommandEnd : -1;
    }

    private static int appendRedactedArguments(String input, int index, StringBuilder redacted) {
        int cursor = index;
        while (cursor < input.length()) {
            int argumentStart = skipHorizontalSpace(input, cursor);
            if (argumentStart == cursor || argumentStart >= input.length()) {
                break;
            }
            int argumentEnd = argumentEnd(input, argumentStart);
            redacted.append(input, cursor, argumentStart).append(REDACTED);
            cursor = argumentEnd;
        }
        return cursor;
    }

    private static int argumentEnd(String input, int start) {
        char quote = input.charAt(start);
        if (quote == '"' || quote == '\'') {
            int close = input.indexOf(quote, start + 1);
            int lineEnd = lineEnd(input, start);
            if (close >= 0 && close < lineEnd) {
                return close + 1;
            }
        }
        int end = start;
        while (end < input.length() && !isAsciiWhitespace(input.charAt(end))) {
            end++;
        }
        return end;
    }

    /** Optional {@code veloauth:} prefix. Returns the index after {@code :}, or {@code -1}. */
    private static int namespaceEnd(String input, int start) {
        int cursor = start;
        while (cursor < input.length() && isNamespaceChar(input.charAt(cursor))) {
            cursor++;
        }
        if (cursor > start && cursor < input.length() && input.charAt(cursor) == ':') {
            return cursor + 1;
        }
        return -1;
    }

    private static int tokenEnd(String input, int start) {
        int cursor = start;
        while (cursor < input.length() && isWord(input.charAt(cursor))) {
            cursor++;
        }
        return cursor;
    }

    private static int skipHorizontalSpace(String input, int start) {
        int cursor = start;
        while (cursor < input.length()) {
            char character = input.charAt(cursor);
            if (character != ' ' && character != '\t') {
                break;
            }
            cursor++;
        }
        return cursor;
    }

    private static int lineEnd(String input, int start) {
        int cursor = start;
        while (cursor < input.length() && input.charAt(cursor) != '\n' && input.charAt(cursor) != '\r') {
            cursor++;
        }
        return cursor;
    }

    private static boolean isNamespaceChar(char character) {
        return character == '.' || character == '-' || isWord(character);
    }

    private static boolean isWord(char character) {
        return character == '_'
                || (character >= '0' && character <= '9')
                || (character >= 'A' && character <= 'Z')
                || (character >= 'a' && character <= 'z');
    }

    private static boolean isAsciiWhitespace(char character) {
        return character == ' ' || character == '\t' || character == '\n'
                || character == '\r' || character == '\f' || character == '\u000B';
    }
}
