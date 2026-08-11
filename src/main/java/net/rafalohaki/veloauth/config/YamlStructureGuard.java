package net.rafalohaki.veloauth.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Preserves the legacy distinction between missing settings and explicit YAML nulls. */
final class YamlStructureGuard {

    private static final Pattern NULL_OR_CONTAINER = Pattern.compile(
            "^([ \\t]*)([A-Za-z0-9_-]+)[ \\t]*:[ \\t]*"
                    + "(?:(?:~|null|Null|NULL)[ \\t]*)?(?:#.*)?$");
    private static final Set<String> MAP_KEYS = Set.of(
            "database", "postgresql", "cache", "auth-server", "embedded", "picolimbo",
            "connection", "security", "password-policy", "premium", "resolver", "floodgate",
            "alerts", "discord", "audit-log", "two-factor", "report");
    private static final Set<String> REQUIRED_SCALAR_KEYS = Set.of("mode");

    private YamlStructureGuard() {
    }

    static void validate(Path configFile) throws IOException {
        List<String> lines = Files.readAllLines(configFile, StandardCharsets.UTF_8);
        for (int index = 0; index < lines.size(); index++) {
            Matcher candidate = NULL_OR_CONTAINER.matcher(lines.get(index));
            if (!candidate.matches()) {
                continue;
            }
            String key = candidate.group(2);
            if (!MAP_KEYS.contains(key) && !REQUIRED_SCALAR_KEYS.contains(key)) {
                continue;
            }
            int indentation = candidate.group(1).length();
            if (!hasNestedValue(lines, index + 1, indentation)) {
                throw new IllegalArgumentException(
                        "Config key '" + key + "' must not be an explicit YAML null");
            }
        }
    }

    private static boolean hasNestedValue(
            List<String> lines,
            int firstCandidate,
            int parentIndentation) {
        int index = firstCandidate;
        while (index < lines.size() && isBlankOrComment(lines.get(index))) {
            index++;
        }
        return index < lines.size()
                && leadingWhitespace(lines.get(index)) > parentIndentation;
    }

    private static boolean isBlankOrComment(String line) {
        String trimmed = line.trim();
        return trimmed.isEmpty() || trimmed.startsWith("#");
    }

    private static int leadingWhitespace(String line) {
        int index = 0;
        while (index < line.length()) {
            char current = line.charAt(index);
            if (current != ' ' && current != '\t') {
                break;
            }
            index++;
        }
        return index;
    }
}
