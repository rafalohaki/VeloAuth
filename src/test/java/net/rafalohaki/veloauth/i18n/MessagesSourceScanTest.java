package net.rafalohaki.veloauth.i18n;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Catches the regression "developer added a new {@code messages.get("...")} call but forgot to
 * add the key to {@code messages_en.properties}".
 * <p>
 * Scans all production {@code .java} sources for literal-argument {@code messages.get("...")}
 * (and {@code .getForLanguage("lang", "...")}) calls and asserts every captured key exists in
 * the English properties file. Dynamic keys (computed strings, concatenation) are deliberately
 * ignored — they cannot be statically verified anyway.
 * <p>
 * Complements {@link SimpleMessagesKeysTest}, which checks the curated REQUIRED_KEYS list
 * against the properties files but cannot detect direct {@code messages.get} usage outside
 * {@code SimpleMessages}.
 */
class MessagesSourceScanTest {

    private static final Path SRC_MAIN = Path.of("src", "main", "java");
    private static final Path EN_PROPERTIES = Path.of("src", "main", "resources", "lang", "messages_en.properties");

    // Matches messages.get("literal-key") and messages.get("literal-key", anyArgs...)
    // plus messages.getForLanguage("lang", "literal-key", ...)
    // Captures the key. Skips calls whose first arg is not a string literal.
    private static final Pattern MESSAGES_GET = Pattern.compile(
            "\\bmessages\\s*\\.\\s*get\\s*\\(\\s*\"([a-zA-Z0-9._-]+)\"");
    private static final Pattern MESSAGES_GET_FOR_LANGUAGE = Pattern.compile(
            "\\bmessages\\s*\\.\\s*getForLanguage\\s*\\(\\s*\"[a-zA-Z0-9_]+\"\\s*,\\s*\"([a-zA-Z0-9._-]+)\"");

    @Test
    void everyLiteralMessagesGetKey_existsInEnglishProperties() throws IOException {
        Properties en = loadEnglish();
        Set<String> keysInProperties = en.stringPropertyNames();

        Set<String> keysInCode = scanLiteralKeys();
        // Filter out keys that look like prefixes (used elsewhere by SimpleMessages) — they
        // are intentionally not present as standalone properties. Heuristic: a key shorter
        // than 3 chars or one matching a known dynamic-suffix base is skipped.
        Set<String> missing = new LinkedHashSet<>();
        for (String key : keysInCode) {
            if (!keysInProperties.contains(key)) {
                missing.add(key);
            }
        }

        assertTrue(missing.isEmpty(),
                "Keys used via messages.get(\"…\") in production sources but missing from "
                        + EN_PROPERTIES + ":\n  " + String.join("\n  ", missing));
    }

    private Set<String> scanLiteralKeys() throws IOException {
        Set<String> keys = new HashSet<>();
        try (Stream<Path> paths = Files.walk(SRC_MAIN)) {
            paths.filter(p -> p.toString().endsWith(".java"))
                    .forEach(p -> collectKeys(p, keys));
        }
        return keys;
    }

    private void collectKeys(Path javaFile, Set<String> keys) {
        try {
            String source = Files.readString(javaFile, StandardCharsets.UTF_8);
            collectMatches(MESSAGES_GET, source, keys);
            collectMatches(MESSAGES_GET_FOR_LANGUAGE, source, keys);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read source file: " + javaFile, e);
        }
    }

    private void collectMatches(Pattern pattern, String source, Set<String> keys) {
        Matcher m = pattern.matcher(source);
        while (m.find()) {
            keys.add(m.group(1));
        }
    }

    private Properties loadEnglish() throws IOException {
        Properties props = new Properties();
        try (var reader = Files.newBufferedReader(EN_PROPERTIES, StandardCharsets.UTF_8)) {
            props.load(reader);
        }
        return props;
    }
}
