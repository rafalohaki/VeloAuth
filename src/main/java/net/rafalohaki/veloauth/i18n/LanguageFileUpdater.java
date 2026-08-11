package net.rafalohaki.veloauth.i18n;

import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * Builds and publishes format-preserving external language-file updates.
 */
final class LanguageFileUpdater {

    private static final String DEFAULT_NEWLINE = "\n";

    private LanguageFileUpdater() {
    }

    static UpdateResult update(
            Path targetFile,
            Properties sourceProperties,
            String missingKeysHeader,
            List<StockMigration> stockMigrations,
            Publisher publisher) throws IOException {
        String original = Files.readString(targetFile, StandardCharsets.UTF_8);
        Properties originalProperties = parseProperties(original, targetFile);
        List<String> missingKeys = findMissingKeys(sourceProperties, originalProperties);
        Document document = Document.parse(original, targetFile);
        Set<String> migratedKeys = document.applyStockMigrations(stockMigrations);
        String candidate = document.renderWithMissingKeys(
                sourceProperties, missingKeys, missingKeysHeader);

        if (candidate.equals(original)) {
            return new UpdateResult(List.copyOf(migratedKeys), missingKeys, false);
        }

        Properties expectedProperties = copyProperties(originalProperties);
        for (StockMigration migration : stockMigrations) {
            if (migratedKeys.contains(migration.key())) {
                expectedProperties.setProperty(migration.key(), migration.newValue());
            }
        }
        for (String missingKey : missingKeys) {
            expectedProperties.setProperty(missingKey, sourceProperties.getProperty(missingKey));
        }

        Properties candidateProperties = parseProperties(candidate, targetFile);
        if (!expectedProperties.equals(candidateProperties)) {
            throw new IOException("Generated language candidate failed semantic validation for "
                    + targetFile.getFileName());
        }

        publisher.publish(targetFile, candidate);
        return new UpdateResult(List.copyOf(migratedKeys), missingKeys, true);
    }

    static void publishAtomically(Path targetFile, String candidate) throws IOException {
        Path parent = targetFile.toAbsolutePath().getParent();
        if (parent == null) {
            throw new IOException("Language file has no parent directory: " + targetFile);
        }

        Path temporaryFile = Files.createTempFile(
                parent, "." + targetFile.getFileName() + ".", ".tmp");
        boolean published = false;
        try {
            Files.copy(targetFile, temporaryFile,
                    StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.COPY_ATTRIBUTES);
            writeAndSync(temporaryFile, candidate);
            Files.move(temporaryFile, targetFile,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
            published = true;
        } finally {
            if (!published) {
                Files.deleteIfExists(temporaryFile);
            }
        }
    }

    private static void writeAndSync(Path targetFile, String candidate) throws IOException {
        ByteBuffer content = StandardCharsets.UTF_8.encode(candidate);
        try (FileChannel channel = FileChannel.open(targetFile,
                StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING)) {
            while (content.hasRemaining()) {
                channel.write(content);
            }
            channel.force(true);
        }
    }

    private static List<String> findMissingKeys(Properties source, Properties target) {
        List<String> missingKeys = new ArrayList<>();
        for (String key : source.stringPropertyNames()) {
            if (!target.containsKey(key)) {
                missingKeys.add(key);
            }
        }
        missingKeys.sort(String::compareTo);
        return List.copyOf(missingKeys);
    }

    private static Properties parseProperties(String content, Path source) throws IOException {
        Properties properties = new Properties();
        try (StringReader reader = new StringReader(content)) {
            properties.load(reader);
            return properties;
        } catch (IllegalArgumentException malformedProperties) {
            throw new IOException("Malformed language file: " + source.getFileName(), malformedProperties);
        }
    }

    private static Properties copyProperties(Properties source) {
        Properties copy = new Properties();
        copy.putAll(source);
        return copy;
    }

    @FunctionalInterface
    interface Publisher {
        void publish(Path targetFile, String candidate) throws IOException;
    }

    record StockMigration(String key, String oldValue, String newValue) {
        StockMigration {
            if (key == null || key.isBlank()) {
                throw new IllegalArgumentException("Stock migration key must not be blank");
            }
            if (oldValue == null || newValue == null || oldValue.equals(newValue)) {
                throw new IllegalArgumentException("Stock migration values must be distinct and non-null");
            }
        }
    }

    record UpdateResult(List<String> migratedKeys, List<String> missingKeys, boolean published) {
        UpdateResult {
            migratedKeys = List.copyOf(migratedKeys);
            missingKeys = List.copyOf(missingKeys);
        }
    }

    private static final class Document {
        private final List<LogicalLine> lines;
        private final String newline;

        private Document(List<LogicalLine> lines, String newline) {
            this.lines = lines;
            this.newline = newline;
        }

        static Document parse(String content, Path source) throws IOException {
            List<PhysicalLine> physicalLines = splitPhysicalLines(content);
            List<LogicalLine> logicalLines = new ArrayList<>();
            String detectedNewline = DEFAULT_NEWLINE;
            boolean newlineDetected = false;

            int index = 0;
            while (index < physicalLines.size()) {
                int start = index;
                PhysicalLine current;
                do {
                    current = physicalLines.get(index++);
                    if (!newlineDetected && !current.terminator().isEmpty()) {
                        detectedNewline = current.terminator();
                        newlineDetected = true;
                    }
                } while (hasContinuation(current.content()) && index < physicalLines.size());

                StringBuilder raw = new StringBuilder();
                for (int lineIndex = start; lineIndex < index; lineIndex++) {
                    raw.append(physicalLines.get(lineIndex).raw());
                }
                logicalLines.add(LogicalLine.parse(raw.toString(), current.terminator(), source));
            }
            return new Document(logicalLines, detectedNewline);
        }

        Set<String> applyStockMigrations(List<StockMigration> migrations) {
            Map<String, List<Integer>> occurrences = propertyOccurrences();
            Set<String> migratedKeys = new LinkedHashSet<>();
            for (StockMigration migration : migrations) {
                List<Integer> matchingLines = occurrences.getOrDefault(migration.key(), List.of());
                if (matchingLines.size() != 1) {
                    continue;
                }

                int lineIndex = matchingLines.getFirst();
                LogicalLine existing = lines.get(lineIndex);
                if (!existing.isCanonical(migration.key(), migration.oldValue())) {
                    continue;
                }
                String replacement = LanguageFileManager.escapePropertyKey(migration.key()) + "="
                        + LanguageFileManager.escapePropertyValue(migration.newValue())
                        + existing.terminator();
                lines.set(lineIndex, existing.withRaw(replacement));
                migratedKeys.add(migration.key());
            }
            return migratedKeys;
        }

        String renderWithMissingKeys(
                Properties sourceProperties, List<String> missingKeys, String header) {
            StringBuilder candidate = new StringBuilder();
            for (LogicalLine line : lines) {
                candidate.append(line.raw());
            }
            if (missingKeys.isEmpty()) {
                return candidate.toString();
            }

            candidate.append(newline).append(header).append(newline);
            for (String missingKey : missingKeys) {
                candidate.append(LanguageFileManager.escapePropertyKey(missingKey))
                        .append('=')
                        .append(LanguageFileManager.escapePropertyValue(
                                sourceProperties.getProperty(missingKey)))
                        .append(newline);
            }
            return candidate.toString();
        }

        private Map<String, List<Integer>> propertyOccurrences() {
            Map<String, List<Integer>> occurrences = new HashMap<>();
            for (int index = 0; index < lines.size(); index++) {
                String key = lines.get(index).key();
                if (key != null) {
                    occurrences.computeIfAbsent(key, ignored -> new ArrayList<>()).add(index);
                }
            }
            return occurrences;
        }

        private static List<PhysicalLine> splitPhysicalLines(String content) {
            List<PhysicalLine> lines = new ArrayList<>();
            int start = 0;
            int index = 0;
            while (index < content.length()) {
                char current = content.charAt(index);
                if (current != '\n' && current != '\r') {
                    index++;
                    continue;
                }

                int terminatorEnd = index + 1;
                String terminator = String.valueOf(current);
                if (current == '\r' && terminatorEnd < content.length()
                        && content.charAt(terminatorEnd) == '\n') {
                    terminatorEnd++;
                    terminator = "\r\n";
                }
                lines.add(new PhysicalLine(
                        content.substring(start, terminatorEnd),
                        content.substring(start, index),
                        terminator));
                start = terminatorEnd;
                index = terminatorEnd;
            }
            if (start < content.length()) {
                lines.add(new PhysicalLine(content.substring(start), content.substring(start), ""));
            }
            return lines;
        }

        private static boolean hasContinuation(String content) {
            int backslashes = 0;
            for (int index = content.length() - 1;
                    index >= 0 && content.charAt(index) == '\\'; index--) {
                backslashes++;
            }
            return backslashes % 2 != 0;
        }
    }

    private record PhysicalLine(String raw, String content, String terminator) {
    }

    private record LogicalLine(String raw, String terminator, String key) {
        static LogicalLine parse(String raw, String terminator, Path source) throws IOException {
            Properties parsed = parseProperties(raw, source);
            if (parsed.size() != 1) {
                return new LogicalLine(raw, terminator, null);
            }
            String key = parsed.stringPropertyNames().iterator().next();
            return new LogicalLine(raw, terminator, key);
        }

        LogicalLine withRaw(String replacement) {
            return new LogicalLine(replacement, terminator, key);
        }

        boolean isCanonical(String expectedKey, String expectedValue) {
            String canonical = LanguageFileManager.escapePropertyKey(expectedKey) + "="
                    + LanguageFileManager.escapePropertyValue(expectedValue) + terminator;
            return raw.equals(canonical);
        }
    }
}
