package net.rafalohaki.veloauth.i18n;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for LanguageFileManager - external language file management.
 */
class LanguageFileManagerTest {

    private static final String QR_WARNING_KEY = "2fa.qr.warning";
    private static final String REPORT_GENERATING_KEY = "admin.report.generating";
    private static final String REPORT_WARNING_KEY = "admin.report.warning";

    private static final String COMMON_OLD_QR_WARNING =
            "§cWarning: §7secret is shown below. Anyone who can read your chat history can copy it.";
    private static final String COMMON_NEW_QR_WARNING =
            "§eFor security, an enrolled 2FA secret cannot be shown again. Run §f/2fa disable <code>§e, "
                    + "then §f/2fa setup §eto enroll a new device.";
    private static final String COMMON_OLD_REPORT_GENERATING =
            "§eGenerating diagnostic report... (config + logs will be uploaded to mclo.gs)";
    private static final String COMMON_NEW_REPORT_GENERATING =
            "§eGenerating diagnostic report... (redacted config and explicitly enabled logs will be uploaded to mclo.gs)";
    private static final String COMMON_OLD_REPORT_WARNING =
            "§eThe report contains redacted config and recent logs. The link is public \\u2014 "
                    + "share it only with trusted parties.";
    private static final String COMMON_NEW_REPORT_WARNING =
            "§eThe report contains redacted config and may contain logs when enabled. The link is public \\u2014 "
                    + "share it only with trusted parties.";

    private static final String POLISH_OLD_QR_WARNING =
            "§cUwaga: §7sekret jest wyświetlony poniżej. Każdy kto przeczyta historię chatu może go skopiować.";
    private static final String POLISH_NEW_QR_WARNING =
            "§eZe względów bezpieczeństwa zapisanego sekretu 2FA nie można ponownie wyświetlić. "
                    + "Użyj §f/2fa disable <kod>§e, a następnie §f/2fa setup§e, aby dodać nowe urządzenie.";
    private static final String POLISH_OLD_REPORT_GENERATING =
            "§eGenerowanie raportu diagnostycznego... (config + logi zostaną wysłane do mclo.gs)";
    private static final String POLISH_NEW_REPORT_GENERATING =
            "§eGenerowanie raportu diagnostycznego... (zredagowany config i jawnie włączone logi "
                    + "zostaną wysłane do mclo.gs)";
    private static final String POLISH_OLD_REPORT_WARNING =
            "§eRaport zawiera zredagowany config i ostatnie logi. Link jest publiczny \\u2014 "
                    + "udostępnij go tylko zaufanym osobom.";
    private static final String POLISH_NEW_REPORT_WARNING =
            "§eRaport zawiera zredagowany config i może zawierać logi, jeśli je włączono. "
                    + "Link jest publiczny \\u2014 udostępnij go tylko zaufanym osobom.";

    @TempDir
    Path tempDir;

    private LanguageFileManager languageFileManager;

    @BeforeEach
    void setUp() {
        languageFileManager = new LanguageFileManager(tempDir);
    }

    @AfterEach
    void tearDown() {
        // Cleanup is handled by @TempDir
    }

    @Test
    void testInitializeLanguageFiles_CreatesDirectory() throws IOException {
        // When
        languageFileManager.initializeLanguageFiles();

        // Then
        Path langDir = tempDir.resolve("lang");
        assertTrue(Files.exists(langDir), "Language directory should be created");
        assertTrue(Files.isDirectory(langDir), "Language directory should be a directory");
    }

    @Test
    void testInitializeLanguageFiles_CopiesDefaultFiles() throws IOException {
        // When
        languageFileManager.initializeLanguageFiles();

        // Then
        Path langDir = tempDir.resolve("lang");
        assertTrue(Files.exists(langDir.resolve("messages_en.properties")), 
                "English language file should be copied");
        assertTrue(Files.exists(langDir.resolve("messages_pl.properties")), 
                "Polish language file should be copied");
    }

    @Test
    void testInitializeLanguageFiles_DoesNotOverwriteExisting() throws IOException {
        // Given
        languageFileManager.initializeLanguageFiles();
        Path enFile = tempDir.resolve("lang/messages_en.properties");
        String originalContent = Files.readString(enFile);

        // When - initialize again
        languageFileManager.initializeLanguageFiles();

        // Then
        String newContent = Files.readString(enFile);
        assertEquals(originalContent, newContent, "Existing files should not be overwritten");
    }

    @Test
    void initializeLanguageFiles_historicalStockDefaults_migratesAllBuiltInLocales() throws IOException {
        languageFileManager.initializeLanguageFiles();
        for (String language : BuiltInLanguages.codes()) {
            Path file = languageFile(language);
            String current = Files.readString(file, StandardCharsets.UTF_8);
            Files.writeString(file, replaceExpectedNewWithHistoricalOld(current, language),
                    StandardCharsets.UTF_8);
        }

        languageFileManager.initializeLanguageFiles();

        for (String language : BuiltInLanguages.codes()) {
            Path file = languageFile(language);
            Properties migrated = loadProperties(file);
            assertEquals(expectedNew(language, QR_WARNING_KEY), migrated.getProperty(QR_WARNING_KEY), language);
            assertEquals(expectedNew(language, REPORT_GENERATING_KEY),
                    migrated.getProperty(REPORT_GENERATING_KEY), language);
            assertEquals(expectedNew(language, REPORT_WARNING_KEY),
                    migrated.getProperty(REPORT_WARNING_KEY), language);
            String content = Files.readString(file, StandardCharsets.UTF_8);
            assertEquals(1, countCanonicalLines(content, QR_WARNING_KEY), language);
            assertEquals(1, countCanonicalLines(content, REPORT_GENERATING_KEY), language);
            assertEquals(1, countCanonicalLines(content, REPORT_WARNING_KEY), language);
        }
    }

    @Test
    void initializeLanguageFiles_customEmptyAndMixedDuplicates_preservesBytesAndCrLf() throws IOException {
        languageFileManager.initializeLanguageFiles();
        Path english = languageFile("en");
        String current = Files.readString(english, StandardCharsets.UTF_8).replace("\n", "\r\n");
        String fixture = current
                .replace(canonicalLine(QR_WARNING_KEY, COMMON_NEW_QR_WARNING),
                        "# operator comment\r\n"
                                + canonicalLine(QR_WARNING_KEY, "operator custom value") + "\r\n"
                                + canonicalLine(QR_WARNING_KEY, COMMON_OLD_QR_WARNING))
                .replace(canonicalLine(REPORT_GENERATING_KEY, COMMON_NEW_REPORT_GENERATING),
                        canonicalLine(REPORT_GENERATING_KEY, ""))
                + "custom.duplicate=first\r\ncustom.duplicate=second\r\n";
        Files.writeString(english, fixture, StandardCharsets.UTF_8);

        languageFileManager.initializeLanguageFiles();

        assertEquals(fixture, Files.readString(english, StandardCharsets.UTF_8),
                "Any custom/empty duplicate occurrence must protect the whole key from stock migration");
    }

    @Test
    void initializeLanguageFiles_duplicateHistoricalDefaults_preservesBytes() throws IOException {
        languageFileManager.initializeLanguageFiles();
        Path english = languageFile("en");
        String current = Files.readString(english, StandardCharsets.UTF_8).replace("\n", "\r\n");
        String historicalLine = canonicalLine(REPORT_WARNING_KEY, COMMON_OLD_REPORT_WARNING);
        String fixture = current.replace(
                canonicalLine(REPORT_WARNING_KEY, COMMON_NEW_REPORT_WARNING),
                historicalLine + "\r\n# comment between duplicate stock lines\r\n" + historicalLine);
        Files.writeString(english, fixture, StandardCharsets.UTF_8);

        languageFileManager.initializeLanguageFiles();

        assertEquals(fixture, Files.readString(english, StandardCharsets.UTF_8),
                "Duplicate stock-default lines are operator-owned and must not be canonicalized");
    }

    @Test
    void initializeLanguageFiles_singleCanonicalHistoricalDefault_migratesWithoutChangingCrLf() throws IOException {
        languageFileManager.initializeLanguageFiles();
        Path english = languageFile("en");
        String current = Files.readString(english, StandardCharsets.UTF_8).replace("\n", "\r\n");
        String fixture = current.replace(
                canonicalLine(REPORT_WARNING_KEY, COMMON_NEW_REPORT_WARNING),
                canonicalLine(REPORT_WARNING_KEY, COMMON_OLD_REPORT_WARNING));
        Files.writeString(english, fixture, StandardCharsets.UTF_8);

        languageFileManager.initializeLanguageFiles();

        assertEquals(current, Files.readString(english, StandardCharsets.UTF_8),
                "Canonical stock migration must retain all surrounding CRLF bytes");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("reformattedHistoricalLines")
    void initializeLanguageFiles_reformattedHistoricalDefault_preservesBytes(
            String description, String reformattedLine) throws IOException {
        languageFileManager.initializeLanguageFiles();
        Path english = languageFile("en");
        String current = Files.readString(english, StandardCharsets.UTF_8).replace("\n", "\r\n");
        String fixture = current.replace(
                canonicalLine(REPORT_WARNING_KEY, COMMON_NEW_REPORT_WARNING), reformattedLine);
        Files.writeString(english, fixture, StandardCharsets.UTF_8);

        languageFileManager.initializeLanguageFiles();

        assertEquals(fixture, Files.readString(english, StandardCharsets.UTF_8), description);
    }

    @Test
    void loadLanguageBundle_customLocaleWithHistoricalText_doesNotRunStockMigration() throws IOException {
        languageFileManager.initializeLanguageFiles();
        Path custom = languageFile("custom");
        String english = Files.readString(languageFile("en"), StandardCharsets.UTF_8);
        String fixture = replaceExpectedNewWithHistoricalOld(english, "en");
        Files.writeString(custom, fixture, StandardCharsets.UTF_8);

        ResourceBundle bundle = languageFileManager.loadLanguageBundle("custom");

        assertEquals(COMMON_OLD_QR_WARNING, bundle.getString(QR_WARNING_KEY));
        assertEquals(fixture, Files.readString(custom, StandardCharsets.UTF_8));
    }

    @Test
    void initializeLanguageFiles_publisherFailure_leavesOriginalFileUntouched() throws IOException {
        languageFileManager.initializeLanguageFiles();
        Path english = languageFile("en");
        String historical = replaceExpectedNewWithHistoricalOld(
                Files.readString(english, StandardCharsets.UTF_8), "en");
        Files.writeString(english, historical, StandardCharsets.UTF_8);
        AtomicInteger publishAttempts = new AtomicInteger();
        LanguageFileManager failingManager = new LanguageFileManager(tempDir, (target, candidate) -> {
            publishAttempts.incrementAndGet();
            throw new IOException("injected atomic publication failure");
        });

        failingManager.initializeLanguageFiles();

        assertEquals(1, publishAttempts.get());
        assertEquals(historical, Files.readString(english, StandardCharsets.UTF_8));
    }

    @Test
    void loadLanguageBundle_missingEnglishKeys_usesAtomicPublisherOnce() throws IOException {
        languageFileManager.initializeLanguageFiles();
        Path custom = languageFile("custom");
        Files.writeString(custom, "custom.present=value\r\n", StandardCharsets.UTF_8);
        AtomicInteger publications = new AtomicInteger();
        LanguageFileManager countingManager = new LanguageFileManager(tempDir, (target, candidate) -> {
            publications.incrementAndGet();
            LanguageFileUpdater.publishAtomically(target, candidate);
        });

        ResourceBundle bundle = countingManager.loadLanguageBundle("custom");

        assertEquals(1, publications.get());
        assertEquals("value", bundle.getString("custom.present"));
        assertEquals(COMMON_NEW_QR_WARNING, bundle.getString(QR_WARNING_KEY));
        String updated = Files.readString(custom, StandardCharsets.UTF_8);
        assertTrue(updated.contains("# === Missing keys (English fallback - please translate) ===\r\n"));
        assertEquals(-1, updated.replace("\r\n", "").indexOf('\n'));
        assertFalse(hasTemporarySibling(custom));
    }

    @Test
    void loadLanguageBundle_missingKeysPublicationFails_leavesPartialFileUntouched() throws IOException {
        languageFileManager.initializeLanguageFiles();
        Path custom = languageFile("custom");
        String partial = "custom.present=value\n";
        Files.writeString(custom, partial, StandardCharsets.UTF_8);
        AtomicInteger publishAttempts = new AtomicInteger();
        LanguageFileManager failingManager = new LanguageFileManager(tempDir, (target, candidate) -> {
            publishAttempts.incrementAndGet();
            throw new IOException("injected atomic publication failure");
        });

        ResourceBundle bundle = failingManager.loadLanguageBundle("custom");

        assertEquals(1, publishAttempts.get());
        assertEquals("value", bundle.getString("custom.present"));
        assertEquals(partial, Files.readString(custom, StandardCharsets.UTF_8));
    }

    @Test
    void initializeLanguageFiles_malformedExistingFile_leavesBytesUntouched() throws IOException {
        languageFileManager.initializeLanguageFiles();
        Path english = languageFile("en");
        String malformed = Files.readString(english, StandardCharsets.UTF_8)
                + "malformed=\\uZZZZ\n";
        Files.writeString(english, malformed, StandardCharsets.UTF_8);

        languageFileManager.initializeLanguageFiles();

        assertEquals(malformed, Files.readString(english, StandardCharsets.UTF_8));
    }

    @ParameterizedTest
    @ValueSource(strings = {"en", "pl", "de"})
    void testLoadLanguageBundle_LoadsLanguageOrFallsBack(String language) throws IOException {
        // Given
        languageFileManager.initializeLanguageFiles();

        // When
        ResourceBundle bundle = languageFileManager.loadLanguageBundle(language);

        // Then
        assertNotNull(bundle, "Bundle should not be null for language: " + language);
        assertTrue(bundle.keySet().size() > 0, "Bundle should contain keys for language: " + language);
    }

    @Test
    void testLoadLanguageBundle_ThrowsExceptionWhenNoFiles() {
        // When/Then - no files initialized
        assertThrows(IOException.class, () -> {
            languageFileManager.loadLanguageBundle("en");
        }, "Should throw IOException when no language files exist");
    }

    // ===== fileExists: pure query, does not mutate the filesystem =====

    @Test
    void fileExists_languageWithoutFile_returnsFalseAndDoesNotCreate() throws IOException {
        languageFileManager.initializeLanguageFiles();
        Path langDir = tempDir.resolve("lang");
        Path bogus = langDir.resolve("messages_pll.properties");

        boolean exists = languageFileManager.fileExists("pll");

        assertEquals(false, exists);
        assertEquals(false, Files.exists(bogus),
                "fileExists must be a pure query — no file should be created");
    }

    @Test
    void fileExists_languageWithFile_returnsTrue() throws IOException {
        languageFileManager.initializeLanguageFiles();
        assertTrue(languageFileManager.fileExists("en"));
        assertTrue(languageFileManager.fileExists("pl"));
    }

    @Test
    void fileExists_nullOrBlank_returnsFalse() {
        assertEquals(false, languageFileManager.fileExists(null));
        assertEquals(false, languageFileManager.fileExists(""));
        assertEquals(false, languageFileManager.fileExists("   "));
    }

    @Test
    void fileExists_invalidLanguageCode_returnsFalseWithoutThrowing() throws IOException {
        languageFileManager.initializeLanguageFiles();
        // Path traversal attempts must not pass validateLanguageCode
        assertEquals(false, languageFileManager.fileExists("../etc/passwd"));
        assertEquals(false, languageFileManager.fileExists("en/../pl"));
    }

    // ===== escapePropertyValue / escapePropertyKey =====

    @Test
    void escapePropertyValue_backslashAndControlChars_escapedPerSpec() {
        assertEquals("a\\\\b", LanguageFileManager.escapePropertyValue("a\\b"));
        assertEquals("line1\\nline2", LanguageFileManager.escapePropertyValue("line1\nline2"));
        assertEquals("col\\tval", LanguageFileManager.escapePropertyValue("col\tval"));
        assertEquals("\\r\\n", LanguageFileManager.escapePropertyValue("\r\n"));
    }

    @Test
    void escapePropertyValue_leadingSpace_escaped() {
        // Leading space in a value would be silently swallowed by Properties.load
        assertEquals("\\ leading", LanguageFileManager.escapePropertyValue(" leading"));
        // Internal spaces left untouched
        assertEquals("a b c", LanguageFileManager.escapePropertyValue("a b c"));
    }

    @Test
    void escapePropertyValue_specialCharsInValueAreSafe() {
        // =, :, #, ! in VALUE position are not separators and need no escaping
        assertEquals("a=b:c#d!e", LanguageFileManager.escapePropertyValue("a=b:c#d!e"));
    }

    @Test
    void escapePropertyValue_null_returnsEmpty() {
        assertEquals("", LanguageFileManager.escapePropertyValue(null));
    }

    @Test
    void escapePropertyKey_separatorCharsEscaped() {
        assertEquals("a\\=b", LanguageFileManager.escapePropertyKey("a=b"));
        assertEquals("a\\:b", LanguageFileManager.escapePropertyKey("a:b"));
        assertEquals("\\#hash", LanguageFileManager.escapePropertyKey("#hash"));
        assertEquals("\\!bang", LanguageFileManager.escapePropertyKey("!bang"));
        assertEquals("a\\ b", LanguageFileManager.escapePropertyKey("a b"));
    }

    @Test
    void escapeRoundTrip_writeThenReadThroughProperties() throws IOException {
        String trickyValue = "leading\\ tab\there\nnewline\r=equals#hash!bang";
        String escaped = LanguageFileManager.escapePropertyValue(trickyValue);

        // Round-trip via real Properties.load to prove escape output is spec-compliant
        Path file = tempDir.resolve("roundtrip.properties");
        Files.writeString(file, "k=" + escaped + "\n");

        java.util.Properties props = new java.util.Properties();
        try (var r = Files.newBufferedReader(file)) {
            props.load(r);
        }
        assertEquals(trickyValue, props.getProperty("k"),
                "Escape output must round-trip cleanly through Properties.load");
    }

    private Path languageFile(String language) {
        return tempDir.resolve("lang").resolve(BuiltInLanguages.fileNameFor(language));
    }

    private static String replaceExpectedNewWithHistoricalOld(String content, String language) {
        String migrated = content;
        for (String key : new String[] {QR_WARNING_KEY, REPORT_GENERATING_KEY, REPORT_WARNING_KEY}) {
            String expected = canonicalLine(key, expectedNew(language, key));
            String historical = canonicalLine(key, historicalOld(language, key));
            String replaced = migrated.replace(expected, historical);
            assertTrue(!replaced.equals(migrated), "Bundled expected NEW missing for " + language + ": " + key);
            migrated = replaced;
        }
        return migrated;
    }

    private static String canonicalLine(String key, String value) {
        return key + "=" + LanguageFileManager.escapePropertyValue(value);
    }

    private static long countCanonicalLines(String content, String key) {
        return content.lines().filter(line -> line.startsWith(key + "=")).count();
    }

    private static Properties loadProperties(Path file) throws IOException {
        Properties properties = new Properties();
        try (var reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }

    private static boolean hasTemporarySibling(Path targetFile) throws IOException {
        String prefix = "." + targetFile.getFileName() + ".";
        try (var siblings = Files.list(targetFile.getParent())) {
            return siblings.anyMatch(path -> path.getFileName().toString().startsWith(prefix));
        }
    }

    private static Stream<Arguments> reformattedHistoricalLines() {
        String escapedKey = LanguageFileManager.escapePropertyKey(REPORT_WARNING_KEY);
        String escapedOld = LanguageFileManager.escapePropertyValue(COMMON_OLD_REPORT_WARNING);
        int continuationSplit = escapedOld.indexOf("recent logs");
        return Stream.of(
                Arguments.of("whitespace separator must be preserved",
                        escapedKey + " = " + escapedOld),
                Arguments.of("colon separator must be preserved",
                        escapedKey + ":" + escapedOld),
                Arguments.of("continued value must be preserved",
                        escapedKey + "=" + escapedOld.substring(0, continuationSplit)
                                + "\\\r\n  " + escapedOld.substring(continuationSplit)),
                Arguments.of("equivalent unicode escape must be preserved",
                        escapedKey + "=\\u00a7" + escapedOld.substring(1)));
    }

    private static String historicalOld(String language, String key) {
        boolean polish = "pl".equals(language);
        return switch (key) {
            case QR_WARNING_KEY -> polish ? POLISH_OLD_QR_WARNING : COMMON_OLD_QR_WARNING;
            case REPORT_GENERATING_KEY -> polish
                    ? POLISH_OLD_REPORT_GENERATING : COMMON_OLD_REPORT_GENERATING;
            case REPORT_WARNING_KEY -> polish ? POLISH_OLD_REPORT_WARNING : COMMON_OLD_REPORT_WARNING;
            default -> throw new IllegalArgumentException("Unexpected stock key: " + key);
        };
    }

    private static String expectedNew(String language, String key) {
        boolean polish = "pl".equals(language);
        return switch (key) {
            case QR_WARNING_KEY -> polish ? POLISH_NEW_QR_WARNING : COMMON_NEW_QR_WARNING;
            case REPORT_GENERATING_KEY -> polish
                    ? POLISH_NEW_REPORT_GENERATING : COMMON_NEW_REPORT_GENERATING;
            case REPORT_WARNING_KEY -> polish ? POLISH_NEW_REPORT_WARNING : COMMON_NEW_REPORT_WARNING;
            default -> throw new IllegalArgumentException("Unexpected stock key: " + key);
        };
    }
}
