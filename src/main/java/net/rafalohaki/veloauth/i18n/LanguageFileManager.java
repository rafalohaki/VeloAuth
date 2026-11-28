package net.rafalohaki.veloauth.i18n;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;
import java.util.regex.Pattern;

/**
 * Manages external language files for VeloAuth.
 * Handles initialization, loading, and validation of language files from the filesystem.
 */
public final class LanguageFileManager {
    
    private static final Logger logger = LoggerFactory.getLogger(LanguageFileManager.class);
    private static final String MESSAGES_PREFIX = "messages_";
    private static final String PROPERTIES_SUFFIX = ".properties";
    // Internal resource path within the JAR, not an external URI
    @SuppressWarnings("java:S1075")
    private static final String LANG_RESOURCE_PATH = "/lang/";
    private static final Pattern VALID_LANGUAGE_CODE = Pattern.compile("^[a-zA-Z0-9_-]+$");

    private static final String QR_WARNING_KEY = "2fa.qr.warning";
    private static final String REPORT_GENERATING_KEY = "admin.report.generating";
    private static final String REPORT_WARNING_KEY = "admin.report.warning";

    private static final List<LanguageFileUpdater.StockMigration> COMMON_STOCK_MIGRATIONS = List.of(
            new LanguageFileUpdater.StockMigration(
                    QR_WARNING_KEY,
                    "§cWarning: §7secret is shown below. Anyone who can read your chat history can copy it.",
                    "§eFor security, an enrolled 2FA secret cannot be shown again. "
                            + "Run §f/2fa disable <code>§e, then §f/2fa setup §eto enroll a new device."),
            new LanguageFileUpdater.StockMigration(
                    REPORT_GENERATING_KEY,
                    "§eGenerating diagnostic report... (config + logs will be uploaded to mclo.gs)",
                    "§eGenerating diagnostic report... (redacted config and explicitly enabled logs "
                            + "will be uploaded to mclo.gs)"),
            new LanguageFileUpdater.StockMigration(
                    REPORT_WARNING_KEY,
                    "§eThe report contains redacted config and recent logs. The link is public \\u2014 "
                            + "share it only with trusted parties.",
                    "§eThe report contains redacted config and may contain logs when enabled. "
                            + "The link is public \\u2014 share it only with trusted parties."));

    private static final List<LanguageFileUpdater.StockMigration> POLISH_STOCK_MIGRATIONS = List.of(
            new LanguageFileUpdater.StockMigration(
                    QR_WARNING_KEY,
                    "§cUwaga: §7sekret jest wyświetlony poniżej. Każdy kto przeczyta historię chatu może go skopiować.",
                    "§eZe względów bezpieczeństwa zapisanego sekretu 2FA nie można ponownie wyświetlić. "
                            + "Użyj §f/2fa disable <kod>§e, a następnie §f/2fa setup§e, "
                            + "aby dodać nowe urządzenie."),
            new LanguageFileUpdater.StockMigration(
                    REPORT_GENERATING_KEY,
                    "§eGenerowanie raportu diagnostycznego... (config + logi zostaną wysłane do mclo.gs)",
                    "§eGenerowanie raportu diagnostycznego... (zredagowany config i jawnie włączone logi "
                            + "zostaną wysłane do mclo.gs)"),
            new LanguageFileUpdater.StockMigration(
                    REPORT_WARNING_KEY,
                    "§eRaport zawiera zredagowany config i ostatnie logi. Link jest publiczny \\u2014 "
                            + "udostępnij go tylko zaufanym osobom.",
                    "§eRaport zawiera zredagowany config i może zawierać logi, jeśli je włączono. "
                            + "Link jest publiczny \\u2014 udostępnij go tylko zaufanym osobom."));
    
    private final Path langDirectory;
    private final LanguageFileUpdater.Publisher publisher;
    
    /**
     * Creates a new LanguageFileManager.
     *
     * @param dataDirectory The plugin's data directory (plugins/veloauth/)
     */
    public LanguageFileManager(Path dataDirectory) {
        this(dataDirectory, LanguageFileUpdater::publishAtomically);
    }

    LanguageFileManager(Path dataDirectory, LanguageFileUpdater.Publisher publisher) {
        this.langDirectory = dataDirectory.resolve("lang");
        this.publisher = Objects.requireNonNull(publisher, "publisher must not be null");
    }
    
    /**
     * Initializes the language file system.
     * <p>
     * First run (the lang directory does not exist yet): creates the directory and extracts
     * every bundled template so operators have a starting point for translations.
     * <p>
     * Subsequent runs: the existing directory is operator-owned. Bundled files that were
     * deliberately removed are <em>not</em> recreated; files that remain on disk still receive
     * the documented missing-key and stock-default migration. Missing translations are served
     * from the JAR by {@link #loadLanguageBundle(String)} without writing anything.
     *
     * @throws IOException if the lang directory cannot be created
     */
    public void initializeLanguageFiles() throws IOException {
        if (!Files.exists(langDirectory)) {
            Files.createDirectories(langDirectory);
            logger.info("Created language directory: {}", langDirectory);
            for (String fileName : BuiltInLanguages.fileNames()) {
                copyLanguageFileFromJar(fileName);
            }
            return;
        }

        for (String fileName : BuiltInLanguages.fileNames()) {
            Path targetFile = langDirectory.resolve(fileName);
            if (Files.exists(targetFile)) {
                mergeLanguageFileSafely(fileName, targetFile);
            }
        }
    }
    
    private static void validateLanguageCode(String language) {
        if (language == null || !VALID_LANGUAGE_CODE.matcher(language).matches()) {
            throw new IllegalArgumentException("Invalid language code: must be alphanumeric/underscore/hyphen");
        }
    }

    /**
     * Copies a language file from the JAR to the external lang directory.
     * If file exists externally, merges missing keys from JAR version.
     *
     * @param filename The language file name (e.g., "messages_en.properties")
     */
    private void copyLanguageFileFromJar(String filename) {
        Path targetFile = langDirectory.resolve(filename);
        
        try {
            if (!Files.exists(targetFile)) {
                copyFromJar(filename, targetFile);
            } else {
                // Merge missing keys from JAR version
                mergeLanguageFile(filename, targetFile);
            }
        } catch (IOException e) {
            logger.warn("Could not copy/merge language file {}: {}", filename, e.getMessage());
        }
    }
    
    private void mergeLanguageFileSafely(String filename, Path targetFile) {
        try {
            mergeLanguageFile(filename, targetFile);
        } catch (IOException e) {
            logger.warn("Could not merge language file {}: {}", filename, e.getMessage());
        }
    }

    /**
     * Copies a language file from JAR to target path.
     */
    private void copyFromJar(String filename, Path targetFile) throws IOException {
        try (InputStream is = getClass().getResourceAsStream(LANG_RESOURCE_PATH + filename)) {
            if (is == null) {
                logger.error("Default language file not found in JAR: {}", filename);
                return;
            }
            Files.copy(is, targetFile);
            logger.debug("Copied default language file: {}", filename);
        }
    }
    
    
    /**
     * Merges missing keys from JAR language file into existing external file.
     * Preserves user customizations while adding new keys.
     *
     * @param filename The language file name
     * @param targetFile Path to existing external file
     * @throws IOException if merge fails
     */
    private void mergeLanguageFile(String filename, Path targetFile) throws IOException {
        try (InputStream jarStream = getClass().getResourceAsStream(LANG_RESOURCE_PATH + filename)) {
            if (jarStream == null) {
                logger.warn("Cannot merge - JAR language file not found: {}", filename);
                return;
            }

            java.util.Properties jarProps = loadProperties(jarStream);
            List<LanguageFileUpdater.StockMigration> stockMigrations = stockMigrationsFor(filename);
            validateBundledStockDefaults(filename, jarProps, stockMigrations);
            LanguageFileUpdater.UpdateResult update = LanguageFileUpdater.update(
                    targetFile,
                    jarProps,
                    "# === Auto-added missing keys ===",
                    stockMigrations,
                    publisher);
            if (!update.published()) {
                logger.debug("Language file {} is up to date", filename);
                return;
            }

            logger.info("Updated {} stock values and added {} missing keys in {}",
                    update.migratedKeys().size(), update.missingKeys().size(), filename);
            if (logger.isDebugEnabled()) {
                logger.debug("Language update details for {}: stock={}, missing={}",
                        filename, update.migratedKeys(), update.missingKeys());
            }
        }
    }

    private static java.util.Properties loadProperties(InputStream stream) throws IOException {
        java.util.Properties props = new java.util.Properties();
        try (InputStreamReader reader = new InputStreamReader(stream, StandardCharsets.UTF_8)) {
            props.load(reader);
        }
        return props;
    }

    /**
     * Pure existence check: does {@code messages_<language>.properties} already live on disk?
     * <p>
     * Unlike {@link #loadLanguageBundle(String)}, this method never creates or copies files.
     * Used by {@code Messages.isLanguageSupported} so a typo in the {@code language} config key
     * (e.g. {@code pll} instead of {@code pl}) does not silently spawn a custom language file.
     */
    public boolean fileExists(String language) {
        if (language == null || language.isBlank()) {
            return false;
        }
        try {
            validateLanguageCode(language);
        } catch (IllegalArgumentException invalidCode) {
            return false;
        }
        String filename = MESSAGES_PREFIX + language.toLowerCase(java.util.Locale.ROOT) + PROPERTIES_SUFFIX;
        Path candidate = langDirectory.resolve(filename).normalize();
        if (!candidate.startsWith(langDirectory.normalize())) {
            return false;
        }
        return Files.exists(candidate);
    }

    /**
     * Loads a language bundle, preferring an operator-supplied external file.
     * <p>
     * When no external file exists, bundled languages are read directly from the JAR and
     * unknown languages fall back to English. Neither path writes to disk: only
     * {@link #initializeLanguageFiles()} creates templates, and only when it creates the
     * lang directory.
     * <p>
     * Existing non-English external files still receive the documented missing-key backfill
     * from the external English file. Player-facing lazy loads use the non-backfill overload
     * so missing keys can be resolved in memory against the configured server language before
     * English.
     *
     * @param language The language code (e.g., "en", "pl")
     * @return ResourceBundle containing the language strings
     * @throws IOException if the language file cannot be loaded
     */
    public ResourceBundle loadLanguageBundle(String language) throws IOException {
        return loadLanguageBundle(language, true);
    }

    /**
     * Loads a language bundle, optionally skipping the external English backfill.
     *
     * @param language              language code
     * @param backfillMissingEnglish whether existing non-English files should receive
     *                               missing English keys on disk
     * @return loaded bundle
     * @throws IOException if the language file cannot be loaded
     */
    ResourceBundle loadLanguageBundle(String language, boolean backfillMissingEnglish) throws IOException {
        validateLanguageCode(language);
        String normalizedLanguage = language.toLowerCase(java.util.Locale.ROOT);
        String filename = BuiltInLanguages.fileNameFor(normalizedLanguage);
        Path languageFile = langDirectory.resolve(filename).normalize();
        if (!languageFile.startsWith(langDirectory.normalize())) {
            throw new IllegalArgumentException("Invalid language code: path traversal detected");
        }

        logger.debug("Loading language: {}", normalizedLanguage);
        logger.debug("Looking for external file: {}", languageFile.toAbsolutePath());
        logger.debug("External file exists: {}", Files.exists(languageFile));

        if (Files.exists(languageFile)) {
            logger.debug("Language file already exists, using: {}", languageFile.getFileName());
            if (backfillMissingEnglish && !BuiltInLanguages.englishCode().equals(normalizedLanguage)) {
                fillMissingKeysFromEnglish(normalizedLanguage);
            }
            ResourceBundle bundle = loadExternalBundle(languageFile);
            if (logger.isDebugEnabled()) {
                logger.debug("Loaded EXTERNAL language file: {} ({} keys)",
                        languageFile.toAbsolutePath(), bundle.keySet().size());
            }
            return bundle;
        }

        ResourceBundle bundled = loadBundledBundle(normalizedLanguage);
        if (bundled != null) {
            logger.debug("Loaded bundled language '{}' directly from JAR (no external file)",
                    normalizedLanguage);
            return bundled;
        }

        logger.warn("Language file not found: {}, falling back to English", filename);
        return loadEnglishFallbackBundle();
    }

    private static ResourceBundle loadExternalBundle(Path languageFile) throws IOException {
        try (InputStream is = Files.newInputStream(languageFile);
             InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
            return new PropertyResourceBundle(reader);
        }
    }

    @javax.annotation.Nullable
    private ResourceBundle loadBundledBundle(String language) throws IOException {
        try (InputStream is = getClass().getResourceAsStream(
                LANG_RESOURCE_PATH + BuiltInLanguages.fileNameFor(language))) {
            if (is == null) {
                return null;
            }
            try (InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
                return new PropertyResourceBundle(reader);
            }
        }
    }

    private ResourceBundle loadEnglishFallbackBundle() throws IOException {
        Path englishFile = langDirectory.resolve(BuiltInLanguages.englishFileName());
        if (Files.exists(englishFile)) {
            return loadExternalBundle(englishFile);
        }

        ResourceBundle bundledEnglish = loadBundledBundle(BuiltInLanguages.englishCode());
        if (bundledEnglish != null) {
            logger.debug("Using bundled English fallback (no external English file)");
            return bundledEnglish;
        }

        throw new IOException("English fallback language file not found at: " + englishFile);
    }

    /**
     * Fills missing keys in a custom language file from English template.
     * This allows users to create partial translations - missing keys will use English values.
     *
     * @param language The language code (e.g., "de", "fr")
     */
    private void fillMissingKeysFromEnglish(String language) {
        Path englishFile = langDirectory.resolve(BuiltInLanguages.englishFileName());
        Path targetFile = langDirectory.resolve(MESSAGES_PREFIX + language + PROPERTIES_SUFFIX);

        if (!Files.exists(englishFile) || !Files.exists(targetFile)) {
            return;
        }

        try {
            java.util.Properties englishProps;
            try (InputStream enStream = Files.newInputStream(englishFile)) {
                englishProps = loadProperties(enStream);
            }
            LanguageFileUpdater.UpdateResult update = LanguageFileUpdater.update(
                    targetFile,
                    englishProps,
                    "# === Missing keys (English fallback - please translate) ===",
                    List.of(),
                    publisher);
            if (!update.published()) {
                return;
            }

            logger.info("Added {} missing keys to messages_{}.properties from English template (run with DEBUG to list them)",
                    update.missingKeys().size(), language);
            if (logger.isDebugEnabled()) {
                logger.debug("Added missing keys to messages_{}.properties: {}",
                        language, update.missingKeys());
            }
        } catch (IOException e) {
            logger.warn("Failed to fill missing keys for language {}: {}", language, e.getMessage());
        }
    }

    private static List<LanguageFileUpdater.StockMigration> stockMigrationsFor(String filename)
            throws IOException {
        if (!filename.startsWith(MESSAGES_PREFIX) || !filename.endsWith(PROPERTIES_SUFFIX)) {
            throw new IOException("Unexpected bundled language filename: " + filename);
        }
        String language = filename.substring(
                MESSAGES_PREFIX.length(), filename.length() - PROPERTIES_SUFFIX.length());
        if (!BuiltInLanguages.isBuiltIn(language)) {
            throw new IOException("Stock migration is restricted to built-in language files: " + filename);
        }
        return "pl".equals(language) ? POLISH_STOCK_MIGRATIONS : COMMON_STOCK_MIGRATIONS;
    }

    private static void validateBundledStockDefaults(
            String filename,
            java.util.Properties bundledProperties,
            List<LanguageFileUpdater.StockMigration> migrations) throws IOException {
        for (LanguageFileUpdater.StockMigration migration : migrations) {
            if (!migration.newValue().equals(bundledProperties.getProperty(migration.key()))) {
                throw new IOException("Bundled stock default drift for " + migration.key()
                        + " in " + filename);
            }
        }
    }

    /**
     * Escapes a .properties value per Java {@link java.util.Properties#store} rules:
     * backslash, control characters, and a leading space. Internal whitespace, {@code =},
     * {@code :}, {@code #}, {@code !} are valid in values without escaping (only the first
     * non-whitespace character determines key/value separation, which is the {@code =} we write).
     */
    static String escapePropertyValue(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length() + 4);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            String controlEscape = controlEscape(c);
            if (controlEscape != null) {
                sb.append(controlEscape);
            } else if (c == ' ' && i == 0) {
                // Leading space in a value must be escaped to survive Properties.load.
                sb.append("\\ ");
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Escapes a .properties key. Keys disallow unescaped {@code =}, {@code :}, {@code #},
     * {@code !}, whitespace, and backslash. VeloAuth keys are ASCII dotted identifiers,
     * but this guards against future renames into more exotic shapes.
     */
    static String escapePropertyKey(String key) {
        if (key == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(key.length() + 4);
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            String controlEscape = controlEscape(c);
            if (controlEscape != null) {
                sb.append(controlEscape);
            } else if (isKeyDelimiter(c)) {
                sb.append('\\').append(c);
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    private static String controlEscape(char c) {
        return switch (c) {
            case '\\' -> "\\\\";
            case '\n' -> "\\n";
            case '\r' -> "\\r";
            case '\t' -> "\\t";
            case '\f' -> "\\f";
            default -> null;
        };
    }

    private static boolean isKeyDelimiter(char c) {
        return c == ' ' || c == '=' || c == ':' || c == '#' || c == '!';
    }

}
