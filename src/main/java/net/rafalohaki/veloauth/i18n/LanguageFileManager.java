package net.rafalohaki.veloauth.i18n;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.PropertyResourceBundle;
import java.util.ResourceBundle;

/**
 * Manages external language files for VeloAuth.
 * Handles initialization, loading, and validation of language files from the filesystem.
 */
public final class LanguageFileManager {
    
    private static final Logger logger = LoggerFactory.getLogger(LanguageFileManager.class);
    private static final String ENGLISH_FILE = "messages_en.properties";
    private static final String POLISH_FILE = "messages_pl.properties";
    private static final String MESSAGES_PREFIX = "messages_";
    private static final String PROPERTIES_SUFFIX = ".properties";
    
    private final Path langDirectory;
    
    /**
     * Creates a new LanguageFileManager.
     *
     * @param dataDirectory The plugin's data directory (plugins/VeloAuth/)
     */
    public LanguageFileManager(Path dataDirectory) {
        this.langDirectory = dataDirectory.resolve("lang");
    }
    
    /**
     * Initializes the language file system.
     * Creates the lang directory if it doesn't exist and copies default language files from JAR.
     *
     * @throws IOException if directory creation or file copying fails
     */
    public void initializeLanguageFiles() throws IOException {
        // Create lang directory if it doesn't exist
        if (!Files.exists(langDirectory)) {
            Files.createDirectories(langDirectory);
            logger.info("Created language directory: {}", langDirectory);
        }
        
        // Copy only built-in default language files from JAR if they don't exist
        copyDefaultLanguageFile(ENGLISH_FILE);
        copyDefaultLanguageFile(POLISH_FILE);
        // Users can add custom language files (e.g., messages_de.properties) to this directory
    }
    
    /**
     * Copies a default language file from the JAR to the external lang directory.
     * If file exists, merges missing keys from JAR version.
     *
     * @param filename The language file name (e.g., "messages_en.properties")
     * @throws IOException if file copying fails
     */
    private void copyDefaultLanguageFile(String filename) throws IOException {
        Path targetFile = langDirectory.resolve(filename);
        
        if (!Files.exists(targetFile)) {
            try (InputStream is = getClass().getResourceAsStream("/lang/" + filename)) {
                if (is == null) {
                    logger.error("Default language file not found in JAR: {}", filename);
                    return;
                }
                Files.copy(is, targetFile);
                logger.info("Copied default language file: {}", filename);
            }
        } else {
            // Merge missing keys from JAR version
            mergeLanguageFile(filename, targetFile);
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
        try (InputStream jarStream = getClass().getResourceAsStream("/lang/" + filename)) {
            if (jarStream == null) {
                logger.warn("Cannot merge - JAR language file not found: {}", filename);
                return;
            }
            
            // Load JAR properties
            java.util.Properties jarProps = new java.util.Properties();
            try (InputStreamReader jarReader = new InputStreamReader(jarStream, StandardCharsets.UTF_8)) {
                jarProps.load(jarReader);
            }
            
            // Load existing external properties
            java.util.Properties externalProps = new java.util.Properties();
            try (InputStream extStream = Files.newInputStream(targetFile);
                 InputStreamReader extReader = new InputStreamReader(extStream, StandardCharsets.UTF_8)) {
                externalProps.load(extReader);
            }
            
            // Find missing keys
            java.util.List<String> missingKeys = new java.util.ArrayList<>();
            for (String key : jarProps.stringPropertyNames()) {
                if (!externalProps.containsKey(key)) {
                    missingKeys.add(key);
                    externalProps.setProperty(key, jarProps.getProperty(key));
                }
            }
            
            if (!missingKeys.isEmpty()) {
                // Append missing keys to file
                try (java.io.BufferedWriter writer = Files.newBufferedWriter(targetFile, StandardCharsets.UTF_8, 
                        java.nio.file.StandardOpenOption.APPEND)) {
                    writer.newLine();
                    writer.write("# === Auto-added missing keys ===");
                    writer.newLine();
                    for (String key : missingKeys) {
                        writer.write(key + "=" + jarProps.getProperty(key));
                        writer.newLine();
                    }
                }
                logger.info("Added {} missing keys to {}: {}", missingKeys.size(), filename, missingKeys);
            } else {
                logger.debug("Language file {} is up to date", filename);
            }
        }
    }
    
    /**
     * Loads a language bundle from the external lang directory.
     * Falls back to English if the requested language is not found.
     * Also fills in missing keys from English template for custom language files.
     *
     * @param language The language code (e.g., "en", "pl")
     * @return ResourceBundle containing the language strings
     * @throws IOException if the language file cannot be loaded
     */
    public ResourceBundle loadLanguageBundle(String language) throws IOException {
        String filename = MESSAGES_PREFIX + language + PROPERTIES_SUFFIX;
        Path languageFile = langDirectory.resolve(filename);
        
        logger.debug("Loading language: {}", language);
        logger.debug("Looking for external file: {}", languageFile.toAbsolutePath());
        logger.debug("External file exists: {}", Files.exists(languageFile));
        
        if (!Files.exists(languageFile)) {
            logger.warn("Language file not found: {}, falling back to English", filename);
            languageFile = langDirectory.resolve(ENGLISH_FILE);
        }
        
        if (!Files.exists(languageFile)) {
            throw new IOException("English fallback language file not found at: " + languageFile);
        }
        
        // For non-English languages, fill missing keys from English
        if (!"en".equals(language) && Files.exists(langDirectory.resolve(filename))) {
            fillMissingKeysFromEnglish(language);
        }
        
        try (InputStream is = Files.newInputStream(languageFile);
             InputStreamReader reader = new InputStreamReader(is, StandardCharsets.UTF_8)) {
            PropertyResourceBundle bundle = new PropertyResourceBundle(reader);
            logger.info("Loaded EXTERNAL language file: {} ({} keys)", languageFile.toAbsolutePath(), bundle.keySet().size());
            return bundle;
        }
    }
    
    /**
     * Fills missing keys in a custom language file from English template.
     * This allows users to create partial translations - missing keys will use English values.
     *
     * @param language The language code (e.g., "de", "fr")
     */
    private void fillMissingKeysFromEnglish(String language) {
        Path englishFile = langDirectory.resolve(ENGLISH_FILE);
        Path targetFile = langDirectory.resolve(MESSAGES_PREFIX + language + PROPERTIES_SUFFIX);
        
        if (!Files.exists(englishFile) || !Files.exists(targetFile)) {
            return;
        }
        
        try {
            // Load English properties as template
            java.util.Properties englishProps = new java.util.Properties();
            try (InputStream enStream = Files.newInputStream(englishFile);
                 InputStreamReader enReader = new InputStreamReader(enStream, StandardCharsets.UTF_8)) {
                englishProps.load(enReader);
            }
            
            // Load target language properties
            java.util.Properties targetProps = new java.util.Properties();
            try (InputStream targetStream = Files.newInputStream(targetFile);
                 InputStreamReader targetReader = new InputStreamReader(targetStream, StandardCharsets.UTF_8)) {
                targetProps.load(targetReader);
            }
            
            // Find missing keys
            java.util.List<String> missingKeys = new java.util.ArrayList<>();
            for (String key : englishProps.stringPropertyNames()) {
                if (!targetProps.containsKey(key)) {
                    missingKeys.add(key);
                }
            }
            
            if (!missingKeys.isEmpty()) {
                // Append missing keys with English values (as placeholder for translation)
                try (java.io.BufferedWriter writer = Files.newBufferedWriter(targetFile, StandardCharsets.UTF_8, 
                        java.nio.file.StandardOpenOption.APPEND)) {
                    writer.newLine();
                    writer.write("# === Missing keys (English fallback - please translate) ===");
                    writer.newLine();
                    for (String key : missingKeys) {
                        writer.write(key + "=" + englishProps.getProperty(key));
                        writer.newLine();
                    }
                }
                logger.info("Added {} missing keys to messages_{}.properties from English template: {}", 
                        missingKeys.size(), language, missingKeys);
            }
        } catch (IOException e) {
            logger.warn("Failed to fill missing keys for language {}: {}", language, e.getMessage());
        }
    }
    
    /**
     * Validates that a language file can be loaded successfully.
     * Logs validation results.
     *
     * @param language The language code to validate
     */
    public void validateLanguageFile(String language) {
        try {
            ResourceBundle bundle = loadLanguageBundle(language);
            logger.info("Validated language file for: {}", language);
            logger.debug("Language file contains {} keys", bundle.keySet().size());
        } catch (IOException e) {
            logger.error("Failed to validate language file for: {}", language, e);
        }
    }
}
