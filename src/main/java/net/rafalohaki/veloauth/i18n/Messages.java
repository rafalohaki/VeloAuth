package net.rafalohaki.veloauth.i18n;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Internationalization manager for VeloAuth messages.
 * Thread-safe message loading and formatting with support for external language files.
 */
public class Messages {

    private static final Logger logger = LoggerFactory.getLogger(Messages.class);

    // Cache for loaded message files (legacy support)
    private static final Map<String, Properties> messageCache = new ConcurrentHashMap<>();

    // Current language
    private String currentLanguage = "en";
    
    // Language file manager for external files
    private final LanguageFileManager languageFileManager;
    
    // Current resource bundle
    private ResourceBundle bundle;
    
    // Flag to indicate if using external files
    private final boolean useExternalFiles;

    /**
     * Creates a Messages instance with external language file support.
     *
     * @param dataDirectory The plugin's data directory
     * @param language The language code (e.g., "en", "pl")
     */
    public Messages(Path dataDirectory, String language) throws IOException {
        this.languageFileManager = new LanguageFileManager(dataDirectory);
        this.currentLanguage = language != null ? language.toLowerCase(Locale.ROOT) : "en";
        this.useExternalFiles = true;
        
        try {
            languageFileManager.initializeLanguageFiles();
            reload();
        } catch (IOException e) {
            throw new IOException("Language initialization failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Creates a Messages instance using JAR-embedded language files (legacy mode).
     * Used for testing and backward compatibility.
     */
    public Messages() {
        this.languageFileManager = null;
        this.useExternalFiles = false;
        this.currentLanguage = "en";
    }

    /**
     * Sets the current language for messages.
     *
     * @param language Language code (e.g., "en", "pl")
     */
    public void setLanguage(String language) {
        if (language == null || language.trim().isEmpty()) {
            logger.warn("Invalid language provided, using default 'en'");
            this.currentLanguage = "en";
            return;
        }

        // Validate language is supported
        if (!isLanguageSupported(language)) {
            logger.warn("Unsupported language '{}', falling back to 'en'", language);
            this.currentLanguage = "en";
            return;
        }

        this.currentLanguage = language.toLowerCase(Locale.ROOT);
        logger.info("Language set to: {}", this.currentLanguage);

        // Reload messages for the new language
        if (useExternalFiles) {
            try {
                reload();
            } catch (IOException e) {
                logger.error("Failed to reload language files", e);
            }
        } else {
            // Pre-load messages for the new language (legacy mode)
            loadMessages(this.currentLanguage);
        }
    }
    
    /**
     * Reloads language files from disk.
     * Only works when using external files.
     *
     * @throws IOException if language file loading fails
     */
    public void reload() throws IOException {
        if (!useExternalFiles) {
            logger.warn("Cannot reload - not using external files");
            // Clear legacy cache anyway
            clearCache();
            return;
        }
        
        // Clear the static message cache to ensure fresh loading
        clearCache();
        
        // Force re-initialization of language files (copies new keys if any)
        languageFileManager.initializeLanguageFiles();
        
        this.bundle = languageFileManager.loadLanguageBundle(currentLanguage);
        logger.info("Reloaded language files for: {} (external files enabled)", currentLanguage);
    }
    
    /**
     * Reloads language files with a new language setting.
     * This should be called after config reload to pick up language changes.
     *
     * @param newLanguage The new language code from config
     * @throws IOException if language file loading fails
     */
    public void reloadWithLanguage(String newLanguage) throws IOException {
        String oldLanguage = this.currentLanguage;
        
        // Update language if provided and valid
        if (newLanguage != null && !newLanguage.trim().isEmpty()) {
            this.currentLanguage = newLanguage.toLowerCase(java.util.Locale.ROOT);
        }
        
        // Log language change if it occurred
        if (!oldLanguage.equals(this.currentLanguage)) {
            logger.info("Language changed from '{}' to '{}'", oldLanguage, currentLanguage);
        }
        
        // Perform full reload
        reload();
    }

    /**
     * Gets the current language.
     *
     * @return Current language code
     */
    public String getCurrentLanguage() {
        return currentLanguage;
    }

    /**
     * Gets a formatted message for the current language.
     *
     * @param key  Message key
     * @param args Arguments for message formatting
     * @return Formatted message or the key if not found
     */
    public String get(String key, Object... args) {
        if (useExternalFiles) {
            return getFromBundle(key, args);
        } else {
            return getForLanguage(currentLanguage, key, args);
        }
    }

    /**
     * Gets a formatted message for a specific language.
     *
     * @param language Language code
     * @param key      Message key
     * @param args     Arguments for message formatting
     * @return Formatted message or the key if not found
     */
    public String getForLanguage(String language, String key, Object... args) {
        Properties messages = loadMessages(language);
        String message = messages.getProperty(key);

        if (message == null) {
            logger.debug("Message key '{}' not found for language '{}', falling back to English", key, language);
            // Fallback to English if key not found in current language
            if (!"en".equals(language)) {
                Properties englishMessages = loadMessages("en");
                message = englishMessages.getProperty(key);
            }

            // If still not found, return the key itself
            if (message == null) {
                logger.warn("Message key '{}' not found in any language file", key);
                message = key;
            }
        }

        // Format message with arguments if provided
        if (args.length > 0) {
            try {
                return MessageFormat.format(message, args);
            } catch (IllegalArgumentException e) {
                if (logger.isWarnEnabled()) {
                    logger.warn("Failed to format message '{}': {}", key, e.getMessage());
                }
                return message;
            }
        }

        return message;
    }
    
    /**
     * Gets a message from the external ResourceBundle.
     * Handles missing keys gracefully by returning a fallback.
     *
     * @param key  Message key
     * @param args Arguments for message formatting
     * @return Formatted message or fallback if not found
     */
    private String getFromBundle(String key, Object... args) {
        try {
            String message = bundle.getString(key);
            return formatMessageSafely(message, key, args);
        } catch (MissingResourceException e) {
            logger.warn("Missing translation key: {}", key);
            return "Missing: " + key;
        }
    }
    
    private String formatMessageSafely(String message, String key, Object... args) {
        if (args.length == 0) {
            return message;
        }

        try {
            // Support both MessageFormat style ({0}, {1}) and lightweight '{}' style used in some translations.
            // If '{}' tokens are present but no numeric indices, convert '{}' -> {0}, {1}, ... for MessageFormat.
            if (message.contains("{}") && !message.matches(".*\\{\\d+}.*")) {
                StringBuilder sb = new StringBuilder();
                int start = 0;
                int index = 0;
                int pos;
                while ((pos = message.indexOf("{}", start)) >= 0) {
                    sb.append(message, start, pos);
                    sb.append('{').append(index++).append('}');
                    start = pos + 2;
                }
                sb.append(message.substring(start));
                message = sb.toString();
            }

            return MessageFormat.format(message, args);
        } catch (IllegalArgumentException e) {
            logger.warn("Failed to format message '{}': {}", key, e.getMessage());
            return message;
        }
    }

    /**
     * Checks if a language is supported.
     * For external file mode: checks if the language file exists.
     * For legacy JAR mode: checks if the resource exists.
     *
     * @param language Language code to check
     * @return true if supported
     */
    public boolean isLanguageSupported(String language) {
        if (language == null) return false;

        String lang = language.toLowerCase(Locale.ROOT);
        
        if (useExternalFiles && languageFileManager != null) {
            // Check if language file exists in external directory
            try {
                languageFileManager.loadLanguageBundle(lang);
                return true;
            } catch (IOException e) {
                return false;
            }
        } else {
            // Legacy mode: check JAR resources (built-in languages only)
            return "en".equals(lang) || "pl".equals(lang);
        }
    }

    /**
     * Gets all supported language codes.
     * Returns built-in languages (en, pl) - users can add custom languages by placing
     * messages_*.properties files in the lang directory.
     *
     * @return Array of built-in language codes
     */
    public String[] getSupportedLanguages() {
        return new String[]{"en", "pl"};
    }

    /**
     * Clears the message cache.
     * This should be called during reload to ensure fresh messages are loaded.
     */
    public void clearCache() {
        int sizeBefore = messageCache.size();
        messageCache.clear();
        if (sizeBefore > 0) {
            logger.info("Message cache cleared ({} entries removed)", sizeBefore);
        }
    }

    /**
     * Loads messages for a specific language from properties file.
     * Uses caching to avoid repeated file reads.
     *
     * @param language Language code
     * @return Properties containing messages
     */
    private Properties loadMessages(String language) {
        return messageCache.computeIfAbsent(language, this::loadMessagesFromFile);
    }

    /**
     * Loads messages from file system.
     *
     * @param language Language code
     * @return Properties containing messages
     */
    private Properties loadMessagesFromFile(String language) {
        Properties properties = new Properties();
        String fileName = "lang/messages_" + language + ".properties";

        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(fileName)) {
            if (inputStream != null) {
                properties.load(new java.io.InputStreamReader(inputStream, java.nio.charset.StandardCharsets.UTF_8));
                logger.debug("Loaded {} messages from file: {}", properties.size(), fileName);
            } else {
                logger.error("Could not find language file: {}", fileName);
            }
        } catch (Exception e) {
            logger.error("Error loading language file: {}", fileName, e);
        }

        return properties;
    }

    /**
     * Gets the language display name in English.
     * Only includes built-in languages - custom languages will return the code.
     *
     * @param languageCode Language code
     * @return Display name or the code if not found
     */
    public String getLanguageDisplayName(String languageCode) {
        return switch (languageCode.toLowerCase(Locale.ROOT)) {
            case "en" -> "English";
            case "pl" -> "Polish";
            default -> languageCode; // Custom languages return their code
        };
    }

    /**
     * Gets the language display name in its native language.
     * Only includes built-in languages - custom languages will return the code.
     *
     * @param languageCode Language code
     * @return Native display name or the code if not found
     */
    public String getLanguageNativeName(String languageCode) {
        return switch (languageCode.toLowerCase(Locale.ROOT)) {
            case "en" -> "English";
            case "pl" -> "Polski";
            default -> languageCode; // Custom languages return their code
        };
    }
}
