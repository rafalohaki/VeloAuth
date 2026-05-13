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
    private static final Map<String, String> DEPRECATED_KEY_ALIASES = Map.of(
            "auth.register.password_too_short", "validation.password.too_short",
            "error.connection.generic", "connection.error.generic"
    );

    // Cache for loaded message files (legacy support)
    private static final Map<String, Properties> messageCache = new ConcurrentHashMap<>();
    private static final Map<String, String> normalizedPatternCache = new ConcurrentHashMap<>();

    // Current language
    private String currentLanguage;
    
    // Language file manager for external files
    private final LanguageFileManager languageFileManager;
    
    // Current resource bundle
    private ResourceBundle bundle;
    // English fallback bundle (used when a key is missing in `bundle`)
    private ResourceBundle englishBundle;

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
        // Pre-load English bundle so getFromBundle can fall back per-key when a
        // user-supplied translation is partial / broken / missing the requested key.
        // For currentLanguage == "en" we keep the reference identical (no double load).
        this.englishBundle = "en".equalsIgnoreCase(currentLanguage)
                ? this.bundle
                : languageFileManager.loadLanguageBundle("en");
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
        String resolvedKey = resolveMessageKey(key);
        if (useExternalFiles) {
            return getFromBundle(resolvedKey, args);
        } else {
            return getForLanguage(currentLanguage, resolvedKey, args);
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
        String resolvedKey = resolveMessageKey(key);
        Properties messages = loadMessages(language);
        String message = messages.getProperty(resolvedKey);

        if (message == null) {
            logger.debug("Message key '{}' not found for language '{}', falling back to English",
                    resolvedKey, language);
            // Fallback to English if key not found in current language
            if (!"en".equals(language)) {
                Properties englishMessages = loadMessages("en");
                message = englishMessages.getProperty(resolvedKey);
            }

            // If still not found, return the key itself
            if (message == null) {
                logger.warn("Message key '{}' not found in any language file", resolvedKey);
                message = resolvedKey;
            }
        }

        // Format message with arguments if provided
        return formatMessageSafely(message, resolvedKey, args);
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
        String resolvedKey = resolveMessageKey(key);
        try {
            String message = bundle.getString(resolvedKey);
            return formatMessageSafely(message, resolvedKey, args);
        } catch (MissingResourceException e) {
            // Per-key fallback to English. Triggered when the active language file is
            // corrupted, manually edited to remove keys, or simply missing newer keys
            // that fillMissingKeysFromEnglish() failed to backfill. Keeps user-facing
            // text in a real language instead of leaking "Missing: …" to the player.
            if (englishBundle != null && englishBundle != bundle) {
                try {
                    String message = englishBundle.getString(resolvedKey);
                    logger.warn("Missing translation key '{}' in language '{}' — falling back to English",
                            resolvedKey, currentLanguage);
                    return formatMessageSafely(message, resolvedKey, args);
                } catch (MissingResourceException ignoredEn) {
                    // fall through to the absolute fallback below
                }
            }
            logger.warn("Missing translation key '{}' in all available languages", resolvedKey);
            return "Missing: " + resolvedKey;
        }
    }
    
    private String formatMessageSafely(String message, String key, Object... args) {
        if (args.length == 0) {
            return message;
        }

        try {
            return MessageFormat.format(normalizeMessagePattern(message), args);
        } catch (IllegalArgumentException e) {
            logger.warn("Failed to format message '{}': {}", key, e.getMessage());
            return message;
        }
    }

    private String normalizeMessagePattern(String message) {
        if (message.indexOf('{') < 0 && message.indexOf('\'') < 0) {
            return message;
        }
        return normalizedPatternCache.computeIfAbsent(message, Messages::normalizeMessageFormatPattern);
    }

    private static String normalizeMessageFormatPattern(String message) {
        return escapeMessageFormatApostrophes(convertBracePlaceholders(message));
    }

    private static String convertBracePlaceholders(String message) {
        if (message.indexOf("{}") < 0 || containsIndexedPlaceholders(message)) {
            return message;
        }

        StringBuilder sb = new StringBuilder(message.length() + 8);
        int start = 0;
        int index = 0;
        int pos;
        while ((pos = message.indexOf("{}", start)) >= 0) {
            sb.append(message, start, pos);
            sb.append('{').append(index++).append('}');
            start = pos + 2;
        }
        sb.append(message.substring(start));
        return sb.toString();
    }

    private static String escapeMessageFormatApostrophes(String message) {
        if (message.indexOf('\'') < 0) {
            return message;
        }

        StringBuilder sb = new StringBuilder(message.length() + 8);
        for (int index = 0; index < message.length(); index++) {
            char character = message.charAt(index);
            if (character != '\'') {
                sb.append(character);
                continue;
            }

            if (index + 1 < message.length() && message.charAt(index + 1) == '\'') {
                sb.append("''");
                index++;
                continue;
            }

            sb.append("''");
        }
        return sb.toString();
    }

    private static boolean containsIndexedPlaceholders(String message) {
        for (int index = 0; index < message.length() - 2; index++) {
            if (message.charAt(index) != '{' || !Character.isDigit(message.charAt(index + 1))) {
                continue;
            }

            int end = index + 2;
            while (end < message.length() && Character.isDigit(message.charAt(end))) {
                end++;
            }
            if (end < message.length() && message.charAt(end) == '}') {
                return true;
            }
        }
        return false;
    }

    private static String resolveMessageKey(String key) {
        return DEPRECATED_KEY_ALIASES.getOrDefault(key, key);
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

        // Pure query — does NOT mutate the filesystem. A typo in the config (e.g. "pll")
        // must surface as "Unsupported language" + EN fallback, not auto-create a custom file.
        // Operators who want a real custom language drop messages_<code>.properties into the
        // lang directory themselves; that file will then be picked up as "supported" on next boot.
        if (useExternalFiles && languageFileManager != null) {
            return BuiltInLanguages.isBuiltIn(lang) || languageFileManager.fileExists(lang);
        }
        return BuiltInLanguages.isBuiltIn(lang);
    }

    /**
     * Gets all supported language codes.
    * Returns built-in languages bundled with the plugin. Users can still add custom languages by placing
     * messages_*.properties files in the lang directory.
     *
     * @return Array of built-in language codes
     */
    public String[] getSupportedLanguages() {
        return BuiltInLanguages.codes();
    }

    /**
     * Clears the message cache.
     * This should be called during reload to ensure fresh messages are loaded.
     */
    public void clearCache() {
        int sizeBefore = messageCache.size();
        messageCache.clear();
        normalizedPatternCache.clear();
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
        } catch (IOException e) {
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
