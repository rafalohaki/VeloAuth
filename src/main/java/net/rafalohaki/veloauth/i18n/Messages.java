package net.rafalohaki.veloauth.i18n;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.text.MessageFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Internationalization manager for VeloAuth messages.
 * Thread-safe message loading and formatting with caching.
 */
public class Messages {
    
    private static final Logger logger = LoggerFactory.getLogger(Messages.class);
    
    // Cache for loaded message files
    private static final Map<String, Properties> messageCache = new ConcurrentHashMap<>();
    
    // Current language
    private String currentLanguage = "en";
    
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
        
        // Pre-load messages for the new language
        loadMessages(this.currentLanguage);
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
     * @param key Message key
     * @param args Arguments for message formatting
     * @return Formatted message or the key if not found
     */
    public String get(String key, Object... args) {
        return get(currentLanguage, key, args);
    }
    
    /**
     * Gets a formatted message for a specific language.
     *
     * @param language Language code
     * @param key Message key
     * @param args Arguments for message formatting
     * @return Formatted message or the key if not found
     */
    public String get(String language, String key, Object... args) {
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
                logger.warn("Failed to format message '{}': {}", key, e.getMessage());
                return message;
            }
        }
        
        return message;
    }
    
    /**
     * Checks if a language is supported.
     *
     * @param language Language code to check
     * @return true if supported
     */
    public boolean isLanguageSupported(String language) {
        if (language == null) return false;
        
        String lang = language.toLowerCase(Locale.ROOT);
        return "en".equals(lang) || "pl".equals(lang);
    }
    
    /**
     * Gets all supported language codes.
     *
     * @return Array of supported language codes
     */
    public String[] getSupportedLanguages() {
        return new String[]{"en", "pl"};
    }
    
    /**
     * Clears the message cache.
     */
    public void clearCache() {
        messageCache.clear();
        logger.info("Message cache cleared");
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
     *
     * @param languageCode Language code
     * @return Display name or the code if not found
     */
    public String getLanguageDisplayName(String languageCode) {
        return switch (languageCode.toLowerCase(Locale.ROOT)) {
            case "en" -> "English";
            case "pl" -> "Polski";
            default -> languageCode;
        };
    }
    
    /**
     * Gets the language display name in its native language.
     *
     * @param languageCode Language code
     * @return Native display name or the code if not found
     */
    public String getLanguageNativeName(String languageCode) {
        return switch (languageCode.toLowerCase(Locale.ROOT)) {
            case "en" -> "English";
            case "pl" -> "Polski";
            default -> languageCode;
        };
    }
}
