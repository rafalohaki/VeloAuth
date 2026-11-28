package net.rafalohaki.veloauth.i18n;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
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
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

/**
 * Internationalization manager for VeloAuth messages.
 * Thread-safe message loading and formatting with support for external language files.
 * Reloads build a complete language generation and publish it through one volatile reference;
 * a failed reload leaves the previous language, bundles and per-locale cache active.
 */
public class Messages {

    private static final Logger logger = LoggerFactory.getLogger(Messages.class);
    private static final Map<String, String> DEPRECATED_KEY_ALIASES = Map.of(
            "auth.register.password_too_short", "validation.password.too_short",
            "error.connection.generic", "connection.error.generic"
    );
    private static final Pattern MINIMESSAGE_HEX_COLOR = Pattern.compile("(?i)<#([0-9a-f]{6})>");
    private static final Pattern SECTION_LEGACY_CODE = Pattern.compile("(?i)§([0-9a-fk-orx#])");
    private static final Pattern AMPERSAND_LEGACY_CODE = Pattern.compile(
            "(?i)&(?:#[0-9a-f]{6}|x(?:&[0-9a-f]){6}|[0-9a-fk-or])");
    private static final String LITERAL_AMPERSAND_MARKER = "\uFDD0";
    private static final String LITERAL_SECTION_MARKER = "\uFDD1";
    private static final String LITERAL_MINIMESSAGE_HEX_MARKER = "\uFDD2";
    private static final LegacyComponentSerializer LEGACY_COMPONENT_SERIALIZER =
            LegacyComponentSerializer.builder().character('&').hexColors().build();

    // Cache for loaded message files (legacy support)
    private static final Map<String, Properties> messageCache = new ConcurrentHashMap<>();
    private static final Map<String, String> normalizedPatternCache = new ConcurrentHashMap<>();

    // One immutable language generation; reload publishes a fully loaded replacement.
    // Readers capture this volatile reference once per render so a concurrent reload can
    // never mix an old language code with newly published bundles.
    private volatile LanguageSnapshot snapshot;

    // Serializes generation builds so a slower older load cannot overwrite a newer one.
    private final ReentrantLock reloadLock = new ReentrantLock();

    // Language file manager for external files
    private final LanguageFileManager languageFileManager;

    private final boolean useExternalFiles;

    /**
     * Creates a Messages instance with external language file support.
     *
     * @param dataDirectory The plugin's data directory
     * @param language The language code (e.g., "en", "pl")
     */
    public Messages(Path dataDirectory, String language) throws IOException {
        this.languageFileManager = new LanguageFileManager(dataDirectory);
        this.useExternalFiles = true;

        String initialLanguage = language != null ? language.toLowerCase(Locale.ROOT) : "en";
        // Publish a bootstrap generation so getCurrentLanguage() is already readable while
        // the first bundles load.
        this.snapshot = new LanguageSnapshot(initialLanguage, null, null);
        try {
            languageFileManager.initializeLanguageFiles();
            if (!isSupportedLanguage(initialLanguage)) {
                logger.warn("Unsupported language '{}', falling back to 'en'", initialLanguage);
                initialLanguage = "en";
            }
            loadLanguage(initialLanguage);
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
        this.snapshot = new LanguageSnapshot("en", null, null);
    }

    /**
     * Sets the current language for messages.
     *
     * @param language Language code (e.g., "en", "pl")
     */
    public void setLanguage(String language) {
        String targetLanguage;
        if (language == null || language.trim().isEmpty()) {
            logger.warn("Invalid language provided, using default 'en'");
            targetLanguage = "en";
        } else if (!isLanguageSupported(language)) {
            // Validate language is supported
            logger.warn("Unsupported language '{}', falling back to 'en'", language);
            targetLanguage = "en";
        } else {
            targetLanguage = language.toLowerCase(Locale.ROOT);
        }

        if (loadLanguageAfterChange(targetLanguage)) {
            logger.info("Language set to: {}", targetLanguage);
        }
    }

    /**
     * Applies a validated target language. External-file mode publishes a complete new
     * generation; if loading fails the previous generation — including its language — stays
     * active.
     *
     * @return true when the requested language is active after the call
     */
    private boolean loadLanguageAfterChange(String language) {
        if (useExternalFiles) {
            try {
                loadLanguage(language);
                return true;
            } catch (IOException e) {
                logger.error("Failed to reload language files", e);
                return false;
            }
        }

        this.snapshot = new LanguageSnapshot(language, null, null);
        // Pre-load messages for the new language (legacy mode)
        loadMessages(language);
        return true;
    }
    
    /**
     * Reloads language files from disk.
     * Only works when using external files. If loading fails, the previously published
     * generation remains active.
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

        // Read the active language while holding the reload lock so a concurrent language
        // change cannot be overwritten by a reload that started earlier.
        reloadLock.lock();
        try {
            loadLanguageLocked(snapshot.language);
        } finally {
            reloadLock.unlock();
        }
    }

    /**
     * Builds and publishes one complete language generation. Both the active bundle and the
     * English fallback (plus a fresh per-locale cache) are loaded before the volatile snapshot
     * is replaced, so readers never observe a half-reloaded state and a failed load leaves the
     * previous generation — language, bundles and client-locale cache — untouched.
     */
    private void loadLanguage(String language) throws IOException {
        reloadLock.lock();
        try {
            loadLanguageLocked(language);
        } finally {
            reloadLock.unlock();
        }
    }

    private void loadLanguageLocked(String language) throws IOException {
        // Re-run migration only for files that are still on disk. An existing lang/
        // directory is operator-owned: removed bundled files stay removed and are served
        // directly from the JAR on demand (#85).
        languageFileManager.initializeLanguageFiles();

        ResourceBundle activeBundle = loadBundle(language);
        // Pre-load English bundle so getFromBundle can fall back per-key when a
        // user-supplied translation is partial / broken / missing the requested key.
        // For language == "en" we keep the reference identical (no double load).
        ResourceBundle fallbackBundle = "en".equalsIgnoreCase(language)
                ? activeBundle
                : loadBundle("en");

        // Publish only after every load succeeded. Old snapshots stay valid for renders
        // that captured them before this point; the new generation starts with an empty
        // per-locale cache so no bundle from an older generation is reused.
        clearStaticCaches();
        this.snapshot = new LanguageSnapshot(language, activeBundle, fallbackBundle);
        logger.info("Reloaded language files for: {} (external files enabled)", language);
    }

    private ResourceBundle loadBundle(String language) throws IOException {
        try {
            return languageFileManager.loadLanguageBundle(language);
        } catch (IllegalArgumentException malformed) {
            // reload()/reloadWithLanguage() declare IOException and their callers handle it.
            // Treat malformed properties (Properties.load throws IllegalArgumentException)
            // as a failed load so the previous generation remains active. Unrelated runtime
            // exceptions are deliberately not caught here.
            throw new IOException("Invalid language file for '" + language + "'", malformed);
        }
    }

    /**
     * Reloads language files with a new language setting.
     * This should be called after config reload to pick up language changes.
     * On failure the previously published language and bundles stay active.
     *
     * @param newLanguage The new language code from config
     * @throws IOException if language file loading fails
     */
    public void reloadWithLanguage(String newLanguage) throws IOException {
        if (!useExternalFiles) {
            // Preserve legacy (JAR) mode semantics: the language changes even though an
            // external reload is a no-op.
            LanguageSnapshot current = snapshot;
            String targetLanguage = resolveTargetLanguage(current.language, newLanguage);
            this.snapshot = new LanguageSnapshot(targetLanguage, null, null);
            loadMessages(targetLanguage);
            reload();
            logLanguageChange(current.language, targetLanguage);
            return;
        }

        // Resolve and publish while holding the lock so a blank request uses the language
        // that is active at publication time rather than a stale pre-reload value.
        reloadLock.lock();
        try {
            LanguageSnapshot current = snapshot;
            String targetLanguage = resolveTargetLanguage(current.language, newLanguage);

            // Publish only after every bundle loaded successfully; on failure `current`
            // remains active with its language and caches.
            loadLanguageLocked(targetLanguage);
            logLanguageChange(current.language, targetLanguage);
        } finally {
            reloadLock.unlock();
        }
    }

    private String resolveTargetLanguage(String currentLanguage, String requestedLanguage) {
        if (requestedLanguage == null || requestedLanguage.trim().isEmpty()) {
            return currentLanguage;
        }
        String normalized = requestedLanguage.toLowerCase(Locale.ROOT);
        if (isSupportedLanguage(normalized)) {
            return normalized;
        }
        // Unknown codes must fall back like setLanguage() rather than creating a custom file
        // or reporting a false current language while serving English text from the JAR.
        logger.warn("Unsupported language '{}', falling back to 'en'", normalized);
        return "en";
    }

    private void logLanguageChange(String oldLanguage, String newLanguage) {
        if (!oldLanguage.equals(newLanguage)) {
            logger.info("Language changed from '{}' to '{}'", oldLanguage, newLanguage);
        }
    }

    /**
     * Gets the current language.
     *
     * @return Current language code
     */
    public String getCurrentLanguage() {
        return snapshot.language;
    }

    /**
     * Gets a formatted message for the current language.
     *
     * @param key  Message key
     * @param args Arguments for message formatting
     * @return Formatted message or the key if not found
     */
    public String get(String key, Object... args) {
        return get(snapshot, key, args);
    }

    /**
     * Renders against one captured generation, so a concurrent reload cannot mix the old
     * language code with newly published bundles.
     */
    private String get(LanguageSnapshot current, String key, Object... args) {
        String resolvedKey = resolveMessageKey(key);
        if (useExternalFiles) {
            return getFromBundle(current, resolvedKey, args);
        }
        return getForLanguage(current.language, resolvedKey, args);
    }

    /**
     * Resolves a localized player-facing message and parses its supported color codes.
     * Placeholder values are protected from accidental color parsing, so color syntax belongs
     * exclusively to the trusted translation template.
     *
     * @param key message key
     * @param fallbackColor color used when the template contains no formatting codes
     * @param args message format arguments
     * @return rendered Adventure component
     */
    public Component component(String key, NamedTextColor fallbackColor, Object... args) {
        // Resolves through the overridable get(String, Object...) so text supplied by a
        // subclass is rendered here too.
        String text = get(key, protectFormattingArguments(args));
        return restoreFormattingArguments(parseWithColors(text, fallbackColor));
    }

    /**
     * Maps a Minecraft client locale to a supported language code (issues #50/#52).
     * Tries the full {@code lang_country} form first (e.g. {@code pt_br}, {@code zh_hk}),
     * then the bare language, then falls back to the configured default language.
     * Missing keys inside a resolved language fall back to the configured default
     * language first, then to English per key.
     *
     * @param clientLocale locale reported by the client, may be {@code null}
     * @return supported language code, never {@code null}
     */
    public String resolvePlayerLanguage(@javax.annotation.Nullable Locale clientLocale) {
        return resolvePlayerLanguage(snapshot, clientLocale);
    }

    private String resolvePlayerLanguage(LanguageSnapshot current,
                                         @javax.annotation.Nullable Locale clientLocale) {
        if (clientLocale == null) {
            return current.language;
        }
        String lang = clientLocale.getLanguage().toLowerCase(Locale.ROOT);
        String country = clientLocale.getCountry().toLowerCase(Locale.ROOT);
        String exactVariant = exactSupportedVariant(lang, country);
        if (exactVariant != null) {
            return exactVariant;
        }
        String baseLanguage = supportedBaseLanguage(lang);
        if (baseLanguage != null) {
            return baseLanguage;
        }
        // Language-family fallback: a client reporting e.g. pt_PT should land on pt_br
        // rather than the default when Portuguese has exactly one bundled variant.
        // Ambiguous families (zh_cn + zh_hk) keep the configured default — no guessing.
        String familyVariant = singleBuiltInVariantOf(lang);
        return familyVariant == null ? current.language : familyVariant;
    }

    @javax.annotation.Nullable
    private String exactSupportedVariant(String lang, String country) {
        if (lang.isEmpty() || country.isEmpty()) {
            return null;
        }
        String full = lang + "_" + country;
        return isSupportedLanguage(full) ? full : null;
    }

    @javax.annotation.Nullable
    private String supportedBaseLanguage(String lang) {
        return !lang.isEmpty() && isSupportedLanguage(lang) ? lang : null;
    }

    @javax.annotation.Nullable
    private String singleBuiltInVariantOf(String lang) {
        String match = null;
        for (String code : BuiltInLanguages.codes()) {
            if (code.startsWith(lang + "_") && isSupportedLanguage(code)) {
                if (match != null) {
                    return null;
                }
                match = code;
            }
        }
        return match;
    }

    /**
     * Resolves a player-facing message for the given client locale — the per-player entry
     * point for client-language detection. A {@code null} locale (or an unsupported one)
     * falls back to the configured default language; a key missing from the requested
     * translation falls back to the configured default language, then to English.
     */
    public Component componentForLocale(@javax.annotation.Nullable Locale clientLocale,
                                        String key, NamedTextColor fallbackColor, Object... args) {
        LanguageSnapshot current = snapshot;
        String language = resolvePlayerLanguage(current, clientLocale);
        if (language.equals(current.language)) {
            return component(key, fallbackColor, args);
        }
        String resolvedKey = resolveMessageKey(key);
        String text = getForPlayerLanguage(current, language, resolvedKey,
                protectFormattingArguments(args));
        return restoreFormattingArguments(parseWithColors(text, fallbackColor));
    }

    /**
     * Resolves the raw localized text for a player's client locale. Uses exactly the same
     * language resolution and per-key fallback hierarchy as {@link #componentForLocale} —
     * requested player language, then the configured server language, then English — but
     * returns the formatted string so callers can layer nested placeholders without
     * round-tripping through a Component serializer.
     *
     * @param clientLocale locale reported by the client, may be {@code null}
     * @param key message key
     * @param args MessageFormat arguments
     * @return localized, formatted text; {@code "Missing: <key>"} when no language has it
     */
    public String getForLocale(@javax.annotation.Nullable Locale clientLocale,
                               String key, Object... args) {
        String resolvedKey = resolveMessageKey(key);
        LanguageSnapshot current = snapshot;
        String language = resolvePlayerLanguage(current, clientLocale);
        if (language.equals(current.language)) {
            return get(resolvedKey, args);
        }
        return getForPlayerLanguage(current, language, resolvedKey, args);
    }

    private String getForPlayerLanguage(LanguageSnapshot current, String language,
                                        String resolvedKey, Object... args) {
        String message = useExternalFiles
                ? getMessageFromPlayerBundle(current, language, resolvedKey)
                : getMessageFromJar(current.language, language, resolvedKey);
        if (message == null) {
            logger.warn("Missing translation key '{}' in all available languages", resolvedKey);
            return "Missing: " + resolvedKey;
        }
        return formatMessageSafely(message, resolvedKey, args);
    }

    /**
     * Per-key hierarchy for client-locale messages: requested translation, then the
     * configured server language, then English. The player bundle is loaded without the
     * eager English backfill so a key absent from the operator's translation is not
     * silently replaced by an English value before this resolution runs.
     */
    @javax.annotation.Nullable
    private String getMessageFromPlayerBundle(LanguageSnapshot current, String language,
                                              String resolvedKey) {
        ResourceBundle playerBundle = current.playerBundles.computeIfAbsent(
                language, code -> loadPlayerBundleSafely(current, code));

        String message = findInBundle(playerBundle, resolvedKey);
        if (message != null) {
            return message;
        }

        if (!language.equals(current.language)) {
            message = findInBundle(current.bundle, resolvedKey);
            if (message != null) {
                logger.debug("Missing translation key '{}' in language '{}' — using configured language '{}'",
                        resolvedKey, language, current.language);
                return message;
            }
        }

        if (!BuiltInLanguages.englishCode().equals(language)) {
            message = findInBundle(current.englishBundle, resolvedKey);
            if (message != null && !BuiltInLanguages.englishCode().equals(current.language)) {
                logger.warn("Missing translation key '{}' in language '{}' and configured language '{}' "
                                + "— falling back to English",
                        resolvedKey, language, current.language);
            }
        }
        return message;
    }

    @javax.annotation.Nullable
    private String getMessageFromJar(String configuredLanguage, String language, String resolvedKey) {
        String message = loadMessages(language).getProperty(resolvedKey);
        if (message != null) {
            return message;
        }

        if (!language.equals(configuredLanguage)) {
            message = loadMessages(configuredLanguage).getProperty(resolvedKey);
            if (message != null) {
                logger.debug("Missing translation key '{}' in language '{}' — using configured language '{}'",
                        resolvedKey, language, configuredLanguage);
                return message;
            }
        }

        if (!BuiltInLanguages.englishCode().equals(language)) {
            message = loadMessages(BuiltInLanguages.englishCode()).getProperty(resolvedKey);
        }
        return message;
    }

    @javax.annotation.Nullable
    private static String findInBundle(@javax.annotation.Nullable ResourceBundle resourceBundle, String key) {
        if (resourceBundle == null) {
            return null;
        }
        try {
            return resourceBundle.getString(key);
        } catch (MissingResourceException missing) {
            return null;
        }
    }

    private ResourceBundle loadPlayerBundleSafely(LanguageSnapshot current, String language) {
        try {
            return languageFileManager.loadLanguageBundle(language, false);
        } catch (IOException | IllegalArgumentException e) {
            logger.warn("Cannot load language '{}' for client-locale messages, using default: {}",
                    language, e.getMessage());
            return current.bundle;
        }
    }

    /**
     * Parses a localized message that has already been resolved by a collaborator.
     * Prefer {@link #component(String, NamedTextColor, Object...)} when the key and
     * formatting arguments are still available, because that path keeps arguments literal.
     *
     * @param resolvedText already localized text
     * @param fallbackColor color used when the text contains no formatting codes
     * @return rendered Adventure component
     */
    public Component componentFromResolvedText(String resolvedText, NamedTextColor fallbackColor) {
        return parseWithColors(resolvedText, fallbackColor);
    }

    private static Component parseWithColors(String text, NamedTextColor fallbackColor) {
        if (text == null || text.isEmpty()) {
            return Component.empty();
        }

        String normalizedText = MINIMESSAGE_HEX_COLOR.matcher(text).replaceAll("&#$1");
        normalizedText = SECTION_LEGACY_CODE.matcher(normalizedText).replaceAll("&$1");
        if (AMPERSAND_LEGACY_CODE.matcher(normalizedText).find()) {
            return LEGACY_COMPONENT_SERIALIZER.deserialize(normalizedText);
        }
        return Component.text(normalizedText, fallbackColor);
    }

    private static Object[] protectFormattingArguments(Object[] args) {
        if (args.length == 0) {
            return args;
        }

        Object[] protectedArgs = args.clone();
        for (int index = 0; index < protectedArgs.length; index++) {
            Object argument = protectedArgs[index];
            if (argument instanceof String stringArgument) {
                protectedArgs[index] = protectFormattingArgument(stringArgument);
            } else if (argument instanceof Character characterArgument) {
                protectedArgs[index] = protectFormattingArgument(characterArgument.toString());
            }
        }
        return protectedArgs;
    }

    private static String protectFormattingArgument(String argument) {
        return argument
                .replace("&", LITERAL_AMPERSAND_MARKER)
                .replace("§", LITERAL_SECTION_MARKER)
                .replace("<#", LITERAL_MINIMESSAGE_HEX_MARKER);
    }

    private static Component restoreFormattingArguments(Component component) {
        return component
                .replaceText(builder -> builder.matchLiteral(LITERAL_AMPERSAND_MARKER).replacement("&"))
                .replaceText(builder -> builder.matchLiteral(LITERAL_SECTION_MARKER).replacement("§"))
                .replaceText(builder -> builder.matchLiteral(LITERAL_MINIMESSAGE_HEX_MARKER).replacement("<#"));
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
    private String getFromBundle(LanguageSnapshot current, String key, Object... args) {
        String resolvedKey = resolveMessageKey(key);
        try {
            String message = current.bundle.getString(resolvedKey);
            return formatMessageSafely(message, resolvedKey, args);
        } catch (MissingResourceException e) {
            // Per-key fallback to English. Triggered when the active language file is
            // corrupted, manually edited to remove keys, or simply missing newer keys
            // that fillMissingKeysFromEnglish() failed to backfill. Keeps user-facing
            // text in a real language instead of leaking "Missing: …" to the player.
            if (current.englishBundle != null && !"en".equals(current.language)) {
                try {
                    String message = current.englishBundle.getString(resolvedKey);
                    logger.warn("Missing translation key '{}' in language '{}' — falling back to English",
                            resolvedKey, current.language);
                    return formatMessageSafely(message, resolvedKey, args);
                } catch (MissingResourceException ignoredEn) {
                    // Both the active language and the English fallback lack this entry, so we
                    // fall through to the placeholder branch below. A debug line gives
                    // translators a hint when they add new strings.
                    logger.debug("English fallback also missing key '{}'", resolvedKey);
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
        // While loop instead of for: doubled apostrophes ("''") consume two chars in one step,
        // which the for-loop variable would otherwise have to be reassigned to track.
        int index = 0;
        while (index < message.length()) {
            char character = message.charAt(index);
            if (character != '\'') {
                sb.append(character);
                index++;
            } else if (index + 1 < message.length() && message.charAt(index + 1) == '\'') {
                sb.append("''");
                index += 2;
            } else {
                sb.append("''");
                index++;
            }
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
     * For external file mode: bundled languages are always supported (served from the JAR
     * when their external file is absent), and custom languages are supported when their
     * file exists. For legacy JAR mode: checks if the bundled resource exists.
     *
     * @param language Language code to check
     * @return true if supported
     */
    public boolean isLanguageSupported(String language) {
        return isSupportedLanguage(language);
    }

    /**
     * Non-overridable lookup used while a generation is being built: resolving a language
     * must not dispatch into a subclass from the constructor or while the reload lock is held.
     */
    private boolean isSupportedLanguage(String language) {
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
        clearStaticCaches();
    }

    /** Clears the JVM-wide caches; also called while the reload lock is held. */
    private void clearStaticCaches() {
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
     * One successfully loaded language generation. Bundles and the lazy per-locale cache are
     * replaced together; a failed reload never mutates the published generation.
     */
    private static final class LanguageSnapshot {
        private final String language;
        @javax.annotation.Nullable
        private final ResourceBundle bundle;
        @javax.annotation.Nullable
        private final ResourceBundle englishBundle;
        // Fresh per generation: a render that captured this snapshot keeps using its own
        // bundles even if a reload publishes a newer generation concurrently.
        private final Map<String, ResourceBundle> playerBundles = new ConcurrentHashMap<>();

        private LanguageSnapshot(String language,
                                 @javax.annotation.Nullable ResourceBundle bundle,
                                 @javax.annotation.Nullable ResourceBundle englishBundle) {
            this.language = language;
            this.bundle = bundle;
            this.englishBundle = englishBundle;
        }
    }

}
