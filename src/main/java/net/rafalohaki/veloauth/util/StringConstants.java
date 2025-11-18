package net.rafalohaki.veloauth.util;

/**
 * Constants for internal system messages and values.
 * This class now contains only internal/debug messages that don't need internationalization.
 * <p>
 * User-facing messages have been moved to the Messages i18n system.
 * Internal messages like cache operations and session logs remain here for developer use.
 * <p>
 * Note: SonarQube rule S2068 (PASSWORD detection) is suppressed because
 * these are internal logging templates, not hardcoded passwords.
 */
@SuppressWarnings("java:S2068")
public final class StringConstants {

    /**
     * Default value used when player information cannot be determined.
     * This is an internal fallback value, not user-facing.
     */
    public static final String UNKNOWN = "unknown";

    // Internal cache and session debug messages (for developer logging)
    // These messages are already internationalized in Messages system but kept here for backward compatibility
    
    /**
     * @deprecated Use messages.get("cache.add.player") instead
     */
    @Deprecated
    public static final String CACHE_ADD_PLAYER = "[CACHE_ADD] Gracz {} dodany do cache autoryzacji";
    
    /**
     * @deprecated Use messages.get("cache.error.add.player") instead
     */
    @Deprecated
    public static final String CACHE_ERROR_ADD_PLAYER = "[CACHE_ERROR] Błąd dodawania gracza {} do cache autoryzacji";
    
    /**
     * @deprecated Use messages.get("cache.error.create.player") instead
     */
    @Deprecated
    public static final String CACHE_ERROR_CREATE_PLAYER = "[CACHE_ERROR] Błąd tworzenia cache dla nowego gracza: {}";
    
    /**
     * @deprecated Use messages.get("cache.remove.player") instead
     */
    @Deprecated
    public static final String CACHE_REMOVE_PLAYER = "[CACHE_REMOVE] Gracz {} usunięty z cache autoryzacji";
    
    /**
     * @deprecated Use messages.get("cache.error.remove.player") instead
     */
    @Deprecated
    public static final String CACHE_ERROR_REMOVE_PLAYER = "[CACHE_ERROR] Błąd usuwania gracza {} z cache autoryzacji";
    
    /**
     * @deprecated Use messages.get("session.start") instead
     */
    @Deprecated
    public static final String SESSION_START = "[SESSION_START] Sesja rozpoczęta dla gracza {} z IP {}";
    
    /**
     * @deprecated Use messages.get("session.error.start") instead
     */
    @Deprecated
    public static final String SESSION_ERROR_START = "[SESSION_ERROR] Błąd rozpoczynania sesji dla gracza: {}";
    
    /**
     * @deprecated Use messages.get("session.end") instead
     */
    @Deprecated
    public static final String SESSION_END = "[SESSION_END] Sesja zakończona dla gracza {}";
    
    /**
     * @deprecated Use messages.get("session.error.end") instead
     */
    @Deprecated
    public static final String SESSION_ERROR_END = "[SESSION_ERROR] Błąd kończenia sesji dla gracza: {}";
    
    /**
     * @deprecated Use messages.get("cache.check.auth") instead
     */
    @Deprecated
    public static final String CACHE_CHECK_AUTH = "[CACHE_CHECK] Sprawdzono autoryzację gracza {}: {}";
    
    /**
     * @deprecated Use messages.get("cache.error.check.auth") instead
     */
    @Deprecated
    public static final String CACHE_ERROR_CHECK_AUTH = "[CACHE_ERROR] Błąd sprawdzania autoryzacji gracza: {}";
    
    /**
     * @deprecated Use messages.get("cache.remove.premium") instead
     */
    @Deprecated
    public static final String CACHE_REMOVE_PREMIUM = "[CACHE_PREMIUM_REMOVE] Status premium usunięty dla gracza {}";
    
    /**
     * @deprecated Use messages.get("cache.error.remove.premium") instead
     */
    @Deprecated
    public static final String CACHE_ERROR_REMOVE_PREMIUM = "[CACHE_ERROR] Błąd usuwania statusu premium gracza: {}";
    
    /**
     * @deprecated Use messages.get("brute.force.reset") instead
     */
    @Deprecated
    public static final String BRUTE_FORCE_RESET = "[BRUTE_FORCE_RESET] Próby brute force zresetowane dla IP {}";
    
    /**
     * @deprecated Use messages.get("cache.error.reset.brute.force") instead
     */
    @Deprecated
    public static final String CACHE_ERROR_RESET_BRUTE_FORCE = "[CACHE_ERROR] Błąd resetowania prób brute force dla IP: {}";
    
    /**
     * @deprecated Use messages.get("cache.cleanup.complete") instead
     */
    @Deprecated
    public static final String CACHE_CLEANUP_COMPLETE = "[CACHE_CLEANUP] Kompletne czyszczenie cache dla gracza {}";
    
    /**
     * @deprecated Use messages.get("cache.error.cleanup") instead
     */
    @Deprecated
    public static final String CACHE_ERROR_CLEANUP = "[CACHE_ERROR] Błąd podczas kompletnego czyszczenia cache dla gracza: {}";

    private StringConstants() {
        // Utility class - prevent instantiation
    }
}
