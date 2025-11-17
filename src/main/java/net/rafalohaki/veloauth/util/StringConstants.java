package net.rafalohaki.veloauth.util;

/**
 * Constants for commonly used string literals to avoid duplication.
 * Centralizes repeated messages and values for better maintainability.
 * <p>
 * Note: SonarQube rule S2068 (PASSWORD detection) is suppressed because
 * these are user-facing message templates, not hardcoded passwords.
 */
@SuppressWarnings("java:S2068")
public final class StringConstants {

    /**
     * Message used when a player is not found in the database.
     */
    public static final String PLAYER_NOT_FOUND_IN_DATABASE = "Gracz {} nie istnieje w bazie danych";
    /**
     * Default value used when player information cannot be determined.
     */
    public static final String UNKNOWN = "unknown";
    /**
     * Message used when a player already exists in the database.
     */
    public static final String PLAYER_ALREADY_EXISTS_IN_DATABASE = "Gracz {} już istnieje w bazie danych";
    /**
     * Message used when a player is successfully registered.
     */
    public static final String PLAYER_SUCCESSFULLY_REGISTERED = "Gracz {} pomyślnie zarejestrowany";
    /**
     * Message used when a player is successfully verified.
     */
    public static final String PLAYER_SUCCESSFULLY_VERIFIED = "Gracz {} pomyślnie zweryfikowany";
    /**
     * Message used when a player successfully changes password.
     */
    public static final String PLAYER_SUCCESSFULLY_CHANGED_PASSWORD = "Gracz {} pomyślnie zmienił hasło";
    /**
     * Message used when a player successfully deletes account.
     */
    public static final String PLAYER_SUCCESSFULLY_DELETED_ACCOUNT = "Gracz {} pomyślnie usunął konto";
    /**
     * Message used for invalid password.
     */
    public static final String INVALID_PASSWORD_FOR_PLAYER = "Nieprawidłowe hasło dla gracza: {}";
    /**
     * Message used for invalid old password during change.
     */
    public static final String INVALID_OLD_PASSWORD_FOR_PLAYER = "Nieprawidłowe stare hasło dla gracza: {}";
    /**
     * Message used for invalid password during account deletion.
     */
    public static final String INVALID_PASSWORD_FOR_ACCOUNT_DELETION = "Nieprawidłowe hasło dla usuwania konta gracza: {}";
    /**
     * Message used when failed to save player.
     */
    public static final String FAILED_TO_SAVE_PLAYER = "Nie udało się zapisać gracza: {}";
    /**
     * Message used when failed to save new password.
     */
    public static final String FAILED_TO_SAVE_NEW_PASSWORD = "Nie udało się zapisać nowego hasła dla gracza: {}";
    /**
     * Message used when failed to delete player account.
     */
    public static final String FAILED_TO_DELETE_PLAYER_ACCOUNT = "Nie udało się usunąć konta gracza: {}";
    /**
     * Message used for error during player registration.
     */
    public static final String ERROR_DURING_PLAYER_REGISTRATION = "Błąd podczas rejestracji gracza: {}";
    /**
     * Message used for error during player login.
     */
    public static final String ERROR_DURING_PLAYER_LOGIN = "Błąd podczas logowania gracza: {}";
    /**
     * Message used for error during password change.
     */
    public static final String ERROR_DURING_PASSWORD_CHANGE = "Błąd podczas zmiany hasła gracza: {}";
    /**
     * Message used for error during account deletion.
     */
    public static final String ERROR_DURING_ACCOUNT_DELETION = "Błąd podczas usuwania konta gracza: {}";
    // Cache and session constants
    public static final String CACHE_ADD_PLAYER = "[CACHE_ADD] Gracz {} dodany do cache autoryzacji";
    public static final String CACHE_ERROR_ADD_PLAYER = "[CACHE_ERROR] Błąd dodawania gracza {} do cache autoryzacji";
    public static final String CACHE_ERROR_CREATE_PLAYER = "[CACHE_ERROR] Błąd tworzenia cache dla nowego gracza: {}";
    public static final String CACHE_REMOVE_PLAYER = "[CACHE_REMOVE] Gracz {} usunięty z cache autoryzacji";
    public static final String CACHE_ERROR_REMOVE_PLAYER = "[CACHE_ERROR] Błąd usuwania gracza {} z cache autoryzacji";
    public static final String SESSION_START = "[SESSION_START] Sesja rozpoczęta dla gracza {} z IP {}";
    public static final String SESSION_ERROR_START = "[SESSION_ERROR] Błąd rozpoczynania sesji dla gracza: {}";
    public static final String SESSION_END = "[SESSION_END] Sesja zakończona dla gracza {}";
    public static final String SESSION_ERROR_END = "[SESSION_ERROR] Błąd kończenia sesji dla gracza: {}";
    public static final String CACHE_CHECK_AUTH = "[CACHE_CHECK] Sprawdzono autoryzację gracza {}: {}";
    public static final String CACHE_ERROR_CHECK_AUTH = "[CACHE_ERROR] Błąd sprawdzania autoryzacji gracza: {}";
    public static final String CACHE_REMOVE_PREMIUM = "[CACHE_PREMIUM_REMOVE] Status premium usunięty dla gracza {}";
    public static final String CACHE_ERROR_REMOVE_PREMIUM = "[CACHE_ERROR] Błąd usuwania statusu premium gracza: {}";
    public static final String BRUTE_FORCE_RESET = "[BRUTE_FORCE_RESET] Próby brute force zresetowane dla IP {}";
    public static final String CACHE_ERROR_RESET_BRUTE_FORCE = "[CACHE_ERROR] Błąd resetowania prób brute force dla IP: {}";
    public static final String CACHE_CLEANUP_COMPLETE = "[CACHE_CLEANUP] Kompletne czyszczenie cache dla gracza {}";
    public static final String CACHE_ERROR_CLEANUP = "[CACHE_ERROR] Błąd podczas kompletnego czyszczenia cache dla gracza: {}";
    private StringConstants() {
        // Utility class - prevent instantiation
    }
}
