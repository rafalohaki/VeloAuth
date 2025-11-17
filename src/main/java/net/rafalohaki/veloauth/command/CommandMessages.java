package net.rafalohaki.veloauth.command;

/**
 * Centralized message constants for VeloAuth commands.
 * Thread-safe: immutable constants.
 * <p>
 * NOTE: Constants containing "PASSWORD" are user-facing message templates,
 * not actual hard-coded credentials. Suppressed S2068 false positive.
 */
@SuppressWarnings("java:S2068")
public final class CommandMessages {

    // Error messages
    public static final String ONLY_PLAYERS = "Ta komenda jest tylko dla graczy!";
    public static final String ALREADY_LOGGED_IN = "Jesteś już zalogowany!";
    public static final String ALREADY_REGISTERED = "Jesteś już zarejestrowany! Użyj /login <hasło>";
    public static final String NOT_REGISTERED = "Nie jesteś zarejestrowany! Użyj /register <hasło> <powtórz>";
    public static final String INVALID_PASSWORD = "Nieprawidłowe hasło!";
    public static final String PASSWORDS_DONT_MATCH = "Hasła nie są identyczne!";
    public static final String PASSWORD_TOO_SHORT = "Hasło jest za krótkie! Minimum %d znaków.";
    public static final String PASSWORD_TOO_LONG = "Hasło jest za długie! Maksimum %d znaków.";
    public static final String EMPTY_PASSWORD = "Hasło nie może być puste!";
    public static final String INVALID_OLD_PASSWORD = "Nieprawidłowe stare hasło!";
    public static final String ACCOUNT_DELETED = "Konto zostało usunięte. Żegnaj!";
    public static final String NO_PERMISSION = "Nie masz uprawnień do tej komendy!";
    // Success messages
    public static final String LOGIN_SUCCESS = "Pomyślnie zalogowano!";
    public static final String REGISTER_SUCCESS = "Pomyślnie zarejestrowano i zalogowano!";
    public static final String PASSWORD_CHANGED_SUCCESS = "Hasło zostało zmienione pomyślnie!";
    // Warning messages
    public static final String RATE_LIMITED_LOGIN = "IP Twojego komputera podjęło zbyt wiele prób logowania. Czekaj 5 minut...";
    public static final String RATE_LIMITED_REGISTER = "IP Twojego komputera podjęło zbyt wielu prób rejestracji. Czekaj 5 minut...";
    public static final String BRUTE_FORCE_BLOCKED = "Zbyt wiele nieudanych prób logowania. Zostałeś tymczasowo zablokowany.";
    public static final String BRUTE_FORCE_BLOCKED_GENERIC = "Zbyt wiele nieudanych prób logowania. Spróbuj ponownie później.";
    // Usage messages
    public static final String LOGIN_USAGE = "Użycie: /login <hasło>";
    public static final String REGISTER_USAGE = "Użycie: /register <hasło> <powtórz>";
    public static final String CHANGE_PASSWORD_USAGE = "Użycie: /changepassword <stare_hasło> <nowe_hasło>";
    public static final String UNREGISTER_USAGE = "Użycie: /unregister <nickname> (tylko dla admina)";
    public static final String UNREGISTER_ADMIN_ONLY = "Ta komenda jest dostępna tylko dla administratorów!";
    // Admin command messages
    public static final String CONFIG_RELOAD_SUCCESS = "Konfiguracja przeładowana pomyślnie!";
    public static final String CONFIG_RELOAD_ERROR = "Błąd podczas przeładowywania konfiguracji!";
    public static final String CACHE_RESET_PLAYER = "Cache gracza %s wyczyszczony!";
    public static final String CACHE_RESET_ALL = "Cały cache wyczyszczony!";
    public static final String PLAYER_NOT_ONLINE = "Gracz %s nie jest online!";
    // Generic error messages
    public static final String DATABASE_ERROR = "Wystąpił błąd podczas operacji bazodanowej. Spróbuj ponownie.";
    public static final String LOGIN_ERROR = "Wystąpił błąd podczas logowania. Spróbuj ponownie.";
    public static final String REGISTER_ERROR = "Wystąpił błąd podczas rejestracji. Spróbuj ponownie.";
    public static final String PASSWORD_CHANGE_ERROR = "Wystąpił błąd podczas zmiany hasła. Spróbuj ponownie.";
    public static final String UNREGISTER_ERROR = "Wystąpił błąd podczas usuwania konta. Spróbuj ponownie.";
    public static final String GENERIC_ERROR = "Wystąpił błąd. Spróbuj ponownie.";
    // Disconnect messages
    public static final String PASSWORD_CHANGED_DISCONNECT = "Hasło do tego konta zostało zmienione. Zaloguj się ponownie.";
    public static final String ACCOUNT_DELETED_DISCONNECT = "Konto zostało usunięte.";
    // Admin help messages
    public static final String ADMIN_HELP_HEADER = "=== VeloAuth Admin ===";
    public static final String ADMIN_HELP_RELOAD = "/vauth reload - Przeładuj konfigurację";
    public static final String ADMIN_HELP_CACHE_RESET = "/vauth cache-reset [gracz] - Wyczyść cache";
    public static final String ADMIN_HELP_STATS = "/vauth stats - Pokaż statystyki";
    // Stats messages
    public static final String STATS_HEADER = "=== VeloAuth Statystyki ===";
    public static final String STATS_AUTHORIZED_PLAYERS = "Autoryzowani gracze: %d";
    public static final String STATS_BRUTE_FORCE_ENTRIES = "Brute force wpisy: %d";
    public static final String STATS_PREMIUM_CACHE = "Premium cache: %d";
    public static final String STATS_CACHE_HIT_RATE = "Cache HIT/MISS: %d/%d (%.1f%% hit rate)";
    public static final String STATS_TOTAL_REQUESTS = "Całkowite zapytania: %d";
    public static final String STATS_DATABASE_CONNECTED = "Baza danych: %s";
    public static final String STATS_DATABASE_CACHE = "Cache bazy: %d graczy";
    private CommandMessages() {
        // Utility class - prevent instantiation
    }

    /**
     * Formats a message with a parameter.
     *
     * @param template  Message template with %s placeholder
     * @param parameter Parameter to insert
     * @return Formatted message
     */
    public static String format(String template, String parameter) {
        return String.format(template, parameter);
    }

    /**
     * Formats a message with an integer parameter.
     *
     * @param template  Message template with %d placeholder
     * @param parameter Parameter to insert
     * @return Formatted message
     */
    public static String format(String template, int parameter) {
        return String.format(template, parameter);
    }

    /**
     * Formats a message with a double parameter.
     *
     * @param template  Message template with %.1f placeholder
     * @param parameter Parameter to insert
     * @return Formatted message
     */
    public static String format(String template, double parameter) {
        return String.format(template, parameter);
    }
}
