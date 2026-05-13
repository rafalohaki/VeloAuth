package net.rafalohaki.veloauth.model;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import net.rafalohaki.veloauth.util.UuidUtils;

import java.util.Objects;
import java.util.UUID;

/**
 * Model danych dla cachowania weryfikowanych kont premium.
 * Tabela PREMIUM_UUIDS przechowuje UUID graczy premium z ich aktualnymi nicknames.
 * Używana do redukcji zapytań do API Mojang i obsługi zmian nicknames.
 */
@DatabaseTable(tableName = "PREMIUM_UUIDS")
public class PremiumUuid {

    private static final String UUID_INVALID_ERROR = "Premium player UUID must be valid";
    private static final String NICKNAME_EMPTY_ERROR = "Premium nickname must not be empty";

    /**
     * UUID gracza premium (klucz główny).
     */
    @DatabaseField(columnName = "UUID", id = true, canBeNull = false)
    private String uuid;

    /**
     * Aktualny nickname gracza (może się zmieniać).
     */
    @DatabaseField(columnName = "NICKNAME", canBeNull = false)
    private String nickname;

    /**
     * Timestamp ostatniej weryfikacji (System.currentTimeMillis()).
     */
    @DatabaseField(columnName = "LAST_SEEN")
    private long lastSeen;

    /**
     * Timestamp pierwszej weryfikacji.
     */
    @DatabaseField(columnName = "VERIFIED_AT")
    private long verifiedAt;

    /**
     * Konstruktor domyślny dla ORMLite.
     */
    public PremiumUuid() {
    }

    /**
     * Konstruktor z parametrami.
     *
     * @param uuid     UUID gracza premium
     * @param nickname Aktualny nickname gracza
     */
    public PremiumUuid(UUID uuid, String nickname) {
        this(uuid.toString(), nickname);
    }

    /**
     * Konstruktor z parametrami String.
     *
     * @param uuid     UUID gracza premium jako String
     * @param nickname Aktualny nickname gracza
     */
    public PremiumUuid(String uuid, String nickname) {
        this.uuid = requireUuid(uuid);
        this.nickname = requireNickname(nickname);
        long now = System.currentTimeMillis();
        this.lastSeen = now;
        this.verifiedAt = now;
    }

    /**
     * Aktualizuje nickname i timestamp ostatniego widzenia.
     * Używane gdy premium gracz zmienia nick.
     *
     * @param newNickname Nowy nickname gracza
     */
    public void updateNickname(String newNickname) {
        this.nickname = requireNickname(newNickname);
        this.lastSeen = System.currentTimeMillis();
    }

    /**
     * Aktualizuje timestamp ostatniego widzenia.
     * Używane przy ponownej weryfikacji.
     */
    public void updateLastSeen() {
        this.lastSeen = System.currentTimeMillis();
    }

    /**
     * Sprawdza czy wpis jest przestarzały (starszy niż podany TTL).
     *
     * @param ttlMinutes TTL w minutach
     * @return true jeśli wpis jest przestarzały
     */
    public boolean isExpired(long ttlMinutes) {
        long ttlMillis = ttlMinutes * 60 * 1000;
        return (System.currentTimeMillis() - lastSeen) > ttlMillis;
    }

    // Gettery i settery

    public UUID getUuid() {
        return UuidUtils.parseUuidSafely(uuid);
    }

    public void setUuid(String uuid) {
        this.uuid = requireUuid(uuid);
    }

    public String getUuidString() {
        return uuid;
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = requireNickname(nickname);
    }

    public long getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(long lastSeen) {
        this.lastSeen = lastSeen;
    }

    public long getVerifiedAt() {
        return verifiedAt;
    }

    public void setVerifiedAt(long verifiedAt) {
        this.verifiedAt = verifiedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PremiumUuid that = (PremiumUuid) o;
        return Objects.equals(uuid, that.uuid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(uuid);
    }

    @Override
    public String toString() {
        return "PremiumUuid{" +
                "uuid='[REDACTED]'" +
                ", nickname='" + nickname + '\'' +
                ", lastSeen=" + lastSeen +
                ", verifiedAt=" + verifiedAt +
                '}';
    }

    private static String requireUuid(String uuid) {
        if (UuidUtils.parseUuidSafely(uuid) == null) {
            throw new IllegalArgumentException(UUID_INVALID_ERROR);
        }
        return uuid;
    }

    private static String requireNickname(String nickname) {
        if (nickname == null || nickname.isBlank()) {
            throw new IllegalArgumentException(NICKNAME_EMPTY_ERROR);
        }
        return nickname;
    }
}
