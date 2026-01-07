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

    /**
     * UUID gracza premium (klucz główny).
     */
    @DatabaseField(columnName = "UUID", id = true)
    private String uuid;

    /**
     * Aktualny nickname gracza (może się zmieniać).
     */
    @DatabaseField(columnName = "NICKNAME")
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
        this.uuid = uuid.toString();
        this.nickname = nickname;
        this.lastSeen = System.currentTimeMillis();
        this.verifiedAt = System.currentTimeMillis();
    }

    /**
     * Konstruktor z parametrami String.
     *
     * @param uuid     UUID gracza premium jako String
     * @param nickname Aktualny nickname gracza
     */
    public PremiumUuid(String uuid, String nickname) {
        this.uuid = uuid;
        this.nickname = nickname;
        this.lastSeen = System.currentTimeMillis();
        this.verifiedAt = System.currentTimeMillis();
    }

    /**
     * Aktualizuje nickname i timestamp ostatniego widzenia.
     * Używane gdy premium gracz zmienia nick.
     *
     * @param newNickname Nowy nickname gracza
     */
    public void updateNickname(String newNickname) {
        this.nickname = newNickname;
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
        this.uuid = uuid;
    }

    public String getUuidString() {
        return uuid;
    }

    public String getNickname() {
        return nickname;
    }

    public void setNickname(String nickname) {
        this.nickname = nickname;
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
                "uuid='" + uuid + '\'' +
                ", nickname='" + nickname + '\'' +
                ", lastSeen=" + lastSeen +
                ", verifiedAt=" + verifiedAt +
                '}';
    }
}
