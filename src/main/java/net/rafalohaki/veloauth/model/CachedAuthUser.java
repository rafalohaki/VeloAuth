package net.rafalohaki.veloauth.model;

import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Model danych użytkownika w cache autoryzacji.
 * Thread-safe immutable object dla bezpiecznego dostępu wielowątkowego.
 * <p>
 * Cache przechowuje tylko niezbędne dane dla szybkiej weryfikacji autoryzacji.
 */
public final class CachedAuthUser {

    /**
     * UUID gracza Minecraft.
     */
    private final UUID uuid;

    /**
     * Oryginalny nickname gracza.
     */
    private final String nickname;

    /**
     * IP adres ostatniego logowania.
     */
    private final String loginIp;

    /**
     * Timestamp utworzenia wpisu w cache (TTL).
     */
    private final long cacheTime;

    /**
     * Timestamp ostatniego dostępu do wpisu (LRU eviction).
     * AtomicLong dla thread-safe update bez synchronizacji.
     */
    private final AtomicLong lastAccessTime;

    /**
     * Timestamp ostatniego logowania.
     */
    private final long loginTime;

    /**
     * Czy gracz ma konto premium.
     */
    private final boolean isPremium;

    /**
     * Premium UUID jeśli gracz ma premium.
     */
    private final UUID premiumUuid;

    /**
     * Tworzy nowy wpis cache autoryzacji.
     *
     * @param uuid        UUID gracza Minecraft
     * @param nickname    Oryginalny nickname gracza
     * @param loginIp     IP adres ostatniego logowania
     * @param loginTime   Timestamp ostatniego logowania
     * @param isPremium   Czy gracz ma konto premium
     * @param premiumUuid Premium UUID (może być null)
     */
    public CachedAuthUser(UUID uuid, String nickname, String loginIp,
                          long loginTime, boolean isPremium, UUID premiumUuid) {
        if (uuid == null) {
            throw new IllegalArgumentException("UUID nie może być null");
        }
        if (nickname == null || nickname.isEmpty()) {
            throw new IllegalArgumentException("Nickname nie może być pusty");
        }

        this.uuid = uuid;
        this.nickname = nickname;
        this.loginIp = loginIp;
        this.loginTime = loginTime;
        this.isPremium = isPremium;
        this.premiumUuid = premiumUuid;
        this.cacheTime = System.currentTimeMillis();
        this.lastAccessTime = new AtomicLong(this.cacheTime);
    }

    /**
     * Tworzy CachedAuthUser z RegisteredPlayer.
     *
     * @param player    Zarejestrowany gracz
     * @param isPremium Status premium gracza (sprawdź przez DatabaseManager.isPremium())
     * @return CachedAuthUser object
     */
    public static CachedAuthUser fromRegisteredPlayer(RegisteredPlayer player, boolean isPremium) {
        if (player == null) {
            throw new IllegalArgumentException("Player nie może być null");
        }

        UUID uuid = player.getUuidAsUUID();
        if (uuid == null) {
            throw new IllegalArgumentException("Player musi mieć prawidłowy UUID");
        }

        return new CachedAuthUser(
                uuid,
                player.getNickname(),
                player.getLoginIp(),
                player.getLoginDate(),
                isPremium,
                null // Premium UUID is now handled separately in PREMIUM_UUIDS table
        );
    }

    /**
     * Zwraca UUID gracza Minecraft.
     *
     * @return UUID gracza
     */
    public UUID getUuid() {
        return uuid;
    }

    /**
     * Zwraca oryginalny nickname gracza.
     *
     * @return Nickname gracza
     */
    public String getNickname() {
        return nickname;
    }

    /**
     * Zwraca IP adres ostatniego logowania.
     *
     * @return IP ostatniego logowania
     */
    public String getLoginIp() {
        return loginIp;
    }

    /**
     * Zwraca timestamp utworzenia wpisu w cache.
     *
     * @return Czas utworzenia cache w milisekundach
     */
    public long getCacheTime() {
        return cacheTime;
    }

    /**
     * Aktualizuje timestamp ostatniego dostępu (LRU touch).
     * Thread-safe dzięki AtomicLong.
     */
    public void touch() {
        lastAccessTime.set(System.currentTimeMillis());
    }

    /**
     * Zwraca timestamp ostatniego dostępu do wpisu cache.
     *
     * @return Czas ostatniego dostępu w milisekundach
     */
    public long getLastAccessTime() {
        return lastAccessTime.get();
    }

    /**
     * Zwraca timestamp ostatniego logowania.
     *
     * @return Czas ostatniego logowania w milisekundach
     */
    public long getLoginTime() {
        return loginTime;
    }

    /**
     * Sprawdza czy gracz ma konto premium.
     *
     * @return true jeśli gracz ma premium
     */
    public boolean isPremium() {
        return isPremium;
    }

    /**
     * Zwraca premium UUID gracza.
     *
     * @return Premium UUID lub null jeśli nie premium
     */
    public UUID getPremiumUuid() {
        return premiumUuid;
    }

    /**
     * Sprawdza czy wpis w cache jest jeszcze ważny.
     *
     * @param ttlMinutes TTL w minutach
     * @return true jeśli cache jest ważny
     */
    public boolean isValid(int ttlMinutes) {
        if (ttlMinutes <= 0) {
            return true; // Nieskończony TTL
        }

        long ttlMillis = ttlMinutes * 60L * 1000L;
        long currentTime = System.currentTimeMillis();

        return (currentTime - cacheTime) < ttlMillis;
    }

    /**
     * Sprawdza czy IP się zgadza z cached IP.
     *
     * @param currentIp Aktualny IP gracza
     * @return true jeśli IP się zgadza, false jeśli nie zgadza lub currentIp jest null
     */
    public boolean matchesIp(String currentIp) {
        // CRITICAL FIX: Don't allow null currentIp to bypass authentication
        if (currentIp == null) {
            return false; // ❌ Null IP should not bypass auth
        }
        if (loginIp == null) {
            return false; // ❌ No cached IP means not authenticated
        }
        return loginIp.equals(currentIp);
    }

    /**
     * Zwraca wiek wpisu cache w minutach.
     *
     * @return Wiek cache w minutach
     */
    public long getCacheAgeMinutes() {
        long currentTime = System.currentTimeMillis();
        return (currentTime - cacheTime) / (60L * 1000L);
    }

    /**
     * Tworzy nowy CachedAuthUser z zaktualizowanym IP logowania.
     *
     * @param newLoginIp Nowy IP logowania
     * @return Nowy CachedAuthUser object
     */
    public CachedAuthUser withUpdatedIp(String newLoginIp) {
        CachedAuthUser updated = new CachedAuthUser(
                this.uuid,
                this.nickname,
                newLoginIp,
                System.currentTimeMillis(), // Aktualizuj czas logowania
                this.isPremium,
                this.premiumUuid
        );
        // Preserve last access time from original entry
        updated.lastAccessTime.set(this.lastAccessTime.get());
        return updated;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;

        CachedAuthUser that = (CachedAuthUser) obj;
        return Objects.equals(uuid, that.uuid) &&
                Objects.equals(nickname, that.nickname);
    }

    @Override
    public int hashCode() {
        return Objects.hash(uuid, nickname);
    }

    @Override
    public String toString() {
        return "CachedAuthUser{" +
                "uuid=" + uuid +
                ", nickname='" + nickname + '\'' +
                ", loginIp='" + loginIp + '\'' +
                ", cacheTime=" + cacheTime +
                ", lastAccessTime=" + lastAccessTime.get() +
                ", loginTime=" + loginTime +
                ", isPremium=" + isPremium +
                ", premiumUuid=" + premiumUuid +
                ", cacheAgeMinutes=" + getCacheAgeMinutes() +
                '}';
    }
}
