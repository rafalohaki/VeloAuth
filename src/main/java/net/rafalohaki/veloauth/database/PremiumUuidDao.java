package net.rafalohaki.veloauth.database;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.misc.TransactionManager;
import com.j256.ormlite.stmt.DeleteBuilder;
import com.j256.ormlite.support.ConnectionSource;
import net.rafalohaki.veloauth.model.PremiumUuid;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Data Access Object dla operacji na tabeli PREMIUM_UUIDS.
 * Oferuje metody do cachowania i odzyskiwania informacji o kontach premium.
 */
public class PremiumUuidDao {

    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");
    private static final Logger logger = org.slf4j.LoggerFactory.getLogger(PremiumUuidDao.class);

    private final Dao<PremiumUuid, String> premiumUuidDao;
    private final ConnectionSource connectionSource;

    /**
     * Tworzy nowy PremiumUuidDao.
     *
     * @param connectionSource Źródło połączenia z bazą danych
     * @throws SQLException Jeśli nie można utworzyć DAO
     */
    public PremiumUuidDao(ConnectionSource connectionSource) throws SQLException {
        this.connectionSource = connectionSource;
        this.premiumUuidDao = DaoManager.createDao(connectionSource, PremiumUuid.class);
        logger.debug(DB_MARKER, "PremiumUuidDao zainicjalizowany");
    }

    /**
     * Znajduje wpis premium UUID po nickname.
     *
     * @param nickname Nickname do wyszukania
     * @return Optional z PremiumUuid jeśli znaleziono
     */
    public Optional<PremiumUuid> findByNickname(String nickname) {
        try {
            List<PremiumUuid> results = premiumUuidDao.queryBuilder()
                    .where()
                    .eq("NICKNAME", nickname)
                    .query();

            if (results.isEmpty()) {
                logger.debug(DB_MARKER, "Nie znaleziono premium UUID dla nickname: {}", nickname);
                return Optional.empty();
            }

            PremiumUuid result = results.get(0);
            logger.debug(DB_MARKER, "Znaleziono premium UUID dla {}: {} -> {}",
                    nickname, result.getUuid(), result.getNickname());
            return Optional.of(result);

        } catch (SQLException e) {
            logger.error(DB_MARKER, "Błąd podczas wyszukiwania premium UUID dla nickname: {}", nickname, e);
            return Optional.empty();
        }
    }

    /**
     * Znajduje wpis premium UUID po UUID.
     *
     * @param uuid UUID do wyszukania
     * @return Optional z PremiumUuid jeśli znaleziono
     */
    public Optional<PremiumUuid> findByUuid(UUID uuid) {
        try {
            PremiumUuid result = premiumUuidDao.queryForId(uuid.toString());
            if (result == null) {
                logger.debug(DB_MARKER, "Nie znaleziono premium UUID dla UUID: {}", uuid);
                return Optional.empty();
            }

            logger.debug(DB_MARKER, "Znaleziono premium UUID dla {}: {}", uuid, result.getNickname());
            return Optional.of(result);

        } catch (SQLException e) {
            logger.error(DB_MARKER, "Błąd podczas wyszukiwania premium UUID dla UUID: {}", uuid, e);
            return Optional.empty();
        }
    }

    /**
     * Zapisuje lub aktualizuje wpis premium UUID.
     * Obsługuje zmiany nickname - jeśli UUID istnieje z innym nickname, aktualizuje.
     * Używa transakcji dla atomowości i zapobiegania race conditions.
     *
     * @param uuid     UUID gracza premium
     * @param nickname Aktualny nickname gracza
     * @return true jeśli operacja się powiodła
     */
    public boolean saveOrUpdate(UUID uuid, String nickname) {
        try {
            return TransactionManager.callInTransaction(connectionSource, () -> {
                // Sprawdź czy UUID już istnieje
                Optional<PremiumUuid> existing = findByUuid(uuid);

                if (existing.isPresent()) {
                    // Aktualizuj istniejący wpis (zmiana nickname)
                    PremiumUuid premiumUuid = existing.get();
                    if (!premiumUuid.getNickname().equals(nickname)) {
                        logger.info(DB_MARKER, "Aktualizacja nickname premium: {} -> {} (UUID: {})",
                                premiumUuid.getNickname(), nickname, uuid);

                        // Premium gracze omijają AUTH table - tylko PREMIUM_UUIDS cache
                        premiumUuid.updateNickname(nickname);
                        premiumUuidDao.update(premiumUuid);
                    } else {
                        // Tylko aktualizuj timestamp
                        premiumUuid.updateLastSeen();
                        premiumUuidDao.update(premiumUuid);
                        logger.debug(DB_MARKER, "Zaktualizowano last_seen dla {}: {}", nickname, uuid);
                    }
                } else {
                    // Sprawdź czy nickname jest używany przez inne UUID (konflikt)
                    Optional<PremiumUuid> byNickname = findByNickname(nickname);
                    if (byNickname.isPresent() && !byNickname.get().getUuid().equals(uuid)) {
                        logger.warn(DB_MARKER, "Konflikt nickname! {} jest już używany przez {}, próba zapisu z {}",
                                nickname, byNickname.get().getUuid(), uuid);
                        // Usuń stary wpis i zapisz nowy (UUID jest autorytatywne)
                        premiumUuidDao.deleteById(byNickname.get().getUuidString());
                    }

                    // Zapisz nowy wpis
                    PremiumUuid premiumUuid = new PremiumUuid(uuid, nickname);
                    premiumUuidDao.create(premiumUuid);
                    logger.info(DB_MARKER, "Zapisano nowy premium UUID: {} -> {}", nickname, uuid);
                }

                return true;
            });

        } catch (Exception e) {
            logger.error(DB_MARKER, "Błąd podczas zapisu/aktualizacji premium UUID: {} -> {}", uuid, nickname, e);
            return false;
        }
    }

    /**
     * Usuwa przestarzałe wpisy (starsze niż podany TTL).
     *
     * @param ttlMinutes TTL w minutach
     * @return Liczba usuniętych wpisów
     */
    public int cleanExpiredEntries(long ttlMinutes) {
        try {
            long cutoffTime = System.currentTimeMillis() - (ttlMinutes * 60 * 1000);

            DeleteBuilder<PremiumUuid, String> deleteBuilder = premiumUuidDao.deleteBuilder();
            deleteBuilder.where().lt("LAST_SEEN", cutoffTime);
            int deleted = deleteBuilder.delete();

            if (deleted > 0) {
                logger.info(DB_MARKER, "Usunięto {} przestarzałych wpisów premium UUID (TTL: {} min)", deleted, ttlMinutes);
            }

            return deleted;

        } catch (SQLException e) {
            logger.error(DB_MARKER, "Błąd podczas czyszczenia przestarzałych wpisów premium UUID", e);
            return 0;
        }
    }

    /**
     * Zwraca liczbę wszystkich wpisów w tabeli.
     *
     * @return Liczba wpisów
     */
    public long getTotalCount() {
        try {
            return premiumUuidDao.countOf();
        } catch (SQLException e) {
            logger.error(DB_MARKER, "Błąd podczas liczenia wpisów premium UUID", e);
            return 0;
        }
    }

    /**
     * Zwraca listę wszystkich wpisów (do debugowania).
     *
     * @return Lista wszystkich PremiumUuid
     */
    public List<PremiumUuid> findAll() {
        try {
            return premiumUuidDao.queryForAll();
        } catch (SQLException e) {
            logger.error(DB_MARKER, "Błąd podczas pobierania wszystkich wpisów premium UUID", e);
            return new ArrayList<>();
        }
    }
}
