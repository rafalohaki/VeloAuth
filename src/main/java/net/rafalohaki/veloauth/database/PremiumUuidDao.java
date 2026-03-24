package net.rafalohaki.veloauth.database;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.field.SqlType;
import com.j256.ormlite.misc.TransactionManager;
import com.j256.ormlite.stmt.DeleteBuilder;
import com.j256.ormlite.stmt.SelectArg;
import com.j256.ormlite.support.ConnectionSource;
import net.rafalohaki.veloauth.model.PremiumUuid;
import org.slf4j.Logger;
import org.slf4j.Marker;
import org.slf4j.MarkerFactory;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Data Access Object dla operacji na tabeli PREMIUM_UUIDS.
 * Oferuje metody do cachowania i odzyskiwania informacji o kontach premium.
 */
public class PremiumUuidDao {

    private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");
    private static final Logger logger = org.slf4j.LoggerFactory.getLogger(PremiumUuidDao.class);

    private final Dao<PremiumUuid, String> dao;
    private final ConnectionSource connectionSource;

    /**
     * Tworzy nowy PremiumUuidDao.
     *
     * @param connectionSource Źródło połączenia z bazą danych
     * @throws SQLException Jeśli nie można utworzyć DAO
     */
    public PremiumUuidDao(ConnectionSource connectionSource) throws SQLException {
        this.connectionSource = connectionSource;
        this.dao = DaoManager.createDao(connectionSource, PremiumUuid.class);
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
            return findByNicknameStrict(nickname);
        } catch (SQLException e) {
            logger.error(DB_MARKER,
                    "Database error looking up premium UUID for nickname '{}' — returning empty (fail-open: caller may treat this as 'not premium')",
                    nickname, e);
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
        if (uuid == null) {
            return Optional.empty();
        }
        try {
            return findByUuidStrict(uuid);
        } catch (SQLException e) {
            logger.error(DB_MARKER,
                    "Database error looking up premium UUID for UUID '{}' — returning empty (fail-open: caller may treat this as 'not premium')",
                    uuid, e);
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
            return saveOrUpdateStrict(uuid, nickname);
        } catch (Exception e) {
            logger.error(DB_MARKER, "Błąd podczas zapisu/aktualizacji premium UUID: {} -> {}", uuid, nickname, e);
            return false;
        }
    }

    Optional<PremiumUuid> findByNicknameStrict(String nickname) throws SQLException {
        String normalizedNickname = normalizeNickname(nickname);
        if (normalizedNickname == null) {
            return Optional.empty();
        }

        List<PremiumUuid> results = queryByNicknameIgnoreCase(normalizedNickname);
        if (results.isEmpty()) {
            logger.debug(DB_MARKER, "Nie znaleziono premium UUID dla nickname: {}", nickname);
            return Optional.empty();
        }

        PremiumUuid preferredResult = results.get(0);
        if (results.size() > 1 && logger.isWarnEnabled()) {
            logger.warn(DB_MARKER, "Wykryto {} wpisów PREMIUM_UUIDS dla nickname {} - używam najnowszego",
                    results.size(), nickname);
        }
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, "Znaleziono premium UUID dla {}: {} -> {}",
                    nickname, preferredResult.getUuid(), preferredResult.getNickname());
        }
        return Optional.of(preferredResult);
    }

    Optional<PremiumUuid> findByUuidStrict(UUID uuid) throws SQLException {
        Objects.requireNonNull(uuid, "uuid nie może być null");
        PremiumUuid result = dao.queryForId(uuid.toString());
        if (result == null) {
            logger.debug(DB_MARKER, "Nie znaleziono premium UUID dla UUID: {}", uuid);
            return Optional.empty();
        }

        validateLoadedEntry(result);
        if (logger.isDebugEnabled()) {
            logger.debug(DB_MARKER, "Znaleziono premium UUID dla {}: {}", uuid, result.getNickname());
        }
        return Optional.of(result);
    }

    boolean saveOrUpdateStrict(UUID uuid, String nickname) throws SQLException {
        Objects.requireNonNull(uuid, "uuid nie może być null");
        String validatedNickname = requireNickname(nickname);
        String normalizedNickname = normalizeNickname(validatedNickname);

        return TransactionManager.callInTransaction(connectionSource, () -> {
            Optional<PremiumUuid> existing = findByUuidStrict(uuid);
            List<PremiumUuid> conflictingEntries = queryByNicknameIgnoreCase(normalizedNickname);
            deleteNicknameConflicts(uuid, validatedNickname, conflictingEntries);

            if (existing.isPresent()) {
                PremiumUuid premiumUuid = existing.get();
                if (!premiumUuid.getNickname().equals(validatedNickname)) {
                    logger.info(DB_MARKER, "Aktualizacja nickname premium: {} -> {} (UUID: {})",
                            premiumUuid.getNickname(), validatedNickname, uuid);
                    premiumUuid.updateNickname(validatedNickname);
                } else {
                    premiumUuid.updateLastSeen();
                    logger.debug(DB_MARKER, "Zaktualizowano last_seen dla {}: {}", validatedNickname, uuid);
                }
                dao.update(premiumUuid);
                return true;
            }

            PremiumUuid premiumUuid = new PremiumUuid(uuid, validatedNickname);
            dao.create(premiumUuid);
            logger.info(DB_MARKER, "Zapisano nowy premium UUID: {} -> {}", validatedNickname, uuid);
            return true;
        });
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

            DeleteBuilder<PremiumUuid, String> deleteBuilder = dao.deleteBuilder();
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
            return dao.countOf();
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
            return dao.queryForAll();
        } catch (SQLException e) {
            logger.error(DB_MARKER, "Błąd podczas pobierania wszystkich wpisów premium UUID", e);
            return new ArrayList<>();
        }
    }

    private List<PremiumUuid> queryByNicknameIgnoreCase(String normalizedNickname) throws SQLException {
        StringBuilder sb = new StringBuilder();
        connectionSource.getDatabaseType().appendEscapedEntityName(sb, "NICKNAME");
        String quotedNickname = sb.toString();

        List<PremiumUuid> results = dao.queryBuilder()
                .where()
                .raw("LOWER(" + quotedNickname + ") = ?", new SelectArg(SqlType.STRING, normalizedNickname))
                .query();
        List<PremiumUuid> validatedResults = new ArrayList<>(results.size());
        for (PremiumUuid result : results) {
            validateLoadedEntry(result);
            validatedResults.add(result);
        }
        validatedResults.sort(Comparator
                .comparingLong(PremiumUuid::getLastSeen)
                .thenComparingLong(PremiumUuid::getVerifiedAt)
                .reversed());
        return validatedResults;
    }

    private void deleteNicknameConflicts(UUID authoritativeUuid, String nickname, List<PremiumUuid> nicknameEntries)
            throws SQLException {
        for (PremiumUuid nicknameEntry : nicknameEntries) {
            if (authoritativeUuid.toString().equalsIgnoreCase(nicknameEntry.getUuidString())) {
                continue;
            }
            logger.warn(DB_MARKER, "Usuwam konflikt nickname {} dla UUID {} (autorytatywny UUID: {})",
                    nickname, nicknameEntry.getUuidString(), authoritativeUuid);
            dao.deleteById(nicknameEntry.getUuidString());
        }
    }

    private void validateLoadedEntry(PremiumUuid entry) throws SQLException {
        if (entry == null) {
            return;
        }
        if (entry.getUuid() == null) {
            throw new SQLException("Invalid PREMIUM_UUIDS row: malformed UUID");
        }
        if (entry.getNickname() == null || entry.getNickname().isBlank()) {
            throw new SQLException("Invalid PREMIUM_UUIDS row: nickname cannot be blank");
        }
    }

    private String normalizeNickname(String nickname) {
        if (nickname == null || nickname.isBlank()) {
            return null;
        }
        return nickname.toLowerCase(Locale.ROOT);
    }

    private String requireNickname(String nickname) {
        if (nickname == null || nickname.isBlank()) {
            throw new IllegalArgumentException("nickname nie może być pusty");
        }
        return nickname;
    }
}
