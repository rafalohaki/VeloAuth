package net.rafalohaki.veloauth.premium;

import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.table.TableUtils;
import net.rafalohaki.veloauth.database.PremiumUuidDao;
import net.rafalohaki.veloauth.model.PremiumUuid;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.helpers.NOPLogger;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression for the {@code hit-ttl-minutes=0} contract: a zero TTL disables caching on
 * every tier, so a fresh {@code PREMIUM_UUIDS} row must not short-circuit the external
 * resolver. Uses a real H2 database and hand-rolled fakes so it runs without Mockito.
 */
class PremiumResolverZeroTtlDbCacheTest {

    private static final String USERNAME = "ZeroTtlNick";

    private JdbcConnectionSource connectionSource;
    private PremiumUuidDao dao;
    private UUID dbUuid;

    @BeforeEach
    void setUp() throws Exception {
        connectionSource = new JdbcConnectionSource(
                "jdbc:h2:mem:ttl_zero_" + System.nanoTime());
        TableUtils.createTableIfNotExists(connectionSource, PremiumUuid.class);
        dao = new PremiumUuidDao(connectionSource);
        dbUuid = UUID.randomUUID();
        PremiumUuid freshRow = new PremiumUuid(dbUuid, USERNAME);
        freshRow.setLastSeen(System.currentTimeMillis());
        dao.saveOrUpdate(dbUuid, USERNAME);
        // saveOrUpdate refreshes lastSeen on its own path; persist the explicit row state
        // so the fixture is independent of DAO internals.
        freshRow = dao.findByNickname(USERNAME).orElseThrow();
        assertTrue(freshRow.getLastSeen() > 0L, "Fixture row must look freshly verified");
        assertEquals(dbUuid, freshRow.getUuid());
    }

    @AfterEach
    void tearDown() throws Exception {
        connectionSource.close();
    }

    @Test
    void hitTtlZero_freshDbRow_stillQueriesResolverOnEveryLogin() {
        UUID apiUuid = UUID.randomUUID();
        AtomicInteger calls = new AtomicInteger();
        PremiumResolver fakeMojang = new PremiumResolver() {
            @Override
            public String id() {
                return "mojang";
            }

            @Override
            public boolean enabled() {
                return true;
            }

            @Override
            public PremiumResolution resolve(String username) {
                calls.incrementAndGet();
                return PremiumResolution.premium(apiUuid, username, "mojang");
            }
        };
        PremiumResolverService service = new PremiumResolverService(
                NOPLogger.NOP_LOGGER, dao, List.of(fakeMojang), 0L, 0L);

        PremiumResolution first = service.resolve(USERNAME);
        PremiumResolution second = service.resolve(USERNAME);

        assertEquals(apiUuid, first.uuid(),
                "hit-ttl=0 must ignore the fresh DB row and use the resolver answer");
        assertEquals("mojang", first.source(),
                "Result must not come from the db-cache short-circuit");
        assertEquals(2, calls.get(),
                "hit-ttl=0 means every login queries the resolver — no memory caching either");
        assertEquals(apiUuid, second.uuid());
    }

    @Test
    void positiveHitTtl_freshDbRow_shortCircuitsResolver() {
        AtomicInteger calls = new AtomicInteger();
        PremiumResolver fakeMojang = new PremiumResolver() {
            @Override
            public String id() {
                return "mojang";
            }

            @Override
            public boolean enabled() {
                return true;
            }

            @Override
            public PremiumResolution resolve(String username) {
                calls.incrementAndGet();
                return PremiumResolution.premium(UUID.randomUUID(), username, "mojang");
            }
        };
        PremiumResolverService service = new PremiumResolverService(
                NOPLogger.NOP_LOGGER, dao, List.of(fakeMojang), 30 * 60_000L, 10 * 60_000L);

        PremiumResolution result = service.resolve(USERNAME);

        assertEquals(dbUuid, result.uuid(),
                "A positive hit-ttl keeps the fresh DB row authoritative");
        assertEquals(0, calls.get(), "Resolver must not be consulted on a fresh DB hit");
    }
}
