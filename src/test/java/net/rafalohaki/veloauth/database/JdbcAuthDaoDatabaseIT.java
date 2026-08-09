package net.rafalohaki.veloauth.database;

import com.j256.ormlite.jdbc.JdbcConnectionSource;
import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Opt-in integration coverage for the production AUTH DAO on PostgreSQL and MySQL.
 * Run through the database scripts or provide the documented {@code veloauth.database.*}
 * system properties. Normal unit-test runs intentionally exclude classes ending in {@code IT}.
 */
class JdbcAuthDaoDatabaseIT {

    private static final String OWNER_HASH = "$2a$10$ownerhashvalueownerhashvalueownerhashvalueo";
    private static final String COMPETING_HASH = "$2a$10$competinghashcompetinghashcompetinghashc";
    private static final String LOOPBACK_ADDRESS = InetAddress.getLoopbackAddress().getHostAddress();

    private String databaseType;
    private String databaseUrl;
    private String databaseUser;
    private String databasePassword;
    private JdbcConnectionSource connectionSource;
    private JdbcAuthDao dao;

    @BeforeEach
    void setUp() throws SQLException {
        databaseType = requiredProperty("veloauth.database.type");
        databaseUrl = requiredProperty("veloauth.database.url");
        databaseUser = requiredProperty("veloauth.database.user");
        databasePassword = requiredProperty("veloauth.database.password");

        DatabaseConfig config = DatabaseConfig.forRemoteJdbcUrl(
                databaseType, databaseUrl, databaseUser, databasePassword);
        connectionSource = new JdbcConnectionSource(databaseUrl, databaseUser, databasePassword);
        new DatabaseMigrationService(config).createTablesAndMigrate(
                connectionSource, "Creating dialect test tables", "Dialect test tables created");
        dao = new JdbcAuthDao(config);
    }

    @AfterEach
    void tearDown() throws SQLException {
        if (connectionSource != null) {
            try {
                connectionSource.close();
            } catch (Exception exception) {
                throw new SQLException("Failed to close database integration connection", exception);
            }
        }
    }

    @Test
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    void insertPlayerIfAbsentDuplicateShouldPreserveOriginalOwner() throws SQLException {
        String nickname = uniqueNickname("Owner");
        RegisteredPlayer owner = player(nickname, OWNER_HASH);
        RegisteredPlayer competingRegistration = player(nickname, COMPETING_HASH);

        assertTrue(dao.insertPlayerIfAbsent(owner), "Initial registration should create the AUTH row");
        assertFalse(dao.insertPlayerIfAbsent(competingRegistration),
                "A duplicate registration must not replace the existing owner");

        RegisteredPlayer stored = dao.findPlayerByLowercaseNickname(owner.getLowercaseNickname());
        assertEquals(OWNER_HASH, stored.getHash(), "Original BCrypt hash must remain stored");
        assertEquals(owner.getUuid(), stored.getUuid(), "Original backend UUID must remain stored");
        assertEquals(1, countRows(owner.getLowercaseNickname()), "Nickname must have exactly one row");
    }

    @Test
    @SuppressWarnings("PMD.UnitTestContainsTooManyAsserts")
    void upsertPlayerConcurrentWritersShouldCompleteWithoutDuplicateRows()
            throws SQLException, InterruptedException, ExecutionException {
        String nickname = uniqueNickname("Race");
        RegisteredPlayer first = player(nickname, OWNER_HASH);
        RegisteredPlayer second = player(nickname, COMPETING_HASH);
        CountDownLatch start = new CountDownLatch(1);

        try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
            Future<Boolean> firstResult = executor.submit(() -> runAfterLatch(start, first));
            Future<Boolean> secondResult = executor.submit(() -> runAfterLatch(start, second));
            start.countDown();

            assertTrue(firstResult.get(), "First concurrent upsert should complete");
            assertTrue(secondResult.get(), "Second concurrent upsert should complete");
        }

        RegisteredPlayer stored = dao.findPlayerByLowercaseNickname(first.getLowercaseNickname());
        assertTrue(OWNER_HASH.equals(stored.getHash()) || COMPETING_HASH.equals(stored.getHash()),
                "The surviving row must contain one complete writer state");
        assertEquals(1, countRows(first.getLowercaseNickname()),
                "Concurrent upsert must preserve the primary-key invariant");
    }

    private boolean runAfterLatch(CountDownLatch start, RegisteredPlayer player)
            throws InterruptedException, SQLException {
        start.await();
        return dao.upsertPlayer(player);
    }

    private RegisteredPlayer player(String nickname, String hash) {
        return new RegisteredPlayer(nickname, hash, LOOPBACK_ADDRESS, UUID.randomUUID().toString());
    }

    private String uniqueNickname(String prefix) {
        return prefix + UUID.randomUUID().toString().replace("-", "").substring(0, 10);
    }

    private int countRows(String lowercaseNickname) throws SQLException {
        boolean postgres = "POSTGRESQL".equalsIgnoreCase(databaseType);
        String table = postgres ? "\"AUTH\"" : "AUTH";
        String column = postgres ? "\"LOWERCASENICKNAME\"" : "LOWERCASENICKNAME";
        try (Connection connection = DriverManager.getConnection(databaseUrl, databaseUser, databasePassword);
             PreparedStatement statement = connection.prepareStatement(
                     "SELECT COUNT(*) FROM " + table + " WHERE " + column + " = ?")) {
            statement.setString(1, lowercaseNickname);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    throw new SQLException("Count query returned no row");
                }
                return resultSet.getInt(1);
            }
        }
    }

    private static String requiredProperty(String name) {
        String value = System.getProperty(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing database integration property: " + name);
        }
        return value;
    }
}
