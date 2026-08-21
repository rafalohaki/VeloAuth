package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * JDBC DAO obsługujący gorące ścieżki logowania/rejestracji bez narzutu ORMLite.
 * Thread-safe: bez stanu mutowalnego, każde wywołanie korzysta z własnego Connection.
 * <p>
 * <b>SQL Injection Safety:</b> All database operations in this class use PreparedStatement
 * with parameter binding to prevent SQL injection attacks. No user input is concatenated
 * directly into SQL queries.
 * </p>
 */
final class JdbcAuthDao {

    private static final Logger logger = LoggerFactory.getLogger(JdbcAuthDao.class);

    // Table name constant
    private static final String TABLE_AUTH = "AUTH";

    // Column name constants - synchronized with RegisteredPlayer ORMLite annotations
    private static final String COL_NICKNAME = "NICKNAME";
    private static final String COL_LOWERCASE_NICKNAME = "LOWERCASENICKNAME";
    private static final String COL_HASH = "HASH";
    private static final String COL_IP = "IP";
    private static final String COL_LOGIN_IP = "LOGINIP";
    private static final String COL_UUID = "UUID";
    private static final String COL_REG_DATE = "REGDATE";
    private static final String COL_LOGIN_DATE = "LOGINDATE";
    private static final String COL_PREMIUM_UUID = "PREMIUMUUID";
    private static final String COL_PRESERVE_UUID = "PRESERVE_UUID";
    private static final String COL_TOTP_TOKEN = "TOTPTOKEN";
    private static final String COL_ISSUED_TIME = "ISSUEDTIME";
    private static final String COL_CONFLICT_MODE = "CONFLICT_MODE";
    private static final String COL_CONFLICT_TIMESTAMP = "CONFLICT_TIMESTAMP";
    private static final String COL_ORIGINAL_NICKNAME = "ORIGINAL_NICKNAME";

    // SQL fragment constants
    private static final String WHERE_CLAUSE = " WHERE ";
    private static final String COMMA_SPACE_EQUALS_QUESTION = " = ?, ";
    private static final String UNIQUE_VIOLATION_SQLSTATE = "23505";
    private static final String SERIALIZATION_FAILURE_SQLSTATE = "40001";
    private static final String POSTGRES_DEADLOCK_SQLSTATE = "40P01";
    private static final int MYSQL_DUPLICATE_KEY_ERROR_CODE = 1062;
    private static final int MYSQL_LOCK_WAIT_TIMEOUT_ERROR_CODE = 1205;
    private static final int MYSQL_DEADLOCK_ERROR_CODE = 1213;
    private static final int MAX_UPSERT_ATTEMPTS = 3;

    private final DatabaseConfig config;
    private final boolean postgres;

    private String selectPlayerSql;
    private String insertPlayerSql;
    private String updatePlayerSql;
    private String deletePlayerSql;

    JdbcAuthDao(DatabaseConfig config) {
        this.config = Objects.requireNonNull(config, "config must not be null");
        this.postgres = DatabaseType.POSTGRESQL.getName().equalsIgnoreCase(config.getStorageType());
        
        initializeSqlStatements();
    }
    
    private void initializeSqlStatements() {
        String authTable = table(TABLE_AUTH);
        String nicknameColumn = column(COL_NICKNAME);
        String lowercaseNicknameColumn = column(COL_LOWERCASE_NICKNAME);
        String hashColumn = column(COL_HASH);
        String ipColumn = column(COL_IP);
        String loginIpColumn = column(COL_LOGIN_IP);
        String uuidColumn = column(COL_UUID);
        String regDateColumn = column(COL_REG_DATE);
        String loginDateColumn = column(COL_LOGIN_DATE);
        String premiumUuidColumn = column(COL_PREMIUM_UUID);
        String totpTokenColumn = column(COL_TOTP_TOKEN);
        String issuedTimeColumn = column(COL_ISSUED_TIME);

        this.selectPlayerSql = "SELECT " + joinColumns(
                nicknameColumn,
                lowercaseNicknameColumn,
                hashColumn,
                ipColumn,
                loginIpColumn,
                uuidColumn,
                regDateColumn,
                loginDateColumn,
                premiumUuidColumn,
                column(COL_PRESERVE_UUID),
                totpTokenColumn,
                issuedTimeColumn,
                column(COL_CONFLICT_MODE),
                column(COL_CONFLICT_TIMESTAMP),
                column(COL_ORIGINAL_NICKNAME)) + " FROM " + authTable + WHERE_CLAUSE + lowercaseNicknameColumn + " = ?";

        this.insertPlayerSql = "INSERT INTO " + authTable + " (" + joinColumns(
                lowercaseNicknameColumn,
                nicknameColumn,
                hashColumn,
                ipColumn,
                loginIpColumn,
                uuidColumn,
                regDateColumn,
                loginDateColumn,
                premiumUuidColumn,
                column(COL_PRESERVE_UUID),
                totpTokenColumn,
                issuedTimeColumn,
                column(COL_CONFLICT_MODE),
                column(COL_CONFLICT_TIMESTAMP),
                column(COL_ORIGINAL_NICKNAME)) + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        this.updatePlayerSql = "UPDATE " + authTable + " SET " +
                nicknameColumn + COMMA_SPACE_EQUALS_QUESTION +
                hashColumn + COMMA_SPACE_EQUALS_QUESTION +
                ipColumn + COMMA_SPACE_EQUALS_QUESTION +
                loginIpColumn + COMMA_SPACE_EQUALS_QUESTION +
                uuidColumn + COMMA_SPACE_EQUALS_QUESTION +
                regDateColumn + COMMA_SPACE_EQUALS_QUESTION +
                loginDateColumn + COMMA_SPACE_EQUALS_QUESTION +
                premiumUuidColumn + COMMA_SPACE_EQUALS_QUESTION +
                column(COL_PRESERVE_UUID) + COMMA_SPACE_EQUALS_QUESTION +
                totpTokenColumn + COMMA_SPACE_EQUALS_QUESTION +
                issuedTimeColumn + COMMA_SPACE_EQUALS_QUESTION +
                column(COL_CONFLICT_MODE) + COMMA_SPACE_EQUALS_QUESTION +
                column(COL_CONFLICT_TIMESTAMP) + COMMA_SPACE_EQUALS_QUESTION +
                column(COL_ORIGINAL_NICKNAME) + " = ?" + WHERE_CLAUSE + lowercaseNicknameColumn + " = ?";

        this.deletePlayerSql = "DELETE FROM " + authTable + WHERE_CLAUSE + lowercaseNicknameColumn + " = ?";
    }

    public RegisteredPlayer findPlayerByLowercaseNickname(String lowercaseNickname) throws SQLException {
        try (Connection connection = openConnection();
                PreparedStatement statement = connection.prepareStatement(selectPlayerSql)) {

            statement.setString(1, lowercaseNickname);

            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return null;
                }
                return mapPlayerWithConflict(resultSet);
            }
        }
    }

    /**
     * Creates a new AUTH row without ever mutating an existing nickname owner.
     * <p>
     * Registration deliberately uses this insert-only operation instead of the general
     * {@link #upsertPlayer(RegisteredPlayer)} path. The database uniqueness constraint is the
     * final concurrency boundary when multiple proxies register the same nickname at once.
     *
     * @return {@code true} when the row was created; {@code false} when it already existed
     */
    public boolean insertPlayerIfAbsent(RegisteredPlayer player) throws SQLException {
        DatabaseManager.RegistrationCommitPermit permit =
                new DatabaseManager.RegistrationCommitPermit();
        DatabaseManager.RegistrationResult result = insertPlayerIfAbsent(player, permit);
        if (result == DatabaseManager.RegistrationResult.COMMIT_UNKNOWN) {
            throw new SQLException("Registration commit outcome is unknown");
        }
        return result == DatabaseManager.RegistrationResult.CREATED;
    }

    DatabaseManager.RegistrationResult insertPlayerIfAbsent(
            RegisteredPlayer player,
            DatabaseManager.RegistrationCommitPermit permit) throws SQLException {
        Objects.requireNonNull(player, "player must not be null");
        Objects.requireNonNull(permit, "permit must not be null");
        if (permit.isCancelled()) {
            return DatabaseManager.RegistrationResult.CANCELLED;
        }

        try (Connection connection = openConnection()) {
            connection.setAutoCommit(false);
            if (permit.isCancelled()) {
                connection.rollback();
                return DatabaseManager.RegistrationResult.CANCELLED;
            }
            return executeRegistrationTransaction(connection, player, permit);
        }
    }

    private DatabaseManager.RegistrationResult executeRegistrationTransaction(
            Connection connection, RegisteredPlayer player,
            DatabaseManager.RegistrationCommitPermit permit) throws SQLException {
        try {
            int inserted = executeInsert(connection, player);
            if (inserted != 1) {
                throw new SQLException("AUTH registration inserted an unexpected row count");
            }
            if (!permit.tryBeginCommit()) {
                connection.rollback();
                return DatabaseManager.RegistrationResult.CANCELLED;
            }
            return commitRegistration(connection, permit);
        } catch (SQLException exception) {
            rollbackAfterRegistrationFailure(connection, exception);
            if (isDuplicateKeyViolation(exception)) {
                return permit.resolveDuplicateAfterRollback();
            }
            if (permit.isCancelled()) {
                return DatabaseManager.RegistrationResult.CANCELLED;
            }
            permit.markFailed();
            throw exception;
        }
    }

    private DatabaseManager.RegistrationResult commitRegistration(
            Connection connection,
            DatabaseManager.RegistrationCommitPermit permit) {
        try {
            connection.commit();
            permit.markCommitted();
            return DatabaseManager.RegistrationResult.CREATED;
        } catch (SQLException commitException) {
            permit.markCommitUnknown();
            try {
                connection.rollback();
            } catch (SQLException rollbackException) {
                commitException.addSuppressed(rollbackException);
            }
            return DatabaseManager.RegistrationResult.COMMIT_UNKNOWN;
        }
    }

    private void rollbackAfterRegistrationFailure(
            Connection connection, SQLException failure) throws SQLException {
        try {
            connection.rollback();
        } catch (SQLException rollbackException) {
            rollbackException.addSuppressed(failure);
            throw rollbackException;
        }
    }

    public boolean upsertPlayer(RegisteredPlayer player) throws SQLException {
        Objects.requireNonNull(player, "player must not be null");

        for (int attempt = 1; attempt <= MAX_UPSERT_ATTEMPTS; attempt++) {
            try {
                return upsertPlayerOnce(player);
            } catch (SQLException e) {
                if (!isRetryableTransactionFailure(e) || attempt == MAX_UPSERT_ATTEMPTS) {
                    throw e;
                }
                if (logger.isDebugEnabled()) {
                    logger.debug("Retrying AUTH upsert after transaction conflict for {} (attempt {}/{})",
                            player.getLowercaseNickname(), attempt + 1, MAX_UPSERT_ATTEMPTS);
                }
            }
        }
        throw new SQLException("AUTH upsert retry loop ended unexpectedly");
    }

    private boolean upsertPlayerOnce(RegisteredPlayer player) throws SQLException {
        boolean duplicateRace;
        try (Connection connection = openConnection()) {
            boolean previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                duplicateRace = executeUpsertTransaction(connection, player);
            } finally {
                connection.setAutoCommit(previousAutoCommit);
            }
        }

        if (duplicateRace) {
            return recoverDuplicateUpsert(player);
        }
        return true;
    }

    public boolean deletePlayer(String lowercaseNickname) throws SQLException {
        try (Connection connection = openConnection();
                PreparedStatement statement = connection.prepareStatement(deletePlayerSql)) {

            statement.setString(1, lowercaseNickname);
            return statement.executeUpdate() > 0;
        }
    }

    /**
     * Counts registrations from a specific IP address.
     *
     * @param ip IP address to count registrations for
     * @return number of registrations from this IP
     */
    @SuppressWarnings("java:S2077")
    public long countRegistrationsByIp(String ip) throws SQLException {
        String sql = "SELECT COUNT(*) FROM " + table(TABLE_AUTH)
                + WHERE_CLAUSE + column(COL_IP) + " = ?";
        try (Connection connection = openConnection();
                PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, ip);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (resultSet.next()) {
                    return resultSet.getLong(1);
                }
                return 0;
            }
        }
    }

    /**
     * Wykonuje prosty health check bazy danych.
     * Zwraca true jeśli połączenie jest zdrowe.
     */
    public boolean healthCheck() {
        try (Connection connection = openConnection()) {
            // Prosty health check - sprawdzamy czy połączenie jest aktywne
            // i czy możemy wykonać proste zapytanie
            try (PreparedStatement statement = connection.prepareStatement("SELECT 1")) {
                try (ResultSet resultSet = statement.executeQuery()) {
                    return resultSet.next(); // Zwróci true jeśli zapytanie się powiodło
                }
            }
        } catch (SQLException ignored) {
            if (logger.isDebugEnabled()) {
                // Driver messages can echo connection properties or account names.
                logger.debug("Database health check failed");
            }
            return false;
        }
    }

    private int executeUpdate(Connection connection, RegisteredPlayer player) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(updatePlayerSql)) {
            bindUpdate(statement, player);
            return statement.executeUpdate();
        }
    }

    private int executeInsert(Connection connection, RegisteredPlayer player) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(insertPlayerSql)) {
            bindInsert(statement, player);
            return statement.executeUpdate();
        }
    }

    /**
     * Executes the update-then-insert transaction.
     *
     * @return {@code true} when another writer inserted the same key after our update check
     */
    private boolean executeUpsertTransaction(Connection connection, RegisteredPlayer player) throws SQLException {
        try {
            int updated = executeUpdate(connection, player);
            if (updated > 1) {
                throw new SQLException("AUTH upsert updated multiple rows for " + player.getLowercaseNickname());
            }
            if (updated == 0 && insertLostDuplicateRace(connection, player)) {
                return true;
            }
            connection.commit();
            return false;
        } catch (SQLException e) {
            connection.rollback();
            throw e;
        }
    }

    /**
     * Attempts the insert half of the upsert.
     *
     * @return {@code true} when a concurrent writer inserted the same key first; the
     *         transaction has already been rolled back and recovery must run on a fresh
     *         connection, exactly as before this method was extracted
     */
    private boolean insertLostDuplicateRace(Connection connection, RegisteredPlayer player) throws SQLException {
        try {
            executeInsert(connection, player);
            return false;
        } catch (SQLException e) {
            if (!isDuplicateKeyViolation(e)) {
                throw e;
            }
            // PostgreSQL marks the whole transaction as failed after a unique violation.
            // Roll it back and recover on a fresh connection instead of issuing UPDATE here.
            connection.rollback();
            return true;
        }
    }

    private boolean recoverDuplicateUpsert(RegisteredPlayer player) throws SQLException {
        try (Connection connection = openConnection()) {
            boolean previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                int recoveredUpdateCount = executeUpdate(connection, player);
                if (recoveredUpdateCount != 1) {
                    throw new SQLException("Failed to recover duplicate-key upsert for "
                            + player.getLowercaseNickname());
                }
                connection.commit();
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(previousAutoCommit);
            }

            if (logger.isDebugEnabled()) {
                logger.debug("Recovered duplicate-key race during AUTH upsert for {}",
                        player.getLowercaseNickname());
            }
            return true;
        }
    }

    private void bindInsert(PreparedStatement statement, RegisteredPlayer player) throws SQLException {
        statement.setString(1, player.getLowercaseNickname());
        bindCorePlayerFields(statement, player, 2);
    }

    private void bindUpdate(PreparedStatement statement, RegisteredPlayer player) throws SQLException {
        int nextIndex = bindCorePlayerFields(statement, player, 1);
        statement.setString(nextIndex, player.getLowercaseNickname());
    }

    private int bindCorePlayerFields(PreparedStatement statement, RegisteredPlayer player, int startIndex) throws SQLException {
        int idx = startIndex;
        statement.setString(idx++, player.getNickname());
        statement.setString(idx++, player.getHash());
        statement.setString(idx++, player.getIp());
        statement.setString(idx++, player.getLoginIp());
        statement.setString(idx++, player.getUuid());
        statement.setLong(idx++, player.getRegDate());
        statement.setLong(idx++, player.getLoginDate());
        statement.setString(idx++, player.getPremiumUuid());
        statement.setBoolean(idx++, player.isPreserveUuid());
        statement.setString(idx++, player.getTotpToken());
        statement.setLong(idx++, player.getIssuedTime());
        statement.setBoolean(idx++, player.getConflictMode());
        statement.setLong(idx++, player.getConflictTimestamp());
        statement.setString(idx++, player.getOriginalNickname());
        return idx;
    }

    private RegisteredPlayer mapPlayer(ResultSet resultSet) throws SQLException {
        String nickname = resultSet.getString(COL_NICKNAME);
        String storedLowercaseNickname = resultSet.getString(COL_LOWERCASE_NICKNAME);
        if (nickname == null || nickname.isBlank()) {
            throw new SQLException("Invalid nickname stored in database");
        }

        RegisteredPlayer player = new RegisteredPlayer();
        try {
            player.setNickname(nickname);
            if (storedLowercaseNickname == null || storedLowercaseNickname.isBlank()
                    || !storedLowercaseNickname.equals(player.getLowercaseNickname())) {
                throw new IllegalArgumentException("Stored lowercase nickname does not match nickname");
            }
            player.setHash(resultSet.getString(COL_HASH));
            player.setIp(resultSet.getString(COL_IP));
            player.setLoginIp(resultSet.getString(COL_LOGIN_IP));
            player.setUuid(resultSet.getString(COL_UUID));
            player.setRegDate(resultSet.getLong(COL_REG_DATE));
            player.setLoginDate(resultSet.getLong(COL_LOGIN_DATE));
            player.setPremiumUuid(resultSet.getString(COL_PREMIUM_UUID));
            player.setPreserveUuid(resultSet.getBoolean(COL_PRESERVE_UUID));
            player.setTotpToken(resultSet.getString(COL_TOTP_TOKEN));
            player.setIssuedTime(resultSet.getLong(COL_ISSUED_TIME));
            return player;
        } catch (IllegalArgumentException e) {
            if (logger.isWarnEnabled()) {
                logger.warn("Invalid AUTH row in database for {}: {}", nickname, e.getMessage());
            }
            if (logger.isDebugEnabled()) {
                logger.debug("Invalid AUTH row failure details for {}", nickname, e);
            }
            throw new SQLException("Invalid AUTH row stored in database for player: " + nickname, e);
        }
    }

    /**
     * 🔥 ADMIN COMMAND: Finds all players in conflict mode.
     * Uses fallback handling for shared LimboAuth databases without conflict
     * columns.
     * 
     * @return List of players with CONFLICT_MODE = true, or empty list if columns
     *         don't exist
     */
    @SuppressWarnings("java:S2077") // Safe: table() and column() only use hardcoded constants, not user input
    public List<RegisteredPlayer> findAllPlayersInConflictMode() throws SQLException {
        String conflictQuery = "SELECT " + column(COL_NICKNAME) + ", " + column(COL_HASH) + ", " + 
                column(COL_IP) + ", " + column(COL_LOGIN_IP) + ", " + column(COL_UUID) + ", " + 
                column(COL_REG_DATE) + ", " + column(COL_LOGIN_DATE) + ", " +
                column(COL_PREMIUM_UUID) + ", " + column(COL_TOTP_TOKEN) + ", " + 
                column(COL_ISSUED_TIME) + ", " + column(COL_PRESERVE_UUID) + ", "
                + column(COL_LOWERCASE_NICKNAME) + ", " +
                column(COL_CONFLICT_MODE) + ", " + column(COL_CONFLICT_TIMESTAMP) + ", " + 
                column(COL_ORIGINAL_NICKNAME) + " " +
                "FROM " + table(TABLE_AUTH) + WHERE_CLAUSE + column(COL_CONFLICT_MODE) + " = ?"; // NOSONAR - SQL from
                                                                                           // constants

        try (Connection connection = openConnection();
                PreparedStatement statement = connection.prepareStatement(conflictQuery)) { // NOSONAR - Uses
                                                                                            // PreparedStatement with
                                                                                            // parameters

            statement.setBoolean(1, true);

            try (ResultSet resultSet = statement.executeQuery()) { // NOSONAR - Parameterized query, SQL injection safe
                List<RegisteredPlayer> conflicts = new ArrayList<>();
                while (resultSet.next()) {
                    RegisteredPlayer player = mapPlayerWithConflict(resultSet);
                    conflicts.add(player);
                }
                return conflicts;
            }
        } catch (SQLException e) {
            if (isMissingConflictColumnsError(e)) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Conflict columns not available in database (shared LimboAuth?): {}", e.getMessage());
                }
                return List.of();
            }
            if (logger.isErrorEnabled()) {
                logger.error("Failed to query conflict-mode players", e);
            }
            throw e;
        }
    }

    /**
     * Maps ResultSet to RegisteredPlayer including conflict tracking fields.
     */
    private RegisteredPlayer mapPlayerWithConflict(ResultSet resultSet) throws SQLException {
        RegisteredPlayer player = mapPlayer(resultSet);

        // Conflict tracking fields (may not exist in pure LimboAuth databases)
        try {
            player.setConflictMode(resultSet.getBoolean(COL_CONFLICT_MODE));
        } catch (SQLException e) {
            player.setConflictMode(false); // Default if column doesn't exist
        }

        try {
            player.setConflictTimestamp(resultSet.getLong(COL_CONFLICT_TIMESTAMP));
        } catch (SQLException e) {
            player.setConflictTimestamp(0L); // Default if column doesn't exist
        }

        try {
            player.setOriginalNickname(resultSet.getString(COL_ORIGINAL_NICKNAME));
        } catch (SQLException e) {
            player.setOriginalNickname(null); // Default if column doesn't exist
        }

        return player;
    }

    private Connection openConnection() throws SQLException {
        DataSource dataSource = config.getDataSource();
        if (dataSource != null) {
            return dataSource.getConnection();
        }
        String user = config.getUser();
        String password = config.getPassword();
        if (user != null || password != null) {
            return DriverManager.getConnection(config.getJdbcUrl(), user, password);
        }
        return DriverManager.getConnection(config.getJdbcUrl());
    }

    private String table(String name) {
        return postgres ? quote(name) : name;
    }

    private String column(String name) {
        return postgres ? quote(name) : name;
    }

    private String joinColumns(String... columns) {
        return String.join(", ", columns);
    }

    private String quote(String identifier) {
        return '"' + identifier + '"';
    }

    private boolean isDuplicateKeyViolation(SQLException exception) {
        String sqlState = exception.getSQLState();
        if (UNIQUE_VIOLATION_SQLSTATE.equals(sqlState)
                || exception.getErrorCode() == MYSQL_DUPLICATE_KEY_ERROR_CODE) {
            return true;
        }
        String message = exception.getMessage();
        if (message == null) {
            return false;
        }
        String normalizedMessage = message.toLowerCase(Locale.ROOT);
        return normalizedMessage.contains("duplicate")
                || normalizedMessage.contains("unique constraint")
                || normalizedMessage.contains("unique index")
                || normalizedMessage.contains("primary key");
    }

    private boolean isRetryableTransactionFailure(SQLException exception) {
        SQLException current = exception;
        while (current != null) {
            String sqlState = current.getSQLState();
            int errorCode = current.getErrorCode();
            if (SERIALIZATION_FAILURE_SQLSTATE.equals(sqlState)
                    || POSTGRES_DEADLOCK_SQLSTATE.equals(sqlState)
                    || errorCode == MYSQL_LOCK_WAIT_TIMEOUT_ERROR_CODE
                    || errorCode == MYSQL_DEADLOCK_ERROR_CODE) {
                return true;
            }
            current = current.getNextException();
        }
        return false;
    }

    private boolean isMissingConflictColumnsError(SQLException exception) {
        String sqlState = exception.getSQLState();
        if ("42S22".equals(sqlState) || "42122".equals(sqlState)) {
            return true;
        }
        String message = exception.getMessage();
        if (message == null) {
            return false;
        }
        String normalizedMessage = message.toLowerCase(Locale.ROOT);
        return (normalizedMessage.contains("column") || normalizedMessage.contains("field"))
                && (normalizedMessage.contains("conflict_mode")
                || normalizedMessage.contains("conflict_timestamp")
                || normalizedMessage.contains("original_nickname"));
    }
}
