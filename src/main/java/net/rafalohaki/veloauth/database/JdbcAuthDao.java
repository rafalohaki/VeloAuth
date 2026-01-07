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
public final class JdbcAuthDao {

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
    private static final String COL_TOTP_TOKEN = "TOTPTOKEN";
    private static final String COL_ISSUED_TIME = "ISSUEDTIME";
    private static final String COL_CONFLICT_MODE = "CONFLICT_MODE";
    private static final String COL_CONFLICT_TIMESTAMP = "CONFLICT_TIMESTAMP";
    private static final String COL_ORIGINAL_NICKNAME = "ORIGINAL_NICKNAME";

    // SQL fragment constants
    private static final String WHERE_CLAUSE = " WHERE ";
    private static final String COMMA_SPACE_EQUALS_QUESTION = " = ?, ";

    private final DatabaseConfig config;
    private final boolean postgres;

    private String selectPlayerSql;
    private String insertPlayerSql;
    private String updatePlayerSql;
    private String deletePlayerSql;

    public JdbcAuthDao(DatabaseConfig config) {
        this.config = Objects.requireNonNull(config, "config nie może być null");
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
                totpTokenColumn,
                issuedTimeColumn) + " FROM " + authTable + WHERE_CLAUSE + lowercaseNicknameColumn + " = ?";

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
                totpTokenColumn,
                issuedTimeColumn) + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        this.updatePlayerSql = "UPDATE " + authTable + " SET " +
                nicknameColumn + COMMA_SPACE_EQUALS_QUESTION +
                hashColumn + COMMA_SPACE_EQUALS_QUESTION +
                ipColumn + COMMA_SPACE_EQUALS_QUESTION +
                loginIpColumn + COMMA_SPACE_EQUALS_QUESTION +
                uuidColumn + COMMA_SPACE_EQUALS_QUESTION +
                regDateColumn + COMMA_SPACE_EQUALS_QUESTION +
                loginDateColumn + COMMA_SPACE_EQUALS_QUESTION +
                premiumUuidColumn + COMMA_SPACE_EQUALS_QUESTION +
                totpTokenColumn + COMMA_SPACE_EQUALS_QUESTION +
                issuedTimeColumn + " = ?" + WHERE_CLAUSE + lowercaseNicknameColumn + " = ?";

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
                return mapPlayer(resultSet);
            }
        }
    }

    public boolean upsertPlayer(RegisteredPlayer player) throws SQLException {
        Objects.requireNonNull(player, "player nie może być null");

        try (Connection connection = openConnection()) {
            boolean previousAutoCommit = connection.getAutoCommit();
            connection.setAutoCommit(false);
            try {
                int updated = executeUpdate(connection, player);
                if (updated == 0) {
                    executeInsert(connection, player);
                }
                connection.commit();
                return true;
            } catch (SQLException e) {
                connection.rollback();
                throw e;
            } finally {
                connection.setAutoCommit(previousAutoCommit);
            }
        }
    }

    public boolean deletePlayer(String lowercaseNickname) throws SQLException {
        try (Connection connection = openConnection();
                PreparedStatement statement = connection.prepareStatement(deletePlayerSql)) {

            statement.setString(1, lowercaseNickname);
            return statement.executeUpdate() > 0;
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
        } catch (SQLException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Health check failed: {}", e.getMessage());
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

    private void executeInsert(Connection connection, RegisteredPlayer player) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(insertPlayerSql)) {
            bindInsert(statement, player);
            statement.executeUpdate();
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
        statement.setString(idx++, player.getTotpToken());
        statement.setLong(idx++, player.getIssuedTime());
        return idx;
    }

    private RegisteredPlayer mapPlayer(ResultSet resultSet) throws SQLException {
        RegisteredPlayer player = new RegisteredPlayer();
        String nickname = null;
        try {
            nickname = resultSet.getString(COL_NICKNAME);
            if (nickname != null && !nickname.isEmpty()) {
                player.setNickname(nickname);
            }
        } catch (IllegalArgumentException e) {
            if (logger.isWarnEnabled()) {
                logger.warn("Nieprawidłowy nickname w bazie danych", e);
            }
            throw new SQLException("Invalid nickname stored in database for player: " + nickname, e);
        }

        // Hash może być null dla graczy premium (limboauth compatibility)
        player.setHash(resultSet.getString(COL_HASH));
        player.setIp(resultSet.getString(COL_IP));
        player.setLoginIp(resultSet.getString(COL_LOGIN_IP));
        player.setUuid(resultSet.getString(COL_UUID));
        player.setRegDate(resultSet.getLong(COL_REG_DATE));
        player.setLoginDate(resultSet.getLong(COL_LOGIN_DATE));

        // Limboauth compatibility columns
        player.setPremiumUuid(resultSet.getString(COL_PREMIUM_UUID));
        player.setTotpToken(resultSet.getString(COL_TOTP_TOKEN));
        player.setIssuedTime(resultSet.getLong(COL_ISSUED_TIME));

        return player;
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
                column(COL_ISSUED_TIME) + ", " + column(COL_LOWERCASE_NICKNAME) + ", " +
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
            // Graceful fallback for shared LimboAuth databases without conflict columns
            if (logger.isDebugEnabled()) {
                logger.debug("Conflict columns not available in database (shared LimboAuth?): {}", e.getMessage());
            }
            return List.of();
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
}
