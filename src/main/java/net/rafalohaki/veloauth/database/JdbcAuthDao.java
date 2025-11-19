package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.model.RegisteredPlayer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * JDBC DAO obsługujący gorące ścieżki logowania/rejestracji bez narzutu ORMLite.
 * Thread-safe: bez stanu mutowalnego, każde wywołanie korzysta z własnego Connection.
 */
public final class JdbcAuthDao {

    private static final Logger logger = LoggerFactory.getLogger(JdbcAuthDao.class);

    // SQL fragment constants
    private static final String WHERE_CLAUSE = " WHERE ";
    private static final String COMMA_SPACE_EQUALS_QUESTION = " = ?, ";

    private final DatabaseConfig config;
    private final boolean postgres;

    private final String selectPlayerSql;
    private final String insertPlayerSql;
    private final String updatePlayerSql;
    private final String deletePlayerSql;

    public JdbcAuthDao(DatabaseConfig config) {
        this.config = Objects.requireNonNull(config, "config nie może być null");
        this.postgres = DatabaseType.POSTGRESQL.getName().equalsIgnoreCase(config.getStorageType());

        String authTable = table("AUTH");
        String nicknameColumn = column("NICKNAME");
        String lowercaseNicknameColumn = column("LOWERCASENICKNAME");
        String hashColumn = column("HASH");
        String ipColumn = column("IP");
        String loginIpColumn = column("LOGINIP");
        String uuidColumn = column("UUID");
        String regDateColumn = column("REGDATE");
        String loginDateColumn = column("LOGINDATE");
        String premiumUuidColumn = column("PREMIUMUUID");
        String totpTokenColumn = column("TOTPTOKEN");
        String issuedTimeColumn = column("ISSUEDTIME");

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
                issuedTimeColumn
        ) + " FROM " + authTable + WHERE_CLAUSE + lowercaseNicknameColumn + " = ?";

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
                issuedTimeColumn
        ) + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

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
        // SQL Injection safe: Using PreparedStatement with parameter binding
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
        // SQL Injection safe: Using PreparedStatement with parameter binding
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
        // SQL Injection safe: Using PreparedStatement with parameter binding
        try (PreparedStatement statement = connection.prepareStatement(updatePlayerSql)) {
            bindUpdate(statement, player);
            return statement.executeUpdate();
        }
    }

    private void executeInsert(Connection connection, RegisteredPlayer player) throws SQLException {
        // SQL Injection safe: Using PreparedStatement with parameter binding
        try (PreparedStatement statement = connection.prepareStatement(insertPlayerSql)) {
            bindInsert(statement, player);
            statement.executeUpdate();
        }
    }

    private void bindInsert(PreparedStatement statement, RegisteredPlayer player) throws SQLException {
        statement.setString(1, player.getLowercaseNickname());
        statement.setString(2, player.getNickname());
        statement.setString(3, player.getHash());
        statement.setString(4, player.getIp());
        statement.setString(5, player.getLoginIp());
        statement.setString(6, player.getUuid());
        statement.setLong(7, player.getRegDate());
        statement.setLong(8, player.getLoginDate());
        statement.setString(9, player.getPremiumUuid());
        statement.setString(10, player.getTotpToken());
        statement.setLong(11, player.getIssuedTime());
    }

    private void bindUpdate(PreparedStatement statement, RegisteredPlayer player) throws SQLException {
        statement.setString(1, player.getNickname());
        statement.setString(2, player.getHash());
        statement.setString(3, player.getIp());
        statement.setString(4, player.getLoginIp());
        statement.setString(5, player.getUuid());
        statement.setLong(6, player.getRegDate());
        statement.setLong(7, player.getLoginDate());
        statement.setString(8, player.getPremiumUuid());
        statement.setString(9, player.getTotpToken());
        statement.setLong(10, player.getIssuedTime());
        statement.setString(11, player.getLowercaseNickname());
    }

    private RegisteredPlayer mapPlayer(ResultSet resultSet) throws SQLException {
        RegisteredPlayer player = new RegisteredPlayer();
        String nickname = null;
        try {
            nickname = resultSet.getString("NICKNAME");
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
        player.setHash(resultSet.getString("HASH"));
        player.setIp(resultSet.getString("IP"));
        player.setLoginIp(resultSet.getString("LOGINIP"));
        player.setUuid(resultSet.getString("UUID"));
        player.setRegDate(resultSet.getLong("REGDATE"));
        player.setLoginDate(resultSet.getLong("LOGINDATE"));

        // Limboauth compatibility columns
        player.setPremiumUuid(resultSet.getString("PREMIUMUUID"));
        player.setTotpToken(resultSet.getString("TOTPTOKEN"));
        player.setIssuedTime(resultSet.getLong("ISSUEDTIME"));

        return player;
    }

    /**
     * 🔥 ADMIN COMMAND: Finds all players in conflict mode.
     * Uses fallback handling for shared LimboAuth databases without conflict columns.
     * 
     * @return List of players with CONFLICT_MODE = true, or empty list if columns don't exist
     */
    @SuppressWarnings("java:S2077") // Safe: table() and column() only use hardcoded constants, not user input
    public List<RegisteredPlayer> findAllPlayersInConflictMode() throws SQLException {
        String conflictQuery = "SELECT NICKNAME, HASH, IP, LOGINIP, UUID, REGDATE, LOGINDATE, " +
                              "PREMIUMUUID, TOTPTOKEN, ISSUEDTIME, LOWERCASENICKNAME, " +
                              "CONFLICT_MODE, CONFLICT_TIMESTAMP, ORIGINAL_NICKNAME " +
                              "FROM " + table("AUTH") + WHERE_CLAUSE + column("CONFLICT_MODE") + " = ?";
        
        try (Connection connection = openConnection();
             PreparedStatement statement = connection.prepareStatement(conflictQuery)) {
            
            statement.setBoolean(1, true);
            
            try (ResultSet resultSet = statement.executeQuery()) {
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
            player.setConflictMode(resultSet.getBoolean("CONFLICT_MODE"));
        } catch (SQLException e) {
            player.setConflictMode(false); // Default if column doesn't exist
        }
        
        try {
            player.setConflictTimestamp(resultSet.getLong("CONFLICT_TIMESTAMP"));
        } catch (SQLException e) {
            player.setConflictTimestamp(0L); // Default if column doesn't exist
        }
        
        try {
            player.setOriginalNickname(resultSet.getString("ORIGINAL_NICKNAME"));
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
