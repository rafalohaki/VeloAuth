package net.rafalohaki.veloauth.database;

import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.support.DatabaseConnection;
import org.slf4j.Logger;
import org.slf4j.Marker;

import java.sql.SQLException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

final class DatabaseStatisticsQueryService {

    private static final String AUTH_TABLE = "AUTH";
    private static final String HASH_COLUMN = "HASH";
    private static final String PREMIUM_UUID_COLUMN = "PREMIUMUUID";
    private static final String WHERE_CLAUSE = " WHERE ";

    private final DatabaseConfig config;
    private final Supplier<ConnectionSource> connectionSourceSupplier;
    private final BooleanSupplier connectedSupplier;
    private final Executor executor;
    private final Logger logger;
    private final Marker dbMarker;

    DatabaseStatisticsQueryService(DatabaseConfig config,
                                   Supplier<ConnectionSource> connectionSourceSupplier,
                                   BooleanSupplier connectedSupplier,
                                   Executor executor,
                                   Logger logger,
                                   Marker dbMarker) {
        this.config = config;
        this.connectionSourceSupplier = connectionSourceSupplier;
        this.connectedSupplier = connectedSupplier;
        this.executor = executor;
        this.logger = logger;
        this.dbMarker = dbMarker;
    }

    CompletableFuture<Integer> getTotalNonPremiumAccounts() {
        return supplyCount(buildCountQuery(quotedColumn(HASH_COLUMN) + " IS NOT NULL"),
                "Error counting non-premium accounts");
    }

    CompletableFuture<Integer> getTotalRegisteredAccounts() {
        return supplyCount(buildCountQuery(null), "Error getting total registered accounts");
    }

    CompletableFuture<Integer> getTotalPremiumAccounts() {
        String whereClause = quotedColumn(PREMIUM_UUID_COLUMN) + " IS NOT NULL OR "
                + quotedColumn(HASH_COLUMN) + " IS NULL";
        return supplyCount(buildCountQuery(whereClause), "Error getting total premium accounts");
    }

    private CompletableFuture<Integer> supplyCount(String sql, String errorMessage) {
        return CompletableFuture.supplyAsync(() -> {
            if (!connectedSupplier.getAsBoolean()) {
                return 0;
            }
            try {
                return executeCountQuery(sql);
            } catch (SQLException e) {
                if (logger.isErrorEnabled()) {
                    logger.error(dbMarker, errorMessage, e);
                }
                return 0;
            }
        }, executor);
    }

    private String buildCountQuery(String whereClause) {
        StringBuilder sql = new StringBuilder("SELECT COUNT(*) FROM ").append(quotedTable(AUTH_TABLE));
        if (whereClause != null && !whereClause.isBlank()) {
            sql.append(WHERE_CLAUSE).append(whereClause);
        }
        return sql.toString();
    }

    private String quotedTable(String tableName) {
        return isPostgresStorage() ? '"' + tableName + '"' : tableName;
    }

    private String quotedColumn(String columnName) {
        return isPostgresStorage() ? '"' + columnName + '"' : columnName;
    }

    private boolean isPostgresStorage() {
        return DatabaseType.POSTGRESQL.getName().equalsIgnoreCase(config.getStorageType());
    }

    private int executeCountQuery(String sql) throws SQLException {
        ConnectionSource connectionSource = connectionSourceSupplier.get();
        DatabaseConnection dbConnection = connectionSource.getReadWriteConnection(null);
        try {
            java.sql.Connection connection = dbConnection.getUnderlyingConnection();
            try (java.sql.PreparedStatement stmt = connection.prepareStatement(sql);
                 java.sql.ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    return rs.getInt(1);
                }
                return 0;
            }
        } finally {
            connectionSource.releaseConnection(dbConnection);
        }
    }
}