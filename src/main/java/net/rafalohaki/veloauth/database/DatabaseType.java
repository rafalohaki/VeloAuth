package net.rafalohaki.veloauth.database;

/**
 * Enumeration of supported database types with their properties.
 * Thread-safe immutable enum.
 */
public enum DatabaseType {

    MYSQL("MYSQL", "com.mysql.cj.jdbc.Driver", "mysql", 3306),
    POSTGRESQL("POSTGRESQL", "org.postgresql.Driver", "postgresql", 5432),
    H2("H2", "org.h2.Driver", "h2", 0),
    SQLITE("SQLITE", "org.sqlite.JDBC", "sqlite", 0);

    private final String name;
    private final String driverClass;
    private final String urlPrefix;
    private final int defaultPort;

    DatabaseType(String name, String driverClass, String urlPrefix, int defaultPort) {
        this.name = name;
        this.driverClass = driverClass;
        this.urlPrefix = urlPrefix;
        this.defaultPort = defaultPort;
    }

    /**
     * Finds database type by name (case-insensitive).
     *
     * @param name Database type name
     * @return DatabaseType or null if not found
     */
    public static DatabaseType fromName(String name) {
        if (name == null) {
            return null;
        }
        try {
            return valueOf(name.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * Detects database type from connection URL.
     *
     * @param url Connection URL
     * @return DatabaseType or null if unsupported
     */
    public static DatabaseType fromUrl(String url) {
        if (url == null || url.isEmpty()) {
            return null;
        }

        if (url.startsWith("postgresql://")) {
            return POSTGRESQL;
        } else if (url.startsWith("mysql://")) {
            return MYSQL;
        } else if (url.startsWith("mariadb://")) {
            return MYSQL; // Use MySQL driver for MariaDB
        }
        return null;
    }

    public String getName() {
        return name;
    }

    public String getDriverClass() {
        return driverClass;
    }

    public String getUrlPrefix() {
        return urlPrefix;
    }

    public int getDefaultPort() {
        return defaultPort;
    }

    public boolean isRemoteDatabase() {
        return this == MYSQL || this == POSTGRESQL;
    }

    public boolean isLocalDatabase() {
        return this == H2 || this == SQLITE;
    }
}
