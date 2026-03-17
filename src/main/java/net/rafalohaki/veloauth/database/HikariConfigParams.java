package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.config.Settings;

/**
 * Configuration parameters for HikariCP connection pool.
 * Groups related parameters to reduce method parameter count.
 */
public final class HikariConfigParams {
    private final String storageType;
    private final String hostname;
    private final int port;
    private final String database;
    private final String user;
    private final String password;
    private final int connectionPoolSize;
    private final int maxLifetime;
    private final String connectionParameters;
    private final Settings.PostgreSQLSettings postgreSQLSettings;
    private final boolean debugEnabled;

    private HikariConfigParams(Builder builder) {
        this.storageType = builder.storageType;
        this.hostname = builder.hostname;
        this.port = builder.port;
        this.database = builder.database;
        this.user = builder.user;
        this.password = builder.password;
        this.connectionPoolSize = builder.connectionPoolSize;
        this.maxLifetime = builder.maxLifetime;
        this.connectionParameters = builder.connectionParameters;
        this.postgreSQLSettings = builder.postgreSQLSettings;
        this.debugEnabled = builder.debugEnabled;
    }

    public String getStorageType() {
        return storageType;
    }

    public String getHostname() {
        return hostname;
    }

    public int getPort() {
        return port;
    }

    public String getDatabase() {
        return database;
    }

    public String getUser() {
        return user;
    }

    public String getPassword() {
        return password;
    }

    public int getConnectionPoolSize() {
        return connectionPoolSize;
    }

    public int getMaxLifetime() {
        return maxLifetime;
    }

    public String getConnectionParameters() {
        return connectionParameters;
    }

    public Settings.PostgreSQLSettings getPostgreSQLSettings() {
        return postgreSQLSettings;
    }

    public boolean isDebugEnabled() {
        return debugEnabled;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String storageType;
        private String hostname;
        private int port;
        private String database;
        private String user;
        private String password;
        private int connectionPoolSize;
        private int maxLifetime;
        private String connectionParameters;
        private Settings.PostgreSQLSettings postgreSQLSettings;
        private boolean debugEnabled;

        public Builder storageType(String storageType) {
            this.storageType = storageType;
            return this;
        }

        public Builder hostname(String hostname) {
            this.hostname = hostname;
            return this;
        }

        public Builder port(int port) {
            this.port = port;
            return this;
        }

        public Builder database(String database) {
            this.database = database;
            return this;
        }

        public Builder user(String user) {
            this.user = user;
            return this;
        }

        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public Builder connectionPoolSize(int connectionPoolSize) {
            this.connectionPoolSize = connectionPoolSize;
            return this;
        }

        public Builder maxLifetime(int maxLifetime) {
            this.maxLifetime = maxLifetime;
            return this;
        }

        public Builder connectionParameters(String connectionParameters) {
            this.connectionParameters = connectionParameters;
            return this;
        }

        public Builder postgreSQLSettings(Settings.PostgreSQLSettings postgreSQLSettings) {
            this.postgreSQLSettings = postgreSQLSettings;
            return this;
        }

        public Builder debugEnabled(boolean debugEnabled) {
            this.debugEnabled = debugEnabled;
            return this;
        }

        public HikariConfigParams build() {
            return new HikariConfigParams(this);
        }
    }
}
