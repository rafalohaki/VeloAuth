package net.rafalohaki.veloauth.database;

import net.rafalohaki.veloauth.config.Settings;

/**
 * Configuration parameters for HikariCP connection pool. Groups related parameters
 * to keep {@link DatabaseConfig#forRemoteWithHikari(HikariConfigParams)}'s signature
 * sane. Kept as a record so the accessor wall stays implicit (the previous explicit
 * getter chain duplicated DatabaseConfig's own field-accessor block byte-for-byte).
 */
public record HikariConfigParams(
        String storageType,
        String hostname,
        int port,
        String database,
        String user,
        String password,
        int connectionPoolSize,
        int maxLifetime,
        String connectionParameters,
        Settings.PostgreSQLSettings postgreSQLSettings,
        boolean debugEnabled) {

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
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

        public Builder storageType(String storageType) { this.storageType = storageType; return this; }
        public Builder hostname(String hostname) { this.hostname = hostname; return this; }
        public Builder port(int port) { this.port = port; return this; }
        public Builder database(String database) { this.database = database; return this; }
        public Builder user(String user) { this.user = user; return this; }
        public Builder password(String password) { this.password = password; return this; }
        public Builder connectionPoolSize(int v) { this.connectionPoolSize = v; return this; }
        public Builder maxLifetime(int v) { this.maxLifetime = v; return this; }
        public Builder connectionParameters(String v) { this.connectionParameters = v; return this; }
        public Builder postgreSQLSettings(Settings.PostgreSQLSettings v) { this.postgreSQLSettings = v; return this; }
        public Builder debugEnabled(boolean v) { this.debugEnabled = v; return this; }

        public HikariConfigParams build() {
            return new HikariConfigParams(storageType, hostname, port, database, user, password,
                    connectionPoolSize, maxLifetime, connectionParameters, postgreSQLSettings, debugEnabled);
        }
    }
}
