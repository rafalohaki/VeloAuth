package net.rafalohaki.veloauth.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Generates default configuration files for VeloAuth.
 * Extracted from Settings for single-responsibility.
 */
class DefaultConfigGenerator {

    private static final Logger logger = LoggerFactory.getLogger(DefaultConfigGenerator.class);

    private DefaultConfigGenerator() {}

    /**
     * Creates the default config.yml file if it doesn't exist.
     */
    static void createDefaultConfig(Path configFile) throws IOException {
        String defaultConfig = """
                # VeloAuth Configuration
                # Complete Velocity Authentication Plugin
                
                # Language configuration (built-in: en, pl; custom languages supported)
                language: en # Plugin language: en = English, pl = Polski
                # To add custom language: create messages_XX.properties in plugins/VeloAuth/lang/
                
                # Debug settings (enable for detailed logging)
                debug-enabled: false # Set to true for development/debugging
                
                # Database storage configuration (supported: H2, MYSQL, POSTGRESQL, SQLITE)
                database:
                  storage-type: H2 # Example: MYSQL, POSTGRESQL, SQLITE
                  hostname: localhost # Database host, e.g. db.example.com
                  port: 3306 # Default ports: MYSQL=3306, POSTGRESQL=5432
                  database: veloauth # Database/schema name
                  user: veloauth # Database user
                  password: "" # Strong password recommended
                  connection-pool-size: 20 # Maximum pooled connections
                  max-lifetime-millis: 1800000 # Connection max lifetime in milliseconds (30 minutes)
                  # Optional: Full database connection URL
                  # If set, will be used instead of individual parameters
                  # Examples:
                  #   postgresql://user:pass@host:5432/database
                  #   postgresql://user:pass@host:5432/database?sslmode=disable
                  #   mysql://user:pass@host:3306/database
                  connection-url: ""
                  # Optional: Additional connection parameters
                  # Example: "?autoReconnect=true&initialTimeout=1&useSSL=false&serverTimezone=UTC"
                  connection-parameters: ""
                
                  # PostgreSQL-specific configuration (used when storage-type is POSTGRESQL)
                  postgresql:
                    # Enable SSL connection to PostgreSQL
                    ssl-enabled: false
                    # SSL mode: disable, allow, prefer, require, verify-ca, verify-full
                    ssl-mode: "prefer"
                    # Path to SSL certificate file (optional)
                    ssl-cert: ""
                    # Path to SSL key file (optional)
                    ssl-key: ""
                    # Path to SSL root certificate file (optional)
                    ssl-root-cert: ""
                    # SSL password for key file (optional)
                    ssl-password: ""
                
                # Authentication cache configuration
                cache:
                  ttl-minutes: 60 # Cache entry lifetime
                  max-size: 10000 # Maximum cached records
                  cleanup-interval-minutes: 5 # Cleanup scheduler interval
                  session-timeout-minutes: 60 # Session inactivity timeout in minutes (default: 60)
                  premium-ttl-hours: 24 # Premium status cache TTL in hours (default: 24)
                  premium-refresh-threshold: 0.8 # Background refresh threshold (0.0-1.0, default: 0.8)
                
                # Auth server (limbo/lobby for unauthenticated players)
                # Compatible with: NanoLimbo, LOOHP/Limbo, LimboService, PicoLimbo, hpfxd/Limbo
                auth-server:
                  server-name: limbo # Must match server name in velocity.toml [servers]
                  timeout-seconds: 300 # Seconds before unauthenticated player is kicked
                
                # Connection settings
                connection:
                  timeout-seconds: 20 # Connection timeout in seconds. Increase if your backend servers are slow.
                
                # Security settings for password hashing and brute-force protection
                security:
                  bcrypt-cost: 10 # BCrypt hashing rounds (4-31)
                  bruteforce-max-attempts: 5 # Attempts before temporary block
                  bruteforce-timeout-minutes: 5 # Block duration in minutes
                  ip-limit-registrations: 3 # Account registrations per IP
                  min-password-length: 4 # Inclusive minimum password length
                  max-password-length: 72 # Inclusive maximum password length
                
                # Premium account detection configuration
                premium:
                  check-enabled: true # Enable premium account verification
                  online-mode-need-auth: false # Force auth for premium players on online-mode proxies
                  resolver:
                    mojang-enabled: true # Query Mojang API
                    ashcon-enabled: true # Query Ashcon API
                    wpme-enabled: false # Query WPME API
                    request-timeout-ms: 2000 # Per-request timeout in milliseconds (2 seconds)
                    hit-ttl-minutes: 10 # Cache TTL for positive hits
                    miss-ttl-minutes: 3 # Cache TTL for misses
                    case-sensitive: true # Preserve username case in resolver cache
                
                # Alert system configuration (optional - Discord webhook notifications)
                alerts:
                  enabled: false # Enable/disable alert system
                  failure-rate-threshold: 0.5 # Alert when failure rate exceeds 50%
                  min-requests-for-alert: 10 # Minimum requests before sending alert
                  check-interval-minutes: 5 # Check metrics every 5 minutes
                  alert-cooldown-minutes: 30 # Cooldown between alerts (prevent spam)
                  
                  # Discord webhook configuration (optional)
                  discord:
                    enabled: false # Enable Discord webhook notifications
                    webhook-url: "" # Discord webhook URL (get from Discord server settings)
                    # Example: "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"
                """;

        Files.writeString(configFile, defaultConfig);
        logger.info("Utworzono domyślny plik konfiguracji");
    }
}
