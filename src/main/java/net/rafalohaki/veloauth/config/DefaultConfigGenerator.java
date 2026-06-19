package net.rafalohaki.veloauth.config;

import net.rafalohaki.veloauth.i18n.BuiltInLanguages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Generates default configuration files for VeloAuth.
 * Extracted from Settings for single-responsibility.
 */
final class DefaultConfigGenerator {

    private static final Logger logger = LoggerFactory.getLogger(DefaultConfigGenerator.class);
    private static final String BUILT_IN_LANGUAGE_CODES_PLACEHOLDER = "__BUILT_IN_LANGUAGE_CODES__";

    private DefaultConfigGenerator() {}

    /**
     * Creates the default config.yml file if it doesn't exist.
     */
    static void createDefaultConfig(Path configFile) throws IOException {
        String defaultConfig = String.join("\n",
                LANGUAGE_SECTION,
                DEBUG_SECTION,
                DATABASE_SECTION,
                CACHE_SECTION,
                AUTH_SERVER_SECTION,
                CONNECTION_SECTION,
                SECURITY_SECTION,
                PREMIUM_SECTION,
                FLOODGATE_SECTION,
                ALERTS_SECTION,
                AUDIT_LOG_SECTION,
                TWO_FACTOR_SECTION,
                REPORT_SECTION,
                "" // trailing newline
        ).replace(BUILT_IN_LANGUAGE_CODES_PLACEHOLDER, BuiltInLanguages.quotedCodeList());

        Files.writeString(configFile, defaultConfig);
        logger.info("Created default configuration file");
    }

    private static final String LANGUAGE_SECTION = """
                # VeloAuth Configuration
                # Complete Velocity Authentication Plugin
                
                # Language configuration (built-in languages listed below; custom languages supported)
                language: en
                # Available built-in language codes: __BUILT_IN_LANGUAGE_CODES__
                # Examples: en=English, pl=Polski, zh_cn=Chinese Simplified, zh_hk=Chinese Traditional (Hong Kong), ja=Japanese, ko=Korean, th=Thai, id=Indonesian, pt_br=Brazilian Portuguese
                # To add custom language: create messages_XX.properties in plugins/VeloAuth/lang/""";

    private static final String DEBUG_SECTION = """
                
                # Debug settings
                # Set to true for development/debugging
                debug-enabled: false""";

    private static final String DATABASE_SECTION = """
                
                # Database storage configuration
                # Supported: H2, MYSQL, POSTGRESQL, SQLITE
                database:
                  # Storage type (e.g. H2, MYSQL, POSTGRESQL, SQLITE)
                  storage-type: H2
                  # Database host (e.g. db.example.com)
                  hostname: localhost
                  # Default ports: MYSQL=3306, POSTGRESQL=5432
                  port: 3306
                  # Database/schema name
                  database: veloauth
                  # Database user
                  user: veloauth
                  # Database password (strong password recommended)
                  password: ""
                  # Maximum pooled connections
                  connection-pool-size: 20
                  # Connection max lifetime in milliseconds (30 minutes)
                  max-lifetime-millis: 1800000
                  # Optional: Full database connection URL
                  # If set, will be used instead of individual parameters
                  # Examples:
                  #   postgresql://user:pass@host:5432/database
                  #   mysql://user:pass@host:3306/database
                  connection-url: ""
                  # Optional: Additional connection parameters
                  # Query parameters inside connection-url are ignored; place them here instead.
                  # For PostgreSQL SSL options, prefer database.postgresql.* settings below.
                  # Example: "?autoReconnect=true&initialTimeout=1&useSSL=false&serverTimezone=UTC"
                  connection-parameters: ""
                 
                  # PostgreSQL-specific configuration (used when storage-type is POSTGRESQL)
                  postgresql:
                    # Enable SSL connection to PostgreSQL (recommended for hosted databases)
                    ssl-enabled: true
                    # SSL mode: disable, allow, prefer, require, verify-ca, verify-full
                    ssl-mode: "require"
                    # Path to SSL certificate file (optional)
                    ssl-cert: ""
                    # Path to SSL key file (optional)
                    ssl-key: ""
                    # Path to SSL root certificate file (optional)
                    ssl-root-cert: ""
                    # SSL password for key file (optional)
                    ssl-password: "\"""";

    private static final String CACHE_SECTION = """
                
                # Authentication cache configuration
                cache:
                  # Cache entry lifetime in minutes
                  ttl-minutes: 60
                  # Maximum cached records
                  max-size: 10000
                  # Cleanup scheduler interval in minutes
                  cleanup-interval-minutes: 5
                  # Session inactivity timeout in minutes
                  session-timeout-minutes: 60
                  # Premium status cache TTL in hours
                  premium-ttl-hours: 24
                  # Background refresh threshold (0.0-1.0)
                  premium-refresh-threshold: 0.8""";

    private static final String AUTH_SERVER_SECTION = """
                
                # Auth server (limbo/lobby for unauthenticated players)
                # Compatible with: NanoLimbo, LOOHP/Limbo, LimboService, PicoLimbo, hpfxd/Limbo
                auth-server:
                  # Must match server name in velocity.toml [servers]
                  server-name: limbo
                  # Seconds before an unauthenticated player is kicked from the auth server.
                  # Set to 0 (or any value <= 0) to disable the kick — the player can stay on
                  # the auth/limbo server indefinitely.
                  timeout-seconds: 300""";

    private static final String CONNECTION_SECTION = """
                
                # Connection settings
                connection:
                  # Connection timeout in seconds
                  # Should be <= Velocity read-timeout (default 30s)
                  timeout-seconds: 30
                  # Ping timeout in milliseconds for pre-transfer availability checks
                  # (auth-server readiness, forced-host target, try-list / fallback backends).
                  # Heavy JVM backend servers with large heaps and long GC pauses may not
                  # answer a ping within the default 2000ms — raise this (e.g. 5000) to give
                  # them more room. Too high delays fallback when a server is genuinely down.
                  ping-timeout-ms: 2000""";

    private static final String SECURITY_SECTION = """
                
                # Security settings for password hashing and brute-force protection
                security:
                  # BCrypt hashing rounds (10-31)
                  bcrypt-cost: 10
                  # Max failed login attempts before temporary block
                  bruteforce-max-attempts: 5
                  # Block duration in minutes
                  bruteforce-timeout-minutes: 5
                  # Max account registrations per IP
                  ip-limit-registrations: 3
                  # Inclusive minimum password length
                  min-password-length: 8
                  # Inclusive maximum password length (BCrypt limit: 72)
                  max-password-length: 72
                  # Password complexity policy (OPTIONAL, all counters default to 0 = no extra constraint).
                  #
                  # By default players can set any password meeting the length limits — friendly for
                  # casual servers where strict rules just annoy players. Tighten only if you actually
                  # need it (e.g. servers with admin accounts, premium economies, regulated regions).
                  #
                  # How it works:
                  #   - Counters apply ON TOP of min-password-length.
                  #   - Each counter = minimum occurrences of that character class in the password.
                  #   - "special" = anything that is NOT a letter or digit (punctuation, spaces, unicode).
                  #   - Set any value to 0 to disable that particular check.
                  #
                  # Examples (uncomment one row to enable that profile):
                  #   Relaxed (default):                      digits=0  upper=0  lower=0  special=0
                  #   Standard (1 digit + 1 letter case mix): digits=1  upper=1  lower=1  special=0
                  #   Strict (NIST-style for admin tier):     digits=1  upper=1  lower=1  special=1
                  #
                  # Validation message keys: validation.password.needs_{digit,upper,lower,special}
                  password-policy:
                    min-digits: 0
                    min-uppercase: 0
                    min-lowercase: 0
                    min-special: 0""";

    private static final String PREMIUM_SECTION = """

                # Premium account detection configuration
                premium:
                  # Master switch for Mojang/Ashcon premium detection.
                  #
                  # true (default): VeloAuth queries Mojang / Ashcon for every new nickname and
                  # forces online mode (Mojang session-server auth) for premium nicks. Premium
                  # owners get their real premium UUID; cracked clients on premium nicks are
                  # rejected with "You are not logged into your Minecraft account.".
                  #
                  # false: zero HTTP traffic to Mojang/Ashcon, zero writes to PREMIUM_UUIDS,
                  # every connection is forced offline mode. All players — including existing
                  # premium owners with PREMIUMUUID already in AUTH — get offline UUIDs.
                  # Intended for cracked-only servers and dev/test environments.
                  check-enabled: true
                  # Allow cracked players to register / log in on premium nicknames.
                  #
                  # Default (false): when somebody connects with a nickname that Mojang knows
                  # (premium), VeloAuth forces Mojang session-server auth via Velocity's
                  # PreLoginComponentResult.forceOnlineMode() — even when velocity.toml has
                  # online-mode = false. Cracked clients on a premium nick are rejected with
                  # "You are not logged into your Minecraft account." This protects premium
                  # owners from nickname theft.
                  #
                  # true: for premium nicknames that have NO record in VeloAuth's database yet,
                  # forceOfflineMode() is used instead, so a cracked client can register the
                  # nickname first. Once registered as offline, the real premium owner can no
                  # longer take over that nickname automatically — they will hit the nickname
                  # conflict path and an admin must resolve it via /vauth conflicts.
                  #
                  # IMPORTANT TRADE-OFF: New premium players connecting for the first time will
                  # get OFFLINE UUIDs permanently. Velocity's PreLoginEvent has no "try online,
                  # fallback offline" mode (see PaperMC/Velocity#1590, closed), so VeloAuth
                  # cannot give different UUIDs to a premium owner vs. a cracked imposter on
                  # the same nickname — it must pick one mode for the whole connection. Existing
                  # premium owners with PREMIUMUUID already in AUTH keep their premium UUID.
                  #
                  # Enable only if your server explicitly accepts cracked players on premium
                  # nicks and you accept that trade-off.
                  allow-cracked-on-premium-nicks: false
                  resolver:
                    # Query Mojang API
                    mojang-enabled: true
                    # Query Ashcon API
                    ashcon-enabled: true
                    # Query WPME API
                    wpme-enabled: false
                    # Per-request timeout in milliseconds
                    request-timeout-ms: 2000
                    # Cache TTL for positive hits in minutes
                    hit-ttl-minutes: 10
                    # Cache TTL for misses in minutes
                    miss-ttl-minutes: 3
                    # Preserve username case in resolver cache
                    case-sensitive: true
                    # Maximum entries kept in the in-memory premium resolution cache. Once exceeded,
                    # the oldest 10% are evicted in a batched LRU sweep. Raise this on busy proxies
                    # (1000+ concurrent players); the default suits servers with up to a few hundred.
                    memory-cache-max-size: 10000""";

    private static final String FLOODGATE_SECTION = """
                
                # Floodgate / Bedrock support configuration
                # Must stay aligned with your Floodgate proxy config.
                floodgate:
                  # Enable Floodgate-specific Bedrock handling in VeloAuth
                  enabled: false
                  # Match Floodgate's username-prefix; use "" if you removed the prefix
                  username-prefix: "."
                  # Bedrock players authenticated by Floodgate can skip auth server
                  bypass-auth-server: true""";

    private static final String ALERTS_SECTION = """
                
                # Alert system configuration (optional - Discord webhook notifications)
                alerts:
                  # Enable/disable alert system
                  enabled: false
                  # Alert when failure rate exceeds this threshold (0.0-1.0)
                  failure-rate-threshold: 0.5
                  # Minimum requests before sending alert
                  min-requests-for-alert: 10
                  # Check metrics interval in minutes
                  check-interval-minutes: 5
                  # Cooldown between alerts in minutes (prevent spam)
                  alert-cooldown-minutes: 30
                  
                  # Discord webhook configuration (optional)
                  discord:
                    # Enable Discord webhook notifications
                    enabled: false
                    # Discord webhook URL (get from Discord server settings)
                    # Example: "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"
                    webhook-url: "\"""";

    private static final String AUDIT_LOG_SECTION = """

                # Audit log (writes authentication events to VELOAUTH_AUDIT_LOG)
                audit-log:
                  # Enable/disable audit logging (writes are async via virtual threads, fail-open)
                  enabled: true
                  # Keep entries this many days; older rows are pruned daily (1-3650)
                  retention-days: 90""";

    private static final String TWO_FACTOR_SECTION = """

                # Two-Factor Authentication (TOTP / RFC 6238) — opt-in per player.
                # Compatible with Google Authenticator, Authy, Aegis, FreeOTP, and LimboAuth tokens.
                # See 2FA.md for the full setup flow and operator handbook.
                two-factor:
                  # Master switch.
                  # - true  → players can /2fa setup; existing tokens are enforced at /login.
                  # - false → /2fa setup is rejected; existing tokens are NOT enforced.
                  #           (Operator can still wipe tokens via /vauth 2fa-remove <nick>.)
                  enabled: true
                  # Name displayed in authenticator apps (Google Authenticator, Authy, …)
                  # next to each saved code. Must not contain ':' (reserved by otpauth URI).
                  issuer: "VeloAuth"
                  # Append a clickable [Scan QR] link to /2fa setup / /2fa qr output. Clicking it
                  # opens the player's browser, which renders the otpauth:// URI as a real QR.
                  # Without it players still get the plain Base32 secret + otpauth URI for manual
                  # entry into their authenticator app.
                  #
                  # PRIVACY: the otpauth URI contains the shared TOTP secret. Enabling this sends
                  # that secret over TLS to the VeloAuth-maintained QR endpoint. If you don't want
                  # any data leaving your infrastructure set this to false — players can still type
                  # the Base32 secret into their app manually.
                  qr-link-enabled: true
                  # Maximum window (seconds) between successful BCrypt verify and TOTP code entry.
                  # After this the player must run /login again. Range: 30-1800. Default: 300 (5 min).
                  pending-timeout-seconds: 300""";

    private static final String REPORT_SECTION = """

                # /vauth report — generates a diagnostic report and uploads it to
                # https://mclo.gs so you can share it with support. The report bundles:
                #   - VeloAuth config.yml (secrets redacted: passwords, webhook URLs, SSL keys)
                #   - velocity.toml (secrets redacted: forwarding-secret, etc.)
                #   - recent proxy logs (mclo.gs attempts to strip IP addresses server-side,
                #     but this is not guaranteed — only share the link with trusted parties)
                #   - metadata: VeloAuth/Velocity/Java versions, server count, online-mode, etc.
                # Set to false to disable the /vauth report command entirely.
                report:
                  enabled: true""";
}
