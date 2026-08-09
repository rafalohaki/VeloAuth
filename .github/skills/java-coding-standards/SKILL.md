---
name: java-coding-standards
description: "Java 21 coding standards for VeloAuth — a Velocity proxy authentication plugin: naming, immutability, thread safety, virtual threads, DbResult pattern, Optional usage, streams, exceptions, generics, logging with markers, and project layout."
origin: ECC
---

# Java 21 Coding Standards — VeloAuth

Standards for readable, maintainable Java 21 code in the VeloAuth Velocity proxy plugin.

## When to Activate

- Writing or reviewing Java code in this Velocity plugin project
- Enforcing naming, immutability, or exception handling conventions
- Working with records, `DbResult<T>`, or discriminated-union patterns
- Reviewing thread safety, virtual threads, or `CompletableFuture` usage
- Working with SLF4J logging and markers
- Structuring packages, visibility, or DAO layer code
- Writing or reviewing tests (JUnit 5, Mockito 5)

## Core Principles

- Prefer clarity over cleverness
- Immutable by default; minimize shared mutable state
- Fail fast with meaningful exceptions; fail-secure in DB layer via `DbResult<T>`
- Never block Velocity event threads — offload I/O to virtual threads
- Package-private by default; only expose what the outside world needs
- No hardcoded user-facing strings — everything goes through i18n `messages_XX.properties`
- Consistent naming, package structure, and marker-based logging

## Naming

```java
// ✅ Classes: PascalCase with role-descriptive suffixes
public class DatabaseManager {}       // *Manager  — resource lifecycle
public class PremiumResolverService {} // *Service  — business logic
class PreLoginHandler {}              // *Handler  — event routing
class LoginCommand {}                 // *Command  — CLI commands
public final class JdbcAuthDao {}     // *Dao      — data access
public final class ValidationUtils {} // *Utils    — stateless helpers
class BruteForceTracker {}            // *Tracker  — state tracking

// ✅ Methods/fields: camelCase with clear verb prefixes
public RegisteredPlayer findPlayerByNickname(String nickname) {} // find*
public boolean isPremium() {}                                    // is*
public boolean hasActiveSession(UUID uuid) {}                    // has*
public void validatePassword(String password) {}                 // validate*
private void handlePremiumDetectionAsync() {}                    // handle*

// ✅ Constants: UPPER_SNAKE_CASE
private static final int MAX_RETRY_ATTEMPTS = 3;
private static final String TABLE_AUTH = "AUTH";

// ✅ Loggers: always `logger` (lowercase), never LOGGER
private static final Logger logger = LoggerFactory.getLogger(DatabaseManager.class);

// ✅ Markers: UPPER_SNAKE_CASE with _MARKER suffix
private static final Marker DB_MARKER = MarkerFactory.getMarker("DATABASE");
private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
private static final Marker SECURITY_MARKER = MarkerFactory.getMarker("SECURITY");
private static final Marker CACHE_MARKER = MarkerFactory.getMarker("CACHE");
```

## Visibility — Package-Private by Default

Extracted classes that are only consumed within their package MUST be package-private.
One public "gateway" class per package exposes the package's API.

```java
// ✅ Public entry point
public class CommandHandler {
    private final CommandContext ctx; // package-private dependency

    public void registerCommands() {
        commandManager.register(meta, new LoginCommand(ctx));
    }
}

// ✅ Package-private internals
class CommandContext { /* shared DI container */ }
class LoginCommand implements SimpleCommand { /* uses ctx */ }
class RegisterCommand implements SimpleCommand { /* uses ctx */ }

// ✅ Cache package — AuthCache is public, helpers are package-private
public class AuthCache { ... }
class BruteForceTracker { ... }  // package-private
class SessionManager { ... }    // package-private
```

## Records — Immutable Data Carriers

Use records for DTOs, configuration bundles, and result types. Add factory methods and compact constructors for validation.

```java
// ✅ Record with factory methods (preferred pattern)
public record PremiumResolution(
    PremiumStatus status,
    UUID uuid,
    String canonicalUsername,
    String source,
    String message
) {
    // Compact constructor for validation
    public PremiumResolution {
        Objects.requireNonNull(status, "status");
    }

    // Factory methods for each variant
    public static PremiumResolution premium(UUID uuid, String name, String source) {
        return new PremiumResolution(PremiumStatus.PREMIUM, uuid, name, source, null);
    }

    public static PremiumResolution offline(String name, String source, String msg) {
        return new PremiumResolution(PremiumStatus.OFFLINE, null, name, source, msg);
    }

    public static PremiumResolution unknown(String source, String msg) {
        return new PremiumResolution(PremiumStatus.UNKNOWN, null, null, source, msg);
    }

    public boolean isPremium() { return status == PremiumStatus.PREMIUM; }

    public enum PremiumStatus { PREMIUM, OFFLINE, UNKNOWN }
}

// ✅ Simple config/stats records
public record AuthCacheConfig(
    int ttlMinutes, int maxSize, int maxSessions,
    int maxPremiumCache, int maxLoginAttempts
) {}

public record CacheStats(
    int authorizedPlayerCount, int premiumCacheCount,
    long cacheHits, long cacheMisses, double hitRate
) {}

// ✅ Lightweight result records
public record ValidationResult(boolean valid, String message) {
    public static ValidationResult success() {
        return new ValidationResult(true, null);
    }
    public static ValidationResult error(String message) {
        return new ValidationResult(false, message);
    }
}
```

## DbResult\<T\> — Discriminated Union for Fail-Secure DB Operations

Public `DatabaseManager` operations return `DbResult<T>` and do not leak `SQLException` to
callers. DAO methods may throw `SQLException`; the manager converts it to the fail-secure result.
This distinguishes "not found" (`value == null`) from "database error"
(`isDatabaseError == true`).

```java
// ✅ DbResult definition (inner class of DatabaseManager)
public static final class DbResult<T> {
    private final T value;
    private final boolean isDatabaseError;
    private final String errorMessage;

    public static <T> DbResult<T> success(T value) {
        return new DbResult<>(value, false, null);
    }
    public static <T> DbResult<T> databaseError(String errorMessage) {
        return new DbResult<>(null, true, errorMessage);
    }

    public boolean isDatabaseError() { return isDatabaseError; }
    public boolean isSuccess() { return !isDatabaseError; }
    @javax.annotation.Nullable public T getValue() { return value; }
}

// ✅ Usage — always check isDatabaseError() first
var dbResult = databaseManager.findPlayerByNickname(username).join();
if (dbResult.isDatabaseError()) {
    logger.error(DB_MARKER, "DB error: {}", dbResult.getErrorMessage());
    player.sendMessage(sm.errorDatabase());
    return;
}
RegisteredPlayer registered = dbResult.getValue();
if (registered == null) {
    // Player not found — distinct from error
}
```

## Thread Safety — Virtual Threads & Concurrency

Java 21 virtual threads require special care: **never use `synchronized`** (it pins virtual threads). Use `ReentrantLock` instead.

```java
// ✅ ConcurrentHashMap for all shared mutable state
private final ConcurrentHashMap<UUID, CachedAuthUser> authorizedPlayers = new ConcurrentHashMap<>();
private final Map<UUID, ScheduledTask> pendingTransfers = new ConcurrentHashMap<>();

// ❌ NEVER plain HashMap for shared state
// ❌ NEVER synchronized blocks (pins virtual threads)

// ✅ ReentrantLock when mutual exclusion is needed
private final ReentrantLock cacheLock = new ReentrantLock();

cacheLock.lock();
try {
    // critical section
} finally {
    cacheLock.unlock();
}

// ✅ Atomics for counters and flags
private final AtomicLong cacheHits = new AtomicLong(0);
private final AtomicBoolean shutdownInitiated = new AtomicBoolean(false);

// ✅ Volatile for visibility-only fields
private volatile boolean connected;
private volatile boolean initialized = false;
```

## Async Operations — CompletableFuture + Virtual Threads

All I/O must run on virtual threads via `VirtualThreadExecutorProvider`. Never block Velocity event threads.

```java
// ✅ Database operations — async with virtual threads
public CompletableFuture<DbResult<RegisteredPlayer>> findPlayerByNickname(String nick) {
    return CompletableFuture.supplyAsync(
        () -> executeFind(nick),
        VirtualThreadExecutorProvider.getVirtualExecutor()
    );
}

// ✅ Chained async with retry
private CompletableFuture<PremiumResolution> executeWithRetriesAsync(
        String username, int attempt, int maxRetries) {
    return CompletableFuture.supplyAsync(
        () -> tryResolveAttempt(username, attempt, maxRetries),
        VirtualThreadExecutorProvider.getVirtualExecutor()
    ).thenCompose(result -> {
        if (result != null) return CompletableFuture.completedFuture(result);
        if (attempt + 1 > maxRetries) {
            return CompletableFuture.completedFuture(
                PremiumResolution.unknown(id(), "max retries exceeded"));
        }
        return executeWithRetriesAsync(username, attempt + 1, maxRetries);
    });
}

// ✅ Composing multiple futures
CompletableFuture.allOf(totalF, premiumF, nonPremiumF).join();

// ✅ Check shutdown before submitting
if (VirtualThreadExecutorProvider.isShutdown()) return;
```

## Optional Usage

Use conservatively — prefer null checks with `DbResult` for DB operations; use `Optional` for API boundaries.

```java
// ✅ Optional from Velocity API
result.getReasonComponent()
    .map(Component::toString)
    .orElse("unknown");

// ✅ var keyword — use when type is obvious from RHS
var dbResult = databaseManager.findPlayerByNickname(username).join();
var result = player.createConnectionRequest(targetServer);
```

## Streams Best Practices

```java
// ✅ Short, focused pipelines
List<String> names = markets.stream()
    .map(Market::name)
    .filter(Objects::nonNull)
    .toList();

// ❌ Avoid complex nested streams — prefer loops for clarity
```

## Exception Handling

- Domain errors: `VeloAuthException` (unchecked) with context
- DB errors: wrap in `DbResult.databaseError()` — never propagate `SQLException`
- Constructor validation: `IllegalArgumentException` for null/empty required args
- Sensitive details: never expose to players; log internally, show generic message

```java
// ✅ VeloAuthException with factory methods
public class VeloAuthException extends RuntimeException {
    public VeloAuthException(String message) { super(message); }
    public VeloAuthException(String message, Throwable cause) { super(message, cause); }

    public static VeloAuthException database(String operation, Throwable cause) {
        return new VeloAuthException("Database operation failed: " + operation, cause);
    }
}

// ✅ Constructor validation
public RegisteredPlayer(String nickname, String hash, String ip, String uuid) {
    if (nickname == null || nickname.isEmpty()) {
        throw new IllegalArgumentException("Nickname nie może być pusty");
    }
    this.nickname = nickname;
    // ...
}

// ✅ Fail-secure error handling — hide details from player
if (dbResult.isDatabaseError()) {
    logger.error(DB_MARKER, "Error for {}: {}", username, dbResult.getErrorMessage());
    player.sendMessage(ValidationUtils.createErrorComponent(messages.get("error.database.query")));
}
```

## Generics & Type Safety

```java
// ✅ Typed CompletableFuture returns
public CompletableFuture<DbResult<Boolean>> isPremium(String username) { ... }

// ✅ Generic utility methods with bounds
private <T> CompletableFuture<DbResult<T>> submitConnectedTask(Supplier<DbResult<T>> task) { ... }

// ✅ Typed concurrent collections
ConcurrentHashMap<UUID, CachedAuthUser> authorizedPlayers;
```

## Logging — SLF4J with Markers

Always use parameterized logging (no string concatenation). Use markers to categorize log output.

```java
// ✅ Marker categories
// AUTH      — authentication events (login, register, password change)
// DATABASE  — DB operations, queries, migrations
// SECURITY  — brute force, suspicious activity, UUID mismatches
// CACHE     — cache hits, misses, evictions, TTL
// PREMIUM   — premium resolution, Mojang API calls

// ✅ Parameterized messages
logger.info(AUTH_MARKER, "Player {} logged in from {}", username, ip);
logger.warn(SECURITY_MARKER, "[BRUTE FORCE BLOCK] IP {} attempted {}", address, command);
logger.error(DB_MARKER, "Error deleting player: {}", nickname, e);

// ✅ Debug with guard for expensive operations
if (logger.isDebugEnabled()) {
    logger.debug(CACHE_MARKER, "Cache hit for: {}", nickname);
}

// ❌ NEVER System.out.println or string concatenation in log calls
```

## DAO Pattern — All SQL Lives in DAO Classes

SQL and query logic belongs exclusively in `*Dao` classes and `DatabaseStatisticsQueryService`.

```java
// ✅ DAO structure
public final class JdbcAuthDao {
    private static final String TABLE_AUTH = "AUTH";
    private String selectPlayerSql;
    private String insertPlayerSql;

    public JdbcAuthDao(DatabaseConfig config) {
        this.config = Objects.requireNonNull(config, "config nie może być null");
        initializeSqlStatements(); // Build SQL once
    }

    // Always use PreparedStatement — prevents SQL injection
    public RegisteredPlayer findPlayerByLowercaseNickname(String nick) throws SQLException {
        try (Connection conn = openConnection();
             PreparedStatement stmt = conn.prepareStatement(selectPlayerSql)) {
            stmt.setString(1, nick);
            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next() ? mapPlayer(rs) : null;
            }
        }
    }

    // Transactions with rollback
    public boolean upsertPlayer(RegisteredPlayer player) throws SQLException {
        try (Connection conn = openConnection()) {
            conn.setAutoCommit(false);
            try {
                int updated = executeUpdate(conn, player);
                if (updated == 0) executeInsert(conn, player);
                conn.commit();
                return true;
            } catch (SQLException e) {
                conn.rollback();
                throw e;
            }
        }
    }
}
```

## ⚠️ ORMLite Pitfalls

ORMLite has subtle API requirements that differ from plain JDBC. **Always verify ORMLite API docs before writing DAO code.**

Key rules:
- `SelectArg` in `.raw()` queries **requires** `SqlType` or column name — bare `new SelectArg(value)` compiles but throws at runtime
- `executeStatement()` second parameter must be `DatabaseConnection.DEFAULT_RESULT_FLAGS` — passing literal `0` works on H2 but throws on PostgreSQL
- Tests use H2 in-memory, production uses PostgreSQL — **passing tests does NOT guarantee production correctness**
- H2 is case-insensitive by default, PostgreSQL is case-sensitive — use explicit `LOWER()` for case-insensitive matching
- Column quoting differs: `"COLUMN"` for PostgreSQL, `` `COLUMN` `` for MySQL — ORMLite handles this if you use its query builder, but raw SQL needs dialect awareness

## Builder Pattern

Use builders for objects with many configuration parameters.

```java
// ✅ Immutable record with a fluent construction helper
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

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        // fields and fluent setters omitted
        public Builder storageType(String v) { this.storageType = v; return this; }
        public Builder hostname(String v)    { this.hostname = v;    return this; }
        public HikariConfigParams build() {
            return new HikariConfigParams(storageType, hostname, port, database, user, password,
                    connectionPoolSize, maxLifetime, connectionParameters,
                    postgreSQLSettings, debugEnabled);
        }
    }
}

// ✅ Usage
HikariConfigParams.builder()
    .storageType(dbType)
    .hostname(host)
    .port(port)
    .build();
```

## i18n — User-Facing Strings

All player-visible text lives in `messages_XX.properties` (17 languages). Never hardcode strings.

```java
// ✅ Use Messages / SimpleMessages
player.sendMessage(sm.loginSuccess());
player.sendMessage(messages.get("auth.login.incorrect_password"));

// ❌ NEVER hardcode user-facing strings
// player.sendMessage(Component.text("Login failed!"));
```

## Project Structure

```
src/main/java/net/rafalohaki/veloauth/
├── VeloAuth.java              → Plugin lifecycle, 8-phase init
├── listener/                  → Velocity event handlers
├── command/                   → CLI commands + shared CommandContext
├── connection/                → Auth/backend server transfers
├── config/                    → Settings, YAML parsing
├── database/                  → DatabaseManager, DAOs, migrations
├── cache/                     → AuthCache, BruteForceTracker, SessionManager
├── auth/totp/                 → RFC 6238 TOTP service and replay protection
├── premium/                   → Premium resolver (3-layer cache)
├── model/                     → RegisteredPlayer, data models
├── i18n/                      → Messages, SimpleMessages, LanguageFileManager
├── report/                    → Redacted diagnostic report generation
├── alert/                     → Discord webhooks, alerts
└── util/                      → VirtualThreadExecutorProvider, ValidationUtils
src/main/resources/
├── velocity-plugin.json
└── lang/messages_XX.properties  → 17 languages
config.yml                        → Generated in the plugin data directory on first startup
src/test/java/...                → Mirrors main structure
```

## Formatting and Style

- **4 spaces** indentation (no tabs)
- Opening brace on same line (K&R style)
- One public top-level type per file
- Keep methods short and focused; extract helpers
- Member order: constants → fields → constructors → public methods → package-private → private
- Use `var` when the type is obvious from the right-hand side

## Null Handling

- Use JSR-305 annotations: `@javax.annotation.Nullable`, `@javax.annotation.Nonnull`
- Constructor/setter validation for required parameters
- Premium detection depends on multiple nullable fields — see "Domain Semantics" section

## Testing Expectations

- **JUnit 5** (Jupiter) + standard assertions (`assertTrue`, `assertEquals`, `assertNull`)
- **Mockito 5** for mocking; avoid partial mocks
- Test classes are **package-private** (no `public` modifier)
- Test DB: **H2 in-memory**
- Test naming: `testMethodName_Scenario_ExpectedResult()`
- Sections: Arrange / Act / Assert
- SonarQube suppressions: `@SuppressWarnings("java:S2068")` for test passwords, `// NOSONAR` inline

```java
@ExtendWith(MockitoExtension.class)
class ValidationUtilsTest {

    @Mock private Player mockPlayer;

    @Test
    void testValidatePassword_ValidPassword_ReturnsSuccess() {
        // Arrange
        String validPassword = "testPassword123"; // NOSONAR - Test password

        // Act
        ValidationResult result = ValidationUtils.validatePassword(validPassword, mockSettings);

        // Assert
        assertTrue(result.valid());
        assertNull(result.getErrorMessage());
    }
}
```

## Code Smells to Avoid

- Long parameter lists → use record / builder
- Deep nesting → early returns
- Magic numbers → named constants
- Static mutable state → dependency injection
- Silent catch blocks → log with marker and act or rethrow
- `synchronized` → `ReentrantLock` (virtual thread safety)
- Plain `HashMap` for shared state → `ConcurrentHashMap`
- Blocking Velocity event threads → `VirtualThreadExecutorProvider`
- Hardcoded player messages → `messages_XX.properties`
- SQL outside DAO classes → move to `*Dao` or `DatabaseStatisticsQueryService`
- `System.out.println` → SLF4J with appropriate marker

## ⚠️ Domain Semantics — Premium Player Detection

Premium detection uses multiple complementary fields in the AUTH table. All premium-checking methods and SQL queries must be consistent with each other.

- When modifying any premium detection logic, first read ALL existing premium-checking methods and their SQL equivalents
- Premium state can come from multiple sources (Mojang API, migration, admin action) — never assume only one path sets premium fields
- The PREMIUM_UUIDS table is a **cache**, not the source of truth — AUTH table is authoritative
- Resolver, AUTH and cache state identify a premium account but do not prove that the current connection completed Mojang authentication
- Only the final Velocity `Player#isOnlineMode()` is a valid trust boundary for `premium.bypass-auth-server`; never authorize passthrough from a nickname, UUID or resolver result alone
- Before changing premium logic, verify behavior for: new premium players, migrated players, offline→premium transitions, and players with partial data

## ⛔ Change Safety Rules

**Before modifying ANY existing method:**

1. **Find ALL callers** — understand every call site before changing behavior
2. **Preserve semantics** — if a method returns X for input Y, your change MUST return X for Y unless the bug IS that wrong value
3. **Never change a method's contract silently** — if you must change semantics, rename the method or add a new one
4. **Verify on production DB type** — H2 tests passing ≠ PostgreSQL working. Check ORMLite API contracts and run `./scripts/test-postgresql.sh` for persistence changes
5. **One concern per change** — don't mix "improve logging" with "change query logic" in the same method edit
6. **Async I/O must use virtual threads** — every `CompletableFuture.supplyAsync()` with I/O needs an explicit executor, never default ForkJoinPool

## Build & Static Analysis

```bash
mvnd test                       # Run the full JUnit/Mockito suite against H2
mvnd clean package              # Build shaded JAR
mvnd clean verify               # Compile + test + PMD + JaCoCo gate/report + shaded JAR
mvnd pmd:check pmd:cpd-check   # Explicit PMD and CPD quality gates
./scripts/test-postgresql.sh    # Real PostgreSQL integration gate (Docker required)
```

- PMD custom ruleset: `pmd-ruleset.xml` (security rules all enabled)
- CPD: 50-token minimum duplicate detection
- CPD is deliberately invoked as a separate command; it is expected to pass before release
- Compiler flags: `-Xlint:deprecation -Xlint:unchecked`
- Shade relocations: `com.j256.ormlite` → `libs.ormlite`, `at.favre.lib.crypto` → `libs.bcrypt`, `com.fasterxml.jackson` → `libs.jackson`

**Remember**: Keep code intentional, typed, thread-safe, and observable. Use virtual threads for I/O, `DbResult<T>` for DB operations, markers for logging, and records for immutable data. Optimize for maintainability over micro-optimizations unless proven necessary.
