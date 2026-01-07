# VeloAuth - AI Coding Agent Instructions

## Project Overview
VeloAuth is a **Velocity proxy authentication plugin** managing player auth flows between Velocity, PicoLimbo (limbo server), and backend Minecraft servers. Uses Java 21 Virtual Threads, ORMLite + HikariCP, and BCrypt security.

## Architecture - Key Components

```
VeloAuth.java          → Plugin lifecycle, DI, 8-phase initialization
├── AuthListener       → Event routing (PreLogin → PostLogin → ServerConnect)
│   ├── PreLoginHandler   → Premium detection, online-mode forcing
│   └── PostLoginHandler  → Auth cache check, PicoLimbo routing
├── CommandHandler     → /login, /register, /changepassword, /vauth admin
├── DatabaseManager    → ORMLite DAOs, async queries, player cache
├── AuthCache          → 4 caches: authorized, premium, brute-force, sessions
├── PremiumResolverService → Mojang/Ashcon API chain with fallback
└── ConnectionManager  → Server transfers via Velocity API
```

## Build & Test Commands
```bash
mvnd clean package              # Build shaded JAR
mvnd test                       # Run tests
mvnd clean test jacoco:report   # Tests with coverage (target/site/jacoco)
mvnd clean package -DskipTests  # Fast build
```

## Critical Patterns

### Virtual Threads (Java 21)
All I/O uses `VirtualThreadExecutorProvider.getVirtualExecutor()`. Never use `synchronized` blocks (causes pinning) - use `ReentrantLock` instead:
```java
private final ReentrantLock lock = new ReentrantLock();
lock.lock();
try { /* critical section */ } finally { lock.unlock(); }
```

### Async Database Operations
All DB calls return `CompletableFuture` and run on virtual threads:
```java
databaseManager.getPlayerAsync(nickname)
    .thenAccept(result -> { /* handle DbResult */ })
    .exceptionally(ex -> { logger.error(...); return null; });
```

### Thread-Safe Collections
Always use `ConcurrentHashMap` for shared state - never plain `HashMap`:
```java
private final ConcurrentHashMap<UUID, CachedAuthUser> authorizedPlayers;
```

### Initialization Protection
Plugin uses `volatile boolean initialized` flag. `EarlyLoginBlocker` rejects connections until all 8 init phases complete. Never bypass this check.

### Premium Detection Flow
1. Check `premiumCache` (memory) → 2. Check DB `PREMIUMUUIDS` table → 3. Query Mojang/Ashcon APIs → 4. Cache result
- Premium = `hash == null || hash.isEmpty()` in RegisteredPlayer
- Minimum 2 resolvers enabled for redundancy

### Logging Standards
Use SLF4J with markers, never `System.out` or `e.printStackTrace()`:
```java
private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
logger.info(AUTH_MARKER, "Player {} authenticated", username);
```

## Package Structure
| Package | Purpose |
|---------|---------|
| `cache` | AuthCache with TTL, brute-force protection |
| `command` | Command handlers, ValidationUtils, IPRateLimiter |
| `config` | Settings.java - YAML via Jackson |
| `connection` | ConnectionManager - Velocity server transfers |
| `database` | ORMLite DAOs, HikariCP config, migrations |
| `listener` | Velocity event handlers (Pre/Post login) |
| `model` | RegisteredPlayer, PremiumUuid, CachedAuthUser |
| `premium` | PremiumResolverService, API clients |
| `i18n` | Messages.java, ResourceBundles (pl/en) |

## Dependency Relocation
Shade plugin relocates to avoid conflicts:
- `com.j256.ormlite` → `net.rafalohaki.veloauth.libs.ormlite`
- `at.favre.lib.crypto` → `net.rafalohaki.veloauth.libs.bcrypt`
- `com.fasterxml.jackson` → `net.rafalohaki.veloauth.libs.jackson`

## Testing Conventions
- JUnit 5 + Mockito for unit tests
- Mirror main package structure in `src/test/java`
- Mock `ProxyServer`, `Player`, `Logger` for Velocity tests
- Test async operations with `CompletableFuture.join()` or `awaitility`

## Common Pitfalls
1. **Never block Velocity event threads** - offload to virtual executor
2. **Always use prepared statements** - SQL is in DAO classes only
3. **Validate all player input** in command handlers before delegation
4. **Keep event listeners thin** - delegate to services
5. **Check `isInitialized()`** before accessing plugin components in handlers

## Key Files for Understanding
- [VeloAuth.java](../src/main/java/net/rafalohaki/veloauth/VeloAuth.java) - initialization sequence
- [AuthListener.java](../src/main/java/net/rafalohaki/veloauth/listener/AuthListener.java) - event flow
- [PreLoginHandler.java](../src/main/java/net/rafalohaki/veloauth/listener/PreLoginHandler.java) - nickname conflict detection (premium vs offline)
- [DatabaseManager.java](../src/main/java/net/rafalohaki/veloauth/database/DatabaseManager.java) - data access
- [docs/INITIALIZATION_SEQUENCE.md](../docs/INITIALIZATION_SEQUENCE.md) - startup protection
- [docs/PREMIUM_RESOLVER_BEST_PRACTICES.md](../docs/PREMIUM_RESOLVER_BEST_PRACTICES.md) - resolver config

## Nickname conflicts (premium vs cracked)
- Detection: implemented in `PreLoginHandler.isNicknameConflict(...)` and handled by `PreLoginHandler.handleNicknameConflictNoEvent(...)`
- Model: `RegisteredPlayer` has a `conflictMode` flag used to mark conflicted accounts
- Key tests: `src/test/java/net/rafalohaki/veloauth/listener/PreLoginHandlerTest.java` and `src/test/java/net/rafalohaki/veloauth/integration/AuthenticationFlowIntegrationTest.java`
- Behavior summary: Offline-owned nicknames block premium players (premium players must authenticate or are redirected/kicked depending on config). Consult tests and `docs/PREMIUM_RESOLVER_BEST_PRACTICES.md` for exact rules.

