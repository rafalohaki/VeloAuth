---
trigger: manual
---

# VeloAuth Development Rules

## Project Overview
Velocity proxy authentication plugin (Java 21) managing auth flows between Velocity, PicoLimbo, and backend servers. Uses Virtual Threads, ORMLite + HikariCP, BCrypt.

## Core Architecture
```
VeloAuth.java → Plugin lifecycle, 8-phase initialization
├── listener/ → AuthListener, PreLoginHandler, PostLoginHandler, EarlyLoginBlocker
├── command/ → CommandHandler, ValidationUtils, IPRateLimiter  
├── database/ → DatabaseManager, ORMLite DAOs, HikariCP
├── cache/ → AuthCache (4 caches: auth, premium, brute-force, sessions)
├── premium/ → PremiumResolverService, API resolvers
├── connection/ → ConnectionManager (Velocity transfers)
├── i18n/ → Messages, ResourceBundles (pl/en)
├── config/ → Settings (YAML via Jackson)
├── util/ → VirtualThreadExecutorProvider, SecurityUtils
├── model/ → RegisteredPlayer, PremiumUuid, CachedAuthUser
├── alert/ → Discord webhook alerts
└── monitoring/ → MetricsCollector
```

## Build & Test
```bash
mvnd clean package              # Build shaded JAR
mvnd test                       # Run tests  
mvnd clean test jacoco:report   # Coverage report
mvnd clean package -DskipTests  # Fast build
```

## Critical Patterns

### Virtual Threads (Java 21)
All async I/O uses `VirtualThreadExecutorProvider.getVirtualExecutor()`. Never use `synchronized` - use `ReentrantLock`:
```java
private final ReentrantLock lock = new ReentrantLock();
lock.lock();
try { /* critical section */ } finally { lock.unlock(); }
```

### Async Operations
Database calls return `CompletableFuture`:
```java
databaseManager.getPlayerAsync(nickname)
    .thenAccept(result -> { /* handle result */ })
    .exceptionally(ex -> { logger.error(...); return null; });
```

### Thread Safety
Use `ConcurrentHashMap` for shared state, never `HashMap`:
```java
private final ConcurrentHashMap<UUID, CachedAuthUser> authorizedPlayers;
```

### Initialization
Plugin uses `volatile boolean initialized` flag. `EarlyLoginBlocker` blocks connections until init completes. Never bypass this check.

### Premium Detection
1. Check cache → 2. Check DB → 3. Query APIs → 4. Cache result
- Premium = `hash == null || hash.isEmpty()` in RegisteredPlayer
- Minimum 2 resolvers for redundancy

### Logging
Use SLF4J with markers, never `System.out`:
```java
private static final Marker AUTH_MARKER = MarkerFactory.getMarker("AUTH");
logger.info(AUTH_MARKER, "Player {} authenticated", username);
```

## Key Dependencies (Shaded)
- `org.bstats` → `net.rafalohaki.veloauth.libs.bstats`
- `com.j256.ormlite` → `net.rafalohaki.veloauth.libs.ormlite`
- `at.favre.lib.crypto` → `net.rafalohaki.veloauth.libs.bcrypt`  
- `com.fasterxml.jackson` → `net.rafalohaki.veloauth.libs.jackson`

## Testing
- JUnit 5 + Mockito
- Mirror package structure in `src/test/java`
- Mock Velocity components for tests
- Test async with `CompletableFuture.join()` or `awaitility`

## Common Pitfalls
1. **Never block Velocity event threads** - offload to virtual executor
2. **Always use prepared statements** - SQL only in DAO classes
3. **Validate player input** in command handlers
4. **Keep listeners thin** - delegate to services
5. **Check initialization** before accessing components

## Key Files
- `VeloAuth.java` - main plugin class, initialization
- `AuthListener.java` - event routing
- `PreLoginHandler.java` - premium detection, nickname conflicts
- `DatabaseManager.java` - data access layer
- `AuthCache.java` - caching with TTL
- `VirtualThreadExecutorProvider.java` - thread management

## Nickname Conflicts
Offline-owned nicknames block premium players. Detection in `PreLoginHandler.isNicknameConflict()`, handled by `PreLoginHandler.handleNicknameConflictNoEvent()`. Model uses `conflictMode` flag in `RegisteredPlayer`.

