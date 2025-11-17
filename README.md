# VeloAuth v1.0.0

[![Modrinth](https://img.shields.io/badge/Modrinth-00AF5C?style=for-the-badge&logo=modrinth&logoColor=white)](https://modrinth.com/plugin/veloauth)
[![Discord](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/e2RkPbc3ZR)

**Complete Velocity Authentication Plugin** with BCrypt, Virtual Threads and multi-database support.

## Description

VeloAuth is an **authorization manager for Velocity proxy** that handles player transfers between Velocity, PicoLimbo and backend servers. The plugin supports all authorization operations on the proxy.

### Key Features:
- ✅ **Authorization Cache** - logged in players bypass login
- ✅ **Transfer via Velocity** - control transfers between servers
- ✅ **Proxy Commands** - `/login`, `/register`, `/changepassword`
- ✅ **BCrypt hashing** - secure password storage (cost 10)
- ✅ **LimboAuth Compatible** - shared database compatibility
- ✅ **Premium and Cracked** - support for both player types
- ✅ **Virtual Threads** - efficient I/O (Java 21+)
- ✅ **Multi-database** - PostgreSQL, MySQL, H2, SQLite

## Requirements

- **Java 21+** (Virtual Threads)
- **Velocity API 3.4.0-SNAPSHOT+**
- **Database**: PostgreSQL 12+, MySQL 8.0+, H2, or SQLite
- **PicoLimbo** or other lobby server

## Installation

### 1. Download

Download from releases

### 2. Install on Velocity
1. Copy `VeloAuth-1.0.0.jar` to `plugins/`
2. Start Velocity - `config.yml` will be created
3. Configure database in `plugins/VeloAuth/config.yml`
4. Restart Velocity

### 3. PicoLimbo Configuration
Add PicoLimbo to `velocity.toml`:
```toml
[servers]
lobby = "127.0.0.1:25566"  # PicoLimbo
survival = "127.0.0.1:25565"  # Backend server
```
Set `try = ["lobby"]` in `velocity.toml`.

## Configuration

### config.yml
```yaml
# VeloAuth Configuration
database:
  storage-type: MYSQL  # MYSQL, POSTGRESQL, H2, SQLITE
  hostname: localhost
  port: 3306
  database: veloauth
  user: veloauth
  password: password
  connection-pool-size: 20
  max-lifetime-millis: 1800000

cache:
  ttl-minutes: 60
  max-size: 10000
  cleanup-interval-minutes: 5

picolimbo:
  server-name: lobby
  timeout-seconds: 300

security:
  bcrypt-cost: 10
  bruteforce-max-attempts: 5
  bruteforce-timeout-minutes: 5
  ip-limit-registrations: 3
  min-password-length: 4
  max-password-length: 72

premium:
  check-enabled: true
  online-mode-need-auth: false
  resolver:
    mojang-enabled: true
    ashcon-enabled: true
    wpme-enabled: false
    request-timeout-ms: 400
```

## Usage

### Player Commands

| Command | Description |
|---------|-------------|
| `/register <password> <confirm>` | Register new account |
| `/login <password>` | Login to account |
| `/changepassword <old> <new>` | Change password |

### Admin Commands

| Command | Permission | Description |
|---------|------------|-------------|
| `/unregister <nickname>` | `veloauth.admin` | Remove player account |
| `/vauth reload` | `veloauth.admin` | Reload configuration |
| `/vauth cache-reset [player]` | `veloauth.admin` | Clear cache |
| `/vauth stats` | `veloauth.admin` | Show statistics |

## Authorization Algorithm

### 1. Player joins Velocity
```
ConnectionEvent → VeloAuth checks cache
├─ Cache HIT → Verification → Forward backend
└─ Cache MISS → Transfer to PicoLimbo
```

### 2. Player on PicoLimbo
```
Player types: /login password or /register password password
↓
VELOCITY INTERCEPTS COMMAND
↓
1. SELECT HASH WHERE LOWERCASENICKNAME = LOWER(nickname)
2. BCrypt.verify(password, HASH)
├─ MATCH → UPDATE LOGINDATE + Cache + Forward backend
└─ NO MATCH → Brute force counter (max 5 attempts, timeout 5 min)
```

### 3. Player on Backend
```
ConnectionEvent → Cache HIT → Direct Backend
```

## Technical Details

### Performance
- **Cache HIT:** 0 DB queries, ~20ms
- **Cache MISS:** 1 DB query, ~100ms
- **/login:** 1 SELECT + 1 UPDATE, ~150ms (BCrypt)
- **/register:** 1 SELECT + 1 INSERT, ~200ms (BCrypt)

### Thread Safety
- **ConcurrentHashMap** for cache
- **ReentrantLock** for critical operations
- **Virtual Threads** for I/O operations

### Security
- **BCrypt cost 10** with salt (at.favre.lib 0.10.2)
- **Brute Force Protection** - 5 attempts / 5 minutes timeout
- **SQL Injection Prevention** - ORMLite prepared statements
- **Rate Limiting** - Velocity command rate limiting
- **IP Registration Limit** - Max 3 accounts per IP

## Compatibility

VeloAuth is **100% compatible** with LimboAuth database - ignores `TOTPTOKEN` and `ISSUEDTIME` fields.

### Migration from LimboAuth
1. Stop LimboAuth
2. Install VeloAuth
3. Configure the same database
4. Start Velocity - VeloAuth will automatically detect existing accounts

## Development

### Project Structure
```
src/main/java/net/rafalohaki/veloauth/
├── VeloAuth.java              # Main plugin class
├── cache/AuthCache.java       # Thread-safe authorization cache
├── command/CommandHandler.java # Command handling
├── config/Settings.java       # YAML configuration
├── connection/ConnectionManager.java # Player transfers
├── database/DatabaseManager.java # ORMLite + connection pooling
├── listener/AuthListener.java # Velocity event handling
└── model/                     # Player models (ORMLite)
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Discord:** [\[Server link\]](https://discord.gg/e2RkPbc3ZR)

---

**VeloAuth v1.0.0** - Complete Velocity Authentication Plugin  
Author: rafalohaki | Java 21 + Virtual Threads + BCrypt + Multi-DB