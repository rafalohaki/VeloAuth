<p align="center">
  <img src="https://cdn.modrinth.com/data/cached_images/a31eec688d48cffe2770bd961e5d134c71b8b662.png" alt="VeloAuth">
</p>

# VeloAuth

[![Modrinth](https://img.shields.io/badge/Modrinth-00AF5C?style=for-the-badge&logo=modrinth&logoColor=white)](https://modrinth.com/plugin/veloauth) 
[![Discord](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/e2RkPbc3ZR)
[![SpigotMC](https://img.shields.io/badge/SpigotMC-VeloAuth-orange?style=for-the-badge&logo=spigotmc&logoColor=white)](https://www.spigotmc.org/resources/veloauth.130240/)
[![License](https://img.shields.io/github/license/rafalohaki/veloauth?style=for-the-badge)](LICENSE)

**Complete Velocity authentication plugin** with intelligent nickname protection, premium auto-login, and secure offline player management.

## What is VeloAuth?

VeloAuth is a comprehensive authentication system for Velocity proxy that handles all player authorization before they reach your backend servers. It works with any limbo server to provide a smooth login experience while protecting nickname ownership through intelligent conflict resolution.

## Key Features

- 🔒 **Intelligent Nickname Protection** - Premium nicknames are reserved unless already registered by cracked players
- ⚡ **Premium Auto-Login** - Mojang account owners skip authentication automatically  
- 🛡️ **Secure Offline Auth** - BCrypt password hashing with brute-force protection
- 🗺️ **Forced Hosts Support** - Players connect via custom domains (e.g., `pvp.server.com`) and are properly routed to their intended server *after* authentication
- 🚫 **Smart Command Hiding** - Authentication commands (`/login`, `/register`) are completely hidden from tab-completion once the player is logged in
- 🚀 **High Performance** - Authorization cache with 24-hour premium status caching
- 🔄 **Conflict Resolution** - Smart handling of premium/cracked nickname conflicts
- 📊 **Admin Tools** - Complete conflict management with `/vauth conflicts`
- 🗄️ **Multi-Database** - MySQL, PostgreSQL, H2, SQLite
- 🌍 **8 Languages** - EN, PL, DE, FR, RU, TR, SI, FI
- 🔄 **LimboAuth Compatible** - 100% database compatibility (no migration needed)
- 📢 **Discord Alerts** - Webhook notifications for security events
- 🧵 **Virtual Threads** - Built on Java 21 for maximum performance

## Requirements

- **Java 21 or newer**
- **Velocity proxy** (API 3.4.0+)
- **Limbo server**: NanoLimbo, LOOHP/Limbo, LimboService, PicoLimbo, hpfxd/Limbo, or any other
- **Database**: MySQL, PostgreSQL, H2, or SQLite

## Quick Setup

### Installation

1. Download VeloAuth from Modrinth
2. Place the file in your Velocity `plugins/` folder
3. Start Velocity - the plugin will create a `config.yml` file
4. Stop Velocity and configure your database and limbo name in `plugins/VeloAuth/config.yml` 
5. Restart Velocity

### Velocity Config

Configure your `velocity.toml` with your limbo/auth server and backend servers:

```toml
[servers]
limbo = "127.0.0.1:25566"  # Auth/limbo server (NanoLimbo, LOOHP/Limbo, etc.)
lobby = "127.0.0.1:25565"  # Typical backend server
survival = "127.0.0.1:25567" # Another backend server

try = ["lobby", "survival"]  # Order matters. Do NOT put 'limbo' here.

[forced-hosts]
# VeloAuth fully respects Velocity's forced hosts! 
# Players connecting via this IP will be sent to limbo to login, 
# and then seamlessly transferred to 'survival' instead of 'lobby'.
"survival.example.com" = ["survival"] 
```

**Important:** The `try` configuration controls where authenticated players are redirected by default. VeloAuth automatically skips the `limbo` server and selects the first available backend server, **unless** the player used a `forced-host` domain, in which case they are natively routed to their intended destination!

### Discord Webhooks

VeloAuth supports Discord notifications for security events. Configure webhook URL in config.yml.

### Database Config

Supported: H2 (out-of-box), MySQL, PostgreSQL, SQLite

## Player Commands

| Command | Description | Restrictions |
|---------|-------------|--------------|
| `/register <password> <confirm>` | Create new account | Hidden after login. No premium nicknames |
| `/login <password>` | Login to your account | Hidden after login. Works for all players |
| `/changepassword <old> <new>` | Change your password | Must be logged in |

## Admin Commands

| Command | Permission | Description |
|---------|------------|-------------|
| `/unregister <nickname>` | `veloauth.admin` | Remove player account (resolves conflicts) |
| `/vauth reload` | `veloauth.admin` | Reload configuration |
| `/vauth cache-reset [player]` | `veloauth.admin` | Clear authorization cache |
| `/vauth stats` | `veloauth.admin` | Show plugin statistics |
| `/vauth conflicts` | `veloauth.admin` | List nickname conflicts |

## How It Works

### Authentication Flow
1. **Player connects** to Velocity
2. **VeloAuth checks** authorization cache
3. If **not cached**, player is sent to the **auth server** (limbo)
4. **Nickname protection** activates during registration
5. Player types **/login** or **/register**
6. **VeloAuth verifies** credentials with BCrypt
7. Player is **redirected to backend server** via `try` configuration

### Nickname Protection System
- **Premium nicknames are reserved** unless already registered by cracked players
- **Conflict resolution** when premium players use cracked-registered nicknames
- **Admin tools** for managing nickname conflicts
- **Automatic blocking** of cracked players trying premium nicknames

## LimboAuth Migration

VeloAuth is **100% compatible** with LimboAuth databases:

1. Stop LimboAuth on your backend servers
2. Install VeloAuth on Velocity
3. Configure VeloAuth to use the same database as LimboAuth
4. Start Velocity - all existing accounts will work automatically

## Contributing

Contributions are welcome! Please open an issue or PR.

## Support

Need help? Found a bug? Open an issue on GitHub or join our Discord server.

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.


