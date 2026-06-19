<p align="center">
  <img src="https://cdn.modrinth.com/data/cached_images/a31eec688d48cffe2770bd961e5d134c71b8b662.png" alt="VeloAuth">
</p>

# VeloAuth

[![Modrinth](https://img.shields.io/badge/Modrinth-00AF5C?style=for-the-badge&logo=modrinth&logoColor=white)](https://modrinth.com/plugin/veloauth) 
[![Discord](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/e2RkPbc3ZR)
[![License](https://img.shields.io/github/license/rafalohaki/veloauth?style=for-the-badge)](LICENSE)
[![bStats](https://img.shields.io/badge/bStats-Tracked-blue?style=for-the-badge)](https://bstats.org/plugin/velocity/VeloAuth)

**Complete Velocity authentication plugin** with intelligent nickname protection, premium auto-login, and secure offline player management.

## What is VeloAuth?

VeloAuth is a comprehensive authentication system for Velocity proxy that handles all player authorization before they reach your backend servers. It works with any limbo server to provide a smooth login experience while protecting nickname ownership through intelligent conflict resolution.

## Key Features

- 🔒 **Intelligent Nickname Protection** - Premium nicknames are reserved unless already registered by cracked players
- ⚡ **Premium Auto-Login** - Mojang account owners skip authentication automatically
- 🔄 **Automatic Nickname Change Detection** - Detects when a premium player renames their Mojang account and updates the database record automatically
- 🛡️ **Secure Offline Auth** - BCrypt password hashing with brute-force protection
- 📱 **Optional Floodgate Support** - Bedrock players can bypass the auth server when Floodgate integration is enabled
- 🗺️ **Forced Hosts Support** - Players connect via custom domains (e.g., `pvp.server.com`) and are properly routed to their intended server *after* authentication
- 🚫 **Smart Command Hiding** - Authentication commands (`/login`, `/register`) are completely hidden from tab-completion once the player is logged in
- 🚀 **High Performance** - Three-layer premium resolution cache: in-memory → database → external API, with 24-hour premium status retention
- 🔐 **Optional 2FA (TOTP)** - Opt-in RFC 6238 second factor compatible with Google Authenticator, Authy, Aegis. See [2FA.md](2FA.md) for the operator + player handbook.
- 🔄 **Conflict Resolution** - Smart handling of premium/cracked nickname conflicts
- 📊 **Admin Tools** - Complete conflict management with `/vauth conflicts`
- 🗄️ **Multi-Database** - MySQL, PostgreSQL, H2, SQLite
- 🌍 **17 Languages** - EN, PL, DE, FR, RU, TR, SI, FI, ZH_CN, ZH_HK, JA, HI, VI, KO, TH, ID, PT_BR
- 🔄 **LimboAuth Compatible** - 100% database compatibility (no migration needed)
- 📢 **Discord Alerts** - Webhook notifications for security events
- 🧵 **Virtual Threads** - Built on Java 21 for maximum performance
- 📈 **bStats Analytics** - Anonymous usage statistics via bStats

## When to use VeloAuth

- **You run a Velocity proxy** with one or more backend servers and need authentication at the proxy layer (not per-backend).
- **You accept both premium and cracked players** and need automatic, fail-secure routing — premium players skip `/login`, cracked players go through BCrypt-hashed registration.
- **You already use LimboAuth** and want to migrate without losing data — VeloAuth reads the same database schema.
- **You want predictable performance** — premium status is resolved through a three-layer cache (in-memory → DB → Mojang/Ashcon API), virtual-thread I/O, and zero blocking on Velocity event threads.

If you only run a single backend server (Paper/Spigot/Folia) without a proxy, you don't need VeloAuth — use a backend-side auth plugin instead.

## Recommended configuration

VeloAuth ships three sensible operating modes. Pick one based on how strict you want nickname-theft protection to be. All settings live under `premium:` in `plugins/VeloAuth/config.yml`.

### Profile 1 — **Mixed strict** (default, recommended)

```yaml
premium:
  check-enabled: true
  allow-cracked-on-premium-nicks: false
```

- **What you get:** premium players auto-login with their real Mojang UUID (no `/login` prompt); cracked players go through `/register` + BCrypt; **premium nicknames are reserved** for their Mojang owners.
- **What you lose:** cracked clients trying to connect with a premium-looking nickname (e.g. someone else's name) are rejected with *"You are not logged into your Minecraft account."*
- **Use when:** public server accepting both premium and cracked players, where nickname ownership matters.

### Profile 2 — **Cracked-only**

```yaml
premium:
  check-enabled: false
```

- **What you get:** zero HTTP traffic to Mojang/Ashcon, zero writes to `PREMIUM_UUIDS`, every player forced into offline mode with deterministic offline UUID. All registrations go through `/register`.
- **What you lose:** **premium auto-login is gone for everyone** — even existing premium owners with a `PREMIUMUUID` record will be downgraded to offline UUID. Nickname-theft protection no longer exists; whoever registers a nickname first owns it.
- **Use when:** cracked-only server, dev/test environment, or any setup where you explicitly don't want Mojang in the loop.

### Profile 3 — **Permissive mixed**

```yaml
premium:
  check-enabled: true
  allow-cracked-on-premium-nicks: true
```

- **What you get:** existing premium owners (those already in AUTH with `PREMIUMUUID`) keep their premium UUID and skip `/login`. Cracked clients **can** register a premium-looking nickname if it's not yet in the database.
- **What you lose:** **new premium players connecting for the first time get offline UUIDs permanently** — Velocity's PreLoginEvent has no "try online, fallback offline" mode ([PaperMC/Velocity#1590](https://github.com/PaperMC/Velocity/pull/1590), closed), so VeloAuth must pick one mode per connection. Once a nickname is registered as offline in VeloAuth, the real Mojang owner can no longer take it back automatically — they will hit the nickname-conflict path (`/vauth conflicts`).
- **Use when:** cracked-first server that wants to accept premium-looking nicknames without kicking anyone, and you accept that new premium owners may lose their premium UUID.

### Quick decision guide

| If you want… | Use profile |
|---|---|
| Strongest protection, premium UUIDs preserved | **1 — Mixed strict** |
| No Mojang contact at all, fully cracked | **2 — Cracked-only** |
| Accept everyone, premium nicks not reserved | **3 — Permissive mixed** |

There is no profile that "gives premium owners premium UUID *and* lets cracked clients on the same nickname through" — that requires a Velocity API feature that does not exist yet.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release-by-release notes, upgrade instructions, and breaking-behavior callouts.

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
4. Stop Velocity and configure your database and auth server name in `plugins/VeloAuth/config.yml`
5. Restart Velocity

**Note:** Floodgate support is disabled by default. Enable it only if you actually use Geyser/Floodgate.

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

### VeloAuth Config

Minimal auth server configuration in `plugins/VeloAuth/config.yml`:

```yaml
language: en
# Built-in language codes: "en", "pl", "si", "ru", "tr", "fr", "de", "fi", "zh_cn", "zh_hk", "ja", "hi", "vi", "ko", "th", "id", "pt_br"

auth-server:
  server-name: limbo
  # Seconds before an unauthenticated player is kicked from the auth server.
  # Set to 0 to disable the kick (player can stay on auth/limbo indefinitely).
  timeout-seconds: 300

# Optional tuning for heavy backend servers (large JVM heap, long GC pauses).
# VeloAuth pings the auth server, forced-host target and try-list/fallback
# backends before transferring a player. The default 2000ms may be too tight
# for big Paper/Spigot servers that don't answer a ping within 2s during a
# GC pause or warmup — raise it (e.g. 5000) so they aren't flagged offline.
# connection:
#   ping-timeout-ms: 2000
```

#### Password complexity policy (optional, off by default)

Default policy is **length-only** (8–72 chars) — friendly for casual servers, backward-compatible with LimboAuth. **If a player sets a weak password under default rules, that's on them.** Enable stricter rules only when you actually need them.

```yaml
security:
  min-password-length: 8
  max-password-length: 72
  # All counters default to 0 = no extra constraint.
  # Set any to >0 to require that many characters of the given class.
  password-policy:
    min-digits: 0       # 0 = off, e.g. 1 = require at least one digit
    min-uppercase: 0    # 0 = off, e.g. 1 = require at least one uppercase letter
    min-lowercase: 0    # 0 = off, e.g. 1 = require at least one lowercase letter
    min-special: 0      # 0 = off, e.g. 1 = require at least one special character
                        # (special = anything that is NOT a letter or digit)
```

**Profiles you can copy in:**

| Profile | digits | upper | lower | special | When to use |
|---|---|---|---|---|---|
| Relaxed (default) | 0 | 0 | 0 | 0 | Casual SMP, friendly servers, lobby networks |
| Standard | 1 | 1 | 1 | 0 | Mid-sized servers with staff accounts |
| Strict | 1 | 1 | 1 | 1 | Servers with economy/premium tiers or regulated regions |

Counters apply **on top of** `min-password-length`. Validation error messages (`validation.password.needs_digit/upper/lower/special`) are localized to all 17 supported languages.

#### Silencing "no server available" notifications

If your setup runs DiscordSRV or another plugin that kicks players before VeloAuth's backend-wait flow finishes, you can silence the in-chat "Waiting for a server…" notifications without forking the plugin: open the language file under `plugins/VeloAuth/lang/messages_<lang>.properties` and set the keys to empty values:

```properties
connection.waiting_for_server=
connection.error.no_servers=
```

Empty value = `sendMessage` is suppressed; logs are still written. Backend transfer retries continue regardless.

Built-in language codes you can copy directly into config:

| Code | Language |
|------|----------|
| `en` | English |
| `pl` | Polish |
| `si` | Slovenian |
| `ru` | Russian |
| `tr` | Turkish |
| `fr` | French |
| `de` | German |
| `fi` | Finnish |
| `zh_cn` | Chinese Simplified |
| `zh_hk` | Chinese Traditional (Hong Kong) |
| `ja` | Japanese |
| `hi` | Hindi |
| `vi` | Vietnamese |
| `ko` | Korean |
| `th` | Thai |
| `id` | Indonesian |
| `pt_br` | Brazilian Portuguese |

Optional Floodgate integration:

```yaml
floodgate:
  enabled: true
  username-prefix: "."
  bypass-auth-server: true
```

Keep the Floodgate prefix aligned with your proxy-side Floodgate configuration.

### Discord Webhooks

VeloAuth posts Discord webhook alerts when premium-resolver failure rates breach a threshold. Wired through `PremiumResolverAlertService` and triggered on every Mojang/Ashcon resolver attempt.

```yaml
alerts:
  enabled: true                 # master switch; false disables all alerting
  discord:
    enabled: true
    webhook-url: "https://discord.com/api/webhooks/.../..."
  failure-rate-threshold: 0.5   # alert when ≥50% of resolutions fail
  min-requests-for-alert: 10    # don't alert until at least N attempts in the window
  check-interval-minutes: 5     # rolling metric window
  alert-cooldown-minutes: 30    # minimum gap between two alerts
```

### Database Config

Supported: H2 (out-of-box), MySQL, PostgreSQL, SQLite

## Player Commands

| Command | Description | Restrictions |
|---------|-------------|--------------|
| `/register <password> <confirm>` | Create new account | Hidden after login. No premium nicknames |
| `/login <password>` | Login to your account | Hidden after login. Works for all players |
| `/changepassword <old> <new>` | Change your password | Must be logged in |
| `/2fa setup` | Enroll a TOTP authenticator (see [2FA.md](2FA.md)) | Must be logged in. Disabled when `two-factor.enabled: false` |
| `/2fa verify <code>` | Confirm enrollment OR pass 2FA at login | — |
| `/2fa disable <code>` | Disable 2FA on your account | Requires a valid code |
| `/2fa qr` / `/2fa status` | Re-show QR / show 2FA status | Must be logged in |

## Admin Commands

| Command | Permission | Description |
|---------|------------|-------------|
| `/unregister <nickname>` | `veloauth.admin` | Remove player account (resolves conflicts) |
| `/vauth reload` | `veloauth.admin` | Reload configuration |
| `/vauth cache-reset [player]` | `veloauth.admin` | Clear authorization cache |
| `/vauth stats` | `veloauth.admin` | Show plugin statistics |
| `/vauth conflicts` | `veloauth.admin` | List nickname conflicts |
| `/vauth 2fa-remove <nickname>` | `veloauth.admin` | Recovery: wipe a player's 2FA token (see [2FA.md](2FA.md)) |

## How It Works

### Authentication Flow
1. **Player connects** to Velocity
2. **VeloAuth checks** in-memory authorization cache (instant, no I/O)
3. If **not in memory**, checks **database premium cache** (persistent across restarts)
4. If **not in DB cache**, resolves via **Mojang/Ashcon API** in parallel using virtual threads
5. If **not premium**, player is sent to the **auth server** (unless Floodgate Bedrock bypass applies)
6. Player types **/login** or **/register**
7. **VeloAuth verifies** credentials with BCrypt
8. Player is **redirected to backend server** via `try` configuration

### Premium Resolution (3 layers)
```
Connect → [In-memory cache] → [Database cache] → [Mojang/Ashcon API]
              ~0ms                ~1ms                 ~200-500ms
```
All API calls run in parallel on virtual threads. Results are cached in the database and survive proxy restarts.

### Nickname Change Detection
When a premium player logs in with a different username than what is stored (Mojang account rename), VeloAuth automatically detects the mismatch and updates the database record, keeping the UUID-to-username mapping accurate without any admin intervention.

### Nickname Protection System
- **Premium nicknames are reserved** unless already registered by cracked players
- **Conflict resolution** when premium players use cracked-registered nicknames
- **Admin tools** for managing nickname conflicts
- **Automatic blocking** of cracked players trying premium nicknames

## FAQ / Troubleshooting

**Q: A cracked player tries to join with a premium nickname and gets "You are not logged into your Minecraft account."**
This is **VeloAuth actively enforcing nickname-theft protection**, not Velocity's own online-mode check. When premium detection finds the nickname in Mojang's database and no record exists in VeloAuth's DB yet, VeloAuth calls Velocity's `PreLoginComponentResult.forceOnlineMode()` — which forces Mojang session-server auth **regardless** of `online-mode = false` in `velocity.toml`. A cracked client cannot pass that handshake and gets kicked.

If your server explicitly accepts cracked players on premium nicknames, you have three options:

1. **Recommended — opt in per-nickname behavior:** set `premium.allow-cracked-on-premium-nicks: true` in `plugins/VeloAuth/config.yml`. Premium nicks with no DB record will be forced into offline mode so a cracked client can register first. Premium owners returning to a nickname that's *already registered as premium* still get the normal Mojang handshake.
2. **Disable premium detection entirely:** set `premium.check-enabled: false`. Removes nickname-theft protection for **all** nicks — every connection is forced offline.
3. **Pre-register the nickname:** have an admin (or the cracked player) register the nickname through `/register` before the premium owner tries to join. The existing nickname-conflict path then routes that nickname to offline mode automatically.

Important trade-off for options 1 and 2: once a premium nickname is registered as offline in VeloAuth, the real Mojang owner can no longer take it back automatically — they will hit the nickname-conflict flow.

**Q: The `Failed to transfer player X: TextComponentImpl{content="...", style=StyleImpl{...}}` spam in logs is gone — anything I need to do?**
No action needed. VeloAuth 1.2.0+ renders kick reasons as plain text via `KickReasonRenderer`. Log lines now read e.g. `Failed to transfer player Alice to server lobby (Status: CONNECTION_CANCELLED): You must link your Discord account to play.`

**Q: My `language: en` config still shows Polish strings in some logs.**
Fixed in 1.2.0 — all operator-facing log messages and exception strings are now English regardless of `language` setting. The `language` key only controls **player-facing** messages.

**Q: Database not connected" right after Velocity startup.**
Fixed in 1.2.0 — health check runs once synchronously before the 30s scheduler kicks in. The `isConnected()` gate used by admin commands now reflects pool state (initialized + not shut down) rather than waiting for the first health check.

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


