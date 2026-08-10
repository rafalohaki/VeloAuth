<p align="center">
  <img src="https://cdn.modrinth.com/data/cached_images/a31eec688d48cffe2770bd961e5d134c71b8b662.png" alt="VeloAuth">
</p>

# VeloAuth

[![Modrinth](https://img.shields.io/badge/Modrinth-00AF5C?style=for-the-badge&logo=modrinth&logoColor=white)](https://modrinth.com/plugin/veloauth)
[![Discord](https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white)](https://discord.gg/e2RkPbc3ZR)
[![License](https://img.shields.io/github/license/rafalohaki/veloauth?style=for-the-badge)](LICENSE)
[![bStats](https://img.shields.io/badge/bStats-Tracked-blue?style=for-the-badge)](https://bstats.org/plugin/velocity/VeloAuth)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/rafalohaki/VeloAuth)

**Complete Velocity authentication plugin** with intelligent nickname protection, premium auto-login, and secure offline player management.

## What is VeloAuth?

VeloAuth is a comprehensive authentication system for Velocity proxy that handles all player authorization before they reach your backend servers. It includes a loopback-only embedded limbo and can also keep using an existing external limbo server, while protecting nickname ownership through intelligent conflict resolution.

## Key Features

- 🔒 **Intelligent Nickname Protection** - Premium nicknames are reserved unless already registered by cracked players
- ⚡ **Premium Auto-Login** - Mojang account owners skip password entry after Velocity verifies their session; auth/limbo passthrough is a separate opt-in
- 🔄 **Automatic Nickname Change Detection** - Detects when a premium player renames their Mojang account and updates the database record automatically
- 🛡️ **Secure Offline Auth** - BCrypt password hashing, brute-force protection, and atomic first-owner registration enforced by the database
- 📱 **Optional Floodgate Support** - Bedrock and linked Floodgate accounts are detected before Mojang resolution; only UUIDs confirmed by Floodgate can bypass the auth server
- 🧩 **Self-Contained Limbo** - New installations can use the built-in 1.8-base limbo with staged ViaVersion snapshot updates for newer Java clients; no separate server, forwarding secret, or ViaVersion plugin is required
- 🗺️ **Forced Hosts Support** - Players connect via custom domains (e.g., `pvp.server.com`) and are properly routed to their intended server *after* authentication
- 🚫 **Smart Command Hiding** - Authentication commands (`/login`, `/register`) are hidden while authorization and the matching login session are active; expired sessions expose the recovery commands again
- 🚀 **High Performance** - Three-layer premium resolution cache: in-memory → database → external API, with configurable positive and negative TTLs
- 🔐 **Optional 2FA (TOTP)** - Opt-in RFC 6238 second factor compatible with Google Authenticator, Authy, Aegis. See [2FA.md](2FA.md) for the operator + player handbook.
- 🔄 **Conflict Resolution** - Smart handling of premium/cracked nickname conflicts
- 📊 **Admin Tools** - Complete conflict management with `/vauth conflicts`
- 🗄️ **Multi-Database** - MySQL, PostgreSQL, H2, SQLite
- 🌍 **17 Languages** - EN, PL, DE, FR, RU, TR, SI, FI, ZH_CN, ZH_HK, JA, HI, VI, KO, TH, ID, PT_BR
- 🔄 **LimboAuth Schema Compatible** - existing accounts are upgraded in place with additive, automatic schema changes; no manual UUID rewrite
- 📢 **Discord Alerts** - Webhook notifications for security events; failed deliveries are retried instead of consuming the alert cooldown
- 🧵 **Virtual Threads** - Built on Java 21 for maximum performance
- 📈 **bStats Analytics** - Anonymous aggregate usage statistics, including privacy-safe client-version and feature-adoption charts; metrics can never block authentication startup

## When to use VeloAuth

- **You run a Velocity proxy** with one or more backend servers and need authentication at the proxy layer (not per-backend).
- **You accept both premium and cracked players** and need automatic, fail-secure routing — premium players skip `/login`, cracked players go through BCrypt-hashed registration.
- **You already use LimboAuth** and want to migrate without losing data — VeloAuth reads the same database schema.
- **You want predictable performance** — premium status is resolved through a three-layer cache (in-memory → DB → Mojang/Ashcon API), while HTTP, Floodgate registry scans, database calls and backend pings stay off Velocity event threads.

If you only run a single backend server (Paper/Spigot/Folia) without a proxy, you don't need VeloAuth — use a backend-side auth plugin instead.

## Recommended configuration

VeloAuth ships three sensible operating modes. Pick one based on how strict you want nickname-theft protection to be. All settings live under `premium:` in `plugins/veloauth/config.yml`.

### Profile 1 — **Mixed strict** (default, recommended)

```yaml
premium:
  check-enabled: true
  allow-cracked-on-premium-nicks: false
  bypass-auth-server: false
```

- **What you get:** premium players are verified by Mojang and auto-login (no `/login` prompt); new accounts use their Mojang UUID, while LimboAuth-migrated `/premium` accounts keep their historical backend UUID so existing progress remains attached; cracked players go through `/register` + BCrypt; **premium nicknames are reserved** for their Mojang owners.
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

- **What you get:** existing premium owners (those already in `AUTH` with `PREMIUMUUID`) keep their established backend UUID identity and skip `/login`. Cracked clients **can** register a premium-looking nickname if it's not yet in the database.
- **What you lose:** **new premium players connecting for the first time get offline UUIDs permanently** — Velocity's PreLoginEvent has no "try online, fallback offline" mode ([PaperMC/Velocity#1590](https://github.com/PaperMC/Velocity/pull/1590), closed), so VeloAuth must pick one mode per connection. Once a nickname is registered as offline in VeloAuth, the real Mojang owner can no longer take it back automatically — they will hit the nickname-conflict path (`/vauth conflicts`).
- **Use when:** cracked-first server that wants to accept premium-looking nicknames without kicking anyone, and you accept that new premium owners may lose their premium UUID.

### Quick decision guide

| If you want… | Use profile |
|---|---|
| Strongest protection, premium UUIDs preserved | **1 — Mixed strict** |
| No Mojang contact at all, fully cracked | **2 — Cracked-only** |
| Accept everyone, premium nicks not reserved | **3 — Permissive mixed** |

There is no profile that "gives premium owners premium UUID *and* lets cracked clients on the same nickname through" — that requires a Velocity API feature that does not exist yet.

`premium.bypass-auth-server` is independent from the three nickname-protection profiles. Keep it
`false` to preserve the established flow where every Java connection briefly visits auth/limbo.
Set it to `true` only if Mojang-verified Java players should connect directly to Velocity's
forced-host/`try` backend target. Cracked players still use auth/limbo, and resolver/cache/name
matches never grant this bypass.

## Architecture and releases

- [ARCHITECTURE.md](ARCHITECTURE.md) documents trust boundaries, event flow, persistence,
  configuration reload semantics and upgrade constraints.
- Published release notes and downloadable artifacts are available on
  [GitHub Releases](https://github.com/rafalohaki/VeloAuth/releases) and
  [Modrinth](https://modrinth.com/plugin/veloauth).

## Requirements

- **Java 21 or newer**
- **Velocity proxy** (3.5.x; VeloAuth currently targets the 3.5 API line)
- **Database**: MySQL, PostgreSQL, H2, or SQLite
- **Embedded mode:** outbound HTTPS access to `repo.viaversion.com` for the first verified runtime
  and a small, asynchronous snapshot check after later successful startups; cached startup remains
  independent of repository availability
- **Optional external mode:** NanoLimbo, LOOHP/Limbo, LimboService, PicoLimbo, hpfxd/Limbo, or
  another Velocity-compatible auth server registered in `velocity.toml`

## Quick Setup

### Installation

1. Download VeloAuth from Modrinth.
2. Place the file in your Velocity `plugins/` folder.
3. Start Velocity. A new installation creates `config.yml`, downloads and verifies the build-pinned
   fallback runtime, and binds its limbo to an automatically selected loopback port. After the proxy
   is ready, VeloAuth may stage a newer ViaVersion snapshot for the next restart.
4. Stop Velocity and configure the database in `plugins/veloauth/config.yml`.
5. Restart Velocity. Plugin upgrades and auth-topology changes always require a full proxy restart.

**Note:** Floodgate support is disabled by default. Enable it only if you actually use Geyser/Floodgate.

### Velocity Config

With the default embedded mode, configure only real backend servers in `velocity.toml`. Do not add
the reserved `veloauth-embedded-limbo` name; VeloAuth registers and removes it atomically at runtime.
When Velocity or Velocity-CTD uses `player-info-forwarding-mode = "modern"`, clients on 1.13 or
newer complete the standard `velocity:player_info` login query automatically. Velocity reads
`forwarding-secret-file` and signs its response; VeloAuth never copies, logs or adds that secret to
`config.yml`. Modern forwarding itself does not support 1.8-1.12 clients, independently of the
embedded limbo's wider protocol matrix.

```toml
[servers]
lobby = "127.0.0.1:25565"  # Typical backend server
survival = "127.0.0.1:25567" # Another backend server

try = ["lobby", "survival"]  # Backend fallback order

[forced-hosts]
# VeloAuth fully respects Velocity's forced hosts!
# With the default premium routing, players connecting via this host visit embedded limbo
# and are then transferred to 'survival'. Verified premium players can keep the
# direct 'survival' target only when premium.bypass-auth-server is explicitly true.
"survival.example.com" = ["survival"]
```

VeloAuth preserves a forced-host target across the auth flow. With premium passthrough enabled, a
Mojang-verified player keeps Velocity's original backend target; if Velocity initially selected an
auth server, VeloAuth asynchronously selects the first reachable non-auth backend.

### VeloAuth Config

Minimal auth server configuration in `plugins/veloauth/config.yml`:

```yaml
language: en
# Built-in language codes: "en", "pl", "si", "ru", "tr", "fr", "de", "fi", "zh_cn", "zh_hk", "ja", "hi", "vi", "ko", "th", "id", "pt_br"

auth-server:
  # New config files use embedded. Existing configs without this key stay external after upgrade.
  mode: embedded
  # External mode only; ignored in embedded mode.
  server-name: limbo
  # Seconds before an unauthenticated player is kicked from the auth server.
  # Set to 0 to disable the kick (player can stay on auth/limbo indefinitely).
  timeout-seconds: 300
  embedded:
    # 0 = automatically select a free loopback port. The bind address is never public.
    # For modern forwarding, Velocity owns the existing forwarding secret and answers
    # VeloAuth's velocity:player_info query; do not copy any secret into this config.
    port: 0
    max-connections: 512
    handshake-timeout-seconds: 10
    login-timeout-seconds: 15

# Optional tuning for heavy backend servers (large JVM heap, long GC pauses).
# VeloAuth pings the auth server, forced-host target and try-list/fallback
# backends before transferring a player. The default 3000ms may be too tight
# for big Paper/Spigot servers that don't answer a ping within 3s during a
# GC pause or warmup — raise it (e.g. 5000) so they aren't flagged offline.
# connection:
#   ping-timeout-ms: 3000

# Optional premium passthrough. Missing key means false, so existing configs keep
# their current routing after an upgrade. No database migration is involved.
premium:
  bypass-auth-server: false
```

Embedded limbo uses a minimal Minecraft 1.8 (protocol 47) server codec. A private ViaVersion runtime
translates every newer release for which ViaVersion exposes a complete path back to 1.8. The pinned
fallback in this release supports **1.8 through 26.2**; later support follows the latest usable
ViaVersion snapshot rather than an MCProtocolLib protocol constant. ViaBackwards is intentionally
not used: it translates older clients to a newer server, the opposite of this 1.8-base topology.
MCProtocolLib remains the embedded listener/session/framing engine and hosts VeloAuth's custom
protocol-47 `PacketCodec`; ViaVersion transforms packets inside that already-created Netty channel.
Because MCProtocolLib always sees the fixed 1.8 codec, a new client release normally requires only a
new ViaVersion mapping, not an MCProtocolLib update.

In embedded mode, startup first uses the last successfully activated runtime, with the release's
checksum-pinned ViaVersion `5.11.0` as the final fallback. Only after VeloAuth reports `Ready` does a
virtual thread check the official repository (at most once per 15 minutes across restart loops). A
new snapshot is resolved to an immutable timestamped JAR, downloaded without redirects, checked
against the repository's SHA-256 sidecar, bounded by size, structurally validated, and written to a
pending manifest. It never replaces the classes serving current players. On the next full restart,
VeloAuth initializes and verifies every advertised translation path before promoting it. An
incompatible/corrupt candidate is rejected automatically and startup falls back to the previous
working runtime, then to the build-pinned runtime. A valid cache continues to start offline.
Corrupt or off-repository manifests are removed automatically, and concurrent runtime preparation
is serialized so one proxy process cannot download/publish the same artifact twice.

External mode performs no snapshot check, download, directory creation, or ViaVersion classloading.
Neither auth-server mode reads or generates a Velocity forwarding secret, and installing the
ViaVersion proxy plugin is not required. In embedded mode the proxy-owned modern-forwarding
handshake uses Velocity's configured secret without exposing it to VeloAuth. Snapshot availability
cannot precede upstream ViaVersion support; “latest” means the newest snapshot that actually
publishes and initializes a complete 1.8 translation path. ViaVersion is separately licensed under
GPL-3.0; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Protocol updates can therefore arrive without a VeloAuth release, but an incompatible future
ViaVersion API/dependency change or a Velocity/Netty transport change still requires a tested plugin
release; such a candidate is rejected rather than activated.

Maintainers can also preflight and package the current snapshot without editing `pom.xml`:

```bash
./scripts/build-latest-protocol.sh
```

The script pins the resolved timestamp, URL and hashes into
`META-INF/veloauth/embedded-runtime.properties`, runs Maven/JaCoCo/PMD/CPD and uses the resulting JAR
in a real Velocity smoke test. `--resolve-only` tests repository resolution, while `--skip-smoke`
is intended only for local diagnostics. The ordinary `mvnd clean verify` remains reproducible.

To retain an existing standalone limbo, use:

```yaml
auth-server:
  mode: external
  server-name: limbo
  timeout-seconds: 300
```

Register `limbo` in `velocity.toml` and keep it out of the backend `try` list. External mode keeps
the historical routing and does not download or initialize the managed protocol runtime.

With `premium.bypass-auth-server: true`, only a connection whose final
`Player#isOnlineMode()` is true skips auth/limbo. This is an opt-in resource trade-off: bots using
valid paid accounts can reach backend resources directly. `/vauth reload` applies this core
premium routing flag immediately; an invalid reload leaves the previous valid configuration active.

#### Reload and restart behavior

`/vauth reload` parses and validates an unpublished configuration candidate first. If config
validation fails, all previously active **configuration values** remain in use. Language bundles
are reloaded as a separate step and are not part of the same transaction; they may refresh even
when config validation fails. Conversely, if config publication succeeds but language reload
fails, the command reports failure although the new hot-reloadable config values may already be
live. Removing `premium.allow-cracked-on-premium-nicks` or `premium.bypass-auth-server` from a
valid config restores the safe `false` default.

The following values are intended to apply immediately: premium core routing flags, BCrypt cost,
password length, registration IP limit, debug, report and language.
Infrastructure captured during startup — database/pool, auth-server topology (including the
embedded port and managed protocol runtime), premium-resolver
limits and sources, Floodgate integration, connection tuning, password complexity policy,
cache/session/brute-force lifetimes, audit retention and 2FA pending-store settings — requires a
full proxy restart. When in doubt, restart the proxy after
editing infrastructure settings; `/vauth reload` logs the effective boundary.

#### Diagnostic report (`/vauth report`)

`/vauth report` generates a diagnostic bundle and uploads it to [mclo.gs](https://mclo.gs) so you can share it with support. The report contains:

- **VeloAuth `config.yml`** — secrets redacted (`password`/`passwd`, webhook URLs, SSL passwords, API/access tokens, client secrets, forwarding secrets and connection-URL/query credentials → `<redacted>`)
- **`velocity.toml`** — secrets redacted (same redaction rules)
- **Recent proxy logs (opt-in)** — omitted by default because logs can contain IPs, chat and third-party secrets. With `include-logs: true`, the tail of `logs/latest.log` is capped at 10 MiB and passed through local best-effort redaction before upload.
- **Metadata** — VeloAuth/Velocity/Java versions, online-mode, server count, database type, ping timeout and effective premium routing flags (visible); active auth-server name/mode/client compatibility, try-list and backend names (hidden, without backend addresses).

```yaml
report:
  enabled: true
  include-logs: false # privacy-safe default
```

Set `enabled: false` to disable the command entirely. Even with local redaction, treat every
generated link as public and share it only with trusted support staff.

#### Anonymous bStats metrics

VeloAuth uses bStats' proxy-wide setting and does not add a second telemetry switch to
`config.yml`. Server owners retain the standard global control in
`plugins/bStats/config.txt`; change `enabled` there and restart Velocity. A missing VeloAuth
configuration key therefore cannot accidentally override the operator's global bStats choice.

The standard bStats Velocity payload already contains aggregate player count, registered backend
count, online mode, Velocity/plugin/Java versions and coarse OS/runtime information. VeloAuth adds
these bounded custom charts:

| Chart ID | bStats type | Reported value |
|---|---|---|
| `client_versions` | Advanced Pie | Current online players grouped only by Velocity protocol version |
| `auth_server_mode` | Simple Pie | `embedded` or `external` active at startup |
| `database_backend` | Simple Pie | `H2`, `SQLITE`, `MYSQL`, `POSTGRESQL`, or `OTHER` |
| `language` | Simple Pie | One of the 17 built-in codes, otherwise the single `custom` bucket |
| `premium_routing` | Simple Pie | `disabled`, `auth-server`, or `verified-bypass` |
| `floodgate_routing` | Simple Pie | `disabled`, `auth-server`, or `verified-bypass` |
| `two_factor_support` | Simple Pie | `enabled` or `disabled` |

`client_versions` is a point-in-time distribution of players online when bStats samples the proxy;
it is not a unique-player counter or session history. VeloAuth never reads or submits player names,
UUIDs, IP addresses, virtual hosts, database names, custom language names, passwords, forwarding
secrets or webhook URLs for these charts. The custom values are public aggregate project metrics.

Code registration alone does not create the visual cards on bStats. The VeloAuth project owner must
open the plugin's bStats page, choose **Edit**, and add the seven chart IDs above with the matching
types once. bStats normally sends its first sample a few minutes after startup and then roughly
every 30 minutes; metrics initialization failures are logged and isolated from player authentication.

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

#### Message colors and HEX gradients

Player-facing messages in `plugins/veloauth/lang/messages_<lang>.properties` support legacy colors, decorations, and six-digit RGB colors. The recommended HEX form is `<#RRGGBB>`; legacy `&#RRGGBB`, `§#RRGGBB`, and `§x§R§R§G§G§B§B` forms are also accepted.

```properties
auth.header=<#FF6700>&lS<#FF7312>&le<#FF8024>&lc<#FF8C36>&lu<#FF9848>&lr<#FFA45A>&li<#FFB16C>&lt<#FFBD7E>&ly
```

Use `&l` for bold, `&o` for italic, `&n` for underline, and `&r` to reset formatting. Colors must contain exactly six hexadecimal digits: `<#FF6700>` is valid, while `<#HEX>` is not. This compact syntax is supported, but arbitrary MiniMessage tags such as `<gradient:...>` are not. Run `/vauth reload` after editing the active language file.

#### Silencing "no server available" notifications

If your setup runs DiscordSRV or another plugin that kicks players before VeloAuth's backend-wait flow finishes, you can silence the in-chat "Waiting for a server…" notifications without forking the plugin: open the language file under `plugins/veloauth/lang/messages_<lang>.properties` and set the keys to empty values:

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

Install Floodgate on the Velocity proxy and set Geyser's `auth-type` to `floodgate` as described in the [official proxy setup guide](https://geysermc.org/wiki/floodgate/setup/proxy-servers/). VeloAuth reads the effective prefix and active player registry from Floodgate's live API. `username-prefix` is retained as a fallback for startup/API-unavailable scenarios; a mismatch is logged and the live Floodgate value wins.

Bedrock handling is deliberately split into two checks:

1. During `PreLoginEvent`, a live Floodgate player (including a linked Java account) is forced into offline mode and never queried against Mojang. This prevents linked Bedrock users from accidentally entering the Java-premium handshake.
2. Auth-server bypass is granted only after Floodgate confirms the final player UUID. A Java/cracked client cannot obtain bypass merely by copying the configured prefix. This check also applies when Velocity's initial target is the auth server; a confirmed Floodgate player is sent to a reachable non-auth forced-host/`try` backend or denied fail-secure when none is available.

With `bypass-auth-server: false`, Floodgate identities are still kept out of Mojang reconciliation, but they follow the normal VeloAuth auth-server flow. With it enabled, Bedrock players go directly to the forced-host/`try` target selected by Velocity.

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

The cooldown begins only after Discord accepts the webhook. A timeout, rejected request or executor
failure leaves the alert eligible for retry; only one delivery attempt can be in flight at a time.

### Database Config

Supported: H2 (default, local), SQLite (local), MySQL and PostgreSQL. Remote databases use HikariCP;
local databases use direct JDBC. A minimal PostgreSQL configuration is:

```yaml
database:
  storage-type: POSTGRESQL
  hostname: db.example.com
  port: 5432
  database: veloauth
  user: veloauth
  password: "replace-me"
  connection-pool-size: 20
  postgresql:
    ssl-enabled: true
    ssl-mode: "require"
```

Prefer the structured fields above. If `connection-url` is used, put query parameters in
`connection-parameters`; credentials and SSL secrets are redacted from `/vauth report`. Always
back up the database before changing storage type, importing LimboAuth data or upgrading a release
that contains schema changes.

H2 and SQLite retain their historical paths under `./data` relative to the proxy working directory.
VeloAuth creates the missing parent directory on a fresh installation; it does not relocate or
rename an existing local database during an upgrade. Registration uses an insert-only database
operation, so two concurrent proxies/clients cannot replace the first account owner. Normal
authenticated account updates still use UPSERT, with duplicate-race recovery in a fresh transaction
for PostgreSQL compatibility and a bounded retry for standard transaction deadlocks/serialization
failures. Migration metadata is limited to the active catalog/schema, so unrelated tables in another
PostgreSQL schema cannot suppress an additive migration.

## Player Commands

| Command | Description | Restrictions |
|---------|-------------|--------------|
| `/register <password> <confirm>` | Create new account | Hidden only while authorization + the matching session are active. Premium nicknames are blocked in strict mode; permissive mixed mode explicitly allows first registration |
| `/login <password>` | Login to your account | Available to registered password accounts while they are on the auth server |
| `/changepassword <old> <new>` | Change your password | Must be logged in |
| `/2fa setup` | Enroll a TOTP authenticator (see [2FA.md](2FA.md)) | Must be logged in. Disabled when `two-factor.enabled: false` |
| `/2fa verify <code>` | Confirm enrollment OR pass 2FA at login | — |
| `/2fa disable <code>` | Disable 2FA on your account | Requires a valid code |
| `/2fa qr` / `/2fa status` | Explain secure re-enrollment / show 2FA status | Must be logged in. Existing secrets are never re-displayed |

## Admin Commands

| Command | Permission | Description |
|---------|------------|-------------|
| `/unregister <nickname>` | `veloauth.admin` | Remove player account (resolves conflicts) |
| `/vauth reload` | `veloauth.admin` | Reload configuration |
| `/vauth cache-reset [player]` | `veloauth.admin` | Clear authorization cache |
| `/vauth stats` | `veloauth.admin` | Show plugin statistics |
| `/vauth conflicts` | `veloauth.admin` | List nickname conflicts |
| `/vauth 2fa-remove <nickname>` | `veloauth.admin` | Recovery: wipe a player's 2FA token (see [2FA.md](2FA.md)) |
| `/vauth report` | `veloauth.admin` | Generate a diagnostic report and upload to [mclo.gs](https://mclo.gs) |

## How It Works

### Authentication Flow
1. **Player connects** to Velocity
2. **VeloAuth checks** authoritative premium state in `AUTH`, then the in-memory premium cache
3. If **not in memory**, checks the `PREMIUM_UUIDS` database cache (persistent across restarts, but never authoritative over `AUTH`)
4. If **not in DB cache**, resolves via **Mojang/Ashcon API** in parallel using virtual threads
5. Velocity completes the selected online/offline handshake; premium Java identity is trusted only when the final `Player#isOnlineMode()` is `true`
6. By default **every Java player** is sent through the auth server. A confirmed Floodgate UUID can use its separate bypass; a Mojang-verified Java player can preserve the original forced-host/`try` target only with `premium.bypass-auth-server: true`
7. Premium players on auth/limbo are transferred automatically; cracked players type **/login** or **/register**, are verified with BCrypt, and first registration ownership is committed atomically by the database
8. **VeloAuth connects** the authorized player to the preserved forced-host target or first available non-auth backend from `try`

### Premium Resolution (3 layers)
```
Connect → [In-memory cache] → [Database cache] → [Mojang/Ashcon API]
              ~0ms                ~1ms                 ~200-500ms
```
API calls run in parallel on virtual threads. Concurrent requests for the same cold nickname
share one lookup; per-IP and global admission limits prevent one source from consuming resolver
capacity for the whole proxy. Results are cached in the database and survive proxy restarts.

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

1. **Recommended — opt in per-nickname behavior:** set `premium.allow-cracked-on-premium-nicks: true` in `plugins/veloauth/config.yml`. Premium nicks with no DB record will be forced into offline mode so a cracked client can register first. Premium owners returning to a nickname that's *already registered as premium* still get the normal Mojang handshake.
2. **Disable premium detection entirely:** set `premium.check-enabled: false`. Removes nickname-theft protection for **all** nicks — every connection is forced offline.
3. **Pre-register the nickname:** have an admin (or the cracked player) register the nickname through `/register` before the premium owner tries to join. The existing nickname-conflict path then routes that nickname to offline mode automatically.

Important trade-off for options 1 and 2: once a premium nickname is registered as offline in VeloAuth, the real Mojang owner can no longer take it back automatically — they will hit the nickname-conflict flow.

**Q: A reconnect says "You are already connecting" or "You are already connected to this proxy" even though the player left.**
These messages come from different layers:

- `You are already connecting. Please wait.` is VeloAuth's concurrent `PreLogin` guard. Since 1.4, an abandoned connection releases ownership immediately; a genuinely active login attempt is still denied to prevent concurrent authentication races. The log contains `[DUPLICATE PRELOGIN]` when this guard is responsible.
- `You are already connected to this proxy!` is Velocity's duplicate-player check after login. For cracked players VeloAuth must not automatically kick the existing session merely because another client supplied the same nickname — that would let anyone disconnect an authenticated player without knowing their password. If this persists beyond a normal network timeout, inspect Velocity's connection logs for a connection that never closed cleanly.

VeloAuth 1.4+ invalidates offline authorization, session state and pending 2FA as soon as Velocity
emits the disconnect event. A cracked player therefore has to `/login` again after reconnecting;
this prevents another client on the same public IP from inheriting a previous connection's session.

**Q: The `Failed to transfer player X: TextComponentImpl{content="...", style=StyleImpl{...}}` spam in logs is gone — anything I need to do?**
No action needed. VeloAuth 1.2.0+ renders kick reasons as plain text via `KickReasonRenderer`. Log lines now read e.g. `Failed to transfer player Alice to server lobby (Status: CONNECTION_CANCELLED): You must link your Discord account to play.`

**Q: My `language: en` config still shows Polish strings in some logs.**
Fixed in 1.2.0 — all operator-facing log messages and exception strings are now English regardless of `language` setting. The `language` key only controls **player-facing** messages.

**Q: "Database not connected" right after Velocity startup.**
Fixed in 1.2.0 — health check runs once synchronously before the 30s scheduler kicks in. The `isConnected()` gate used by admin commands now reflects pool state (initialized + not shut down) rather than waiting for the first health check.

## LimboAuth Migration

VeloAuth is schema-compatible with supported LimboAuth databases and performs required additive
changes automatically:

1. Stop LimboAuth on your backend servers
2. Install VeloAuth on Velocity
3. Configure VeloAuth to use the same database as LimboAuth
4. Start Velocity and verify the migration logs before allowing players to connect

Players who previously used LimboAuth's `/premium` keep the historical `AUTH.UUID` exposed to
backend servers, while the Mojang-verified UUID is stored separately in `AUTH.PREMIUMUUID`.
`AUTH.PRESERVE_UUID` and supporting indexes are created automatically and idempotently; no manual
UUID rewrite is required. This is still a database migration: take a database and backend-player-data
backup, test on a copy, and keep the previous JAR/config available for rollback.

## Verification

Run the normal Java/H2/SQLite gates and the explicit duplication gate together with
`mvnd clean verify pmd:cpd-check`. With Docker available, run both real-driver harnesses:

```bash
./scripts/test-postgresql.sh
./scripts/test-mysql.sh
```

The PostgreSQL harness verifies case-insensitive premium nickname reconciliation, batched conflict
deletion, idempotent LimboAuth migration, insert-only registration ownership and concurrent AUTH
UPSERT. The MySQL harness verifies the same registration/UPSERT invariants on Connector/J. Both use
ephemeral containers and remove them afterwards. GitHub Actions runs the normal build and both
database gates before uploading a release artifact.

The normal suite also performs a native 1.8 login, translated status handshakes for representative
1.12.2, 1.16.5, 1.20.1 and 1.21.4 clients, and a complete MCProtocolLib 26.2 login. The real
Velocity smoke proves pinned startup, snapshot staging, activation on restart and a third restart
that rejects a tampered pending manifest while retaining client availability.

Automated tests do not prove the real Velocity protocol flow. Before production, test premium,
cracked and Floodgate clients on a staging proxy with forced hosts, `try` fallback, reconnects,
backend outages and both values of `premium.bypass-auth-server`.

## Contributing

Contributions are welcome. Read [ARCHITECTURE.md](ARCHITECTURE.md), follow the coding rules in
`.github/skills/java-coding-standards/SKILL.md`, and run all verification commands above before
opening a pull request.

Release impact and upgrade notes are maintained in [CHANGELOG.md](CHANGELOG.md).

## Support

Need help? Found a bug? Open an issue on GitHub or join our Discord server. Never attach database
passwords, forwarding secrets, webhook URLs, TOTP secrets, current TOTP codes or complete
`otpauth://` URIs. Use `/vauth report` with logs disabled unless trusted support explicitly needs
sanitized logs.

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
