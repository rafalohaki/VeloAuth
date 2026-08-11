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
- 🧩 **Optional Self-Contained Limbo** - Explicitly enabled installations can use the built-in 1.8-base limbo with a reviewed, checksum-pinned ViaVersion runtime; external limbo remains the default
- 🗺️ **Forced Hosts Support** - Players connect via custom domains (e.g., `pvp.server.com`) and are properly routed to their intended server *after* authentication
- 🚫 **Smart Command Hiding** - Authentication commands (`/login`, `/register`) are hidden while authorization and the matching login session are active; expired sessions expose the recovery commands again
- 🚀 **High Performance** - Bounded three-layer premium cache, non-blocking ordered backend selection and ownership-safe per-player tasks keep proxy event loops free
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

The VeloAuth 1.5 candidate has one identity across every publication surface: Maven version
`1.5.0`, immutable tag `v1.5.0`, and unchanged artifact name `veloauth-1.5.0.jar`. Before release,
`scripts/verify-release-identity.sh v1.5.0` verifies the POM, generated plugin metadata,
`BuildConstants.VERSION`, packaged Maven metadata and the adjacent SHA-256. Once the release-manifest
producer is present, the same command also requires and validates the adjacent manifest. Whether an
operator privately distributed an earlier 1.5.0 build cannot be inferred from Git history; that is
an external release gate. If confirmed, bump the candidate to 1.5.1 everywhere before tagging.

Version tags are the only publication trigger; pushes to `main` or pull requests verify but never
release. A tag job builds one candidate with the checked-in Maven 3.9.16 wrapper and exact Temurin
21.0.12+8, carries the same absolute JAR through both real-proxy smokes, then publishes a workflow
artifact containing exactly the JAR, its SHA-256 sidecar and its canonical manifest. Maven/JVM
override variables are rejected; user/system Maven RC files are disabled, and the canonical build
uses a task-owned settings file, Maven user home and local repository. The manifest's stable
`buildCommand` records the public build contract; those controlled environment files are the
hermetic execution context for that command. Velocity-CTD build 355 itself uses Java 25 bytecode,
so only that proxy process runs on exact Temurin 25.0.4+7 during its smoke; the plugin build,
Maven integration client, ordinary Velocity smoke and manifest identity remain on exact Temurin
21.0.12+8.

The GitHub `production-release` environment is a mandatory protected environment with manual
maintainer approval. Before anyone creates a version tag, GitHub's immutable-releases repository
setting, a protected tag ruleset that blocks update/deletion of `v*` tags, and that environment
protection must already be enabled. Store `RELEASE_POLICY_TOKEN` as an environment secret backed by
a fine-grained token with repository `Administration (read)` permission; the job uses it only to
fail closed on the immutable-releases policy before and after publication. The release job can be
approved only after the exact workflow candidate passes the external-limbo canary; protected
environment variables must set `EXTERNAL_CANARY_GREEN=true` and
`OPERATOR_RELEASE_SIGNOFF=v1.5.0:<40-character-source-commit>`. The job downloads the same workflow
artifact, verifies its provenance, and refuses to create or modify an already existing release. It
remotely peels either a lightweight or annotated version tag to the workflow commit immediately
before publication and checks it again afterward. It never moves a `latest` tag, renames the JAR,
rebuilds the candidate, or replaces release assets.

## Requirements

- **Java 21 or newer**
- **Velocity proxy** (3.5.x; VeloAuth currently targets the 3.5 API line)
- **Database**: MySQL, PostgreSQL, H2, or SQLite
- **Default external mode:** NanoLimbo, LOOHP/Limbo, LimboService, PicoLimbo, hpfxd/Limbo, or
  another Velocity-compatible auth server registered in `velocity.toml`
- **Optional embedded mode:** outbound HTTPS access to `repo.viaversion.com` for the first verified,
  release-pinned runtime. Cached startup remains independent of repository availability. Reviewed
  runtime staging is a separate restart-only opt-in and never follows mutable `latest` metadata.

## Quick Setup

### Installation

1. Prepare a Velocity-compatible external limbo and register it as `limbo` in `velocity.toml`.
2. Download VeloAuth from Modrinth and place the file in your Velocity `plugins/` folder.
3. Start Velocity. A new installation creates `config.yml` with `auth-server.mode: external` and
   uses the registered `limbo` server. Embedded mode remains an explicit staging/canary opt-in.
4. Stop Velocity and configure the database in `plugins/veloauth/config.yml`.
5. Restart Velocity. Plugin upgrades and auth-topology changes always require a full proxy restart.

**Note:** Floodgate support is disabled by default. Enable it only if you actually use Geyser/Floodgate.

### Upgrading from 1.4 or a LimboAuth lineage

1. Stop the proxy and take restorable backups of the authentication database, backend player data,
   `config.yml`, `lang/`, and `velocity.toml`. Keep the previous 1.4 JAR and external-limbo profile.
2. Test a copy first. Inventory passwordless legacy rows and distinguish the lineage-safe eligible
   shape: `HASH` is null/blank and `PREMIUMUUID` is null or equal to `AUTH.UUID`. A passwordless row
   with a different premium UUID is deliberately ineligible; hashed offline accounts are controls.
3. Start 1.5 against the copy and review the `VA-1501 legacy UUID preservation candidates=...,
   marked=...` log. Those per-run counts include only eligible rows whose `PRESERVE_UUID` is null or
   false; an already-true eligible row is not an outstanding candidate on a rerun. The idempotent
   backfill sets only `PRESERVE_UUID=true` and records schema provenance version 2 after success. It
   does not rewrite account UUIDs, hashes, IPs, TOTP values, registration dates or login dates.
4. Existing configurations without `auth-server.mode` and freshly generated configurations both
   use `external`; an existing explicit `embedded` selection remains embedded. Files are not
   rewritten. The absent-key automatic-transfer delay changes from the historical 300 ms to 1500 ms;
   set `connection.auto-transfer-delay-ms` explicitly only after testing the desired dwell time.
5. Existing external language values remain operator-owned, with one narrow 1.5 repair: in the 17
   built-in locale files VeloAuth replaces the exact historical stock defaults for
   `2fa.qr.warning`, `admin.report.generating` and `admin.report.warning` with their corrected 1.5
   defaults. Only one exact canonical physical line is eligible; custom, empty, reformatted or
   duplicate entries are preserved byte-for-byte. Custom-language files are never stock-migrated.
   Missing bundled keys are still appended. Back up and review the resulting `lang/` files before
   production rollout.
6. Replace the JAR and perform a full restart. Canary premium, cracked register/login/reconnect,
   2FA, optional Floodgate, forced hosts, Velocity `try` fallback and backend outage recovery with
   the exact checksummed candidate.
7. If the canary fails, restore the previous database/config copy and 1.4 JAR, select `external`
   mode, and perform another full restart. `/vauth reload` is neither an upgrade nor rollback path.

### Velocity Config

The default external mode requires the configured auth server in `velocity.toml`; keep it out of
the backend `try` list. If you explicitly opt in to embedded mode, do not add the reserved
`veloauth-embedded-limbo` name: VeloAuth registers and removes it atomically at runtime. When
Velocity or Velocity-CTD uses `player-info-forwarding-mode = "modern"`, clients on 1.13 or newer
complete the standard `velocity:player_info` login query automatically. Velocity reads
`forwarding-secret-file` and signs its response; VeloAuth never copies, logs or adds that secret to
`config.yml`. Modern forwarding itself does not support 1.8-1.12 clients, independently of the
embedded limbo's wider protocol matrix.

The embedded limbo has no player-chat surface; `/login`, `/register` and `/2fa` remain
Velocity-owned commands. Its private protocol translator marks that temporary, chat-free state as
secure so modern clients do not show the misleading "Chat messages can't be verified" toast. The
real backend still supplies its own signed-chat policy after transfer; VeloAuth does not change it.
Cracked players deliberately stay connected in this limbo, including across recurring keepalives,
until the required authentication steps succeed; only the existing post-auth flow transfers them
to a real backend.

The chunk-free holding state is presented to clients as `minecraft:the_end`, giving the temporary
authentication screen a darker backdrop without creating or saving an End world. This is not a
configuration option and affects only embedded limbo: after authentication the backend sends its
own dimension, game mode and world state normally. Embedded Join Game uses spectator mode so an
idle vanilla client remains suspended instead of producing continuous fall movement. The limbo
still has no blocks, world ticks, physics, fall damage or persisted gameplay state.

```toml
[servers]
limbo = "127.0.0.1:25566"  # Default external auth server; keep it out of try
lobby = "127.0.0.1:25565"  # Typical backend server
survival = "127.0.0.1:25567" # Another backend server

try = ["lobby", "survival"]  # Backend fallback order

[forced-hosts]
# VeloAuth fully respects Velocity's forced hosts!
# With the default premium routing, players connecting via this host visit the auth server
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
  # Fresh configs and files without this key use external. Embedded is an explicit canary opt-in.
  mode: external
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
    # This is a holding-session cap, not a promise that every host can absorb the same-size burst.
    # Through Velocity, budget roughly three socket descriptors per waiting player and stage-test
    # heap, ViaVersion path length, OS limits and event-loop latency before raising this value.
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
#   # Compatibility buffer before automatic auth/limbo -> backend transfer.
#   # 0-30000ms; default 1500ms. This is especially useful for modded clients.
#   auto-transfer-delay-ms: 1500

# Optional premium passthrough. Missing key means false, so existing configs keep
# their current routing after an upgrade. No database migration is involved.
premium:
  bypass-auth-server: false
```

Upgraded files are not rewritten to add `auto-transfer-delay-ms`; when it is absent, 1.5 still uses
the new 1500 ms default. Connection tuning is restart-scoped, so changing it requires a full proxy
restart rather than `/vauth reload`.

Embedded limbo uses a minimal Minecraft 1.8 (protocol 47) server codec. A private ViaVersion runtime
translates every newer release for which ViaVersion exposes a complete path back to 1.8. The pinned
runtime in this release supports **1.8 through 26.2**; later support requires a maintainer-reviewed
ViaVersion artifact rather than an MCProtocolLib protocol constant. ViaBackwards is intentionally
not used: it translates older clients to a newer server, the opposite of this 1.8-base topology.
MCProtocolLib remains the embedded listener/session/framing engine and hosts VeloAuth's custom
protocol-47 `PacketCodec`; ViaVersion transforms packets inside that already-created Netty channel.
Because MCProtocolLib always sees the fixed 1.8 codec, a new client release normally requires only a
new ViaVersion mapping, not an MCProtocolLib update.

In embedded mode, startup may use a previously activated reviewed runtime only when its complete
version, HTTPS URL and SHA-256 still exactly match an immutable descriptor compiled into the
installed VeloAuth release; the release's checksum-pinned ViaVersion `5.11.0` remains the final
fallback. `reviewed-runtime-updates: false` is the default and performs no remote update check. When
an operator explicitly enables that restart-only setting, VeloAuth may stage only the exact
candidate descriptor embedded by the VeloAuth maintainers in the installed release. It does not
read Maven `latest` metadata or a same-origin checksum sidecar. The artifact download has no
redirects, is time/size bounded, structurally validated and atomically published; legacy manifests
and self-asserted descriptors are rejected.

A staged candidate never replaces classes serving current players. On the next full restart,
VeloAuth initializes every advertised translation path and completes a real loopback login plus
keepalive with the bundled client (currently 26.2) before selecting it. Pending remains staged until
the actual embedded listener is published in Velocity; only then is it promoted. An incompatible,
corrupt or behaviorally broken candidate falls back to an active descriptor still approved by the
installed release and then the build-pinned runtime in the same startup. Approved cached candidates
continue to start offline. A plugin upgrade that no longer embeds an old active descriptor removes
that manifest and safely returns to the new release's build pin.
Corrupt or off-repository manifests are removed automatically, and concurrent runtime preparation
is serialized so one proxy process cannot download/publish the same artifact twice.

External mode performs no runtime check, download, directory creation, or ViaVersion classloading.
Neither auth-server mode reads or generates a Velocity forwarding secret, and installing the
ViaVersion proxy plugin is not required. In embedded mode the proxy-owned modern-forwarding
handshake uses Velocity's configured secret without exposing it to VeloAuth. Protocol support cannot
precede upstream ViaVersion support or maintainer review. ViaVersion is separately licensed under
GPL-3.0; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Maintainers can preflight a current snapshot only after obtaining and reviewing its SHA-256 through
an independent channel:

```bash
./scripts/build-latest-protocol.sh --reviewed-sha256 <64-hex-digest>
```

The manual-only script refuses network access without that digest, pins the resolved timestamp, URL
and hash into
`META-INF/veloauth/embedded-runtime.properties`, runs Maven/JaCoCo/PMD/CPD and uses the resulting JAR
in a real Velocity smoke test. CI instead runs `test-protocol-build-resolver.sh`, a local XML fixture
that downloads and executes no JAR. `--skip-smoke` is intended only for local diagnostics. An
ordinary `./mvnw clean verify` proves the test, coverage
and static-analysis gates; it does not by itself prove byte-for-byte reproducibility or publication
provenance. Those are separate release-candidate gates. The checked-in Maven Wrapper pins Maven
3.9.16 and verifies the official distribution checksum before use.

For a repeatable local direct-listener baseline, run:

```bash
./scripts/benchmark-embedded-limbo.sh
```

`VELOAUTH_BENCHMARK_CONNECTIONS` controls held connections and
`VELOAUTH_BENCHMARK_CONCURRENCY` controls the login burst. Framing uses
`VELOAUTH_BENCHMARK_FRAMES` measured operations after `VELOAUTH_BENCHMARK_WARMUP` warm-up
operations. The benchmark intentionally isolates native protocol 47 and includes test-client
overhead, so it is useful for before/after regression checks but does not certify the full Velocity
+ ViaVersion topology. Production capacity still requires a real-proxy load test with
representative protocol versions, file-descriptor monitoring, JFR, heap/RSS, GC and event-loop lag.

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

Only premium core routing flags, debug, report controls and language apply immediately. All
password and registration policy (BCrypt, length, complexity and per-IP limits) is restart-only.
Database/pool, auth-server topology (including the embedded runtime), connection tuning,
premium-resolver limits and sources, Floodgate, cache/session/brute-force policy, alerts, audit and
the complete two-factor/TOTP tree also require a full proxy restart. A successful reload preserves
those active values, validates and records the configured candidate, and reports the exact groups
waiting for restart. Invalid candidates leave both active values and pending status unchanged.

#### Diagnostic report (`/vauth report`)

`/vauth report` generates a diagnostic bundle and uploads it to [mclo.gs](https://mclo.gs) so you can share it with support. The report contains:

- **VeloAuth `config.yml`** — secrets redacted (`password`/`passwd`, webhook URLs, SSL passwords, API/access tokens, client secrets, forwarding secrets and connection-URL/query credentials → `<redacted>`)
- **`velocity.toml`** — secrets redacted (same redaction rules)
- **Active/pending settings status** — restart-only groups configured but not yet active
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

During an upgrade, existing external values remain authoritative except for three known historical
stock defaults. In the 17 built-in locales, exact unchanged values of `2fa.qr.warning`,
`admin.report.generating` and `admin.report.warning` are upgraded to the bundled 1.5 wording.
Only one exact canonical physical line is eligible; VeloAuth preserves custom, empty, reformatted
and duplicate entries byte-for-byte. Custom languages never receive this replacement. Missing
bundled keys are appended (custom languages receive English fallback keys). Publication uses a
validated sibling file and atomic replacement; a failed publication leaves the original untouched.
Back up and review `lang/` before the full restart because language-file migration is separate from
transactional config loading.

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
| `/logout` | End the current proxy connection and invalidate its authentication state | Self-service; no permission required. Reconnect is a new authentication attempt |
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

**Q: What does `/logout` do for cracked, premium and 2FA-enabled players?**
`/logout` ends the invoking player's current proxy connection; it never transfers that connection
back to auth/limbo. Disconnect cleanup invalidates that concrete connection's authorization,
session, pending 2FA challenge, auth timeout and transfer work. Cracked players must enter their
password (and TOTP when enabled) after reconnecting. Premium and Floodgate clients still perform
their normal upstream identity handshake and may be authorized automatically under the configured
bypass policy. Disconnecting discards an unfinished setup challenge but does not remove an already
stored TOTP secret or reset one-time-code replay protection. If auth/limbo is unavailable on
reconnect, normal fail-secure
routing applies; `/logout` does not keep or resurrect the old session. A delayed disconnect from a
replaced connection cannot clear the newer connection's state.

**Q: The `Failed to transfer player X: TextComponentImpl{content="...", style=StyleImpl{...}}` spam in logs is gone — anything I need to do?**
No action needed. VeloAuth 1.2.0+ renders kick reasons as plain text via `KickReasonRenderer`. Log lines now read e.g. `Failed to transfer player Alice to server lobby (Status: CONNECTION_CANCELLED): You must link your Discord account to play.`

**Q: My `language: en` config still shows Polish strings in some logs.**
Fixed in 1.2.0 — all operator-facing log messages and exception strings are now English regardless of `language` setting. The `language` key only controls **player-facing** messages.

**Q: "Database not connected" right after Velocity startup.**
Fixed in 1.2.0 — health check runs once synchronously before the 30s scheduler kicks in. The `isConnected()` gate used by admin commands now reflects pool state (initialized + not shut down) rather than waiting for the first health check.

**Q: Shutdown prints `FileNotFoundException: logs/latest.log (Permission denied)`.**
This path is Velocity's global Log4j output, not a VeloAuth log file. Stop the proxy and verify that
the same OS/container user that launches Java can traverse the proxy directory and create, append
and rename files under `logs/`. In a hosting panel, repair the owner/group through its file manager
or support tooling; do not grant world-writable permissions and do not make VeloAuth change host
filesystem ownership. The embedded smoke test checks that VeloAuth itself closes cleanly and that
this error is absent in a writable runtime directory, but it cannot repair permissions outside the
plugin data directory.

## LimboAuth Migration

VeloAuth is schema-compatible with supported LimboAuth databases and performs required additive
changes automatically. Always test the exact lineage on a database and backend-player-data copy:

1. Stop LimboAuth on your backend servers
2. Install VeloAuth on Velocity
3. Configure VeloAuth to use the same database as LimboAuth
4. Before startup, inventory passwordless rows. The lineage-safe eligible shape has `HASH` null/blank
   and `PREMIUMUUID` null or equal to `AUTH.UUID`
5. Start Velocity and verify the migration candidate/marked counts before allowing players to
   connect. Only eligible rows whose `PRESERVE_UUID` is null or false are outstanding candidates on
   that run; already-true rows are excluded on rerun

Players who previously used LimboAuth's `/premium` keep the historical `AUTH.UUID` exposed to
backend servers, while the Mojang-verified UUID is stored separately in `AUTH.PREMIUMUUID`.
`AUTH.PRESERVE_UUID` and supporting indexes are created automatically and idempotently; schema
provenance version 2 is recorded only after the required backfill succeeds. Passwordless rows with
a distinct existing premium UUID and ordinary hashed accounts are not auto-marked. No manual UUID
rewrite is required. This is still a database migration: keep the previous 1.4 JAR/config and an
external-limbo rollback profile available for a full-restart rollback.

## Verification

Run the normal Java/H2/SQLite gates and the explicit duplication gate together with
`mvnd clean verify pmd:cpd-check`. With Docker available, run both real-driver harnesses:

```bash
./scripts/test-postgresql.sh
./scripts/test-mysql.sh
```

Dependency declarations are a release gate, not documentation-only metadata. The build pins
[Maven Dependency Plugin 3.11.0](https://maven.apache.org/plugins/maven-dependency-plugin/analyze-only-mojo.html)
and runs `analyze-only` during `verify` with warnings fatal and non-compile scopes included. The
same check can be reproduced directly:

```bash
./mvnw -B test-compile dependency:analyze-only \
  -DfailOnWarning=true -DignoreNonCompile=false
```

The only unused-declaration exceptions are runtime-discovered dependencies: the four JDBC drivers
(`java.sql.Driver` SPI and trusted driver class names), Velocity-provided Gson/Netty handler types
used through embedded-runtime descriptors, and the JUnit Jupiter `TestEngine` SPI. The dependency
tree proves `netty-resolver` is already supplied by `netty-transport`; the broad `netty-codec`
aggregator is replaced by the directly used `netty-codec-base` module.

[CycloneDX Maven Plugin 2.9.3](https://github.com/CycloneDX/cyclonedx-maven-plugin/releases/tag/cyclonedx-maven-plugin-2.9.3)
generates `target/veloauth-1.5.0.cdx.json` as a CycloneDX 1.6 production SBOM during `package`.
Compile, runtime and provided dependencies are included; test-only dependencies are excluded.
After packaging, this fixture verifies the SBOM, the shaded inventory, all four original JDBC
drivers and their merged SPI descriptor, relocated private libraries, and absence of proxy-owned
SLF4J, Jakarta Inject, Adventure, Gson and Netty classes:

```bash
./scripts/test-dependency-hygiene.sh
```

CI pins [Dependency Review v5.0.0](https://github.com/actions/dependency-review-action/releases/tag/v5.0.0)
to `a1d282b36b6f3519aa1f3fc636f609c47dddb294` for pull requests and pins
[OSV-Scanner v2.5.0](https://github.com/google/osv-scanner-action/releases/tag/v2.5.0) to
`8deb546fdb875b9996d27d4950be7312dac076a1` for full `pom.xml` scans on pushes, tags and the weekly
schedule. OSV cannot resolve the immutable timestamped MCProtocolLib build by itself, so the same
workflow first resolves Maven's complete production graph into the tested CycloneDX SBOM. OSV scans
both the direct POM inventory and that same-run transitive inventory with external
re-resolution disabled; this avoids silently dropping custom-repository dependencies. A tag release
waits for the OSV job from the same workflow run, so candidate construction cannot race vulnerability
admission. There are no vulnerability allowlists. Any future vulnerability exception must include an
advisory ID, reason, owner and expiry date; an expired or incomplete exception is invalid.

After the exact candidate JAR and SHA-256 sidecar exist, verify its identity before any smoke,
attestation or upload:

```bash
./scripts/verify-release-identity.sh v1.5.0
```

The canonical tag candidate is created only by CI. A downloaded candidate directory can be checked
without rebuilding or running either smoke test:

```bash
./scripts/verify-release-candidate.sh --existing /absolute/candidate-directory v1.5.0
gh attestation verify /absolute/candidate-directory/veloauth-1.5.0.jar \
  --repo rafalohaki/VeloAuth \
  --signer-workflow rafalohaki/VeloAuth/.github/workflows/build-and-release.yml \
  --source-ref refs/tags/v1.5.0 \
  --source-digest <40-character-source-commit>
```

The verifier requires exactly three flat files, canonical JSON, a decimal workflow run ID, the POM
version/output timestamp, current source commit, fixed signer workflow and an exact checksum. In
GitHub Actions it additionally matches every available `GITHUB_*` identity field. It also runs the
read-only Task5 internal identity check for `velocity-plugin.json`, packaged `pom.properties` and
`BuildConstants.VERSION` using exact Temurin 21. The root POM version is parsed directly as XML;
the identity verifier neither invokes Maven nor reads Maven settings or repositories. `--existing`
performs zero builds and zero smoke tests; it is the offline Task8/canary handoff contract and
requires exact Temurin 21.0.12+8 to be discoverable or supplied through `VELOAUTH_JAVA21_HOME`.

Prove byte-for-byte reproducibility from a clean committed HEAD with the exact Temurin 21.0.12+8
toolchain. The verifier creates two local, no-hardlink clones, gives each build an isolated Maven
repository, builds both through the checked-in wrapper and compares their JAR bytes:

```bash
VELOAUTH_JAVA21_HOME=/path/to/temurin-21.0.12+8/Contents/Home \
  ./scripts/verify-reproducible-jar.sh
```

For a release, `verify-release-candidate.sh --build` first performs the one canonical full build,
copies that exact JAR into the candidate directory, then invokes the verifier with
`--compare-existing /absolute/candidate.jar`. Both fresh clone builds must match the canonical JAR
directly before either real-proxy smoke, manifest creation or attestation can begin; the verifier
never replaces the candidate.

On macOS the verifier also checks `java_home`, then `JAVA_HOME` and `PATH`, but accepts only that
exact Temurin build. It never installs a JDK silently. Maven and Java option environment variables
must be empty or unset, and Maven user/system RC files are disabled for the controlled builds; the
verifier fails instead of silently producing a different but internally repeatable artifact. This
identity and reproducibility evidence is necessary but not sufficient for production: provenance,
the external-limbo canary and explicit operator approval remain separate gates.

The PostgreSQL harness verifies case-insensitive premium nickname reconciliation, batched conflict
deletion, idempotent LimboAuth migration, insert-only registration ownership and concurrent AUTH
UPSERT. The MySQL harness verifies the same registration/UPSERT invariants on Connector/J. Both use
ephemeral containers and remove them afterwards. GitHub Actions runs the normal build and both
database gates before uploading a release artifact.

The normal suite also performs a native 1.8 login, bidirectional protocol-47 keepalive checks,
translated status handshakes for representative 1.12.2, 1.16.5, 1.20.1 and 1.21.4 clients, and a
complete MCProtocolLib 26.2 login held through the first keepalive. That latest-client path also
requires the translated End registry/type/world identifiers, ViaVersion's level-loading event and a
spectator spawn above the unloaded void, preventing gravity-driven idle movement and the client from
remaining on "Loading terrain". Regression tests also cover the GAME read-timeout handoff, ordered
early backend selection, per-player task ownership and shutdown-safe task publication. The real
Velocity smoke proves pinned startup with updates disabled and a second restart that rejects a
legacy origin-trusted pending manifest while retaining client availability through the same
keepalive boundary. It also submits a rejected `/login` attempt and verifies that the cracked client
remains in limbo with authentication commands still usable.

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
