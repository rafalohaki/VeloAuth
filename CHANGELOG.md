# Changelog

All notable user-visible changes to VeloAuth are documented in this file.

## [1.5.0] - 2026-08-11

### Added

- `/logout` as a terminal, self-service proxy disconnect. The owning disconnect cleanup invalidates
  authorization, session, pending 2FA, auth timeout and transfer work, and records a `LOGOUT` audit
  event without transferring the player back to auth/limbo.
- Optional `premium.bypass-auth-server` routing for Mojang-verified Java players. The default is
  `false`; cracked players and unverified premium candidates still use the auth server.
- Loopback-only embedded auth/limbo with a native Minecraft 1.8 protocol base and a private,
  checksum-verified ViaVersion runtime covering the pinned 1.8-26.2 range.
- Restart-staged ViaVersion snapshot updates. Candidates are resolved to immutable artifacts,
  verified before publication and activated only after isolated initialization on a later restart.
- Embedded runtime status, compatibility and topology details in `/vauth report` and startup logs.
- Privacy-safe bStats custom charts for online client protocol versions, auth topology, database
  family, language bucket and premium/Floodgate/2FA feature adoption.
- An opt-in embedded listener/framing benchmark with configurable held connections and login
  concurrency for repeatable before/after capacity checks.
- `connection.auto-transfer-delay-ms` (default `1500`, range `0-30000`) controls the compatibility
  buffer before automatic auth/limbo-to-backend transfers.
- Protocol-47 embedded limbo sends explicit spectator `PlayerAbilities` and `MC|Brand`
  (`VeloAuth`) packets before the initial position.

### Changed

- Fresh configurations and upgraded configurations without `auth-server.mode` both use `external`.
  Existing explicit `embedded` selections remain embedded; configuration files are not rewritten.
- Automatic auth/limbo-to-backend routing now waits `1500` ms by default instead of the historical
  `300` ms. Upgraded files are not rewritten, but the new in-memory default applies when the key is
  absent; operators can set `connection.auto-transfer-delay-ms` explicitly after canary testing.
- Auth-server identity is now owned by one restart-scoped provider so forced hosts, Velocity `try`
  fallback and backend exclusion use the same external or embedded target.
- Embedded protocol responsibilities are separated behind `ProtocolRuntime`; remote repository
  resolution and verified artifact publication have independent, testable boundaries.
- MCProtocolLib and Adventure now share Velocity's Gson runtime instead of relocating a private
  copy, preventing a shaded `NoSuchMethodError` while decoding modern play packets.
- Embedded limbo presents its chunk-free holding state as `minecraft:the_end` for a darker
  authentication backdrop. It does not create a world or change the backend dimension after
  transfer.
- Embedded limbo now uses spectator Join Game state so idle vanilla clients remain suspended in
  the void instead of continuously falling. The backend replaces that temporary game mode during
  the normal server switch.
- Ordered backend selection now completes as soon as the highest-priority reachable result is
  known and avoids pinging `try` candidates again during the immediate all-server fallback.
- The repeated diagnostic warning for switching from the Velocity `try` list to registered-server
  fallback is globally aggregated to one warning per 30 seconds; retry timing and player messages
  are unchanged.
- bStats Velocity was updated to 3.2.1, its lifecycle is closed explicitly, and fresh generated
  configs now explain telemetry privacy, global opt-out, embedded forwarding and restart semantics.
- Existing external `lang/messages_*.properties` values remain operator-owned. In the 17 built-in
  locale files, startup upgrades only the exact historical stock defaults for `2fa.qr.warning`,
  `admin.report.generating` and `admin.report.warning`, and only when the key has one exact canonical
  physical line. Custom, empty, reformatted, duplicate and all custom-language entries remain
  untouched. Missing bundled keys are still appended, and both changes are validated and atomically
  published so a failed update leaves the original file intact.

### Fixed

- Embedded limbo completes Velocity/Velocity-CTD modern forwarding automatically by sending the
  standard login query before login success. Velocity keeps exclusive ownership of the forwarding
  secret; no additional VeloAuth configuration is required.
- Embedded limbo advertises its deliberately chat-free state as secure to modern clients, avoiding
  the misleading "Chat messages can't be verified" toast during authentication. This does not
  change signed-chat policy on real backends or how Velocity handles authentication commands.
- Minecraft 1.8 keepalive challenges now use the protocol-47 VarInt wire format in both directions.
  Cracked players can remain in embedded limbo beyond the first 15-second keepalive, authenticate,
  and then follow the existing post-auth backend transfer instead of being disconnected by Velocity.
- Translated clients now spawn above the unloaded void world instead of at Y=64, preventing modern
  cracked clients from remaining on "Loading terrain" before they can use `/login` or `/register`.
  Native Minecraft 1.8 keeps its previous spawn height.
- Removing premium security opt-ins from a valid reload restores their safe `false` defaults.
- Concurrent runtime preparation in one proxy process no longer downloads or publishes the same
  artifact twice.
- Corrupt, malformed or off-repository runtime manifests are removed before the pinned/active
  fallback is selected.
- Future timestamped runtime versions with three or four numeric release components are ordered
  monotonically and unknown formats fail closed.
- A staged ViaVersion runtime now completes a bundled-client loopback login and keepalive before
  selection and is promoted only after the real embedded listener is published successfully.
  Failed preflights fall back to the previous active or build-pinned runtime in the same startup.
- Concurrent proxy shutdown can no longer resurrect a partially initialized embedded provider,
  listener or protocol classloader after it has entered the closed state.
- A stale auth/transfer retry callback can no longer remove or execute over a newer per-player task
  after rapid reconnect, rescheduling or cancellation.
- Connection and authentication task registries now close atomically with plugin shutdown, so a
  late asynchronous completion cannot publish new work after cleanup.
- GAME sessions no longer retain both MCProtocolLib's read-timeout timer and VeloAuth's keepalive
  timer; handshake/login remain timeout-protected and an unanswered keepalive still disconnects.
- Removed the duplicate premium-cache cleanup thread; `AuthCache` already maintains the same cache
  on its bounded scheduler.
- LimboAuth and early VeloAuth premium rows now receive the lineage-safe `PRESERVE_UUID` backfill
  even when older schema provenance already exists. The eligible shape is a passwordless row whose
  `PREMIUMUUID` is null or equal to `AUTH.UUID`; each run counts and marks only eligible rows whose
  `PRESERVE_UUID` is null or false, so already-true rows are not repeat candidates. Account UUIDs,
  hashes, IPs, TOTP data and timestamps are not rewritten.
- Concurrent manual login, automatic transfer and retry callbacks now share one identity-owned
  backend connection slot, preventing duplicate Velocity `connect()` attempts for one player.
- Backend results, auth fallback, timeout and wait callbacks from a replaced player connection can
  no longer cancel, message or reschedule work owned by the current connection.
- Failed embedded Velocity forwarding writes log their cause before the channel is closed.
- Expired one-time embedded redirect expectations are cleaned during normal redirect traffic,
  instead of waiting until the registry reaches capacity.

### Security

- Embedded redirects require a bounded, one-time Velocity UUID/username correlation and accept
  loopback connections only.
- Runtime metadata, checksums and JARs use bounded responses, strict origin validation, disabled XML
  external entities, SHA-256 verification and atomic publication.
- Minecraft frames, unauthenticated connections and handshake/login durations are bounded.
- Custom metrics use fixed or allow-listed aggregate categories and never read player identity,
  addresses, virtual hosts, custom operator names or secrets.

### Upgrade notes

- Requires Java 21 and a Velocity 3.5 API-compatible proxy.
- A full proxy restart is required. Do not use `/vauth reload` as a plugin-upgrade substitute.
- Back up the database, backend player data, `config.yml`, external language files and
  `velocity.toml`. Run the LimboAuth/pre-1.4 lineage preflight on a copy and review the logged
  candidate/marked counts before accepting traffic.
- Existing `config.yml` and language values remain intact. Missing built-in language keys are
  appended; review those additions and the new `1500` ms transfer default before rollout.
- Canary premium, cracked, Floodgate, 2FA, forced-host and backend-fallback journeys with the exact
  checksummed candidate. Prefer rollback to the previous 1.4 JAR in `external` mode with a full
  proxy restart if the canary fails.
- Candidate identity is `1.5.0`, immutable tag `v1.5.0`, and artifact
  `veloauth-1.5.0.jar`. Confirmation that no private 1.5.0 binary was distributed remains an
  external release gate; if one was, the candidate must become 1.5.1 before tagging.
