# Changelog

All notable user-visible changes to VeloAuth are documented in this file.

## [1.5.0] - 2026-08-10

### Added

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

### Changed

- Fresh installations generate `auth-server.mode: embedded`. Existing configurations without the
  new key remain `external`, retain their historical server name and are not rewritten on load.
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
- Existing `config.yml` files remain untouched. To display custom charts, the VeloAuth bStats page
  owner must add the documented chart IDs once; server operators do not need a new config key.
- Version 1.5.0 adds no database table, column or migration and does not rewrite player UUIDs,
  password hashes, TOTP secrets, `AUTH` or `PREMIUM_UUIDS` records.
- Back up the database, `config.yml`, language files and `velocity.toml`; canary premium, cracked,
  Floodgate, 2FA, forced-host and backend-fallback journeys before production traffic.
