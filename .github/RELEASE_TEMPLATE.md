# VeloAuth {{VERSION}}

## Installation

```bash
wget https://github.com/rafalohaki/VeloAuth/releases/download/v{{VERSION}}/veloauth-{{VERSION}}.jar
# Place the JAR file in your Velocity proxy plugins directory
# Restart your Velocity proxy
```

## Requirements

- Java 21+
- Velocity 3.5 API-compatible proxy
- An external limbo registered in `velocity.toml` (default), or explicitly enabled embedded auth/limbo (1.8 base, 1.8–26.2 pinned fallback, staged ViaVersion updates)
- H2, SQLite, MySQL or PostgreSQL database

## Features

- 🔒 Fail-secure database operations
- 🛡️ Database bypass vulnerability protection
- 📊 Database health monitoring
- 🔐 BCrypt password hashing
- 🔑 RFC 6238 TOTP two-factor authentication
- ⚡ Virtual Thread support for Java 21+
- 🎯 UUID verification and session management
- 💎 Premium passwordless auto-login after Velocity online-mode verification
- 🚦 Optional premium auth-server passthrough (`premium.bypass-auth-server`, default `false`)
- 🌊 Optional Floodgate bypass
- 🧩 Loopback-only embedded limbo with staged, restart-validated ViaVersion snapshot updates and a checksum-pinned fallback
- 📝 Comprehensive logging and security events
- 🌍 17 synchronized language bundles

## Upgrade checklist

1. Confirm the release identity is Maven `{{VERSION}}`, immutable tag `v{{VERSION}}`, and unchanged
   artifact `veloauth-{{VERSION}}.jar`. Confirm separately that no private build already used this
   version; if it did, choose a new version before tagging.
2. Back up the VeloAuth database, backend player data, `config.yml`, external language files and
   `velocity.toml`; retain the previous 1.4 JAR and external-limbo profile.
3. On a database copy, inventory LimboAuth/pre-1.4 passwordless rows. The lineage-safe eligible shape
   has null/blank `HASH` and `PREMIUMUUID` null/equal to `AUTH.UUID`; rows with a distinct premium UUID
   and hashed offline accounts must not be auto-marked. Candidate/marked counts on a run further
   require `PRESERVE_UUID` null/false, so already-true eligible rows are not rerun candidates.
4. Run `mvnd clean verify pmd:cpd-check`,
   `./scripts/verify-release-identity.sh v{{VERSION}}`,
   `./scripts/verify-embedded-dependencies.sh`, `./scripts/test-velocity-embedded.sh`,
   `./scripts/test-postgresql.sh` and `./scripts/test-mysql.sh`; retain the CI logs with the release.
   The identity command must validate the adjacent checksum and release manifest.
5. Keep `premium.bypass-auth-server: false` unless premium direct routing has been tested on a
   staging proxy with forced hosts, the Velocity `try` order and every backend destination.
6. Existing configs without `auth-server.mode` and fresh configs use `external`; explicit embedded
   selections remain embedded. Existing files are not rewritten. Review the absent-key automatic
   transfer delay change from 300 ms to 1500 ms.
7. Existing external language values and intentional empty values remain unchanged; only missing
   bundled keys are appended. Review those additions before rollout.
8. Replace the JAR and perform a full proxy restart. Do not use `/vauth reload` as an upgrade
   substitute.
9. Review the schema-v2 migration candidate/marked counts, then verify cracked login/register
   (including two simultaneous registrations of one new nickname),
   premium login, 2FA, Floodgate (if enabled), forced hosts, backend fallback and database reconnect
   behavior before production traffic.
10. In embedded mode, verify a clean first download, cached offline restart, tamper failure, Java 1.8
   and newest-supported clients, pending snapshot activation on restart, incompatible-snapshot
   fallback, automatic loopback port publication and rollback to external mode. Confirm that
   external mode performs no runtime repository traffic. No forwarding secret or separately
   installed ViaVersion plugin should be required.
11. Compare `AUTH`/`PREMIUM_UUIDS` row counts and account samples before and after staging. Confirm
    that UUIDs, hashes, IPs, TOTP values, timestamps and local H2/SQLite paths did not change
    unexpectedly; only eligible `PRESERVE_UUID` flags may be added by the lineage backfill.
12. Prove rollback on a database/config copy with the previous 1.4 JAR and external mode before
    enabling production traffic. Rollback means a full proxy restart, not a hot reload.

Database schema additions are migrated automatically at startup. The migration is intended to
preserve LimboAuth-compatible data, but it is not a replacement for a tested backup and rollback
plan.

VeloAuth 1.5 records schema provenance version 2 after its idempotent lineage-safe
`PRESERVE_UUID` backfill. It does not rewrite player UUIDs, password hashes, IPs, TOTP values or
history timestamps. A green local build or identity check is not production approval: retain the
exact checksummed/manifested candidate through reproducibility, attestation and external canary
gates, then require operator sign-off.

## Recent Changes

{{CHANGELOG}}

## Support

- Issues: <https://github.com/rafalohaki/VeloAuth/issues>
- Architecture and operator behavior: `ARCHITECTURE.md` and `README.md`
- Admin command help: `/vauth help`

Redact database passwords, forwarding secrets, webhook URLs, TOTP secrets/codes and complete
`otpauth://` URIs from every support report.
