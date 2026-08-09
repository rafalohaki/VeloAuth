# VeloAuth {{VERSION}}

## Installation

```bash
wget https://github.com/rafalohaki/VeloAuth/releases/download/{{VERSION}}/veloauth-{{VERSION}}.jar
# Place the JAR file in your Velocity proxy plugins directory
# Restart your Velocity proxy
```

## Requirements

- Java 21+
- Velocity 3.5 API-compatible proxy
- Embedded auth/limbo (1.8 base, 1.8–26.2 pinned fallback, staged ViaVersion updates) or an external limbo registered in `velocity.toml`
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

1. Back up the VeloAuth database, `config.yml`, language files and `velocity.toml`.
2. Read the changes below and compare newly generated defaults with the existing config.
3. Run `mvnd clean verify pmd:cpd-check`,
   `./scripts/verify-embedded-dependencies.sh`, `./scripts/test-velocity-embedded.sh`,
   `./scripts/test-postgresql.sh` and `./scripts/test-mysql.sh`; retain the CI logs with the release.
4. Keep `premium.bypass-auth-server: false` unless premium direct routing has been tested on a
   staging proxy with forced hosts, the Velocity `try` order and every backend destination.
5. Replace the JAR and perform a full proxy restart. Do not use `/vauth reload` as an upgrade
   substitute.
6. Verify cracked login/register (including two simultaneous registrations of one new nickname),
   premium login, 2FA, Floodgate (if enabled), forced hosts, backend fallback and database reconnect
   behavior before production traffic.
7. In embedded mode, verify a clean first download, cached offline restart, tamper failure, Java 1.8
   and newest-supported clients, pending snapshot activation on restart, incompatible-snapshot
   fallback, automatic loopback port publication and rollback to external mode. Confirm that
   external mode performs no runtime repository traffic. No forwarding secret or separately
   installed ViaVersion plugin should be required.
8. Compare `AUTH`/`PREMIUM_UUIDS` row counts and account samples before and after staging. Confirm
   that existing UUIDs, password hashes and local H2/SQLite file paths did not change unexpectedly.
9. Prove rollback on a database/config copy with the previous JAR before enabling production
   traffic. Rollback means a full proxy restart, not a hot reload.

Database schema additions are migrated automatically at startup. The migration is intended to
preserve LimboAuth-compatible data, but it is not a replacement for a tested backup and rollback
plan.

For releases with no schema change, state that explicitly in the change notes. Registration
atomicity, routing, redaction and event-thread fixes in the current unreleased work do not add DDL
or relocate local databases.

## Recent Changes

{{CHANGELOG}}

## Support

- Issues: <https://github.com/rafalohaki/VeloAuth/issues>
- Architecture and operator behavior: `ARCHITECTURE.md` and `README.md`
- Admin command help: `/vauth help`

Redact database passwords, forwarding secrets, webhook URLs, TOTP secrets/codes and complete
`otpauth://` URIs from every support report.
