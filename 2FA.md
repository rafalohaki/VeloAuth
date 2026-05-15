# Two-Factor Authentication (2FA / TOTP)

VeloAuth ships with RFC 6238 Time-based One-Time Password (TOTP) support. This is the same
algorithm Google Authenticator, Authy, Aegis, FreeOTP and 1Password all speak — so a player can
enroll with whichever authenticator app they already use, no extra setup required.

This document is the operator + player handbook. Source code lives under
[`net/rafalohaki/veloauth/auth/totp/`](src/main/java/net/rafalohaki/veloauth/auth/totp/).

---

## TL;DR

- **Opt-in per player.** Nobody is forced into 2FA. Players who want it run `/2fa setup`.
- **Operator master switch.** `two-factor.enabled` in `config.yml`. Set to `false` to globally
  disable enrollment **and** enforcement.
- **Drop-in compatible with LimboAuth.** VeloAuth reads the same `TOTPTOKEN` column with the
  same RFC 6238 parameters. Migrated players keep their existing authenticator entries.
- **Codes rotate every 30 seconds.** The shared 160-bit secret stays in the database; the
  6-digit codes are derived from `HMAC-SHA1(secret, current_30s_window)`.

---

## How it works (the 60-second version)

TOTP is not encryption. It is a shared HMAC key plus a clock:

```
secret    = 160 random bits, stored ONCE in TOTPTOKEN (Base32-encoded, 32 chars)
window    = floor(now_seconds / 30)
code      = last 6 digits of HMAC-SHA1(secret, window)
```

The server and the player's authenticator app independently compute the same code from the same
secret and the same 30-second window. The player types it; the server checks. Done. No phone-server
network call happens during login — the only secret exchange is at enrollment time, when the
player scans the QR code or types the Base32 secret into their app.

VeloAuth accepts codes from the current window **and** the two adjacent windows (±30 s) so phones
with a slight clock drift still authenticate. Brute-force attempts go through the same per-IP +
per-username tracker as password attempts, so 5 wrong codes get the IP / username temporarily
blocked just like 5 wrong passwords.

---

## For players

### Enrolling

```
/2fa setup
```

Run this **after** logging in (the normal `/login <password>` flow). VeloAuth will print:

1. The Base32 secret (in case your app prefers manual entry).
2. The `otpauth://` URI.
3. A clickable QR link, if the operator keeps `qr-link-enabled: true`.

If `qr-link-enabled: true` (default), the chat also contains a clickable `[ Click here to
scan the QR code in your browser ]` line — clicking it opens your default browser to a
configured QR rendering service that draws a real, scannable QR image. Once you see it,
scan with your authenticator app.

If you'd rather not click the link (privacy: it sends your TOTP secret to the configured service
over TLS), paste the Base32 secret manually into your authenticator's "enter setup key"
field. Both paths produce the same result. Then confirm:

```
/2fa verify 123456
```

…using the 6-digit code your app currently shows. On success VeloAuth writes the secret to the
database and 2FA is active from your next login.

> The secret is shown in chat. After scanning, clear your chat history if you share the screen
> with anyone. **You don't need to copy the secret anywhere else** — VeloAuth stores it server-side.

### Logging in with 2FA

```
/login <password>          ← password check (same as before)
/2fa verify <6-digit code> ← second factor
```

If you skip the second step within ~5 minutes (configurable), your "pending" verification times
out and you have to `/login` again. If you mistype the code 5 times you'll get rate-limited
exactly like 5 wrong passwords would.

### Disabling 2FA

```
/2fa disable <6-digit code>
```

You must produce a valid code to disable. This prevents anyone with temporary access to your
account from quietly turning 2FA off.

### Re-scanning on a new phone

If you switch phones and **still have access to the account** (you're already logged in on
Minecraft):

```
/2fa qr
```

…re-prints the otpauth URI + QR for your existing secret. Scan with the new app, done.

If you lost the phone **and** can't log in — talk to an operator. See "Operator handbook" below.

### Status

```
/2fa status
```

Tells you whether 2FA is currently enabled on your account.

---

## For operators

### Enabling 2FA on a server

It's on by default. The relevant block in `config.yml`:

```yaml
two-factor:
  enabled: true
  issuer: "VeloAuth"
  qr-link-enabled: true
  qr-link-url-template: "https://qr.autarch.workers.dev/siemaa?data={uri}"
  pending-timeout-seconds: 300
```

- `enabled` — master switch. `false` disables `/2fa setup` **and** stops enforcing existing
  tokens at login. Wipe specific players' tokens with `/vauth 2fa-remove <nick>` if you need a
  clean state.
- `issuer` — what shows up in the player's authenticator app next to each saved code
  (typically your server name). Must not contain `:` (reserved by the otpauth URI format).
- `qr-link-enabled` — when `true` (default), `/2fa setup` and `/2fa qr` append a clickable
  `[ Click here to scan ... ]` line whose target is an external QR-rendering URL. **Privacy
  trade-off:** the `otpauth://` URI contains the player's shared TOTP secret; enabling this
  sends that secret over TLS to whatever service `qr-link-url-template` points at. Set to
  `false` to keep enrollment text-only — the player still gets the Base32 secret and the
  `otpauth://` URI and can either type the secret into their authenticator app or paste the
  URI on a phone that supports it.
- `qr-link-url-template` — the URL the clickable QR link opens. `{uri}` is replaced at runtime
  with the URL-encoded `otpauth://` URI. Default uses the VeloAuth-maintained
  `https://qr.autarch.workers.dev/siemaa?data={uri}` endpoint. Self-hosting: point this at your own QR endpoint, e.g.
  `https://qr.mydomain.tld/?data={uri}`. Validation requires `http(s)://` scheme + literal
  `{uri}` placeholder.
- `pending-timeout-seconds` — how long a post-`/login` player has to enter a TOTP code before
  the pending state expires. Range: 30–1800. Default: 300.

### Helping a locked-out player

```
/vauth 2fa-remove <nickname>
```

Admin / console-only. Wipes the TOTP token from the database. If the player is online, they get
disconnected; their next `/login` succeeds with just the password and lets them set up 2FA fresh
on the new device. Use sparingly — this is the recovery path that bypasses the second factor, so
treat it the same way you'd treat a manual password reset.

### Audit log

Every 2FA event is recorded in `VELOAUTH_AUDIT_LOG` (when `audit-log.enabled=true`). Event types:

- `TWO_FACTOR_ENABLED` — fires on a successful `/2fa setup` + verify.
- `TWO_FACTOR_DISABLED` — fires on a successful `/2fa disable` (player) or
  `/vauth 2fa-remove` (admin; the `details` column holds `admin=<name> uuid=<dbUuid>`).
- `TWO_FACTOR_VERIFY_OK` — fires on a successful login-time code verification.
- `TWO_FACTOR_VERIFY_FAIL` — fires on each wrong code submitted during login verification.
- `TWO_FACTOR_PENDING_EXPIRED` — fires when a `pending-timeout-seconds` window elapses without
  the player completing verification.

Use these to spot stuck flows or suspicious activity. Brute-force events also fire the regular
`LOGIN_FAIL` (with `details=brute-force-blocked`) because 2FA misses go through the same
brute-force tracker as password misses.

### Migrating from LimboAuth

If you're switching from LimboAuth and players already have 2FA enabled there, you do nothing.
VeloAuth uses the same `TOTPTOKEN` column with the same algorithm parameters (SHA-1, 30 s, 6
digits). Existing tokens validate against existing authenticator app entries on first login.

### Disabling 2FA globally

```yaml
two-factor:
  enabled: false
```

This is the kill switch. New setups are rejected; existing tokens stop being enforced. The
column stays in the database — flipping `enabled` back to `true` restores enforcement for every
player who has a saved token. To permanently wipe tokens, run `/vauth 2fa-remove <nick>` for each
affected player, or issue a one-off SQL `UPDATE AUTH SET TOTPTOKEN = NULL`.

---

## Threat model

What 2FA protects:

- **Password leaks.** A leaked password alone is no longer sufficient. Attacker needs the 30 s
  rolling code too.
- **Brute-force password guessing.** The post-BCrypt 2FA step is itself rate-limited via the
  existing brute-force tracker; an attacker who somehow got past 5 password attempts still has
  to pass 5 code attempts.

What 2FA does **not** protect:

- **A compromised authenticator app.** If the attacker has the player's phone unlocked, they
  get codes too. The same caveat applies to every TOTP implementation everywhere.
- **An operator with database access.** `TOTPTOKEN` is stored in plaintext (Base32-encoded
  shared secret, as required by RFC 6238 — the server must HMAC against it, so it can't be a
  one-way hash). Encrypt your database backups.
- **Replay within the 90 s tolerance window.** A code is valid for ±30 s around its generation.
  We do not store "this code was already used" — if you need that level of paranoia, point a PR
  at `TotpService.verify`. Practically irrelevant for any real-world attacker because the
  rate-limiter blocks them after 5 attempts.

---

## Operational notes

- `TOTPTOKEN` column is `VARCHAR(32)`. A 160-bit RFC 6238 secret encodes to exactly 32 Base32
  characters (no padding). Don't change the column width.
- The Base32 alphabet is uppercase + `2-7`. VeloAuth's decoder accepts lowercase and tolerates
  whitespace + `=` padding, so a copy-paste from an authenticator app's "manual entry" screen
  works regardless of how the app formats the secret.
- Pending 2FA state lives in memory (Caffeine cache, bounded to 10 000 concurrent entries,
  TTL = `pending-timeout-seconds`). A plugin reload or proxy restart wipes pending states; the
  affected players just `/login` again.
- QR rendering is **not** done in-chat. Earlier versions tried to render an ASCII QR using
  Unicode block characters but Minecraft's chat font is taller-than-wide and varies across
  resource packs / client mods — the result was unscannable on most setups. The clickable
  link approach (delegated to a browser-rendered QR) is the practical replacement; set
  `qr-link-enabled: false` to keep enrollment fully on-server.

---

## Spec compliance

VeloAuth's TOTP implementation conforms to:

- [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) — TOTP algorithm.
- [RFC 4226](https://www.rfc-editor.org/rfc/rfc4226) — HOTP (the HMAC-truncation routine TOTP
  builds on).
- [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) §6 — Base32 alphabet for secret encoding.
- [Google Authenticator key-uri-format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
  — the `otpauth://` URI grammar consumed by every modern authenticator app.

If a code generated by an external compliant authenticator app fails to verify, that's a bug —
please file an issue with the secret, the timestamp the code was generated, and the code itself.
