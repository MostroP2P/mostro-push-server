# Configuration

The server reads its configuration from environment variables at startup. `dotenv` is loaded from `.env` if present. There is no TOML or YAML config file path; `config.toml.example` is leftover and not currently parsed.

Copy the template and edit it:

```bash
cp .env.example .env
```

## Required

| Variable        | Description                                                                                  |
|-----------------|----------------------------------------------------------------------------------------------|
| `NOSTR_RELAYS`  | Comma-separated list of Nostr relay URLs. Used by `NostrListener` to subscribe to kind 1059. |

`NOSTR_RELAYS` is the only variable without a default; the server fails to boot if it is unset.

## Nostr listener

The listener has no instance-specific configuration. It does NOT filter
events by `authors` (privacy invariant; see [architecture.md](./architecture.md)).

## Trusted Mostro instance whitelist

The set of Mostro instance pubkeys allowed to register devices is compiled
into the binary from `config/trusted_mostro_pubkeys.json` at build time.
Activation is gated by a runtime feature flag, so the JSON can ship
populated while the filter stays inert until the mobile rollout is ready.

| Variable                     | Default | Description                                                                                                                |
|------------------------------|---------|----------------------------------------------------------------------------------------------------------------------------|
| `TRUSTED_WHITELIST_ENABLED`  | `false` | When `true`, `/api/register` rejects requests whose declared `mostro_pubkey` is missing or not on the embedded whitelist.  |

Activation rule: the filter on `/api/register` only fires when **both**
`TRUSTED_WHITELIST_ENABLED=true` **and** the embedded whitelist is
non-empty. Either side off => permissive mode and the `mostro_pubkey`
field is ignored.

About the embedded JSON:

- The file must contain a JSON array of 64-character hex pubkeys
  (lowercase preferred; `load()` canonicalizes to lowercase regardless).
- An empty array keeps the filter permissive even when the flag is on.
- The file is parsed at startup; malformed JSON or any entry that is not
  64 hex characters causes the process to panic immediately (fail-fast).
- Editing the list requires a rebuild because the JSON is embedded at
  compile time via `include_str!`. Toggling the flag does not.

When the filter rejects, the response is `403 Forbidden` with one of two
distinct bodies (see [api.md](./api.md) for the wire details):

- `{"success":false,"message":"Mostro instance pubkey required"}` when the
  field is absent — typical for an old mobile client that pre-dates the
  feature.
- `{"success":false,"message":"Mostro instance not trusted"}` when the
  field is present but its value is not on the whitelist.

To change the list, edit `config/trusted_mostro_pubkeys.json` and rebuild.
To turn the filter on/off without rebuilding, flip
`TRUSTED_WHITELIST_ENABLED`.

## HTTP server

| Variable      | Default     | Description                                  |
|---------------|-------------|----------------------------------------------|
| `SERVER_HOST` | `0.0.0.0`   | Bind address                                 |
| `SERVER_PORT` | `8080`      | Bind port                                    |

## Push backends

| Variable                        | Default | Description                                                                                |
|---------------------------------|---------|--------------------------------------------------------------------------------------------|
| `FCM_ENABLED`                   | `true`  | Enable Firebase Cloud Messaging backend                                                    |
| `UNIFIEDPUSH_ENABLED`           | `true`  | Enable UnifiedPush backend                                                                 |
| `UNIFIEDPUSH_ALLOWED_HOSTS_REGEX` | unset | Optional regex allowlist for UnifiedPush endpoint hostnames. Matched against the lowercase parsed host, not the full URL. Invalid regex fails startup. |
| `FIREBASE_PROJECT_ID`           | -       | Firebase project ID, required when `FCM_ENABLED=true`                                      |
| `FIREBASE_SERVICE_ACCOUNT_PATH` | -       | Absolute path to the Firebase service-account JSON. If missing or unreadable, FCM is disabled at startup with a warning; the server keeps running. |
| `BATCH_DELAY_MS`                | `5000`  | Reserved (declared on `PushConfig`; not currently consumed)                                |
| `COOLDOWN_MS`                   | `60000` | Reserved (declared on `PushConfig`; not currently consumed)                                |

## Token store

| Variable                  | Default | Description                                                                  |
|---------------------------|---------|------------------------------------------------------------------------------|
| `TOKEN_TTL_HOURS`         | `48`    | Tokens older than this are evicted by the cleanup task                       |
| `CLEANUP_INTERVAL_HOURS`  | `1`     | How often the cleanup task runs                                              |

## `/api/notify` rate limiter

The dual-keyed rate limiter is documented in detail in [architecture.md](./architecture.md). Defaults are tuned for the Fly.io single-machine deployment.

| Variable                                      | Default  | Description                                                                                          |
|-----------------------------------------------|----------|------------------------------------------------------------------------------------------------------|
| `NOTIFY_RATE_PER_PUBKEY_PER_MIN`              | `30`     | Per-`trade_pubkey` quota; burst is fixed at 10 and is NOT env-overridable                            |
| `NOTIFY_RATE_PER_IP_PER_MIN`                  | `120`    | Per-IP quota; burst is fixed at 30 and is NOT env-overridable                                        |
| `NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS`     | `60`     | How often `retain_recent` runs on each keyed limiter to bound memory                                 |
| `NOTIFY_PUBKEY_LIMITER_SOFT_CAP`              | `100000` | Soft cap on the per-pubkey limiter map size; exceeding it produces a `warn!` log line                |
| `NOTIFY_TRUST_PROXY_HEADERS`                  | `false`  | When `true`, trust `Fly-Client-IP` then rightmost `X-Forwarded-For` for the per-IP key. **Set to `true` only behind a trusted proxy** (e.g. the Fly.io edge). On a directly reachable server an attacker can rotate these headers per request and defeat the per-IP limiter. |

Setting either of `NOTIFY_RATE_PER_PUBKEY_PER_MIN` or `NOTIFY_RATE_PER_IP_PER_MIN` to `0` causes startup to fail with a chained error message; both must be greater than zero.

## Legacy / reserved

| Variable                | Default                                                                | Description                                                                                              |
|-------------------------|------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| `RATE_LIMIT_PER_MINUTE` | `60`                                                                   | Reserved (declared on `RateLimitConfig`; not currently consumed). Independent from `NOTIFY_RATE_*`.       |
| `SERVER_PRIVATE_KEY`    | `0x00…01`                                                              | Reserved for future encrypted-token registration. Inert in the current build because the `crypto` module is gated `#[allow(dead_code)]` and the registration handler accepts plaintext. |

## Logging

| Variable   | Default | Description                                          |
|------------|---------|------------------------------------------------------|
| `RUST_LOG` | `info`  | Standard `env_logger` filter syntax.                 |

```bash
# Standard
RUST_LOG=info

# Module-specific
RUST_LOG=mostro_push_backend=debug,actix_web=info
```

## Example `.env`

```bash
# Nostr
NOSTR_RELAYS=wss://relay.mostro.network

# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Push backends
FCM_ENABLED=true
UNIFIEDPUSH_ENABLED=false
# Optional host allowlist for UnifiedPush endpoint URLs
# UNIFIEDPUSH_ALLOWED_HOSTS_REGEX=(^|\.)example\.com$
FIREBASE_PROJECT_ID=mostro-mobile
FIREBASE_SERVICE_ACCOUNT_PATH=/secrets/mostro-mobile-firebase-adminsdk.json

# Token store
TOKEN_TTL_HOURS=48
CLEANUP_INTERVAL_HOURS=1

# /api/notify rate limiter (Fly.io defaults)
NOTIFY_RATE_PER_PUBKEY_PER_MIN=30
NOTIFY_RATE_PER_IP_PER_MIN=120
NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS=60
NOTIFY_PUBKEY_LIMITER_SOFT_CAP=100000
NOTIFY_TRUST_PROXY_HEADERS=true

# Logging
RUST_LOG=info
```

## Generating a Firebase service account

1. [Firebase Console](https://console.firebase.google.com/) → your project → Project Settings → Service accounts.
2. Click **Generate new private key**, save the JSON file outside the repo.
3. Mount it into the runtime (Docker volume, Fly.io secret file, or a path on disk for systemd).
4. Set `FIREBASE_SERVICE_ACCOUNT_PATH` to the path the binary will read at startup.

If FCM init fails (file missing, JSON invalid, OAuth refusal) the server logs a warning and runs without FCM. UnifiedPush, if enabled, continues to work.
