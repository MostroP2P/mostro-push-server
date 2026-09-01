# Configuration

The server reads its configuration from environment variables at startup. `dotenv` is loaded from `.env` if present. There is no TOML or YAML config file path; `config.toml.example` is leftover and not currently parsed.

Copy the template and edit it:

```bash
cp .env.example .env
```

## Required

| Variable        | Description                                                                                  |
|-----------------|----------------------------------------------------------------------------------------------|
| `NOSTR_RELAYS`  | Comma-separated list of Nostr relay URLs. Used by `NostrListener` to subscribe to kinds 1059 and 14. |

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
| `UNIFIEDPUSH_ENABLED`           | `false` | Enable UnifiedPush backend. Opt-in on purpose: the dispatch path POSTs to the client-supplied device token treated as a URL, so the backend stays off unless set explicitly. |
| `FIREBASE_PROJECT_ID`           | -       | Firebase project ID, required when `FCM_ENABLED=true`                                      |
| `FIREBASE_SERVICE_ACCOUNT_JSON` | -       | The Firebase service-account JSON itself. Takes precedence over the path form; an empty value is treated as absent. |
| `FIREBASE_SERVICE_ACCOUNT_PATH` | -       | Absolute path to the Firebase service-account JSON. Used when the JSON form is unset. If neither resolves, FCM is disabled at startup with an `error` log and the server keeps running. |
| `BATCH_DELAY_MS`                | `5000`  | Reserved (declared on `PushConfig`; not currently consumed)                                |
| `COOLDOWN_MS`                   | `60000` | Reserved (declared on `PushConfig`; not currently consumed)                                |

## Token store

| Variable                  | Default | Description                                                                  |
|---------------------------|---------|------------------------------------------------------------------------------|
| `TOKEN_TTL_HOURS`         | `48`    | Tokens older than this are evicted by the cleanup task                       |
| `CLEANUP_INTERVAL_HOURS`  | `1`     | How often the cleanup task runs                                              |

## HTTP rate limiters

The `/api/notify` dual-keyed rate limiter is documented in detail in
[architecture.md](./architecture.md). Defaults are tuned for the Fly.io
single-machine deployment.

| Variable                                      | Default  | Description                                                                                          |
|-----------------------------------------------|----------|------------------------------------------------------------------------------------------------------|
| `NOTIFY_RATE_PER_PUBKEY_PER_MIN`              | `30`     | Per-`trade_pubkey` quota; burst is fixed at 10 and is NOT env-overridable                            |
| `NOTIFY_RATE_PER_IP_PER_MIN`                  | `120`    | Per-IP quota; burst is fixed at 30 and is NOT env-overridable                                        |
| `NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS`     | `60`     | How often `retain_recent` runs on each keyed limiter to bound memory                                 |
| `NOTIFY_PUBKEY_LIMITER_SOFT_CAP`              | `100000` | Soft cap on the per-pubkey limiter map size; exceeding it produces a `warn!` log line                |
| `NOTIFY_TRUST_PROXY_HEADERS`                  | `false`  | When `true`, trust `Fly-Client-IP` then rightmost `X-Forwarded-For` for the per-IP key. **Set to `true` only behind a trusted proxy** (e.g. the Fly.io edge). On a directly reachable server an attacker can rotate these headers per request and defeat the per-IP limiter. |

Setting either of `NOTIFY_RATE_PER_PUBKEY_PER_MIN` or `NOTIFY_RATE_PER_IP_PER_MIN` to `0` causes startup to fail with a chained error message; both must be greater than zero.

`/api/register` and `/api/unregister` also share a fixed per-IP limiter:
`120/min`, burst `100`. It is intentionally separate from `/api/notify` so
registration churn cannot consume the notify per-IP bucket, and notify traffic
cannot disable client re-registration.

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
FIREBASE_PROJECT_ID=mostro-mobile
FIREBASE_SERVICE_ACCOUNT_PATH=/app/secrets/firebase-service-account.json

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

## UnifiedPush endpoint policy

When UnifiedPush is enabled, the registered device token *is* the URL the
server POSTs to, which makes it a request-forgery surface reachable from the
unauthenticated `/api/register` and `/api/notify` pair. `src/push/endpoint_guard.rs`
refuses any endpoint that is not `https`, or whose host is (or resolves to) a
non-routable address: loopback, RFC1918, link-local, CGNAT, unique-local and
the rest.

There is no configuration knob to relax this. Two consequences for operators:

- **A UnifiedPush distributor on a private range is not reachable.** Front it
  with a public hostname and a TLS certificate. This is deliberate: the blast
  radius of accidentally reaching a cloud metadata service or a container-local
  admin port is far worse than that of an operator having to publish a name.
- **Local mock servers cannot be used to exercise the dispatch path**, since
  they bind to loopback.

Full detail, including the known DNS-rebinding limitation, is in
[unifiedpush.md](./unifiedpush.md#endpoint-validation).

## Generating a Firebase service account

1. [Firebase Console](https://console.firebase.google.com/) → your project → Project Settings → Service accounts.
2. Click **Generate new private key**, save the JSON file outside the repo.
3. Mount it into the runtime (Docker volume, Fly.io secret file, or a path on disk for systemd).
4. Supply it at runtime with either `FIREBASE_SERVICE_ACCOUNT_JSON` (the JSON
   itself) or `FIREBASE_SERVICE_ACCOUNT_PATH` (a path to a mounted file). It is
   deliberately not baked into the container image; see
   [deployment.md](./deployment.md#provisioning-the-firebase-service-account).

   The container runs as UID 10001, so a bind-mounted file must be readable by
   that UID on the host.

If FCM init fails (no credential configured, JSON invalid, OAuth refusal) the server logs at `error` and runs without FCM. UnifiedPush, if enabled, continues to work.
