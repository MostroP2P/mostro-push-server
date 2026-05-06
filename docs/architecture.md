# Architecture Overview

A single-binary Rust service built on Tokio and Actix-web. It has two ingress paths into the push pipeline (Nostr listener and `POST /api/notify`), a single in-memory token store, and a fan-out dispatcher that routes to FCM and/or UnifiedPush.

## Module layout

```
src/
├── main.rs                 # Boot: loads config, wires services, spawns tasks, starts HTTP server
├── config.rs               # Typed env-var config (Config::from_env)
├── api/
│   ├── routes.rs           # /api/health|info|status|register|unregister wiring + AppState
│   ├── notify.rs           # /api/notify handler + x-request-id middleware
│   ├── rate_limit.rs       # Per-IP and per-pubkey limiter middleware (governor)
│   └── test_support.rs     # In-process test fixtures (StubPushService, app factory)
├── nostr/
│   └── listener.rs         # Persistent Nostr subscription, kind 1059 dispatch
├── push/
│   ├── mod.rs              # PushService trait + Arc<T> blanket impls
│   ├── dispatcher.rs       # PushDispatcher (lock-free Arc<[Arc<dyn PushService>]>)
│   ├── fcm.rs              # FCM v1 backend, OAuth2 service-account JWT
│   └── unifiedpush.rs      # UnifiedPush backend, persistent endpoint store
├── store/
│   └── mod.rs              # In-memory TokenStore (RwLock<HashMap>) + TTL cleanup
├── crypto/
│   └── mod.rs              # ECDH+ChaCha20 token decryption (gated, unused at runtime)
└── utils/
    ├── log_pubkey.rs       # Salted truncated BLAKE3 keyed hash for log correlators
    └── batching.rs         # Reserved (unused at runtime)
```

## Components

### HTTP server (`actix-web`)

Five always-on endpoints (`/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister`) plus the rate-limited `/api/notify` resource. The `/api/notify` resource is the only endpoint wrapped by middleware: `request_id_mw` (outermost) and `per_ip_rate_limit_mw`.

### Nostr listener (`nostr-sdk`)

Connects to all configured relays, subscribes to `kind 1059` events with no author filter, and reconnects automatically on close (5 s) or error (10 s). For each event it extracts the `p` tag and looks up the corresponding token in the store; on hit it calls `PushDispatcher::dispatch`.

The listener generates an ephemeral `Keys::generate()` for the connection itself; this key only signs subscriptions, it never identifies a user.

### Token store (`tokio::sync::RwLock<HashMap>`)

Maps `trade_pubkey -> RegisteredToken { device_token, platform, registered_at }`. In-memory only; restart clears it. A background `tokio::spawn` task runs every `CLEANUP_INTERVAL_HOURS` and evicts entries older than `TOKEN_TTL_HOURS`.

### Push dispatcher

`PushDispatcher` owns an immutable `Arc<[Arc<dyn PushService>]>` slice plus a parallel `Arc<[&'static str]>` of backend names. Dispatch iterates services, skips backends that do not support the platform, and stops on the first success. The slice is built once at startup and never mutated, so dispatch is lock-free.

Two entry points:

- `dispatch` — used by the Nostr listener path. Backends call `send_to_token`.
- `dispatch_silent` — used by `/api/notify`. Backends call `send_silent_to_token`. The trait's default delegates to `send_to_token`; FCM overrides it with a data-only payload (`apns-priority: 5`, `apns-push-type: background`).

### FCM backend (`reqwest` + `jsonwebtoken`)

Builds an RS256 JWT from the Firebase service-account JSON, exchanges it for a short-lived access token, and caches the token under an `RwLock<Option<CachedToken>>` until 60 seconds before expiry. Sends to `fcm.googleapis.com/v1/projects/{project}/messages:send`. Supports both `Platform::Android` and `Platform::Ios`.

### UnifiedPush backend

Treats the `device_token` as the UnifiedPush distributor endpoint URL. POSTs a small JSON payload (`{"type":"silent_wake","timestamp":<unix>}`). Endpoints are mirrored to `data/unifiedpush_endpoints.json` via temp-file + atomic rename. Supports `Platform::Android` only.

### Privacy log correlator (`utils::log_pubkey`)

A salted truncated BLAKE3 keyed hash. The salt is a 32-byte random value generated once at process start and never persisted or logged, so log lines from different runs cannot be correlated. Every place that logs a `trade_pubkey` (`api/notify.rs`, `api/routes.rs`, `store/mod.rs`, `nostr/listener.rs`) goes through this helper.

## Data flow

### Listener path (`kind 1059` from a relay)

```
Sender (any Nostr client)
    │
    │  publish kind 1059 (p tag = trade_pubkey)
    ▼
Nostr relay
    │
    │  delivered to subscription
    ▼
NostrListener.connect_and_listen
    │
    │  extract p tag, lookup TokenStore
    ▼
PushDispatcher.dispatch(token)
    │
    ▼
FcmPush.send_to_token  OR  UnifiedPushService.send_to_token
    │
    ▼
device wake-up
```

### Sender-triggered path (`POST /api/notify`)

```
Mobile client (sender)
    │
    │  POST /api/notify { trade_pubkey }
    ▼
request_id_mw (strip inbound X-Request-Id, generate UUIDv4)
    │
    ▼
per_ip_rate_limit_mw  ── 429 (byte-identical) ──▶ client
    │
    ▼
notify_token handler
    ├── validate pubkey (64 hex)            ── 400 ──▶ client
    ├── per-pubkey check_key                ── 429 (byte-identical) ──▶ client
    └── try_acquire_owned on Semaphore(50)
            │ ok                                    │ saturated
            ▼                                       ▼
      tokio::spawn { dispatch_silent }        warn! log (no pubkey)
            │
            ▼
      always 202 { "accepted": true } ──▶ client
```

### Token-store update (`POST /api/register` / `unregister`)

Synchronous write under `RwLock::write`, then `200`. No fan-out; the next `kind 1059` for that `trade_pubkey` will pick up the new token via the listener path.

## Concurrency model

- **Dispatch path is lock-free.** The dispatcher slice is an immutable `Arc<[Arc<dyn PushService>]>`; replacing it would require swapping out the dispatcher itself.
- **Token store** uses `tokio::sync::RwLock<HashMap>`. `TokenStore::get` clones the value out and drops the read guard before returning, so no guard is held across `await` in callers.
- **FCM access-token cache** is `Arc<RwLock<Option<CachedToken>>>`.
- **UnifiedPush endpoints** are `RwLock<HashMap<String, UnifiedPushEndpoint>>`, persisted via atomic rename on every mutation.
- **`/api/notify` spawn pool** is bounded by `Arc<Semaphore>(50)`. On saturation the handler logs (without the pubkey, to avoid an oracle) and skips the spawn; the response is still 202.
- **Rate limiters** are `governor::DefaultKeyedRateLimiter` instances — `<String>` keyed by `trade_pubkey`, `<IpAddr>` keyed by client IP. A periodic task calls `retain_recent` on each to bound memory growth, with a soft cap (default 100 000 keys) to surface unbounded growth in logs.

The 50-permit semaphore is intentionally distinct from the `fly.toml` `hard_limit = 25`. The Fly limit caps inbound TCP connections; the semaphore caps in-flight outbound dispatch tasks. They serve different purposes.

## Error handling

| Component             | Strategy                                                                                              |
|-----------------------|-------------------------------------------------------------------------------------------------------|
| Nostr connection      | Auto-reconnect: 5 s on clean close, 10 s on error; loops forever                                      |
| FCM init              | Logged warning, FCM excluded from the dispatcher slice; server keeps running                          |
| FCM send              | `error!` log with response body; dispatcher tries the next backend                                    |
| UnifiedPush load      | Logged warning, starts with empty endpoint map                                                        |
| UnifiedPush send      | `error!` log; dispatcher tries the next backend                                                       |
| `/api/register` input | `400` with `RegisterResponse { success: false, message }`                                             |
| `/api/notify` input   | `400` (malformed body or invalid pubkey)                                                              |
| Rate-limit hit        | `429` with `Retry-After` and a body byte-identical between per-IP and per-pubkey paths                |
| Per-IP key extraction | Fail-closed `500` (never share a global bucket)                                                       |
| Config error          | `expect("Failed to load configuration")` — startup aborts on misconfiguration                         |

## Privacy invariants

These are non-negotiable; reintroducing any of them is treated as a regression.

1. The Nostr listener's `Filter` MUST NOT call `.authors(...)`. Gift Wrap uses an ephemeral outer key; admin DMs in disputes are user-to-user, not Mostro-daemon-signed.
2. `/api/notify` always returns `202` on parse-valid input. It MUST NOT distinguish registered vs unregistered pubkeys in status code, body, headers, or timing.
3. `/api/notify` MUST NOT accept a `sender_pubkey`, signature, `Authorization` header, or `Idempotency-Key`. Anything that would let the operator correlate sender and recipient is out of scope.
4. Per-IP and per-pubkey 429 bodies MUST be byte-identical so a client cannot distinguish which limiter it tripped.
5. Inbound `X-Request-Id` on `/api/notify` MUST be stripped before the response header is set. The server never echoes a client-controlled correlator.
6. `trade_pubkey`s MUST NOT appear in logs in raw form. All log sites use `log_pubkey(salt, pubkey)`.
