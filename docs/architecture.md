# Architecture Overview

A single-binary Rust service built on Tokio and Actix-web. It has two ingress paths into the push pipeline (Nostr listener and `POST /api/notify`), a single token store (in memory, optionally persisted to SQLite), and a fan-out dispatcher that routes to FCM and/or UnifiedPush.

## Module layout

```
src/
├── main.rs                 # Boot: loads config, wires services, spawns tasks, starts HTTP server
├── config.rs               # Typed env-var config (Config::from_env)
├── api/
│   ├── cors.rs             # CORS middleware for the browser-facing endpoints (CORS_ALLOWED_ORIGINS)
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
│   ├── mod.rs              # TokenStore (RwLock<HashMap>), TTL cleanup, MAX_TOKENS cap
│   ├── sqlite.rs           # Optional SQLite persistence (TOKEN_STORE_PATH)
│   └── cipher.rs           # Device-token encryption at rest (TOKEN_STORE_KEY)
├── crypto/
│   └── mod.rs              # ECDH+ChaCha20 token decryption (gated, unused at runtime)
└── utils/
    ├── log_pubkey.rs       # Salted truncated BLAKE3 keyed hash for log correlators
    └── batching.rs         # Reserved (unused at runtime)
```

## Components

### HTTP server (`actix-web`)

Five always-on endpoints (`/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister`) plus `/api/notify`. `/api/register` and `/api/unregister` share a per-IP middleware to bound token-store churn. `/api/notify` has its own middleware stack: `request_id_mw` (outermost), `cors_mw` and `per_ip_rate_limit_mw`. `cors_mw` also wraps `/api/register` and `/api/unregister`, outside their limiter, so CORS preflights from browser clients are answered without spending a rate-limit token.

### Nostr listener (`nostr-sdk`)

Connects to all configured relays, subscribes to `kind 1059` (Mostro protocol v1 Gift Wrap) and `kind 14` (Mostro protocol v2 NIP-44 direct) events with no author filter, and reconnects automatically on close (5 s) or error (10 s). For each event it extracts the `p` tag and looks up the corresponding token in the store; on hit it calls `PushDispatcher::dispatch` in a spawned task, so a slow push backend never stalls events arriving from other relays. The listener caps in-flight dispatches at 50 with its own `Semaphore`, separate from the `/api/notify` one; when all permits are taken it drops the push with a `warn!` rather than waiting, because a blocked loop would let nostr-sdk's bounded notification channel overflow and silently discard events from every relay. Relays on which the subscription fails are logged at `warn!`; if it fails on every relay, the listener reconnects, because nostr-sdk never resends a subscription that failed.

The listener uses `Client::new()` with no signer: it only subscribes and never publishes, so it holds no keys and nothing it sends identifies a user.

### Token store (`tokio::sync::RwLock<HashMap>`)

Maps `trade_pubkey -> RegisteredToken { device_token, platform, registered_at }`. A background `tokio::spawn` task runs every `CLEANUP_INTERVAL_HOURS` and evicts entries older than `TOKEN_TTL_HOURS`. New `trade_pubkey`s are refused once the map holds `MAX_TOKENS` entries; refreshing an existing one always succeeds.

Reads always come from memory. With `TOKEN_STORE_PATH` set, `store/sqlite.rs` mirrors the map to SQLite so registrations survive restarts:

- **Startup:** check the key fingerprint (wipe every row if the key changed), delete expired rows, decrypt the rest into memory, drop rows that cannot be read.
- **Register / unregister / cleanup:** the in-memory change and its SQLite write run under the `write_order` mutex, so the file sees changes in the same order as memory. A failed register or cleanup write is logged and heals on its own (the client re-registers; expired rows are purged at startup). An unregister deletes from disk first and, if that fails, changes nothing and answers `500`, since a restart would otherwise restore an acknowledged opt-out.
- **Row format:** `trade_pubkey` in the clear; the device token sealed by `store/cipher.rs` (ChaCha20-Poly1305, key derived with HKDF from `TOKEN_STORE_KEY`, random nonce per row, `trade_pubkey` as associated data).
- **Deletion:** `secure_delete` zeroes deleted rows and every cleanup truncates the WAL.

### Push dispatcher

`PushDispatcher` owns an immutable `Arc<[Arc<dyn PushService>]>` slice plus a parallel `Arc<[&'static str]>` of backend names. Dispatch iterates services, skips backends that do not support the platform, and stops on the first success. The slice is built once at startup and never mutated, so dispatch is lock-free.

Two entry points:

- `dispatch` — used by the Nostr listener path. Backends call `send_to_token`.
- `dispatch_silent` — used by `/api/notify`. Backends call `send_silent_to_token`. The trait's default delegates to `send_to_token`; FCM overrides it with a data-only payload (`apns-priority: 5`, `apns-push-type: background`).

### FCM backend (`reqwest` + `jsonwebtoken`)

Builds an RS256 JWT from the Firebase service-account JSON, exchanges it for a short-lived access token, and caches the token under an `RwLock<Option<CachedToken>>` until 60 seconds before expiry. Sends to `fcm.googleapis.com/v1/projects/{project}/messages:send`. Supports `Platform::Android`, `Platform::Ios` and `Platform::Web` (a browser's FCM Web Push token). Web tokens get a `webpush.notification.tag` of `mostro-trade` on the listener-path payload, so repeated pushes replace each other in the browser, and `renotify: true`, so each replacement alerts again: without it the browser swaps the text silently and a user who never opened the first notice misses the next one. The payload sets no `webpush.fcm_options.link`; a tap is the web client's own service worker's to handle (`notificationclick`).

The token exchange is serialised by a `Mutex` so only one refresh runs at a time; concurrent dispatches that miss the cache wait for that result instead of each calling Google. When a refresh exhausts its attempts, the failure is shared for a 10-second window, so the callers queued behind it fail with the same cause rather than each re-running the sequence against a dependency that is still down. It retries transient failures (5xx, 429, network errors, including a connection that dies while the response body is read) up to three times with exponential backoff and jitter. It fails fast on 4xx, which signal wrong credentials, clock or scope, and on a body that arrived in full but does not parse; repeating the request cannot fix either.

Both are bounded on purpose. The sequence runs while the caller holds one of the 50 `/api/notify` semaphore permits, and that handler drops the dispatch silently once the pool saturates, so an unbounded retry would convert a Google outage into a much larger loss of notifications than no retry at all. A unit test pins the worst-case budget.

### UnifiedPush backend

Treats the `device_token` as the UnifiedPush distributor endpoint URL. POSTs a small JSON payload (`{"type":"silent_wake","timestamp":<unix>}`). Endpoints are mirrored to `data/unifiedpush_endpoints.json` via temp-file + atomic rename. Supports `Platform::Android` only.

### Privacy log correlator (`utils::log_pubkey`)

A salted truncated BLAKE3 keyed hash. The salt is a 32-byte random value generated once at process start and never persisted or logged, so log lines from different runs cannot be correlated. Every place that logs a `trade_pubkey` (`api/notify.rs`, `api/routes.rs`, `store/mod.rs`, `nostr/listener.rs`) goes through this helper.

## Data flow

### Listener path (`kind 1059` / `kind 14` from a relay)

```
Sender (any Nostr client)
    │
    │  publish kind 1059 or kind 14 (p tag = trade_pubkey)
    ▼
Nostr relay
    │
    │  delivered to subscription
    ▼
NostrListener.connect_and_listen
    │
    │  extract p tag, lookup TokenStore
    │  try listener permit (50; drop if full), tokio::spawn
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
- **Token store** uses `tokio::sync::RwLock<HashMap>`. `TokenStore::get` clones the value out and drops the read guard before returning, so no guard is held across `await` in callers. Writers also take the `write_order` mutex across their SQLite write; SQLite calls run on `spawn_blocking`, and readers never wait on them.
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
