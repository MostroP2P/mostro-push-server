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
│   ├── disputes.rs         # /api/disputes/watch|unwatch handlers
│   ├── rate_limit.rs       # Per-IP and per-pubkey limiter middleware (governor)
│   └── test_support.rs     # In-process test fixtures (StubPushService, app factory)
├── nostr/
│   └── listener.rs         # Kind-14 and new-dispute (kind 38386) subscriptions from trusted Mostro nodes
├── push/
│   ├── mod.rs              # PushService trait + Arc<T> blanket impls
│   ├── dispatcher.rs       # PushDispatcher (lock-free Arc<[Arc<dyn PushService>]>)
│   ├── fcm.rs              # FCM v1 backend, OAuth2 service-account JWT
│   └── unifiedpush.rs      # UnifiedPush backend, persistent endpoint store
├── store/
│   ├── mod.rs              # TokenStore (RwLock<HashMap>), TTL cleanup, MAX_TOKENS cap
│   ├── watchers.rs         # WatcherStore: node -> devices watching its disputes
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

Connects to all configured relays, subscribes to `kind 14` (Mostro protocol v2 NIP-44 direct) events authored by the trusted Mostro nodes (`config/trusted_mostro_pubkeys.json`), and reconnects automatically on close (5 s) or error (10 s). It refuses to start with an empty trusted list. For each event it checks the author again (a relay may ignore the filter; nostr-sdk has already verified the signature), extracts the `p` tag and looks up the corresponding token in the store. A registered `trade_pubkey` may trigger at most 10 pushes per minute (`PUSHES_PER_TRADE_PER_MIN`, a keyed `governor` limiter swept by the same cleanup task as the `/api/notify` limiters); nodes are not limited as such, every trade has its own budget. On hit it calls `PushDispatcher::dispatch` in a spawned task, so a slow push backend never stalls events arriving from other relays. The listener caps in-flight dispatches at 50 with its own `Semaphore`, separate from the `/api/notify` one; when all permits are taken it drops the push with a `warn!` rather than waiting, because a blocked loop would let nostr-sdk's bounded notification channel overflow and silently discard events from every relay. Relays on which the subscription fails are logged at `warn!`; if it fails on every relay, the listener reconnects, because nostr-sdk never resends a subscription that failed.

A second subscription, on the same connection and for the same authors, asks for `kind 38386` with `s` = `initiated`: the disputes those nodes open. Its `since` reaches 10 minutes back (kind 14's reaches one), so a dispute opened during a restart or a reconnect is not missed. A dispute event names no recipient; it goes to every device watching its node:

- **Admission** (`EventHandler::admit_dispute`): the author again, the `s` tag again (a relay may ignore the filter), a `d` tag of at most 64 bytes, a `created_at` within 10 minutes of now either way (`DISPUTE_FRESHNESS`; the event's own date, not its `published_at` tag, since it is when the node signed this revision and what a relay's `since` compares), a (node, dispute id) that did not ring in the last 30 minutes (`DISPUTE_MEMORY`, in memory, 10 000 entries at most), somebody watching the node, and the node's allowance of 5 dispute pushes per minute. The memory lasts more than twice the freshness window, so no event is still fresh when its dispute is forgotten. It is asked before the allowance, so the events a relay sends again when the listener starts over spend nothing, and written only for a dispute that is about to ring: one the allowance dropped is not remembered, and one given up waiting for a permit, or whose pushes reached no device (the backend down, or the deadline cutting them all), is forgotten. The memory is shared by every node, and this way one node adds to it no more than it may ring; and a dispute nobody was told about is not marked as told. That rarely makes it ring: nostr-sdk hands each event over once per client, and a relay that reconnects is the same client, so the event does not come again then. It does when the listener starts over with a new client (the subscription failed on every relay), while the event is still fresh, or when the node signs the dispute again as `initiated`; and it then needs the node's allowance again, which is not given back for a dispute that did not ring. The allowance is also spent before the memory can turn the dispute down for being full, which takes 10 000 disputes rung in half an hour.
- **Fan-out** (`ring_watchers`): `WatcherStore::watchers_of` copies the node's live watches out of memory, and one spawned task sends `PushKind::DisputeNew` to each, 25 at a time (`FANOUT_CONCURRENCY`), within 60 seconds in all (`FANOUT_DEADLINE`). The task holds one of 10 permits (`MAX_IN_FLIGHT_FANOUTS`) of a pool separate from the trade pushes': a busy minute of trades must not drop a dispute, which is every solver of a node rather than one trader.  The loop never waits for a permit: the task is spawned either way, and with every permit taken it is the task that waits, up to two minutes (`FANOUT_MAX_WAIT`), reading the node's watchers again once it has one. Disputes that arrive together (several nodes at once, a relay sending the recent ones when the listener starts) so all ring, while the requests open to FCM stay at 250. A dispute that got no permit in that time is given up with a `warn!` and forgotten. One that waited is sent without checking that it is still `initiated`: a solver may be told of a dispute another took in those two minutes. Closing that needs the listener to follow the later revisions of each dispute, which it does not subscribe to. No push is retried. A device no backend sends the push to (it depends on its platform) counts as failed and does not stop the others. The watchers are shuffled first: the store hands them out in the order of its map, which does not change between disputes, so with a slow backend the deadline would leave the same devices unsent every time.
- **Dead tokens:** a watch whose token the backend reports as `Unregistered` is removed, after the sends and outside their deadline, since a removal writes to disk, and after the fan-out's permit was given back, so the next dispute does not wait for the removals. An `Unregistered` answer the deadline cut is never read, so that watch stays until another dispute or its expiry. `SenderMismatch`, `InvalidArgument` and every other failure remove nothing: a wrong credential or a payload built wrong would read the same for every device, and removing on it would silently empty a node's list.
- **Logs:** one line per dispute: the hashed node, the event id, and how many devices were watching, delivered, failed, removed and left unfinished, which add up to the first (removed counts a dead token whose device stopped watching by itself during the sends); and one more with the first failure, if any. No token. `FcmPush` writes its line per device at `debug!` for this push (at `info!` and `error!` for the others): a dispute goes to up to a thousand devices.

The listener uses `Client::new()` with no signer: it only subscribes and never publishes, so it holds no keys and nothing it sends identifies a user.

### Token store (`tokio::sync::RwLock<HashMap>`)

Maps `trade_pubkey -> RegisteredToken { device_token, platform, registered_at }`. A background `tokio::spawn` task runs every `CLEANUP_INTERVAL_HOURS` and evicts entries older than `TOKEN_TTL_HOURS`. New `trade_pubkey`s are refused once the map holds `MAX_TOKENS` entries; refreshing an existing one always succeeds.

Reads always come from memory. With `TOKEN_STORE_PATH` set, `store/sqlite.rs` mirrors the map to SQLite so registrations survive restarts:

- **Startup:** check the key fingerprint (wipe every row if the key changed), delete expired rows, decrypt the rest into memory, drop rows that cannot be read.
- **Register / unregister / cleanup:** the in-memory change and its SQLite write run under the `write_order` mutex, so the file sees changes in the same order as memory. A failed register or cleanup write is logged and heals on its own (the client re-registers; expired rows are purged at startup). An unregister deletes from disk first and, if that fails, changes nothing and answers `500`, since a restart would otherwise restore an acknowledged opt-out.
- **Row format:** `trade_pubkey` in the clear; the device token sealed by `store/cipher.rs` (ChaCha20-Poly1305, key derived with HKDF from `TOKEN_STORE_KEY`, random nonce per row, `trade_pubkey` as associated data).
- **Deletion:** `secure_delete` zeroes deleted rows and every cleanup truncates the WAL.

### Watcher store (`store/watchers.rs`)

Maps a node's pubkey to the devices watching its disputes: `mostro_pubkey -> device_token -> Watcher { device_token, platform, watched_at }`. `TokenStore` cannot hold this: it keeps one device per `trade_pubkey`, and a dispute is announced by the node and goes to every device watching it.

- **Lifetime:** 30 days since the day of the last watch; the same hourly task evicts older ones. Only that day is kept, in memory and on disk alike, so the two always expire the same watches.
- **Caps:** `MAX_WATCHERS_PER_NODE` and `MAX_WATCHERS`. A device already on a list is always renewed.
- **Trusted nodes only:** at startup the watches of a node that is no longer on the trusted list are dropped, from memory and from disk. The listener never rings for such a node and its watches cannot be renewed. An empty list drops nothing: it is a broken deployment, which the listener refuses to start with. A node removed by mistake does lose its watches at that deploy; its solvers watch again when their app starts.
- **Admission:** `/api/disputes/watch` stores a new token only after FCM knew it (`TokenChecker`, `messages:send` with `validate_only`). Without that anyone could fill a node's list with invented tokens. A valid token is cheap to come by, though, so new watches are also limited per IP address, or per /64 for IPv6 (`NEW_WATCHES_PER_IP_PER_HOUR`, 5), and the check is given up on after 8 seconds; the two together raise the cost of filling a list, they do not make it impossible (see the limits in #53). FCM names `message.token` when the token is the malformed part; an `INVALID_ARGUMENT` that does not is a fault of the message this server built, and is answered `503`, not `400`.
- **Persistence:** the `watchers` table of the same SQLite file (schema version 2), under the same `write_order` discipline. A watch is written to disk before memory, and one the disk refuses is answered `500`, not kept: it lasts 30 days, so a watch that a restart silently drops would leave a solver without notifications. A row keeps the node's pubkey in the clear (it is public) and the token sealed as in `tokens`, with the node's pubkey as associated data. Of when the device watched it keeps only the day: a device renewing several nodes at once would otherwise write rows that share a second, and so group themselves. The table is `WITHOUT ROWID` for the same reason: a rowid numbers rows in the order they were written. Its primary key is a BLAKE3 hash of (node, token) keyed from `TOKEN_STORE_KEY`, so the rows of one device on two nodes share nothing. A changed key wipes both tables in one transaction.

The listener reads it with `watchers_of(node)` when that node opens a dispute, and removes a watch whose token FCM no longer knows. A watch past its lifetime is not rung even before the cleanup removes it.

### Push dispatcher

`PushDispatcher` owns an immutable `Arc<[Arc<dyn PushService>]>` slice plus a parallel `Arc<[&'static str]>` of backend names. Dispatch iterates services, skips backends that do not support the kind on the platform, and stops on the first success. The slice is built once at startup and never mutated, so dispatch is lock-free.

One entry point, `dispatch(kind, token)`, which calls each backend's `send`. The `PushKind` decides the payload:

- `TradeUpdate` — the Nostr listener path: a visible notification.
- `ChatWake` — `/api/notify`: for FCM a data-only payload (`apns-priority: 5`, `apns-push-type: background`). UnifiedPush sends the same payload for both kinds.
- `DisputeNew` — a dispute opened on a watched node: a visible notification whose text is named by `title_loc_key` / `body_loc_key` and resolved on the device. FCM and Android only; no backend sends it to another platform, and UnifiedPush never sends it. Nothing dispatches it yet.

A backend says what it delivers through `supports(kind, platform)`.

### FCM backend (`reqwest` + `jsonwebtoken`)

Builds an RS256 JWT from the Firebase service-account JSON, exchanges it for a short-lived access token, and caches the token under an `RwLock<Option<CachedToken>>` until 60 seconds before expiry. Sends to `fcm.googleapis.com/v1/projects/{project}/messages:send`. Supports `Platform::Android`, `Platform::Ios` and `Platform::Web` (a browser's FCM Web Push token). Web tokens get a `webpush.notification.tag` of `mostro-trade` on the listener-path payload, so repeated pushes replace each other in the browser, and `renotify: true`, so each replacement alerts again: without it the browser swaps the text silently and a user who never opened the first notice misses the next one. It also carries `webpush.headers.Urgency: high`, matching `android.priority: high` and `apns-priority: 10`: Web Push defaults to `normal` (RFC 8030 §5.3), which a phone in Doze may defer. The data-only `chat_wake` push from `/api/notify` gets the same `Urgency: high` for web tokens, since the web client shows a notice for each one. The payload sets no `webpush.fcm_options.link`; a tap is the web client's own service worker's to handle (`notificationclick`).

The token exchange is serialised by a `Mutex` so only one refresh runs at a time; concurrent dispatches that miss the cache wait for that result instead of each calling Google. When a refresh exhausts its attempts, the failure is shared for a 10-second window, so the callers queued behind it fail with the same cause rather than each re-running the sequence against a dependency that is still down. It retries transient failures (5xx, 429, network errors, including a connection that dies while the response body is read) up to three times with exponential backoff and jitter. It fails fast on 4xx, which signal wrong credentials, clock or scope, and on a body that arrived in full but does not parse; repeating the request cannot fix either.

Both are bounded on purpose. The sequence runs while the caller holds one of the 50 `/api/notify` semaphore permits, and that handler drops the dispatch silently once the pool saturates, so an unbounded retry would convert a Google outage into a much larger loss of notifications than no retry at all. A unit test pins the worst-case budget.

### UnifiedPush backend

Treats the `device_token` as the UnifiedPush distributor endpoint URL. POSTs a small JSON payload (`{"type":"silent_wake","timestamp":<unix>}`). Endpoints are mirrored to `data/unifiedpush_endpoints.json` via temp-file + atomic rename. Supports `Platform::Android` only.

### Privacy log correlator (`utils::log_pubkey`)

A salted truncated BLAKE3 keyed hash. The salt is a 32-byte random value generated once at process start and never persisted or logged, so log lines from different runs cannot be correlated. Every place that logs a `trade_pubkey` (`api/notify.rs`, `api/routes.rs`, `store/mod.rs`, `nostr/listener.rs`) goes through this helper, and so does the node of a dispute watch (`api/disputes.rs`, `store/watchers.rs`). A watcher's token is never logged.

## Data flow

### Listener path (`kind 14` from a trusted Mostro node)

```
Trusted Mostro node
    │
    │  publish kind 14 (p tag = trade_pubkey)
    ▼
Nostr relay
    │
    │  delivered to subscription (kind 14, authors = trusted nodes)
    ▼
NostrListener.connect_and_listen
    │
    │  check author, extract p tag, lookup TokenStore
    │  per-trade limit (10/min; drop if exceeded)
    │  try listener permit (50; drop if full), tokio::spawn
    ▼
PushDispatcher.dispatch(TradeUpdate, token)
    │
    ▼
FcmPush.send  OR  UnifiedPushService.send
    │
    ▼
device wake-up
```

### Dispute path (`kind 38386` from a trusted Mostro node)

```
Trusted Mostro node
    │
    │  publish kind 38386 (d = dispute id, s = initiated)
    ▼
Nostr relay
    │
    │  delivered to subscription (kind 38386, #s = initiated, authors = trusted nodes)
    ▼
NostrListener.connect_and_listen
    │
    │  check author, s and d; created_at within 10 min
    │  first time for (node, dispute id) in 30 min
    │  per-node limit (5/min; drop if exceeded)
    │  WatcherStore.watchers_of(node)
    │  tokio::spawn; the task takes a fan-out permit (10), waiting up to 2 min
    ▼
ring_watchers: 25 at a time, 60 s in all
    │
    ▼
PushDispatcher.dispatch(DisputeNew, token)   × every watcher
    │
    ▼
FcmPush.send ── Unregistered ──▶ WatcherStore.unwatch(node, token)
    │
    ▼
visible notification on each device
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
      tokio::spawn { dispatch(ChatWake) }     warn! log (no pubkey)
            │
            ▼
      always 202 { "accepted": true } ──▶ client
```

### Token-store update (`POST /api/register` / `unregister`)

Synchronous write under `RwLock::write`, then `200`. No fan-out; the next `kind 14` for that `trade_pubkey` will pick up the new token via the listener path.

### Dispute watch (`POST /api/disputes/watch` / `unwatch`)

Validation, the trusted list, then for a device not yet on the node's list: the caps, the per-IP limit on new watches, and one `validate_only` request to FCM. Only then is the watch written, to SQLite and then to memory. A renewal skips the caps and FCM. The write, and the delete of an unwatch, run in a task of their own, and so does the FCM check: actix drops a handler whose caller hangs up, and each of them must not be cut short between its two halves.

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

1. The Nostr listener MUST only push for `kind 14` events authored by a trusted Mostro node: filtered with `.authors(...)` in the subscription and checked again per event. Otherwise anyone could trigger a visible push by tagging a registered (public) `trade_pubkey`. Chat envelopes are addressed to a conversation key and go through `/api/notify`. The one other subscription is `kind 38386` with `s` = `initiated`, under the same author rule; its push goes to the devices watching the node and names no dispute, node or party.
2. `/api/notify` always returns `202` on parse-valid input. It MUST NOT distinguish registered vs unregistered pubkeys in status code, body, headers, or timing.
3. `/api/notify` MUST NOT accept a `sender_pubkey`, signature, `Authorization` header, or `Idempotency-Key`. Anything that would let the operator correlate sender and recipient is out of scope.
4. Per-IP and per-pubkey 429 bodies MUST be byte-identical so a client cannot distinguish which limiter it tripped.
5. Inbound `X-Request-Id` on `/api/notify` MUST be stripped before the response header is set. The server never echoes a client-controlled correlator.
6. `trade_pubkey`s MUST NOT appear in logs in raw form. All log sites use `log_pubkey(salt, pubkey)`.
