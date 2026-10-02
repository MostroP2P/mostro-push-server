# Mostro Push Server

Privacy-preserving push notification backend for the Mostro P2P trading ecosystem. Rust + Actix-web + Tokio. The server observes the NIP-44 direct messages (`kind 14`, Mostro protocol v2) that trusted Mostro nodes publish on configured relays, looks up registered device tokens by `trade_pubkey`, and dispatches silent push notifications via Firebase Cloud Messaging (FCM) and UnifiedPush. Inspired by [MIP-05](https://github.com/MostroP2P/MIPs).

For deeper context (data flow, components, ops): [docs/architecture.md](docs/architecture.md), [docs/api.md](docs/api.md), [docs/configuration.md](docs/configuration.md).

## Tech stack

- **Language**: Rust, edition 2021. MSRV 1.75 (Docker builder pinned to 1.90).
- **Async runtime**: Tokio 1.35 (`full`).
- **HTTP**: `actix-web 4.9` (built with `default-features = false`; the `compress-brotli`/`compress-gzip`/`compress-zstd` features are deliberately off), `actix-rt 2.9`. Actix decompresses request bodies inside the JSON extractor, before `JsonConfig::limit` is consulted, into an unbounded buffer — 316 bytes of brotli decode to 382 MB — so the body caps would guard the wrong side of the decompressor. Do NOT re-enable those features; `compressed_bodies_are_refused_rather_than_decompressed` in `src/api/routes.rs` fails if you do.
- **Nostr**: `nostr-sdk 0.45` (locked at 0.45.2).
- **HTTP client**: shared `reqwest::Client` with explicit timeouts (2 s connect, 5 s total). UnifiedPush is the one exception: it builds its own via `UnifiedPushService::build_client()`, identical except that redirects and environment-configured proxies are refused. Its endpoint URL is attacker-supplied, and the SSRF guard only inspects the first hop.
- **Rate limiting**: `governor 0.6` (already approved, dual-keyed limiter).
- **Privacy hash**: `blake3` (salted truncated keyed hash for log correlators).
- **Other notable deps**: `jsonwebtoken` (FCM OAuth), `secp256k1`, `chacha20poly1305`, `hkdf`, `sha2` (gated `crypto` module reserved for future encrypted-token registration), `uuid` (UUIDv4 `x-request-id`).

## Hard constraints (must not be violated)

These are the privacy and compatibility invariants of the project. Reintroducing any of them is a regression.

1. **The Nostr listener only pushes for kind-14 events authored by a trusted Mostro node.** `subscription_filter` in `src/nostr/listener.rs` asks relays for `kind 14` with `.authors(...)` set to `config/trusted_mostro_pubkeys.json`, and `EventHandler::handle` checks the author again (a relay may ignore the filter). nostr-sdk verifies every event's id and signature before delivering it, so the author cannot be forged. Do NOT drop the author filter nor re-add `kind 1059`:
   - Without it anyone could trigger a visible push by tagging a registered (public) `trade_pubkey`, and relays stream every kind-14 DM on the network.
   - Gift Wrap (NIP-59, `kind 1059`, protocol v1) is no longer used by any Mostro node nor the mobile app; every community node advertises `protocol_version = 2`.
   - P2P and dispute chat envelopes are addressed to a conversation key, never a `trade_pubkey`, so the listener never matched them; they reach devices through `/api/notify`.
   - The listener refuses to start with an empty trusted list, and allows each `trade_pubkey` at most `PUSHES_PER_TRADE_PER_MIN` (10) pushes per minute; nodes themselves are not limited.

2. **`/api/notify` is the *only* unauthenticated entry point with a strict privacy contract**:
   - Always `202 { "accepted": true }` on parse-valid input. Registered vs unregistered pubkeys MUST be indistinguishable (status, body, headers, timing).
   - `400` only on JSON parse failure or pubkey validation failure (64 hex chars).
   - `429` body MUST be byte-identical between the per-IP middleware and the per-pubkey check inside the handler. `Retry-After` is whole seconds, `.max(1)`.
   - No `sender_pubkey`, no signature, no `Authorization` header, no `Idempotency-Key`. Anything that lets the operator correlate sender and recipient is rejected.
   - Inbound `X-Request-Id` is stripped; server generates UUIDv4 per request.
   - CORS headers (`src/api/cors.rs`) depend only on the request's `Origin`, never on the pubkey or on registration state.
   - Dispatch happens in a `tokio::spawn` task detached from the response, bounded by `Arc<Semaphore>(50)`.

3. **Backwards compatibility of the existing endpoints.** `/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister` response bodies are byte-identical to fixtures captured before v1.1. Field order on `RegisterResponse` is `success, message, platform`. The `mostro_pubkey` field added to `RegisterTokenRequest` is request-only and does not change response shapes.

   **Exception (off by default):** when `TRUSTED_WHITELIST_ENABLED=true` AND the embedded whitelist is non-empty, `/api/register` MAY return a new `403 Forbidden` with one of two distinct bodies — `{"success":false,"message":"Mostro instance pubkey required"}` (missing field) or `{"success":false,"message":"Mostro instance not trusted"}` (untrusted value). The flag defaults to `false` precisely so the byte-identical fixture set continues to hold for clients that pre-date the feature; only flip it after the mobile rollout.

   **Exception (always on):** `/api/register` and `/api/unregister` are wrapped by `register_ip_rate_limit_mw` and MAY return `429 Too Many Requests` with the shared `rate_limited_response` body — `{"success":false,"message":"rate limited"}` plus a `Retry-After` header in whole seconds, `.max(1)` — or `500 Internal Server Error` with `{"success":false,"message":"internal error"}` when the per-IP key cannot be extracted (fail-closed, same rule as `/api/notify`). `/api/register` also returns that same `429` body when the token store is full (`MAX_TOKENS`) and the `trade_pubkey` is new; refreshing an existing registration is always accepted. `/api/unregister` returns that same `500` body when the persisted row cannot be deleted: the registration is left untouched rather than acknowledged and restored on the next restart. Both bodies keep the `success, message` field order. The `200` and `400` bodies are unchanged, so the pre-1.1 fixture set still holds for every request that is not rate-limited.

   **Platform `web` (additive):** `/api/register` accepts `"platform": "web"` (FCM Web Push tokens from browsers). The invalid-platform `400` message is unchanged and still names only `android` and `ios`. `/api/status` appends `"web": n` after `ios` only while `n > 0`, so a store holding no web registrations, which is every state a pre-web server could reach, still serves the fixture body byte for byte.

   **CORS (headers only):** `/api/register`, `/api/unregister` and `/api/notify` answer preflights from origins in `CORS_ALLOWED_ORIGINS` with `204` and add `Access-Control-Allow-Origin` + `Vary: Origin` to their responses. Bodies are untouched, and requests without an allowed `Origin` are answered exactly as before. `cors_mw` is hand-rolled on `middleware::from_fn` because `actix-cors` would be a new dependency (constraint 6).

4. **Persisted registrations are minimal, encrypted and short-lived.** With `TOKEN_STORE_PATH` set, `src/store/sqlite.rs` mirrors the in-memory map to SQLite so registrations survive restarts; without it the store is in-memory only. The rules below are the privacy contract of that file:
   - Only live registrations are kept: rows expire with the TTL, are deleted on `unregister`, and are purged at startup. Deletion is real (`secure_delete = ON`, WAL truncated after each cleanup).
   - `trade_pubkey` is stored in the clear (it is public on the relays); the device token is sealed with ChaCha20-Poly1305 (`src/store/cipher.rs`) under a key derived from `TOKEN_STORE_KEY`, with a **random nonce per row** so rows of one device cannot be grouped, and `trade_pubkey` as associated data.
   - `TOKEN_STORE_KEY` never touches the disk or the logs (`config::Secret` redacts it in `Debug`). A changed key is detected through a stored fingerprint and wipes the rows instead of failing.
   - Reads (listener, `/api/notify`) are served from memory and never touch the disk.
   - The Fly volume holding the file has scheduled snapshots disabled. UnifiedPush endpoints are the other on-disk state (atomic JSON write to `data/unifiedpush_endpoints.json`).

5. **Logs never carry raw pubkeys.** Every log site that touches a `trade_pubkey` goes through `crate::utils::log_pubkey::log_pubkey(salt, pubkey)`. The salt is a 32-byte random value generated once per process and never persisted.

6. **No new dependencies without explicit approval.** Per the global CLAUDE.md. The crates already in `Cargo.toml` are approved; everything else needs to be discussed before adding.

## Concurrency invariants

- **Dispatch path is lock-free.** `PushDispatcher` (`src/push/dispatcher.rs`) owns an immutable `Arc<[Arc<dyn PushService>]>`. Do NOT add a `Mutex` around the dispatcher or its services slice.
- **`/api/notify` spawn pile is capped at 50 permits.** This is intentionally distinct from `fly.toml`'s `hard_limit = 25` (inbound TCP connections vs in-flight outbound dispatch tasks).
- **Listener dispatch is spawned, not awaited inline.** `EventHandler::handle` in `src/nostr/listener.rs` takes a permit from its own `Semaphore(50)` with `try_acquire_owned` (drops the push with a `warn!` when saturated; never `acquire().await`) and runs the push in a `tokio::spawn` task. Awaiting `dispatch` or a permit inside the notification loop would let one slow FCM/UnifiedPush call (UnifiedPush endpoints are registrant-chosen) stall events from every relay and overflow nostr-sdk's 4096-slot notification channel, which drops events without logging them.
- **Token store** uses `tokio::sync::RwLock<HashMap>`. `TokenStore::get` clones the value out and drops the read guard before returning, so callers do not hold a guard across `await`. Mutations take the separate `write_order` mutex across the in-memory change and its SQLite write, so the database sees changes in memory order while readers never wait on the disk.
- **Per-IP key fail-closed.** If `extract_client_ip` fails, the middleware returns `500`. Never share a global bucket — that defeats per-IP rate limiting.
- **`NOTIFY_TRUST_PROXY_HEADERS` defaults to `false`.** Set it to `true` only when a trusted proxy (e.g. Fly.io edge) overwrites `Fly-Client-IP` / `X-Forwarded-For`. Otherwise an attacker rotates those headers per request and bypasses the per-IP limiter.

## Conventions

- **Naming**: `snake_case` modules, functions, fields. `PascalCase` types. `SCREAMING_SNAKE_CASE` constants. Module entry points are `mod.rs`.
- **Errors**: async fallible operations return `Result<T, Box<dyn std::error::Error[+ Send + Sync]>>`. HTTP handlers return `impl Responder`. Validation at the HTTP boundary; trust internal types beyond it.
- **Logging**: `log` macros (`info!`, `warn!`, `error!`, `debug!`). `info!` for lifecycle, `warn!` for recoverable problems, `error!` for failures requiring attention. No JSON-formatted logs.
- **Style**: default `rustfmt`, default `clippy`. 4-space indent (Rust default).
- **Docs and comments**: English only. Minimal comments. Doc comments (`///`) only where intent is non-obvious.
- **Commits**: Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, etc.). English. Atomic.

## Source layout

```
src/
├── main.rs              # Boot + wiring
├── config.rs            # Config::from_env (typed env-var loader)
├── trusted_pubkeys.rs   # Compile-time whitelist (include_str! the JSON below)
├── api/
│   ├── cors.rs          # CORS middleware for /register, /unregister, /notify
│   ├── routes.rs        # /health, /info, /status, /register, /unregister + AppState
│   ├── notify.rs        # /api/notify handler + request_id_mw
│   ├── rate_limit.rs    # per-IP / per-pubkey limiter middleware (governor)
│   └── test_support.rs  # In-process test fixtures
├── nostr/listener.rs    # Kind-14 subscription from trusted Mostro nodes, per-trade push limit
├── push/
│   ├── mod.rs           # PushService trait
│   ├── dispatcher.rs    # PushDispatcher (lock-free)
│   ├── endpoint_guard.rs # SSRF guard for UnifiedPush endpoint URLs
│   ├── fcm.rs           # FCM v1, OAuth2 service-account JWT
│   └── unifiedpush.rs   # UnifiedPush backend, persistent endpoint store
├── store/
│   ├── mod.rs           # TokenStore (in-memory map, TTL cleanup, MAX_TOKENS cap)
│   ├── sqlite.rs        # Optional SQLite persistence (TOKEN_STORE_PATH)
│   └── cipher.rs        # Device-token encryption at rest (TOKEN_STORE_KEY)
├── crypto/mod.rs        # Reserved (gated #[allow(dead_code)])
└── utils/
    ├── log_pubkey.rs    # Salted BLAKE3 keyed hash
    └── batching.rs      # Reserved (unused at runtime)

config/
└── trusted_mostro_pubkeys.json  # Trusted Mostro nodes (64-hex); includes every community in mobile/lib/core/config/communities.dart
```

## Trusted Mostro nodes

`config/trusted_mostro_pubkeys.json` lists the trusted Mostro nodes, embedded
into the binary via `include_str!`. It must include every community of the
mobile app (`lib/core/config/communities.dart`) and may list other nodes the
team trusts; adding a node means editing the file and deploying. It has two
consumers:

- **The Nostr listener (always):** only kind-14 events authored by these nodes
  trigger a push (hard constraint 1). The server refuses to start with an
  empty list. Users of a node missing from the list get no trade-update
  pushes; `/api/notify` (chat) still works for them.
- **`/api/register` (only with `TRUSTED_WHITELIST_ENABLED=true`):** the mobile
  client sends the selected node in `mostro_pubkey`; missing or unknown
  values are rejected with `403 Forbidden`, malformed ones with
  `400 Bad Request`. Keep the flag off unless every user's node is listed:
  a rejected registration also loses the `/api/notify` chat pushes.
- The `/api/register` filter is honour-system only — the device
  cryptographically proves nothing about which Mostro instance it uses. It
  will be hardened in a future phase. Do NOT remove the whitelist code on the basis that it
  "isn't really enforcing anything"; it deliberately blocks well-behaved
  clients from arbitrary instances and the harder protocol depends on this
  field staying in the request shape.
- The previous `MOSTRO_PUBKEY` environment variable has been removed; it
  was only used as log context.

## Common commands

```bash
cargo run                      # dev
cargo build --release          # production binary
cargo test                     # in-process integration tests
cargo clippy
cargo fmt
./test_server.sh               # shell smoke test against a running instance
```

## Deployment

Fly.io is the reference target. Single 512 MB machine, region `gru`, `hard_limit = 25`. See [docs/deployment.md](docs/deployment.md). The repo also ships `Dockerfile` and `docker-compose.yml`.
