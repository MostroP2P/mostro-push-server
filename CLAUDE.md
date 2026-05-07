# Mostro Push Server

Privacy-preserving push notification backend for the Mostro P2P trading ecosystem. Rust + Actix-web + Tokio. The server observes Nostr Gift Wrap events (`kind 1059`) on configured relays, looks up registered device tokens by `trade_pubkey`, and dispatches silent push notifications via Firebase Cloud Messaging (FCM) and UnifiedPush. Inspired by [MIP-05](https://github.com/MostroP2P/MIPs).

For deeper context (data flow, components, ops): [docs/architecture.md](docs/architecture.md), [docs/api.md](docs/api.md), [docs/configuration.md](docs/configuration.md).

## Tech stack

- **Language**: Rust, edition 2021. MSRV 1.75 (Docker builder pinned to 1.83).
- **Async runtime**: Tokio 1.35 (`full`).
- **HTTP**: `actix-web 4.9`, `actix-rt 2.9`.
- **Nostr**: `nostr-sdk 0.27`.
- **HTTP client**: shared `reqwest::Client` with explicit timeouts (2 s connect, 5 s total).
- **Rate limiting**: `governor 0.6` (already approved, dual-keyed limiter).
- **Privacy hash**: `blake3` (salted truncated keyed hash for log correlators).
- **Other notable deps**: `jsonwebtoken` (FCM OAuth), `secp256k1`, `chacha20poly1305`, `hkdf`, `sha2` (gated `crypto` module reserved for future encrypted-token registration), `uuid` (UUIDv4 `x-request-id`).

## Hard constraints (must not be violated)

These are the privacy and compatibility invariants of the project. Reintroducing any of them is a regression.

1. **No author filter on the Nostr listener.** `src/nostr/listener.rs::Filter::new()` MUST NOT call `.authors(...)`. Gift Wrap uses an ephemeral outer key per event, and admin DMs in disputes are sent user-to-user — an author filter would silently drop those. The forbidden line is guarded by a comment block above `Filter::new()`.

2. **`/api/notify` is the *only* unauthenticated entry point with a strict privacy contract**:
   - Always `202 { "accepted": true }` on parse-valid input. Registered vs unregistered pubkeys MUST be indistinguishable (status, body, headers, timing).
   - `400` only on JSON parse failure or pubkey validation failure (64 hex chars).
   - `429` body MUST be byte-identical between the per-IP middleware and the per-pubkey check inside the handler. `Retry-After` is whole seconds, `.max(1)`.
   - No `sender_pubkey`, no signature, no `Authorization` header, no `Idempotency-Key`. Anything that lets the operator correlate sender and recipient is rejected.
   - Inbound `X-Request-Id` is stripped; server generates UUIDv4 per request.
   - Dispatch happens in a `tokio::spawn` task detached from the response, bounded by `Arc<Semaphore>(50)`.

3. **Backwards compatibility of the existing endpoints.** `/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister` response bodies are byte-identical to fixtures captured before v1.1. Field order on `RegisterResponse` is `success, message, platform`. The `mostro_pubkey` field added to `RegisterTokenRequest` is request-only and does not change response shapes.

4. **Token store is in-memory only.** No persistence to disk for `trade_pubkey -> device_token`. UnifiedPush endpoints are the only on-disk state (atomic JSON write to `data/unifiedpush_endpoints.json`).

5. **Logs never carry raw pubkeys.** Every log site that touches a `trade_pubkey` goes through `crate::utils::log_pubkey::log_pubkey(salt, pubkey)`. The salt is a 32-byte random value generated once per process and never persisted.

6. **No new dependencies without explicit approval.** Per the global CLAUDE.md. The crates already in `Cargo.toml` are approved; everything else needs to be discussed before adding.

## Concurrency invariants

- **Dispatch path is lock-free.** `PushDispatcher` (`src/push/dispatcher.rs`) owns an immutable `Arc<[Arc<dyn PushService>]>`. Do NOT add a `Mutex` around the dispatcher or its services slice.
- **`/api/notify` spawn pile is capped at 50 permits.** This is intentionally distinct from `fly.toml`'s `hard_limit = 25` (inbound TCP connections vs in-flight outbound dispatch tasks).
- **Token store** uses `tokio::sync::RwLock<HashMap>`. `TokenStore::get` clones the value out and drops the read guard before returning, so callers do not hold a guard across `await`.
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
│   ├── routes.rs        # /health, /info, /status, /register, /unregister + AppState
│   ├── notify.rs        # /api/notify handler + request_id_mw
│   ├── rate_limit.rs    # per-IP / per-pubkey limiter middleware (governor)
│   └── test_support.rs  # In-process test fixtures
├── nostr/listener.rs    # Persistent subscription, kind 1059 dispatch
├── push/
│   ├── mod.rs           # PushService trait
│   ├── dispatcher.rs    # PushDispatcher (lock-free)
│   ├── fcm.rs           # FCM v1, OAuth2 service-account JWT
│   └── unifiedpush.rs   # UnifiedPush backend, persistent endpoint store
├── store/mod.rs         # In-memory TokenStore + TTL cleanup
├── crypto/mod.rs        # Reserved (gated #[allow(dead_code)])
└── utils/
    ├── log_pubkey.rs    # Salted BLAKE3 keyed hash
    └── batching.rs      # Reserved (unused at runtime)

config/
└── trusted_mostro_pubkeys.json  # JSON array of 64-hex pubkeys; mirrors mobile/lib/core/config/communities.dart
```

## Trusted Mostro instance whitelist

`/api/register` filters registrations against a compile-time whitelist of
trusted Mostro instance pubkeys, embedded into the binary via
`include_str!("../config/trusted_mostro_pubkeys.json")`. The mobile client is
expected to send the pubkey of the selected Mostro instance in the
`mostro_pubkey` field of the registration body.

- An empty JSON array disables the whitelist (permissive mode); the field
  is then ignored.
- A non-empty array activates the filter; missing or unknown
  `mostro_pubkey` values are rejected with `403 Forbidden`. Malformed
  values (length or hex) return `400 Bad Request`.
- This filter is honour-system only — the device cryptographically proves
  nothing about which Mostro instance it actually uses. It will be hardened
  in a future phase. Do NOT remove the whitelist code on the basis that it
  "isn't really enforcing anything"; it deliberately blocks well-behaved
  clients from arbitrary instances and the harder protocol depends on this
  field staying in the request shape.
- The previous `MOSTRO_PUBKEY` environment variable has been removed; it
  was only used as log context and was never an authors filter.

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
