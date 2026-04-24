# Architecture

**Analysis Date:** 2026-04-24

## Pattern Overview

**Overall:** Modular asynchronous service with a layered, trait-based push abstraction. The application is a single long-running Rust binary that combines an Actix-web HTTP API with a background Nostr WebSocket listener and pluggable push notification backends. State is held in-memory behind async locks; persistence is limited to UnifiedPush endpoints serialized to a JSON file.

**Key Characteristics:**
- Single-binary Tokio/Actix runtime (`#[actix_web::main]`) wiring all subsystems in `src/main.rs`.
- Trait-based polymorphism (`PushService`) for FCM and UnifiedPush backends, registered as `Vec<Box<dyn PushService>>`.
- Event-driven push delivery: Nostr `kind 1059` (Gift Wrap) events trigger lookups in the in-memory token store and dispatch to one matching backend.
- Currently in **Phase 3** (token registration without encryption); the ECDH/ChaCha20 crypto module exists in `src/crypto/mod.rs` but is gated `#[allow(dead_code)]` in `src/main.rs:14-15` for a future Phase 4.
- Configuration entirely from environment variables via `dotenv` plus a typed `Config` struct.
- Concurrency: `Arc<Mutex<Vec<Box<dyn PushService>>>>` for push services, `Arc<RwLock<...>>` for UnifiedPush endpoints and FCM token cache, `RwLock<HashMap<...>>` for the token store.

## Layers

**Entry / Wiring Layer:**
- Purpose: Boot the runtime, load config, instantiate services, spawn background tasks, start the HTTP server.
- Location: `src/main.rs`
- Contains: Tokio main, `AppState` construction, push service registration, cleanup task spawn.
- Depends on: `config`, `store`, `nostr`, `push`, `api`, `crypto` (gated).
- Used by: External (binary entry point).

**Configuration Layer:**
- Purpose: Strongly-typed configuration loaded from environment variables.
- Location: `src/config.rs`
- Contains: `Config`, `NostrConfig`, `PushConfig`, `ServerConfig`, `RateLimitConfig`, `CryptoConfig`, `StoreConfig`, plus `Config::from_env()` factory.
- Depends on: `serde`, `std::env`, `dotenv` (loaded in main).
- Used by: All other layers as a cloneable value type.

**HTTP API Layer:**
- Purpose: REST endpoints for client token registration/unregistration and server status.
- Location: `src/api/routes.rs` (re-exported via `src/api/mod.rs`).
- Contains: `AppState`, `RegisterTokenRequest`, `UnregisterTokenRequest`, `RegisterResponse`, `StatusResponse`, `configure(cfg)`, and async handlers `health_check`, `status`, `server_info`, `register_token`, `unregister_token`.
- Depends on: `actix-web`, `crate::store`.
- Used by: Mobile clients via HTTP.

**Nostr Listener Layer:**
- Purpose: Maintain a persistent subscription to Nostr relays for `kind 1059` events and trigger push delivery.
- Location: `src/nostr/listener.rs` (re-exported from `src/nostr/mod.rs`).
- Contains: `NostrListener`, `NostrListener::new`, `start` (reconnect loop), `connect_and_listen` (subscription + handler closure).
- Depends on: `nostr-sdk`, `tokio`, `crate::config`, `crate::push`, `crate::store`.
- Used by: `main.rs` (spawned as a Tokio task).

**Push Service Layer:**
- Purpose: Abstracted push notification dispatch with concrete FCM and UnifiedPush backends.
- Location: `src/push/mod.rs`, `src/push/fcm.rs`, `src/push/unifiedpush.rs`.
- Contains: `PushService` trait (`send_silent_push`, `send_to_token`, `supports_platform`), `FcmPush` and `UnifiedPushService` implementations, blanket `impl PushService for Arc<...>`.
- Depends on: `reqwest`, `jsonwebtoken` (FCM), `tokio::fs` (UnifiedPush persistence), `crate::config`, `crate::store::Platform`.
- Used by: `nostr::listener` (dispatch) and `main.rs` (registration).

**Token Store Layer:**
- Purpose: In-memory `trade_pubkey -> RegisteredToken` map with TTL cleanup and stats.
- Location: `src/store/mod.rs`.
- Contains: `Platform` enum, `RegisteredToken`, `TokenStore` (`register`, `unregister`, `get`, `cleanup_expired`, `count`, `get_stats`), `TokenStoreStats`, `start_cleanup_task` background loop.
- Depends on: `tokio::sync::RwLock`, `chrono`, `serde`.
- Used by: HTTP handlers, Nostr listener, cleanup task.

**Crypto Layer (gated, Phase 4):**
- Purpose: ECDH (secp256k1) + HKDF-SHA256 + ChaCha20-Poly1305 token decryption with platform/length framing and 220-byte padding.
- Location: `src/crypto/mod.rs` (declared `#[allow(dead_code)] mod crypto` in `src/main.rs:14-15`).
- Contains: `Platform`, `DecryptedToken`, `TokenCrypto::new`, `public_key_hex`, `decrypt_token`, `CryptoError`, plus `HKDF_SALT`, `HKDF_INFO`, `ENCRYPTED_TOKEN_SIZE` (294 bytes).
- Depends on: `secp256k1`, `chacha20poly1305`, `hkdf`, `sha2`, `hex`, `base64`.
- Used by: Currently unused at runtime; reserved for Phase 4 encrypted-token registration.

**Utilities Layer:**
- Purpose: Cross-cutting helpers.
- Location: `src/utils/mod.rs`, `src/utils/batching.rs`.
- Contains: `BatchingManager` skeleton (`new`, `should_send`) for cooldown/rate-limit batching.
- Depends on: `tokio::time::Instant`.
- Used by: Currently unused at runtime; reserved for future batching logic.

## Data Flow

**Token Registration Flow (HTTP):**

1. Mobile client POSTs to `POST /api/register` with `{ trade_pubkey, token, platform }` (`src/api/routes.rs:78-137`).
2. `register_token` validates `trade_pubkey` is 64 hex chars, token is non-empty, platform is `"android"` or `"ios"`.
3. Handler calls `AppState::token_store.register(...)` which inserts into the `RwLock<HashMap>` (`src/store/mod.rs:43-63`).
4. Handler returns `RegisterResponse { success: true, platform }` as JSON.
5. `POST /api/unregister` mirrors the flow via `TokenStore::unregister` (`src/store/mod.rs:65-83`).

**Push Notification Flow (Nostr -> Push):**

1. `NostrListener::start` runs an infinite reconnect loop calling `connect_and_listen` (`src/nostr/listener.rs:42-55`).
2. `connect_and_listen` builds an ephemeral `Keys::generate()` client, adds each relay from `config.nostr.relays`, connects, and subscribes with `Filter::new().kinds(vec![Kind::Custom(1059)]).since(now - 60s)` (`src/nostr/listener.rs:57-83`).
3. The closure passed to `client.handle_notifications` receives `RelayPoolNotification::Event` items, filters to `kind 1059`, and extracts the `p` tag value as `trade_pubkey` (`src/nostr/listener.rs:89-141`).
4. Listener calls `token_store.get(&trade_pubkey)`; on hit, it locks the push services vector and iterates calling `service.send_to_token(&device_token, &platform)` for the first service whose `supports_platform` matches, breaking on first success.
5. `FcmPush::send_to_token` (`src/push/fcm.rs:268-300`) acquires/refreshes an OAuth2 access token via JWT-bearer exchange against `https://oauth2.googleapis.com/token` and POSTs the FCM v1 payload to `https://fcm.googleapis.com/v1/projects/{project_id}/messages:send`.
6. `UnifiedPushService::send_to_token` (`src/push/unifiedpush.rs:165-193`) treats the device token as a UnifiedPush endpoint URL and POSTs the silent payload directly.

**Token Cleanup Flow (background):**

1. `start_cleanup_task` spawns a Tokio task on startup (`src/store/mod.rs:139-153`).
2. Every `cleanup_interval_hours` hours, the task calls `TokenStore::cleanup_expired`, which retains entries with `now - registered_at < ttl_hours` and logs the number removed.

**FCM Auth Token Caching:**

- `FcmPush::get_access_token` (`src/push/fcm.rs:95-158`) returns a cached token if `expires_at > now + 60`; otherwise it constructs `Claims { iss, scope, aud, iat, exp }`, signs with `RS256` from the service-account PEM, exchanges for an access token, and caches it under `RwLock<Option<CachedToken>>`.

**State Management:**

- Token map: `RwLock<HashMap<String, RegisteredToken>>` inside `TokenStore`; shared via `Arc<TokenStore>` to the HTTP server and Nostr listener.
- Push services: `Arc<Mutex<Vec<Box<dyn PushService>>>>` shared between `main.rs` and the Nostr listener.
- UnifiedPush endpoints: `RwLock<HashMap<String, UnifiedPushEndpoint>>` persisted atomically to `data/unifiedpush_endpoints.json` via temp-file rename (`src/push/unifiedpush.rs:73-83`).
- FCM access token cache: `Arc<RwLock<Option<CachedToken>>>`.
- No database, no external cache; restart clears all in-memory state except UnifiedPush endpoints loaded from disk.

## Key Abstractions

**`PushService` trait:**
- Purpose: Uniform async interface over disparate push backends so the Nostr listener dispatches without backend-specific knowledge.
- Examples: `src/push/mod.rs:13-23` (definition), `src/push/fcm.rs:218-305` (FCM impl), `src/push/unifiedpush.rs:125-199` (UnifiedPush impl).
- Pattern: `#[async_trait]` trait with three methods, plus blanket `impl PushService for Arc<T>` so an `Arc`-shared concrete service can be wrapped in `Box<dyn PushService>` (`src/push/mod.rs:27-63`).

**`Platform` enum:**
- Purpose: Tag tokens and route them to the correct backend.
- Examples: `src/store/mod.rs:8-21` (runtime variants `Android`, `Ios`, `Display` impl).
- Pattern: Two parallel definitions exist - the runtime store version and a crypto-module version with byte-tag conversions (`src/crypto/mod.rs:24-54`, with `PLATFORM_ANDROID = 0x02`, `PLATFORM_IOS = 0x01`). The crypto variant becomes load-bearing in Phase 4.

**`Config` value object:**
- Purpose: Centralized typed configuration injected by clone into every subsystem.
- Examples: `src/config.rs:4-12` (struct), `src/config.rs:52-115` (`from_env`).
- Pattern: `#[derive(Debug, Clone, Deserialize)]` value type populated from `std::env::var` with hard-coded defaults; cloned wherever needed.

**`AppState`:**
- Purpose: Carry shared state into Actix handlers.
- Examples: `src/api/routes.rs:36-39`.
- Pattern: `#[derive(Clone)]` struct holding `Arc<TokenStore>`; registered via `web::Data::new(...)` in `src/main.rs:107-109`.

**`RegisteredToken`:**
- Purpose: Value object storing per-device push metadata keyed by `trade_pubkey`.
- Examples: `src/store/mod.rs:23-28` (`device_token`, `platform`, `registered_at`).

**`TokenCrypto` (Phase 4 abstraction):**
- Purpose: Encapsulate server keypair and token decryption.
- Examples: `src/crypto/mod.rs:62-100`.
- Pattern: Constructor parses hex secret key, derives public key; `decrypt_token` verifies fixed `ENCRYPTED_TOKEN_SIZE` and unwraps via ECDH + HKDF + ChaCha20-Poly1305.

## Entry Points

**Binary entry point:**
- Location: `src/main.rs:23-115` (`#[actix_web::main] async fn main`).
- Triggers: `cargo run`, the compiled `target/release/mostro-push-backend`, or the Docker `CMD` in `Dockerfile`.
- Responsibilities: init logger and dotenv, load `Config`, build `Arc<TokenStore>`, spawn cleanup task, build `FcmPush` and `UnifiedPushService`, populate `Vec<Box<dyn PushService>>`, spawn `NostrListener::start` task, bind `HttpServer` on `{host}:{port}`.

**HTTP routes:**
- Location: `src/api/routes.rs:41-49` (`configure`).
- Mounted under `/api`:
  - `GET  /api/health` -> `health_check` (`src/api/routes.rs:52-54`).
  - `GET  /api/status` -> `status` (returns `TokenStoreStats`).
  - `GET  /api/info` -> `server_info` (advertises `encryption_enabled: false`).
  - `POST /api/register` -> `register_token`.
  - `POST /api/unregister` -> `unregister_token`.

**Background tasks:**
- `tokio::spawn(async move { nostr_listener.start().await; })` in `src/main.rs:88-90`.
- `tokio::spawn` cleanup loop in `src/store/mod.rs:140-152` started by `store::start_cleanup_task` (called from `src/main.rs:39`).

## Error Handling

**Strategy:** Component-local handling with logging and graceful continuation. No global error type; most fallible paths return `Result<_, Box<dyn std::error::Error>>` and are either propagated to the caller or logged and swallowed in background loops.

**Patterns:**
- Reconnection with backoff: `NostrListener::start` retries forever, sleeping 5s on a clean close and 10s on errors (`src/nostr/listener.rs:42-55`).
- Validation at the boundary: HTTP handlers reject malformed `trade_pubkey` (must be 64 hex chars), empty tokens, and unknown platforms with `400 Bad Request` and a `RegisterResponse { success: false, message }` (`src/api/routes.rs:86-117`).
- Non-fatal startup degradation: FCM init failures log a warning and exclude FCM from the dispatch list (`src/main.rs:62-72`); UnifiedPush endpoint load failures log and continue (`src/main.rs:51-54`, `src/push/unifiedpush.rs:64-69`).
- Push send failure: `error!` log with the response body, then the next service in the list is tried; the `break` happens only on first success (`src/nostr/listener.rs:120-135`).
- Crypto errors: `CryptoError` enum returned from `TokenCrypto::decrypt_token` for `InvalidSecretKey`, `InvalidTokenSize`, etc. (`src/crypto/mod.rs:62-100`).
- Configuration errors: `Config::from_env` returns `Result<Self, Box<dyn std::error::Error>>`; `main.rs:33` calls `.expect("Failed to load configuration")` so misconfiguration aborts startup.
- Pubkey validation: `NostrListener::new` rejects pubkeys that are not 64 chars or not valid `XOnlyPublicKey`, surfaced as a `Failed to initialize Nostr listener` panic in main (`src/nostr/listener.rs:25-32`, `src/main.rs:82-86`).

## Cross-Cutting Concerns

**Logging:** `log` crate macros (`info!`, `warn!`, `error!`, `debug!`) backed by `env_logger::init()` in `src/main.rs:25`. Log level is controlled by `RUST_LOG` (default `info` in `Dockerfile` and `.env.example`).

**Validation:** Inline in HTTP handlers (length and hex check on `trade_pubkey`, non-empty token, platform whitelist). No request schema framework beyond `serde::Deserialize`.

**Authentication:**
- Inbound HTTP: none - the API is unauthenticated.
- Outbound FCM: OAuth2 service-account JWT bearer flow (`src/push/fcm.rs:95-158`) with token caching.
- Nostr: ephemeral keypair generated per connection (`Keys::generate()` in `src/nostr/listener.rs:61`); the listener filters incoming events by `p` tag rather than by signed origin.

**Rate limiting:** Configuration plumbed (`RATE_LIMIT_PER_MINUTE`, `BATCH_DELAY_MS`, `COOLDOWN_MS`) via `RateLimitConfig` and `BatchingManager`, but not yet enforced on any endpoint or push call. `governor` is in `Cargo.toml` but currently unused.

**Persistence:**
- Token store: in-memory only; lost on restart.
- UnifiedPush endpoints: atomic JSON write to `data/unifiedpush_endpoints.json` (`src/push/unifiedpush.rs:30`, `src/push/unifiedpush.rs:73-83`).
- FCM service account: read once at startup from `FIREBASE_SERVICE_ACCOUNT_PATH`.

**Secrets handling:** `.env` loaded via `dotenv::dotenv().ok()`. Firebase service-account JSON is read from a path. `.gitignore` excludes `.env`, `*.json`, and `secrets/`, while the `Dockerfile` copies `secrets/` into the image at build time.

---

*Architecture analysis: 2026-04-24*
