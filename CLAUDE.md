<!-- GSD:project-start source:PROJECT.md -->
## Project

**Mostro Push Server**

Privacy-preserving push notification backend for the Mostro P2P trading ecosystem. A Rust service that observes Nostr Gift Wrap events (kind 1059) on configured relays, looks up registered device tokens by `trade_pubkey`, and dispatches silent push notifications via Firebase Cloud Messaging (FCM) and UnifiedPush so Mostro Mobile clients can wake up and process trade events without exposing user identity, message content, or peer relationships to the server operator or to Google/Apple. Inspired by [MIP-05](https://github.com/MostroP2P/MIPs).

**Core Value:** The mobile client receives a silent push the moment a relevant Nostr event lands on the configured relays — without the push server, Google/Apple, or any operator learning who is trading with whom or what is being said.

### Constraints

- **Tech stack:** Rust + Actix-web + Tokio. The new endpoint is additive — must not introduce a different framework, async runtime, or HTTP client. Reuse `reqwest::Client` and the `PushService` trait wherever possible.
- **Privacy:** Hard requirement that the server never learns `sharedKey`s, peer-to-peer relationships, or sender identity. Designs that would weaken this (e.g. signature auth on `/api/notify`, registering `sharedKey`s, forwarding plaintext) are rejected.
- **Backwards compatibility:** Existing `/api/register`, `/api/unregister`, `/api/health`, `/api/info`, `/api/status` contracts must not change in this milestone. Mobile clients on the current API must keep working.
- **Mobile contract:** The new endpoint must match what `mobile/docs/plans/CHAT_NOTIFICATIONS_PLAN.md` Phase 4 specifies (`POST /api/notify { "trade_pubkey": "<64-char hex>" }`, returns `200`/`404`/`429`). Detailed wire format (response body, error shape) is finalized in `/gsd-plan-phase`.
- **Deployment:** Single Fly.io machine, 512MB RAM, hard connection cap of 25 (`fly.toml`). Rate limits and any new state structures must respect this.
- **Anti-requirement:** No Mostro-daemon author filter on the Nostr listener. Dispute admin DMs are sent directly user-to-user; filtering by `mostro_pubkey` author would silently drop them.
- **No new dependencies without explicit approval** (per global CLAUDE.md). The `governor` crate is already declared and counts as already-approved.
- **Language:** Code, comments, commit messages, branch names, and documentation in English. Conversation in Spanish (per global CLAUDE.md).
<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->
## Technology Stack

## Languages
- Rust (edition 2021) - Entire backend implementation under `src/`
- Bash - Deployment and test scripts: `deploy-fly.sh`, `test_server.sh`
- TOML - Project and runtime configuration: `Cargo.toml`, `fly.toml`, `config.toml.example`
- Dockerfile / YAML - Container build and orchestration: `Dockerfile`, `docker-compose.yml`
## Runtime
- Rust toolchain >= 1.75 (README requirement); Docker base image pinned to `rust:1.83` in `Dockerfile`
- Async runtime: Tokio 1.35 with the `full` feature flag (`Cargo.toml:13`)
- HTTP runtime: Actix runtime via `actix-rt = "2.9"` (`Cargo.toml:9`)
- Production base image: `debian:bookworm-slim` (`Dockerfile:9`)
- Cargo (Rust standard)
- Lockfile: present (`Cargo.lock`, committed and copied into Docker build at `Dockerfile:4`)
## Frameworks
- `actix-web = "4.4"` - HTTP server and routing (`src/main.rs`, `src/api/routes.rs`)
- `actix-rt = "2.9"` - Actix async runtime
- `tokio = "1.35"` - Async runtime, channels, sync primitives, background tasks
- `tokio-tungstenite = "0.21"` - WebSocket client library (declared in `Cargo.toml:12`; Nostr relay traffic actually flows via `nostr-sdk`)
- `nostr-sdk = "0.27"` - Nostr protocol client used in `src/nostr/listener.rs`
- `mockito = "1.2"` - HTTP mocking for unit tests, declared in `[dev-dependencies]` (`Cargo.toml:55-56`)
- Built-in `cargo test` runner (no integration test suite present in repo)
- `cargo build --release` - Production build (used in `Dockerfile:7` and README workflow)
- `cargo run` - Development runner
- `cargo clippy` - Linting (referenced in `README.md`)
- `cargo fmt` - Formatting (referenced in `README.md`)
## Key Dependencies
- `nostr-sdk = "0.27"` - Subscribes to Nostr relays, parses Gift Wrap (kind 1059) events (`src/nostr/listener.rs:2`)
- `actix-web = "4.4"` - REST API surface for token registration (`src/api/routes.rs:1`)
- `reqwest = "0.11"` (with `json` feature) - HTTPS client for FCM v1 API and UnifiedPush endpoint POSTs (`src/push/fcm.rs:3`, `src/push/unifiedpush.rs:4`)
- `jsonwebtoken = "9"` - Signs RS256 JWTs for Firebase OAuth2 token exchange (`src/push/fcm.rs:8`)
- `serde = "1.0"` (`derive`) and `serde_json = "1.0"` - Configuration, request bodies, FCM payloads, persisted endpoint store
- `tokio` (`full`) - Concurrency primitives (`Mutex`, `RwLock`), background tasks, time intervals
- `chrono = "0.4"` (`serde`) - Timestamps for token TTL and registration metadata (`src/store/mod.rs:1`)
- `secp256k1 = "0.28"` (`rand-std` feature) - Public/secret key handling (`src/crypto/mod.rs:8`)
- `chacha20poly1305 = "0.10"` - AEAD cipher for token decryption
- `hkdf = "0.12"` and `sha2 = "0.10"` - Key derivation
- `rand = "0.8"`, `hex = "0.4"`, `base64 = "0.21"` - Encoding helpers
- The `crypto` module is gated with `#[allow(dead_code)]` in `src/main.rs:13-15`
- `config = "0.14"` - Configuration loader (declared in `Cargo.toml:30`; runtime config currently uses `std::env` directly in `src/config.rs`)
- `dotenv = "0.15"` - Loads `.env` at startup (`src/main.rs:26`)
- `env_logger = "0.11"` and `log = "0.4"` - Logging facade and stdout backend
- `governor = "0.6"` - Rate-limiting primitive (declared, not yet wired into request handlers)
- `futures = "0.3"` and `async-trait = "0.1"` - Async trait support (`src/push/mod.rs:1`)
## Configuration
- Loaded from process env (and `.env` via `dotenv`) inside `Config::from_env()` at `src/config.rs:53-115`
- Notable variables: `NOSTR_RELAYS`, `MOSTRO_PUBKEY`, `SERVER_PRIVATE_KEY`, `FIREBASE_PROJECT_ID`, `FIREBASE_SERVICE_ACCOUNT_PATH`, `FCM_ENABLED`, `UNIFIEDPUSH_ENABLED`, `SERVER_HOST`, `SERVER_PORT`, `TOKEN_TTL_HOURS`, `CLEANUP_INTERVAL_HOURS`, `RATE_LIMIT_PER_MINUTE`, `BATCH_DELAY_MS`, `COOLDOWN_MS`, `RUST_LOG`
- Reference template: `.env.example`
- Local development env file: `.env` (gitignored, contents not inspected)
- Alternative TOML template: `config.toml.example` (exists but not currently parsed by `Config::from_env`)
- `Cargo.toml` - Crate manifest and dependency graph
- `Cargo.lock` - Pinned dependency versions
- `Dockerfile` - Multi-stage build (rust:1.83 builder -> debian:bookworm-slim runtime)
- `docker-compose.yml` - Local container orchestration with Firebase JSON volume mount
- `fly.toml` - Fly.io deployment manifest (region `gru`, internal port 8080, 512mb VM)
- `deploy-fly.sh` - Idempotent secrets-set + `flyctl deploy` wrapper
## Platform Requirements
- Rust toolchain (1.75+ per `README.md`, 1.83 per Docker builder)
- Cargo
- Optional: Docker / docker-compose for containerized runs
- Optional: `flyctl` for Fly.io deploys
- Primary deployment target: Fly.io (`fly.toml`, app name `mostro-push-server`, region `gru`)
- Container image built via `Dockerfile` (multi-stage, Debian slim runtime)
- Outbound network access required to:
- Persistent local filesystem for `data/unifiedpush_endpoints.json` (`src/push/unifiedpush.rs:30`)
- Firebase service account JSON file mounted into the container (Fly.io path `/secrets/...` per `deploy-fly.sh`)
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

## Naming Patterns
- Module entry points use `mod.rs` (e.g., `src/store/mod.rs`, `src/api/mod.rs`, `src/push/mod.rs`, `src/nostr/mod.rs`, `src/crypto/mod.rs`, `src/utils/mod.rs`).
- Submodules use `snake_case.rs` matching the module's role (e.g., `src/api/routes.rs`, `src/nostr/listener.rs`, `src/push/fcm.rs`, `src/push/unifiedpush.rs`, `src/utils/batching.rs`).
- Top-level configuration as a flat file: `src/config.rs`.
- `snake_case` for all functions and methods (e.g., `register_token`, `get_access_token`, `send_to_token`, `cleanup_expired`, `start_cleanup_task`).
- Constructors named `new` (e.g., `TokenStore::new`, `FcmPush::new`, `NostrListener::new`).
- Async functions are explicitly declared with `async fn`; no naming suffix differentiates sync from async.
- Boolean queries use predicate-style names (e.g., `supports_platform`, `should_send`).
- `snake_case` for locals, parameters, and fields (e.g., `token_store`, `push_services`, `device_token`, `trade_pubkey`, `mostro_pubkey`).
- Boolean fields prefixed by intent (e.g., `fcm_enabled`, `unifiedpush_enabled`, `ephemeral_pubkey_valid`).
- `PascalCase` for structs, enums, and traits (e.g., `Config`, `TokenStore`, `RegisteredToken`, `PushService`, `Platform`, `CryptoError`, `UnifiedPushEndpoint`, `AppState`).
- Request/response DTOs end with `Request` or `Response` (e.g., `RegisterTokenRequest`, `UnregisterTokenRequest`, `RegisterResponse`, `StatusResponse`).
- Error enums end with `Error` (e.g., `CryptoError`).
- `SCREAMING_SNAKE_CASE` for module-level constants (e.g., `HKDF_SALT`, `HKDF_INFO`, `PLATFORM_ANDROID`, `PLATFORM_IOS`, `PADDED_PAYLOAD_SIZE`, `EPHEMERAL_PUBKEY_SIZE`, `NONCE_SIZE`, `AUTH_TAG_SIZE`, `ENCRYPTED_TOKEN_SIZE`) defined in `src/crypto/mod.rs`.
- Single-word `snake_case` module names (`api`, `nostr`, `push`, `store`, `crypto`, `utils`, `config`).
## Code Style
- No `rustfmt.toml` or `.rustfmt.toml` present; default `rustfmt` formatting is implicit.
- Indentation is 4 spaces (Rust default).
- Edition pinned to `2021` in `Cargo.toml`.
- No `clippy.toml` or `.clippy.toml` present; default Clippy lints apply if/when invoked.
- `#[allow(dead_code)]` is used at the module level for code preserved for future phases (see `mod crypto` declaration in `src/main.rs` line 14).
- `pub` is applied per-item (no `pub(crate)` or restricted visibility currently used).
- Internal helpers default to private (e.g., `save_endpoints` in `src/push/unifiedpush.rs`, `get_access_token` and `build_payload_for_token` in `src/push/fcm.rs`, `connect_and_listen` in `src/nostr/listener.rs`).
- Module re-exports use `pub use` to flatten paths (e.g., `pub use listener::NostrListener;` in `src/nostr/mod.rs`, `pub use fcm::FcmPush;` and `pub use unifiedpush::UnifiedPushService;` in `src/push/mod.rs`).
## Import Organization
- Multi-symbol imports use brace expansion (e.g., `use log::{debug, info, warn};`, `use serde::{Deserialize, Serialize};`, `use actix_web::{web, HttpResponse, Responder};`).
- None. Plain `crate::` and `super::` paths are used throughout.
## Error Handling
- Boxed trait objects are the dominant return type: `Result<T, Box<dyn std::error::Error>>` and `Result<T, Box<dyn std::error::Error + Send + Sync>>` (e.g., `src/push/mod.rs` lines 14-20, `src/push/fcm.rs` line 86, `src/push/unifiedpush.rs` line 41).
- The `?` operator propagates errors with implicit `From` conversion.
- Errors are converted to strings at trait boundaries using `.map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })` (see `src/push/fcm.rs` lines 222, 274) to satisfy `Send + Sync` differences.
- `CryptoError` in `src/crypto/mod.rs` (lines 173-204) implements `Display` and `std::error::Error` manually with one variant per failure mode (`InvalidSecretKey`, `InvalidTokenSize`, `InvalidEphemeralKey`, `HkdfError`, `CipherError`, `DecryptionFailed`, `InvalidPayloadSize`, `InvalidTokenLength`, `InvalidPlatform`, `InvalidTokenEncoding`).
- `error!` is logged immediately before returning errors (see `src/crypto/mod.rs` lines 93-97, 134-137, `src/push/fcm.rs` line 297).
- Hand-written guards in `src/api/routes.rs` validate input length and hex format, return `HttpResponse::BadRequest().json(...)` with a structured `RegisterResponse` body (see lines 86-117).
- Production: only used at startup for unrecoverable configuration (see `src/main.rs` line 33 `Config::from_env().expect("Failed to load configuration")` and line 86 for `NostrListener::new`).
- `unwrap` in `src/crypto/mod.rs` test-helper functions (`encrypt_token_like_client`, `encrypt_token_with_debug`, lines 364, 375, 377, 420, 430, 432) is acceptable because those functions are test fixtures used only with controlled inputs.
- Within `#[cfg(test)]` modules, `unwrap` is used freely.
- Some non-fatal errors are logged but not returned (e.g., `src/main.rs` lines 52-54 logs and continues if `load_endpoints` fails; `src/main.rs` lines 67-71 disables FCM but keeps the server running).
## Logging
- `log` crate macros (`info!`, `warn!`, `error!`, `debug!`).
- Initialized in `src/main.rs` line 25 via `env_logger::init()`.
- `info!`: lifecycle events, successful operations, registration/unregistration confirmations (e.g., `src/store/mod.rs` lines 58-62, 70-74, `src/api/routes.rs` lines 82-83, 126-130).
- `warn!`: recoverable problems, missing optional config, validation failures (e.g., `src/api/routes.rs` lines 87, 110, `src/main.rs` lines 68-69).
- `error!`: failures requiring operator attention (e.g., `src/nostr/listener.rs` line 49, `src/push/fcm.rs` lines 264, 297).
- `debug!`: high-volume diagnostic detail (e.g., crypto intermediate values in `src/crypto/mod.rs` lines 106-108, FCM token previews in `src/push/fcm.rs` line 283).
- Plain English sentences with structured interpolation; no JSON-formatted logs.
- Sensitive identifiers (pubkeys, tokens) are truncated using `&value[..16.min(value.len())]` or `&token[..20.min(...)]` to avoid leaking full values (e.g., `src/store/mod.rs` lines 60, 73, 78; `src/api/routes.rs` lines 83, 144; `src/push/fcm.rs` line 283).
## Comments
- Multi-line `///` doc comments document public API and non-obvious behavior (e.g., `RegisterTokenRequest` in `src/api/routes.rs` line 8, `build_payload_for_token` in `src/push/fcm.rs` lines 160-167, `encrypt_token_like_client` in `src/crypto/mod.rs` lines 342-343).
- Inline `//` comments explain non-obvious logic, phase-specific decisions, and protocol quirks (e.g., `src/main.rs` lines 13-15 about future phases, `src/nostr/listener.rs` lines 73-75 explaining Gift Wrap filtering).
- Phase markers ("Phase 3", "Phase 4", "Phase 5") are used inline to signal future work (e.g., `src/api/routes.rs` lines 8, 69-70; `src/config.rs` lines 100-102).
- Comments are written in English.
- No emojis are used in source files (emojis appear only in the shell test script `test_server.sh`).
- Avoid restating what code does; explain why, especially for cryptographic invariants (`src/crypto/mod.rs` line 357 explaining `secret_bytes()` semantics).
## Function Design
- Most functions are under 50 lines. Larger functions are HTTP handlers with inline validation (`register_token` in `src/api/routes.rs` lines 78-137, ~60 lines) and the Nostr event loop (`connect_and_listen` in `src/nostr/listener.rs` lines 57-149).
- The crypto debug helper `debug_decrypt_token` in `src/crypto/mod.rs` (lines 223-339) is intentionally long to capture intermediate values.
- Owned `String` for values stored long-term (e.g., `TokenStore::register` in `src/store/mod.rs` line 43-48 takes `String`, `String`, `Platform`).
- `&str` for read-only string inputs (e.g., `unregister(&self, trade_pubkey: &str)` in `src/store/mod.rs` line 65).
- `&Platform` for shared references to enums (`supports_platform` and `send_to_token` in `src/push/mod.rs`).
- Configuration is passed as cloned `Config` values into services (e.g., `FcmPush::new(config.clone())`, `UnifiedPushService::new(config.clone())` in `src/main.rs`).
- Constructors return `Self` directly, or `Result<Self, _>` when validation can fail (`Config::from_env`, `TokenCrypto::new`, `NostrListener::new`).
- Async fallible operations return `Result<T, Box<dyn std::error::Error[+ Send + Sync]>>`.
- HTTP handlers return `impl Responder`.
- Tokio runtime via `actix_web::main` attribute on `main` (`src/main.rs` line 23).
- `async-trait` crate is used for async methods on the `PushService` trait (`src/push/mod.rs` line 12).
- Background tasks spawned via `tokio::spawn` (e.g., `src/main.rs` line 88, `src/store/mod.rs` line 140).
## Module Design
- Modules expose public types via `pub use` re-exports at the module root for ergonomic access (`src/nostr/mod.rs`, `src/push/mod.rs`).
- `src/api/mod.rs` keeps `routes` as a sub-module without re-exporting (callers use `api::routes::AppState`, `api::routes::configure`).
- `src/utils/mod.rs` declares `batching` but no re-export (only used internally).
- Each module's `mod.rs` acts as a small barrel exposing the public surface. No deep re-export hierarchies.
## Concurrency Patterns
- `Arc<TokenStore>` and `Arc<Mutex<Vec<Box<dyn PushService>>>>` are passed into background tasks (`src/main.rs` lines 36, 79-89).
- Internal state uses `tokio::sync::RwLock` for read-heavy maps (`TokenStore::tokens` in `src/store/mod.rs` line 31, `UnifiedPushService::endpoints` in `src/push/unifiedpush.rs` line 24, `FcmPush::cached_token` in `src/push/fcm.rs` line 47).
- `tokio::sync::Mutex` is used for the dynamic dispatch push-service vector (`src/main.rs` line 79).
- `Arc<T>` blanket impls of `PushService` are provided in `src/push/mod.rs` lines 27-63 to allow `Arc<UnifiedPushService>` and `Arc<FcmPush>` to be used as `Box<dyn PushService>` while keeping a separate `Arc` reference.
## Configuration & Env Vars
- All configuration flows through `Config::from_env()` in `src/config.rs`, parsing `std::env` variables with sensible string defaults via `unwrap_or_else`.
- `dotenv::dotenv().ok()` is called once at startup in `src/main.rs` line 26.
- Env var names are `SCREAMING_SNAKE_CASE` (e.g., `NOSTR_RELAYS`, `MOSTRO_PUBKEY`, `FCM_ENABLED`, `UNIFIEDPUSH_ENABLED`, `BATCH_DELAY_MS`, `COOLDOWN_MS`, `SERVER_HOST`, `SERVER_PORT`, `RATE_LIMIT_PER_MINUTE`, `SERVER_PRIVATE_KEY`, `TOKEN_TTL_HOURS`, `CLEANUP_INTERVAL_HOURS`, `FIREBASE_SERVICE_ACCOUNT_PATH`, `FIREBASE_PROJECT_ID`).
- Numeric values are parsed via `.parse()?` after `unwrap_or_else` provides a string default. This means defaults are written as strings (e.g., `"5000"`, `"60"`), not typed constants.
## Serialization
- `#[derive(Debug, Clone, Deserialize)]` on config structs (`src/config.rs`).
- `#[derive(Serialize)]` on response DTOs (`src/api/routes.rs`).
- `#[derive(Deserialize)]` on request DTOs.
- `#[derive(Serialize, Deserialize)]` on persisted types (`UnifiedPushEndpoint` in `src/push/unifiedpush.rs` line 14).
- `#[serde(skip_serializing_if = "Option::is_none")]` to omit absent fields (e.g., `RegisterResponse::platform` in `src/api/routes.rs` line 32).
- `serde_json::json!` macro is used for inline payload construction (e.g., `src/api/routes.rs` lines 53, 71-75, 149-167; `src/push/fcm.rs` lines 169-215).
## Persistence
- `UnifiedPushService` writes `data/unifiedpush_endpoints.json` using `serde_json::to_string_pretty` (`src/push/unifiedpush.rs` lines 73-83).
- Atomic writes via temp-file + rename: write to `*.tmp`, then `fs::rename` to final path.
- `TokenStore` is in-memory only (`HashMap` behind `RwLock`), with TTL-based cleanup via a tokio interval task started in `start_cleanup_task` (`src/store/mod.rs` lines 139-153).
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

## Pattern Overview
- Single-binary Tokio/Actix runtime (`#[actix_web::main]`) wiring all subsystems in `src/main.rs`.
- Trait-based polymorphism (`PushService`) for FCM and UnifiedPush backends, registered as `Vec<Box<dyn PushService>>`.
- Event-driven push delivery: Nostr `kind 1059` (Gift Wrap) events trigger lookups in the in-memory token store and dispatch to one matching backend.
- Currently in **Phase 3** (token registration without encryption); the ECDH/ChaCha20 crypto module exists in `src/crypto/mod.rs` but is gated `#[allow(dead_code)]` in `src/main.rs:14-15` for a future Phase 4.
- Configuration entirely from environment variables via `dotenv` plus a typed `Config` struct.
- Concurrency: `Arc<Mutex<Vec<Box<dyn PushService>>>>` for push services, `Arc<RwLock<...>>` for UnifiedPush endpoints and FCM token cache, `RwLock<HashMap<...>>` for the token store.
## Layers
- Purpose: Boot the runtime, load config, instantiate services, spawn background tasks, start the HTTP server.
- Location: `src/main.rs`
- Contains: Tokio main, `AppState` construction, push service registration, cleanup task spawn.
- Depends on: `config`, `store`, `nostr`, `push`, `api`, `crypto` (gated).
- Used by: External (binary entry point).
- Purpose: Strongly-typed configuration loaded from environment variables.
- Location: `src/config.rs`
- Contains: `Config`, `NostrConfig`, `PushConfig`, `ServerConfig`, `RateLimitConfig`, `CryptoConfig`, `StoreConfig`, plus `Config::from_env()` factory.
- Depends on: `serde`, `std::env`, `dotenv` (loaded in main).
- Used by: All other layers as a cloneable value type.
- Purpose: REST endpoints for client token registration/unregistration and server status.
- Location: `src/api/routes.rs` (re-exported via `src/api/mod.rs`).
- Contains: `AppState`, `RegisterTokenRequest`, `UnregisterTokenRequest`, `RegisterResponse`, `StatusResponse`, `configure(cfg)`, and async handlers `health_check`, `status`, `server_info`, `register_token`, `unregister_token`.
- Depends on: `actix-web`, `crate::store`.
- Used by: Mobile clients via HTTP.
- Purpose: Maintain a persistent subscription to Nostr relays for `kind 1059` events and trigger push delivery.
- Location: `src/nostr/listener.rs` (re-exported from `src/nostr/mod.rs`).
- Contains: `NostrListener`, `NostrListener::new`, `start` (reconnect loop), `connect_and_listen` (subscription + handler closure).
- Depends on: `nostr-sdk`, `tokio`, `crate::config`, `crate::push`, `crate::store`.
- Used by: `main.rs` (spawned as a Tokio task).
- Purpose: Abstracted push notification dispatch with concrete FCM and UnifiedPush backends.
- Location: `src/push/mod.rs`, `src/push/fcm.rs`, `src/push/unifiedpush.rs`.
- Contains: `PushService` trait (`send_silent_push`, `send_to_token`, `supports_platform`), `FcmPush` and `UnifiedPushService` implementations, blanket `impl PushService for Arc<...>`.
- Depends on: `reqwest`, `jsonwebtoken` (FCM), `tokio::fs` (UnifiedPush persistence), `crate::config`, `crate::store::Platform`.
- Used by: `nostr::listener` (dispatch) and `main.rs` (registration).
- Purpose: In-memory `trade_pubkey -> RegisteredToken` map with TTL cleanup and stats.
- Location: `src/store/mod.rs`.
- Contains: `Platform` enum, `RegisteredToken`, `TokenStore` (`register`, `unregister`, `get`, `cleanup_expired`, `count`, `get_stats`), `TokenStoreStats`, `start_cleanup_task` background loop.
- Depends on: `tokio::sync::RwLock`, `chrono`, `serde`.
- Used by: HTTP handlers, Nostr listener, cleanup task.
- Purpose: ECDH (secp256k1) + HKDF-SHA256 + ChaCha20-Poly1305 token decryption with platform/length framing and 220-byte padding.
- Location: `src/crypto/mod.rs` (declared `#[allow(dead_code)] mod crypto` in `src/main.rs:14-15`).
- Contains: `Platform`, `DecryptedToken`, `TokenCrypto::new`, `public_key_hex`, `decrypt_token`, `CryptoError`, plus `HKDF_SALT`, `HKDF_INFO`, `ENCRYPTED_TOKEN_SIZE` (294 bytes).
- Depends on: `secp256k1`, `chacha20poly1305`, `hkdf`, `sha2`, `hex`, `base64`.
- Used by: Currently unused at runtime; reserved for Phase 4 encrypted-token registration.
- Purpose: Cross-cutting helpers.
- Location: `src/utils/mod.rs`, `src/utils/batching.rs`.
- Contains: `BatchingManager` skeleton (`new`, `should_send`) for cooldown/rate-limit batching.
- Depends on: `tokio::time::Instant`.
- Used by: Currently unused at runtime; reserved for future batching logic.
## Data Flow
- `FcmPush::get_access_token` (`src/push/fcm.rs:95-158`) returns a cached token if `expires_at > now + 60`; otherwise it constructs `Claims { iss, scope, aud, iat, exp }`, signs with `RS256` from the service-account PEM, exchanges for an access token, and caches it under `RwLock<Option<CachedToken>>`.
- Token map: `RwLock<HashMap<String, RegisteredToken>>` inside `TokenStore`; shared via `Arc<TokenStore>` to the HTTP server and Nostr listener.
- Push services: `Arc<Mutex<Vec<Box<dyn PushService>>>>` shared between `main.rs` and the Nostr listener.
- UnifiedPush endpoints: `RwLock<HashMap<String, UnifiedPushEndpoint>>` persisted atomically to `data/unifiedpush_endpoints.json` via temp-file rename (`src/push/unifiedpush.rs:73-83`).
- FCM access token cache: `Arc<RwLock<Option<CachedToken>>>`.
- No database, no external cache; restart clears all in-memory state except UnifiedPush endpoints loaded from disk.
## Key Abstractions
- Purpose: Uniform async interface over disparate push backends so the Nostr listener dispatches without backend-specific knowledge.
- Examples: `src/push/mod.rs:13-23` (definition), `src/push/fcm.rs:218-305` (FCM impl), `src/push/unifiedpush.rs:125-199` (UnifiedPush impl).
- Pattern: `#[async_trait]` trait with three methods, plus blanket `impl PushService for Arc<T>` so an `Arc`-shared concrete service can be wrapped in `Box<dyn PushService>` (`src/push/mod.rs:27-63`).
- Purpose: Tag tokens and route them to the correct backend.
- Examples: `src/store/mod.rs:8-21` (runtime variants `Android`, `Ios`, `Display` impl).
- Pattern: Two parallel definitions exist - the runtime store version and a crypto-module version with byte-tag conversions (`src/crypto/mod.rs:24-54`, with `PLATFORM_ANDROID = 0x02`, `PLATFORM_IOS = 0x01`). The crypto variant becomes load-bearing in Phase 4.
- Purpose: Centralized typed configuration injected by clone into every subsystem.
- Examples: `src/config.rs:4-12` (struct), `src/config.rs:52-115` (`from_env`).
- Pattern: `#[derive(Debug, Clone, Deserialize)]` value type populated from `std::env::var` with hard-coded defaults; cloned wherever needed.
- Purpose: Carry shared state into Actix handlers.
- Examples: `src/api/routes.rs:36-39`.
- Pattern: `#[derive(Clone)]` struct holding `Arc<TokenStore>`; registered via `web::Data::new(...)` in `src/main.rs:107-109`.
- Purpose: Value object storing per-device push metadata keyed by `trade_pubkey`.
- Examples: `src/store/mod.rs:23-28` (`device_token`, `platform`, `registered_at`).
- Purpose: Encapsulate server keypair and token decryption.
- Examples: `src/crypto/mod.rs:62-100`.
- Pattern: Constructor parses hex secret key, derives public key; `decrypt_token` verifies fixed `ENCRYPTED_TOKEN_SIZE` and unwraps via ECDH + HKDF + ChaCha20-Poly1305.
## Entry Points
- Location: `src/main.rs:23-115` (`#[actix_web::main] async fn main`).
- Triggers: `cargo run`, the compiled `target/release/mostro-push-backend`, or the Docker `CMD` in `Dockerfile`.
- Responsibilities: init logger and dotenv, load `Config`, build `Arc<TokenStore>`, spawn cleanup task, build `FcmPush` and `UnifiedPushService`, populate `Vec<Box<dyn PushService>>`, spawn `NostrListener::start` task, bind `HttpServer` on `{host}:{port}`.
- Location: `src/api/routes.rs:41-49` (`configure`).
- Mounted under `/api`:
- `tokio::spawn(async move { nostr_listener.start().await; })` in `src/main.rs:88-90`.
- `tokio::spawn` cleanup loop in `src/store/mod.rs:140-152` started by `store::start_cleanup_task` (called from `src/main.rs:39`).
## Error Handling
- Reconnection with backoff: `NostrListener::start` retries forever, sleeping 5s on a clean close and 10s on errors (`src/nostr/listener.rs:42-55`).
- Validation at the boundary: HTTP handlers reject malformed `trade_pubkey` (must be 64 hex chars), empty tokens, and unknown platforms with `400 Bad Request` and a `RegisterResponse { success: false, message }` (`src/api/routes.rs:86-117`).
- Non-fatal startup degradation: FCM init failures log a warning and exclude FCM from the dispatch list (`src/main.rs:62-72`); UnifiedPush endpoint load failures log and continue (`src/main.rs:51-54`, `src/push/unifiedpush.rs:64-69`).
- Push send failure: `error!` log with the response body, then the next service in the list is tried; the `break` happens only on first success (`src/nostr/listener.rs:120-135`).
- Crypto errors: `CryptoError` enum returned from `TokenCrypto::decrypt_token` for `InvalidSecretKey`, `InvalidTokenSize`, etc. (`src/crypto/mod.rs:62-100`).
- Configuration errors: `Config::from_env` returns `Result<Self, Box<dyn std::error::Error>>`; `main.rs:33` calls `.expect("Failed to load configuration")` so misconfiguration aborts startup.
- Pubkey validation: `NostrListener::new` rejects pubkeys that are not 64 chars or not valid `XOnlyPublicKey`, surfaced as a `Failed to initialize Nostr listener` panic in main (`src/nostr/listener.rs:25-32`, `src/main.rs:82-86`).
## Cross-Cutting Concerns
- Inbound HTTP: none - the API is unauthenticated.
- Outbound FCM: OAuth2 service-account JWT bearer flow (`src/push/fcm.rs:95-158`) with token caching.
- Nostr: ephemeral keypair generated per connection (`Keys::generate()` in `src/nostr/listener.rs:61`); the listener filters incoming events by `p` tag rather than by signed origin.
- Token store: in-memory only; lost on restart.
- UnifiedPush endpoints: atomic JSON write to `data/unifiedpush_endpoints.json` (`src/push/unifiedpush.rs:30`, `src/push/unifiedpush.rs:73-83`).
- FCM service account: read once at startup from `FIREBASE_SERVICE_ACCOUNT_PATH`.
<!-- GSD:architecture-end -->

<!-- GSD:skills-start source:skills/ -->
## Project Skills

No project skills found. Add skills to any of: `.claude/skills/`, `.agents/skills/`, `.cursor/skills/`, or `.github/skills/` with a `SKILL.md` index file.
<!-- GSD:skills-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd-quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd-debug` for investigation and bug fixing
- `/gsd-execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd-profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
