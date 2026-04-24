# Coding Conventions

**Analysis Date:** 2026-04-24

## Naming Patterns

**Files:**
- Module entry points use `mod.rs` (e.g., `src/store/mod.rs`, `src/api/mod.rs`, `src/push/mod.rs`, `src/nostr/mod.rs`, `src/crypto/mod.rs`, `src/utils/mod.rs`).
- Submodules use `snake_case.rs` matching the module's role (e.g., `src/api/routes.rs`, `src/nostr/listener.rs`, `src/push/fcm.rs`, `src/push/unifiedpush.rs`, `src/utils/batching.rs`).
- Top-level configuration as a flat file: `src/config.rs`.

**Functions:**
- `snake_case` for all functions and methods (e.g., `register_token`, `get_access_token`, `send_to_token`, `cleanup_expired`, `start_cleanup_task`).
- Constructors named `new` (e.g., `TokenStore::new`, `FcmPush::new`, `NostrListener::new`).
- Async functions are explicitly declared with `async fn`; no naming suffix differentiates sync from async.
- Boolean queries use predicate-style names (e.g., `supports_platform`, `should_send`).

**Variables:**
- `snake_case` for locals, parameters, and fields (e.g., `token_store`, `push_services`, `device_token`, `trade_pubkey`, `mostro_pubkey`).
- Boolean fields prefixed by intent (e.g., `fcm_enabled`, `unifiedpush_enabled`, `ephemeral_pubkey_valid`).

**Types:**
- `PascalCase` for structs, enums, and traits (e.g., `Config`, `TokenStore`, `RegisteredToken`, `PushService`, `Platform`, `CryptoError`, `UnifiedPushEndpoint`, `AppState`).
- Request/response DTOs end with `Request` or `Response` (e.g., `RegisterTokenRequest`, `UnregisterTokenRequest`, `RegisterResponse`, `StatusResponse`).
- Error enums end with `Error` (e.g., `CryptoError`).

**Constants:**
- `SCREAMING_SNAKE_CASE` for module-level constants (e.g., `HKDF_SALT`, `HKDF_INFO`, `PLATFORM_ANDROID`, `PLATFORM_IOS`, `PADDED_PAYLOAD_SIZE`, `EPHEMERAL_PUBKEY_SIZE`, `NONCE_SIZE`, `AUTH_TAG_SIZE`, `ENCRYPTED_TOKEN_SIZE`) defined in `src/crypto/mod.rs`.

**Modules:**
- Single-word `snake_case` module names (`api`, `nostr`, `push`, `store`, `crypto`, `utils`, `config`).

## Code Style

**Formatting:**
- No `rustfmt.toml` or `.rustfmt.toml` present; default `rustfmt` formatting is implicit.
- Indentation is 4 spaces (Rust default).
- Edition pinned to `2021` in `Cargo.toml`.

**Linting:**
- No `clippy.toml` or `.clippy.toml` present; default Clippy lints apply if/when invoked.
- `#[allow(dead_code)]` is used at the module level for code preserved for future phases (see `mod crypto` declaration in `src/main.rs` line 14).

**Visibility:**
- `pub` is applied per-item (no `pub(crate)` or restricted visibility currently used).
- Internal helpers default to private (e.g., `save_endpoints` in `src/push/unifiedpush.rs`, `get_access_token` and `build_payload_for_token` in `src/push/fcm.rs`, `connect_and_listen` in `src/nostr/listener.rs`).
- Module re-exports use `pub use` to flatten paths (e.g., `pub use listener::NostrListener;` in `src/nostr/mod.rs`, `pub use fcm::FcmPush;` and `pub use unifiedpush::UnifiedPushService;` in `src/push/mod.rs`).

## Import Organization

**Order:**
1. External crates (e.g., `actix_web`, `tokio`, `log`, `serde`, `reqwest`, `chrono`, `nostr_sdk`, `chacha20poly1305`).
2. Standard library (`std::sync::Arc`, `std::collections::HashMap`, `std::env`, `std::fs`).
3. Internal crate paths via `crate::` (e.g., `crate::config::Config`, `crate::store::Platform`).
4. Local module siblings via `super::` (e.g., `super::PushService` in `src/push/fcm.rs` and `src/push/unifiedpush.rs`).

Order is loosely consistent across files; mixed external/std blocks appear in `src/main.rs` and `src/store/mod.rs`. No automated import sorting is enforced.

**Grouped imports:**
- Multi-symbol imports use brace expansion (e.g., `use log::{debug, info, warn};`, `use serde::{Deserialize, Serialize};`, `use actix_web::{web, HttpResponse, Responder};`).

**Path Aliases:**
- None. Plain `crate::` and `super::` paths are used throughout.

## Error Handling

**Production paths return `Result`:**
- Boxed trait objects are the dominant return type: `Result<T, Box<dyn std::error::Error>>` and `Result<T, Box<dyn std::error::Error + Send + Sync>>` (e.g., `src/push/mod.rs` lines 14-20, `src/push/fcm.rs` line 86, `src/push/unifiedpush.rs` line 41).
- The `?` operator propagates errors with implicit `From` conversion.
- Errors are converted to strings at trait boundaries using `.map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })` (see `src/push/fcm.rs` lines 222, 274) to satisfy `Send + Sync` differences.

**Custom error enum:**
- `CryptoError` in `src/crypto/mod.rs` (lines 173-204) implements `Display` and `std::error::Error` manually with one variant per failure mode (`InvalidSecretKey`, `InvalidTokenSize`, `InvalidEphemeralKey`, `HkdfError`, `CipherError`, `DecryptionFailed`, `InvalidPayloadSize`, `InvalidTokenLength`, `InvalidPlatform`, `InvalidTokenEncoding`).

**Logging at error sites:**
- `error!` is logged immediately before returning errors (see `src/crypto/mod.rs` lines 93-97, 134-137, `src/push/fcm.rs` line 297).

**Validation pattern (HTTP layer):**
- Hand-written guards in `src/api/routes.rs` validate input length and hex format, return `HttpResponse::BadRequest().json(...)` with a structured `RegisterResponse` body (see lines 86-117).

**`unwrap`/`expect` policy:**
- Production: only used at startup for unrecoverable configuration (see `src/main.rs` line 33 `Config::from_env().expect("Failed to load configuration")` and line 86 for `NostrListener::new`).
- `unwrap` in `src/crypto/mod.rs` test-helper functions (`encrypt_token_like_client`, `encrypt_token_with_debug`, lines 364, 375, 377, 420, 430, 432) is acceptable because those functions are test fixtures used only with controlled inputs.
- Within `#[cfg(test)]` modules, `unwrap` is used freely.

**Best-effort with logging fallback:**
- Some non-fatal errors are logged but not returned (e.g., `src/main.rs` lines 52-54 logs and continues if `load_endpoints` fails; `src/main.rs` lines 67-71 disables FCM but keeps the server running).

## Logging

**Framework:**
- `log` crate macros (`info!`, `warn!`, `error!`, `debug!`).
- Initialized in `src/main.rs` line 25 via `env_logger::init()`.

**Level usage:**
- `info!`: lifecycle events, successful operations, registration/unregistration confirmations (e.g., `src/store/mod.rs` lines 58-62, 70-74, `src/api/routes.rs` lines 82-83, 126-130).
- `warn!`: recoverable problems, missing optional config, validation failures (e.g., `src/api/routes.rs` lines 87, 110, `src/main.rs` lines 68-69).
- `error!`: failures requiring operator attention (e.g., `src/nostr/listener.rs` line 49, `src/push/fcm.rs` lines 264, 297).
- `debug!`: high-volume diagnostic detail (e.g., crypto intermediate values in `src/crypto/mod.rs` lines 106-108, FCM token previews in `src/push/fcm.rs` line 283).

**Message style:**
- Plain English sentences with structured interpolation; no JSON-formatted logs.
- Sensitive identifiers (pubkeys, tokens) are truncated using `&value[..16.min(value.len())]` or `&token[..20.min(...)]` to avoid leaking full values (e.g., `src/store/mod.rs` lines 60, 73, 78; `src/api/routes.rs` lines 83, 144; `src/push/fcm.rs` line 283).

## Comments

**When to Comment:**
- Multi-line `///` doc comments document public API and non-obvious behavior (e.g., `RegisterTokenRequest` in `src/api/routes.rs` line 8, `build_payload_for_token` in `src/push/fcm.rs` lines 160-167, `encrypt_token_like_client` in `src/crypto/mod.rs` lines 342-343).
- Inline `//` comments explain non-obvious logic, phase-specific decisions, and protocol quirks (e.g., `src/main.rs` lines 13-15 about future phases, `src/nostr/listener.rs` lines 73-75 explaining Gift Wrap filtering).
- Phase markers ("Phase 3", "Phase 4", "Phase 5") are used inline to signal future work (e.g., `src/api/routes.rs` lines 8, 69-70; `src/config.rs` lines 100-102).

**Style:**
- Comments are written in English.
- No emojis are used in source files (emojis appear only in the shell test script `test_server.sh`).
- Avoid restating what code does; explain why, especially for cryptographic invariants (`src/crypto/mod.rs` line 357 explaining `secret_bytes()` semantics).

## Function Design

**Size:**
- Most functions are under 50 lines. Larger functions are HTTP handlers with inline validation (`register_token` in `src/api/routes.rs` lines 78-137, ~60 lines) and the Nostr event loop (`connect_and_listen` in `src/nostr/listener.rs` lines 57-149).
- The crypto debug helper `debug_decrypt_token` in `src/crypto/mod.rs` (lines 223-339) is intentionally long to capture intermediate values.

**Parameters:**
- Owned `String` for values stored long-term (e.g., `TokenStore::register` in `src/store/mod.rs` line 43-48 takes `String`, `String`, `Platform`).
- `&str` for read-only string inputs (e.g., `unregister(&self, trade_pubkey: &str)` in `src/store/mod.rs` line 65).
- `&Platform` for shared references to enums (`supports_platform` and `send_to_token` in `src/push/mod.rs`).
- Configuration is passed as cloned `Config` values into services (e.g., `FcmPush::new(config.clone())`, `UnifiedPushService::new(config.clone())` in `src/main.rs`).

**Return Values:**
- Constructors return `Self` directly, or `Result<Self, _>` when validation can fail (`Config::from_env`, `TokenCrypto::new`, `NostrListener::new`).
- Async fallible operations return `Result<T, Box<dyn std::error::Error[+ Send + Sync]>>`.
- HTTP handlers return `impl Responder`.

**Async:**
- Tokio runtime via `actix_web::main` attribute on `main` (`src/main.rs` line 23).
- `async-trait` crate is used for async methods on the `PushService` trait (`src/push/mod.rs` line 12).
- Background tasks spawned via `tokio::spawn` (e.g., `src/main.rs` line 88, `src/store/mod.rs` line 140).

## Module Design

**Exports:**
- Modules expose public types via `pub use` re-exports at the module root for ergonomic access (`src/nostr/mod.rs`, `src/push/mod.rs`).
- `src/api/mod.rs` keeps `routes` as a sub-module without re-exporting (callers use `api::routes::AppState`, `api::routes::configure`).
- `src/utils/mod.rs` declares `batching` but no re-export (only used internally).

**Barrel Files:**
- Each module's `mod.rs` acts as a small barrel exposing the public surface. No deep re-export hierarchies.

## Concurrency Patterns

**Shared state:**
- `Arc<TokenStore>` and `Arc<Mutex<Vec<Box<dyn PushService>>>>` are passed into background tasks (`src/main.rs` lines 36, 79-89).
- Internal state uses `tokio::sync::RwLock` for read-heavy maps (`TokenStore::tokens` in `src/store/mod.rs` line 31, `UnifiedPushService::endpoints` in `src/push/unifiedpush.rs` line 24, `FcmPush::cached_token` in `src/push/fcm.rs` line 47).
- `tokio::sync::Mutex` is used for the dynamic dispatch push-service vector (`src/main.rs` line 79).

**Trait objects with shared ownership:**
- `Arc<T>` blanket impls of `PushService` are provided in `src/push/mod.rs` lines 27-63 to allow `Arc<UnifiedPushService>` and `Arc<FcmPush>` to be used as `Box<dyn PushService>` while keeping a separate `Arc` reference.

## Configuration & Env Vars

**Loading:**
- All configuration flows through `Config::from_env()` in `src/config.rs`, parsing `std::env` variables with sensible string defaults via `unwrap_or_else`.
- `dotenv::dotenv().ok()` is called once at startup in `src/main.rs` line 26.
- Env var names are `SCREAMING_SNAKE_CASE` (e.g., `NOSTR_RELAYS`, `MOSTRO_PUBKEY`, `FCM_ENABLED`, `UNIFIEDPUSH_ENABLED`, `BATCH_DELAY_MS`, `COOLDOWN_MS`, `SERVER_HOST`, `SERVER_PORT`, `RATE_LIMIT_PER_MINUTE`, `SERVER_PRIVATE_KEY`, `TOKEN_TTL_HOURS`, `CLEANUP_INTERVAL_HOURS`, `FIREBASE_SERVICE_ACCOUNT_PATH`, `FIREBASE_PROJECT_ID`).

**Defaults:**
- Numeric values are parsed via `.parse()?` after `unwrap_or_else` provides a string default. This means defaults are written as strings (e.g., `"5000"`, `"60"`), not typed constants.

## Serialization

**Serde derives:**
- `#[derive(Debug, Clone, Deserialize)]` on config structs (`src/config.rs`).
- `#[derive(Serialize)]` on response DTOs (`src/api/routes.rs`).
- `#[derive(Deserialize)]` on request DTOs.
- `#[derive(Serialize, Deserialize)]` on persisted types (`UnifiedPushEndpoint` in `src/push/unifiedpush.rs` line 14).

**Field-level attributes:**
- `#[serde(skip_serializing_if = "Option::is_none")]` to omit absent fields (e.g., `RegisterResponse::platform` in `src/api/routes.rs` line 32).

**Ad-hoc JSON:**
- `serde_json::json!` macro is used for inline payload construction (e.g., `src/api/routes.rs` lines 53, 71-75, 149-167; `src/push/fcm.rs` lines 169-215).

## Persistence

**On-disk format:**
- `UnifiedPushService` writes `data/unifiedpush_endpoints.json` using `serde_json::to_string_pretty` (`src/push/unifiedpush.rs` lines 73-83).
- Atomic writes via temp-file + rename: write to `*.tmp`, then `fs::rename` to final path.

**In-memory:**
- `TokenStore` is in-memory only (`HashMap` behind `RwLock`), with TTL-based cleanup via a tokio interval task started in `start_cleanup_task` (`src/store/mod.rs` lines 139-153).

---

*Convention analysis: 2026-04-24*
