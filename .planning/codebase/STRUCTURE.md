# Codebase Structure

**Analysis Date:** 2026-04-24

## Directory Layout

```
mostro-push-server/
|-- Cargo.toml                 # Crate manifest (binary `mostro-push-backend` v0.2.0, edition 2021)
|-- Cargo.lock                 # Resolved dependency lockfile
|-- Dockerfile                 # Multi-stage build (rust:1.83 -> debian:bookworm-slim)
|-- docker-compose.yml         # Local Docker Compose definition
|-- fly.toml                   # Fly.io deployment configuration (region gru, port 8080)
|-- deploy-fly.sh              # Fly deploy helper script (executable)
|-- DEPLOY.md                  # Fly.io deployment documentation
|-- BACKEND_UNIFIEDPUSH.md     # Long-form UnifiedPush integration notes
|-- README.md                  # Project overview and quickstart
|-- LICENSE                    # MIT license
|-- config.toml.example        # Example TOML configuration (legacy/optional)
|-- .env                       # Local environment (git-ignored)
|-- .env.example               # Documented environment variables
|-- .gitignore                 # Excludes target, .env, *.json, secrets/, *.log
|-- test_server.sh             # Integration smoke-test script (executable)
|-- docs/                      # Long-form documentation
|   |-- README.md
|   |-- architecture.md
|   |-- api.md
|   |-- configuration.md
|   |-- cryptography.md
|   |-- deployment.md
|   `-- IMPLEMENTATION_PHASES.md
|-- secrets/                   # Service-account JSON (git-ignored; copied into Docker image)
|   `-- mostro-mobile-firebase-adminsdk-*.json
|-- src/                       # Rust sources
|   |-- main.rs                # Binary entry point and wiring
|   |-- config.rs              # Environment-based typed configuration
|   |-- api/
|   |   |-- mod.rs             # `pub mod routes;`
|   |   `-- routes.rs          # Actix HTTP handlers and `AppState`
|   |-- nostr/
|   |   |-- mod.rs             # Re-exports `NostrListener`
|   |   `-- listener.rs        # Nostr relay subscription and push dispatch
|   |-- push/
|   |   |-- mod.rs             # `PushService` trait + Arc blanket impls
|   |   |-- fcm.rs             # Firebase Cloud Messaging backend
|   |   `-- unifiedpush.rs     # UnifiedPush backend (degoogled Android)
|   |-- store/
|   |   `-- mod.rs             # `TokenStore`, `Platform`, cleanup task
|   |-- crypto/
|   |   `-- mod.rs             # Phase 4 ECDH/ChaCha20 token decryption
|   `-- utils/
|       |-- mod.rs             # `pub mod batching;`
|       `-- batching.rs        # `BatchingManager` skeleton
|-- target/                    # Cargo build artifacts (git-ignored)
|-- .planning/                 # GSD planning artifacts
|   `-- codebase/              # Codebase mapper outputs
`-- .git/                      # Git metadata
```

## Directory Purposes

**`src/`:**
- Purpose: All Rust source code for the `mostro-push-backend` binary crate.
- Contains: One module per concern (api, nostr, push, store, crypto, utils, config) plus `main.rs`.
- Key files: `src/main.rs`, `src/config.rs`.

**`src/api/`:**
- Purpose: HTTP layer (Actix-web).
- Contains: `mod.rs` (re-export) and `routes.rs` (handlers, request/response DTOs, `AppState`, `configure`).
- Key files: `src/api/routes.rs`.

**`src/nostr/`:**
- Purpose: Nostr relay subscription and event-driven dispatch to push services.
- Contains: `mod.rs` (re-exports `NostrListener`) and `listener.rs` (reconnect loop and notification handler).
- Key files: `src/nostr/listener.rs`.

**`src/push/`:**
- Purpose: Push notification abstraction and concrete backends.
- Contains: `mod.rs` (`PushService` trait + `Arc` blanket impls), `fcm.rs` (Firebase v1 API), `unifiedpush.rs` (UnifiedPush HTTP POST + JSON persistence).
- Key files: `src/push/mod.rs`, `src/push/fcm.rs`, `src/push/unifiedpush.rs`.

**`src/store/`:**
- Purpose: In-memory token store, platform enum, and TTL cleanup task.
- Contains: `mod.rs` only (single-file module).
- Key files: `src/store/mod.rs`.

**`src/crypto/`:**
- Purpose: ECDH-based token decryption planned for Phase 4 (currently `#[allow(dead_code)]`).
- Contains: `mod.rs` only.
- Key files: `src/crypto/mod.rs`.

**`src/utils/`:**
- Purpose: Cross-cutting helpers.
- Contains: `mod.rs` and `batching.rs` (`BatchingManager` skeleton).
- Key files: `src/utils/batching.rs`.

**`docs/`:**
- Purpose: Project documentation - architecture, API reference, cryptography spec, deployment guide, configuration reference, implementation phases.
- Contains: Markdown files only.
- Key files: `docs/architecture.md`, `docs/api.md`, `docs/cryptography.md`, `docs/IMPLEMENTATION_PHASES.md`.

**`secrets/`:**
- Purpose: Hold the Firebase service-account JSON used by `FcmPush` to obtain OAuth2 access tokens.
- Contents: `mostro-mobile-firebase-adminsdk-*.json` (existence noted; contents not read - this file contains credentials).
- Generated: No.
- Committed: Excluded by `.gitignore` (`secrets/`, `*.json`).

**`target/`:**
- Purpose: Cargo build outputs.
- Generated: Yes (by `cargo build`).
- Committed: No.

**`.planning/codebase/`:**
- Purpose: GSD codebase mapping artifacts produced by `gsd-map-codebase`.
- Generated: Yes (by tooling).

## Key File Locations

**Entry Points:**
- `src/main.rs`: Tokio/Actix `main`, wires config, store, listener, push services, HTTP server.
- `src/api/routes.rs`: HTTP route definitions under `/api`.

**Configuration:**
- `src/config.rs`: Typed `Config` struct and `from_env`.
- `.env.example`: Documented environment variables (`NOSTR_RELAYS`, `MOSTRO_PUBKEY`, `SERVER_PRIVATE_KEY`, `FIREBASE_PROJECT_ID`, `FIREBASE_SERVICE_ACCOUNT_PATH`, `UNIFIEDPUSH_ENABLED`, `FCM_ENABLED`, `SERVER_HOST`, `SERVER_PORT`, `TOKEN_TTL_HOURS`, `CLEANUP_INTERVAL_HOURS`, `RATE_LIMIT_PER_MINUTE`, `BATCH_DELAY_MS`, `COOLDOWN_MS`, `RUST_LOG`).
- `config.toml.example`: Example TOML (legacy/optional).
- `fly.toml`: Fly.io app config (`primary_region = 'gru'`, `internal_port = 8080`, `min_machines_running = 1`).
- `Dockerfile`: Build/runtime image specification.

**Core Logic:**
- `src/nostr/listener.rs`: Nostr subscription, reconnect, push trigger.
- `src/store/mod.rs`: `TokenStore`, `Platform`, `RegisteredToken`, `start_cleanup_task`.
- `src/push/mod.rs`: `PushService` trait.
- `src/push/fcm.rs`: FCM v1 with OAuth2 JWT-bearer auth.
- `src/push/unifiedpush.rs`: UnifiedPush POST + on-disk endpoint persistence.

**Phase 4 / Future:**
- `src/crypto/mod.rs`: ECDH + ChaCha20-Poly1305 decryption, gated `#[allow(dead_code)]` in `src/main.rs:14-15`.
- `src/utils/batching.rs`: `BatchingManager` skeleton.

**Testing:**
- `test_server.sh`: Shell-based smoke test against the running server.
- `src/crypto/mod.rs` lines 453-823: unit tests for crypto roundtrips.
- No top-level `tests/` directory.
- `Cargo.toml` declares `mockito = "1.2"` under `[dev-dependencies]`.

**Deployment:**
- `Dockerfile`: Two-stage build (`rust:1.83` builder -> `debian:bookworm-slim` runtime). Copies `secrets/` into `/secrets/` in the final image.
- `docker-compose.yml`: Local Docker Compose definition.
- `fly.toml` + `deploy-fly.sh`: Fly.io deployment.
- `DEPLOY.md`: Deployment notes.

## Naming Conventions

**Files:**
- Rust source files use `snake_case.rs` (e.g., `listener.rs`, `unifiedpush.rs`, `batching.rs`).
- Each module that needs submodules uses a directory plus `mod.rs` (e.g., `src/api/mod.rs`, `src/push/mod.rs`); single-file modules collapse to `<dir>/mod.rs` (e.g., `src/store/mod.rs`, `src/crypto/mod.rs`).
- Documentation files in `docs/` use lowercase with optional `_` separators (`architecture.md`); `IMPLEMENTATION_PHASES.md` is the exception (SCREAMING_SNAKE_CASE).
- Top-level project docs use SCREAMING_SNAKE_CASE markdown (`README.md`, `DEPLOY.md`, `BACKEND_UNIFIEDPUSH.md`, `LICENSE`).
- Shell scripts use lowercase with `-` and `_` (`deploy-fly.sh`, `test_server.sh`).

**Directories:**
- All-lowercase, no separators (`api`, `nostr`, `push`, `store`, `crypto`, `utils`, `docs`, `secrets`).

**Rust identifiers (observed):**
- Modules: `snake_case` (`api`, `nostr`, `push`, `store`, `crypto`, `utils`).
- Types/structs/enums: `PascalCase` (`Config`, `NostrListener`, `PushService`, `FcmPush`, `UnifiedPushService`, `TokenStore`, `RegisteredToken`, `Platform`, `AppState`, `RegisterTokenRequest`).
- Functions and methods: `snake_case` (`register_token`, `get_access_token`, `cleanup_expired`, `start_cleanup_task`, `send_to_token`).
- Constants: `SCREAMING_SNAKE_CASE` (`HKDF_SALT`, `HKDF_INFO`, `PLATFORM_ANDROID`, `PLATFORM_IOS`, `PADDED_PAYLOAD_SIZE`, `EPHEMERAL_PUBKEY_SIZE`, `NONCE_SIZE`, `AUTH_TAG_SIZE`, `ENCRYPTED_TOKEN_SIZE` in `src/crypto/mod.rs:12-22`).
- Environment variables: `SCREAMING_SNAKE_CASE` (`NOSTR_RELAYS`, `MOSTRO_PUBKEY`, `SERVER_PRIVATE_KEY`, `FIREBASE_SERVICE_ACCOUNT_PATH`).

## Where to Add New Code

**New HTTP endpoint:**
- Add handler function and DTOs in `src/api/routes.rs`.
- Register the route in `configure(cfg: &mut web::ServiceConfig)` at `src/api/routes.rs:41-49`.
- If new shared state is required, extend `AppState` (`src/api/routes.rs:36-39`) and update construction in `src/main.rs:93-95`.

**New push backend:**
- Create `src/push/<backend>.rs`.
- Implement `#[async_trait] impl PushService for <Backend>` providing `send_silent_push`, `send_to_token`, `supports_platform`.
- Add a blanket `impl PushService for Arc<<Backend>>` in `src/push/mod.rs` mirroring the existing FCM/UnifiedPush impls (`src/push/mod.rs:27-63`).
- Wire it up in `src/main.rs` next to the existing `if config.push.fcm_enabled { ... }` and `if config.push.unifiedpush_enabled { ... }` blocks (`src/main.rs:57-77`).
- Extend `PushConfig` in `src/config.rs:22-28` with an enable flag and any backend-specific env vars.

**New configuration option:**
- Add a field to the relevant `*Config` struct in `src/config.rs`.
- Read it in `Config::from_env()` (`src/config.rs:52-115`) using `env::var(...)` with a default.
- Document it in `.env.example` and `docs/configuration.md`.

**New persisted state:**
- For ephemeral runtime state, extend `TokenStore` in `src/store/mod.rs` (or create a new in-memory store module).
- For on-disk persistence, follow the UnifiedPush atomic-write pattern in `src/push/unifiedpush.rs:73-83` (write to `<path>.tmp`, then `fs::rename`).

**New Nostr event handling:**
- Currently the listener handles only `kind 1059`. To handle additional kinds, modify the `Filter::new().kinds(...)` builder in `src/nostr/listener.rs:77-79` and the `if event.kind == Kind::Custom(1059)` branch in `src/nostr/listener.rs:92`.

**Shared utilities:**
- Add new helper modules under `src/utils/` and re-export from `src/utils/mod.rs`.

**Cryptographic primitives (Phase 4):**
- Extend `src/crypto/mod.rs`. To activate the module, remove `#[allow(dead_code)]` from `src/main.rs:14-15` and instantiate `TokenCrypto::new(&config.crypto.server_private_key)` during startup.

**Tests:**
- Unit tests: add `#[cfg(test)] mod tests { ... }` blocks at the bottom of the relevant `*.rs` file.
- Integration tests: create `tests/<name>.rs` at the crate root (no `tests/` directory exists yet; `mockito` is already in `[dev-dependencies]`).

## Special Directories

**`secrets/`:**
- Purpose: Holds the Firebase service-account JSON consumed by `FcmPush::new` (`src/push/fcm.rs:50-83`) when `FIREBASE_SERVICE_ACCOUNT_PATH` points to a file.
- Contents: `mostro-mobile-firebase-adminsdk-fbsvc-1ff8f6232c.json`.
- Generated: No (operator-supplied).
- Committed: No (`.gitignore` excludes `secrets/` and `*.json`).
- Note: `Dockerfile:16` copies `secrets/` into the image, so the credential is baked into builds.

**`target/`:**
- Purpose: Cargo build artifacts.
- Generated: Yes (by `cargo build`).
- Committed: No.

**`data/` (created at runtime):**
- Purpose: Persistence for `UnifiedPushService` endpoints.
- Generated: Yes - `src/push/unifiedpush.rs:30` sets `storage_path = "data/unifiedpush_endpoints.json"` and `load_endpoints` calls `fs::create_dir_all` if missing (`src/push/unifiedpush.rs:42-45`).
- Committed: No.

**`.planning/`:**
- Purpose: GSD command artifacts (codebase maps, plans).
- Generated: Yes (by tooling).

**`docs/`:**
- Purpose: Authoritative long-form documentation. `docs/architecture.md` contains a hand-written architecture overview; `docs/IMPLEMENTATION_PHASES.md` defines the Phase 1-5 roadmap (current state is Phase 3, Phase 4 will activate `src/crypto/`).

---

*Structure analysis: 2026-04-24*
