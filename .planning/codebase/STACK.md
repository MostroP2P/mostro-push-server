# Technology Stack

**Analysis Date:** 2026-04-24

## Languages

**Primary:**
- Rust (edition 2021) - Entire backend implementation under `src/`

**Secondary:**
- Bash - Deployment and test scripts: `deploy-fly.sh`, `test_server.sh`
- TOML - Project and runtime configuration: `Cargo.toml`, `fly.toml`, `config.toml.example`
- Dockerfile / YAML - Container build and orchestration: `Dockerfile`, `docker-compose.yml`

## Runtime

**Environment:**
- Rust toolchain >= 1.75 (README requirement); Docker base image pinned to `rust:1.83` in `Dockerfile`
- Async runtime: Tokio 1.35 with the `full` feature flag (`Cargo.toml:13`)
- HTTP runtime: Actix runtime via `actix-rt = "2.9"` (`Cargo.toml:9`)
- Production base image: `debian:bookworm-slim` (`Dockerfile:9`)

**Package Manager:**
- Cargo (Rust standard)
- Lockfile: present (`Cargo.lock`, committed and copied into Docker build at `Dockerfile:4`)

## Frameworks

**Core:**
- `actix-web = "4.4"` - HTTP server and routing (`src/main.rs`, `src/api/routes.rs`)
- `actix-rt = "2.9"` - Actix async runtime
- `tokio = "1.35"` - Async runtime, channels, sync primitives, background tasks
- `tokio-tungstenite = "0.21"` - WebSocket client library (declared in `Cargo.toml:12`; Nostr relay traffic actually flows via `nostr-sdk`)
- `nostr-sdk = "0.27"` - Nostr protocol client used in `src/nostr/listener.rs`

**Testing:**
- `mockito = "1.2"` - HTTP mocking for unit tests, declared in `[dev-dependencies]` (`Cargo.toml:55-56`)
- Built-in `cargo test` runner (no integration test suite present in repo)

**Build/Dev:**
- `cargo build --release` - Production build (used in `Dockerfile:7` and README workflow)
- `cargo run` - Development runner
- `cargo clippy` - Linting (referenced in `README.md`)
- `cargo fmt` - Formatting (referenced in `README.md`)

## Key Dependencies

**Critical:**
- `nostr-sdk = "0.27"` - Subscribes to Nostr relays, parses Gift Wrap (kind 1059) events (`src/nostr/listener.rs:2`)
- `actix-web = "4.4"` - REST API surface for token registration (`src/api/routes.rs:1`)
- `reqwest = "0.11"` (with `json` feature) - HTTPS client for FCM v1 API and UnifiedPush endpoint POSTs (`src/push/fcm.rs:3`, `src/push/unifiedpush.rs:4`)
- `jsonwebtoken = "9"` - Signs RS256 JWTs for Firebase OAuth2 token exchange (`src/push/fcm.rs:8`)
- `serde = "1.0"` (`derive`) and `serde_json = "1.0"` - Configuration, request bodies, FCM payloads, persisted endpoint store
- `tokio` (`full`) - Concurrency primitives (`Mutex`, `RwLock`), background tasks, time intervals
- `chrono = "0.4"` (`serde`) - Timestamps for token TTL and registration metadata (`src/store/mod.rs:1`)

**Cryptography stack (currently scaffolded for Phase 4, not active):**
- `secp256k1 = "0.28"` (`rand-std` feature) - Public/secret key handling (`src/crypto/mod.rs:8`)
- `chacha20poly1305 = "0.10"` - AEAD cipher for token decryption
- `hkdf = "0.12"` and `sha2 = "0.10"` - Key derivation
- `rand = "0.8"`, `hex = "0.4"`, `base64 = "0.21"` - Encoding helpers
- The `crypto` module is gated with `#[allow(dead_code)]` in `src/main.rs:13-15`

**Infrastructure / Utilities:**
- `config = "0.14"` - Configuration loader (declared in `Cargo.toml:30`; runtime config currently uses `std::env` directly in `src/config.rs`)
- `dotenv = "0.15"` - Loads `.env` at startup (`src/main.rs:26`)
- `env_logger = "0.11"` and `log = "0.4"` - Logging facade and stdout backend
- `governor = "0.6"` - Rate-limiting primitive (declared, not yet wired into request handlers)
- `futures = "0.3"` and `async-trait = "0.1"` - Async trait support (`src/push/mod.rs:1`)

## Configuration

**Environment:**
- Loaded from process env (and `.env` via `dotenv`) inside `Config::from_env()` at `src/config.rs:53-115`
- Notable variables: `NOSTR_RELAYS`, `MOSTRO_PUBKEY`, `SERVER_PRIVATE_KEY`, `FIREBASE_PROJECT_ID`, `FIREBASE_SERVICE_ACCOUNT_PATH`, `FCM_ENABLED`, `UNIFIEDPUSH_ENABLED`, `SERVER_HOST`, `SERVER_PORT`, `TOKEN_TTL_HOURS`, `CLEANUP_INTERVAL_HOURS`, `RATE_LIMIT_PER_MINUTE`, `BATCH_DELAY_MS`, `COOLDOWN_MS`, `RUST_LOG`
- Reference template: `.env.example`
- Local development env file: `.env` (gitignored, contents not inspected)
- Alternative TOML template: `config.toml.example` (exists but not currently parsed by `Config::from_env`)

**Build:**
- `Cargo.toml` - Crate manifest and dependency graph
- `Cargo.lock` - Pinned dependency versions
- `Dockerfile` - Multi-stage build (rust:1.83 builder -> debian:bookworm-slim runtime)
- `docker-compose.yml` - Local container orchestration with Firebase JSON volume mount
- `fly.toml` - Fly.io deployment manifest (region `gru`, internal port 8080, 512mb VM)
- `deploy-fly.sh` - Idempotent secrets-set + `flyctl deploy` wrapper

## Platform Requirements

**Development:**
- Rust toolchain (1.75+ per `README.md`, 1.83 per Docker builder)
- Cargo
- Optional: Docker / docker-compose for containerized runs
- Optional: `flyctl` for Fly.io deploys

**Production:**
- Primary deployment target: Fly.io (`fly.toml`, app name `mostro-push-server`, region `gru`)
- Container image built via `Dockerfile` (multi-stage, Debian slim runtime)
- Outbound network access required to:
  - Nostr relay(s) over WSS (e.g. `wss://relay.mostro.network`)
  - `https://oauth2.googleapis.com/token` (Firebase OAuth2)
  - `https://fcm.googleapis.com/v1/projects/{project_id}/messages:send` (FCM v1)
  - UnifiedPush distributor endpoints (arbitrary HTTPS URLs supplied by clients)
- Persistent local filesystem for `data/unifiedpush_endpoints.json` (`src/push/unifiedpush.rs:30`)
- Firebase service account JSON file mounted into the container (Fly.io path `/secrets/...` per `deploy-fly.sh`)

---

*Stack analysis: 2026-04-24*
