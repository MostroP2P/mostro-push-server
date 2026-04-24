# External Integrations

**Analysis Date:** 2026-04-24

## APIs & External Services

**Nostr protocol:**
- Service: Nostr relay(s), default `wss://relay.mostro.network`
- Purpose: Subscribe to kind 1059 (Gift Wrap) events whose `p` tag identifies a recipient `trade_pubkey`
- SDK/Client: `nostr-sdk = "0.27"` (`src/nostr/listener.rs:2`)
- Connection lifecycle: ephemeral key generation, relay add + connect, filter subscription, infinite reconnect loop with backoff (`src/nostr/listener.rs:42-148`)
- Configuration: `NOSTR_RELAYS` (comma-separated), `MOSTRO_PUBKEY` (consumed at `src/config.rs:54-72`)
- Auth: none (public relay, ephemeral key per session generated via `Keys::generate()` at `src/nostr/listener.rs:61`)

**Firebase Cloud Messaging (FCM v1):**
- Service: Google FCM HTTP v1 API
- Purpose: Deliver push notifications to Android and iOS device tokens
- SDK/Client: `reqwest` HTTP client invoking REST endpoints directly (`src/push/fcm.rs`)
- Endpoints used:
  - `POST https://oauth2.googleapis.com/token` for OAuth2 JWT-bearer access token exchange (`src/push/fcm.rs:132`)
  - `POST https://fcm.googleapis.com/v1/projects/{project_id}/messages:send` for notification delivery (`src/push/fcm.rs:225`, `src/push/fcm.rs:277`)
- Auth: Service-account JWT (RS256) signed by `jsonwebtoken` and exchanged for a 1h bearer token; cached in-memory (`src/push/fcm.rs:95-158`)
- Scope requested: `https://www.googleapis.com/auth/firebase.messaging`
- Configuration: `FIREBASE_PROJECT_ID`, `FIREBASE_SERVICE_ACCOUNT_PATH` (read at `src/push/fcm.rs:52-75`)
- Conditional init: only enabled when `FCM_ENABLED=true` and the service-account JSON loads successfully (`src/main.rs:57-72`)

**UnifiedPush:**
- Service: Arbitrary UnifiedPush distributor endpoints (one HTTPS URL per registered device)
- Purpose: Deliver push notifications to degoogled Android (GrapheneOS, LineageOS) clients
- SDK/Client: `reqwest` POSTing JSON to the client-provided endpoint URL (`src/push/unifiedpush.rs:140-192`)
- Auth: none on the outbound POST; trust is established at registration time
- Configuration: `UNIFIEDPUSH_ENABLED` (`src/config.rs:78`); endpoints managed at runtime via the registration store

## Data Storage

**Databases:**
- None. The system has no relational or NoSQL database dependency.

**In-memory state:**
- Token store: `tokio::sync::RwLock<HashMap<String, RegisteredToken>>` keyed by `trade_pubkey` (`src/store/mod.rs:30-41`)
  - TTL configurable via `TOKEN_TTL_HOURS` (default 48h)
  - Background cleanup task scheduled via `start_cleanup_task` at `src/store/mod.rs:139-153`
- FCM access-token cache: `Arc<RwLock<Option<CachedToken>>>` (`src/push/fcm.rs:38-48`)
- UnifiedPush endpoints (in-memory mirror): `RwLock<HashMap<String, UnifiedPushEndpoint>>` (`src/push/unifiedpush.rs:21-26`)

**File Storage:**
- Local filesystem JSON file for UnifiedPush endpoints
  - Path: `data/unifiedpush_endpoints.json` (`src/push/unifiedpush.rs:30`)
  - Atomic write via temp file + rename (`src/push/unifiedpush.rs:73-83`)
  - Loaded at startup in `src/main.rs:52-54`
- Firebase service-account JSON
  - Path supplied by `FIREBASE_SERVICE_ACCOUNT_PATH`
  - In production deploys: mounted under `/secrets/` in the container (`Dockerfile:16`, `deploy-fly.sh:32`)

**Caching:**
- FCM OAuth2 access-token caching with 60s pre-expiry refresh (`src/push/fcm.rs:96-156`)
- No external cache (Redis, Memcached, etc.)

## Authentication & Identity

**Auth Provider:**
- None for the public HTTP API. `POST /api/register` and `POST /api/unregister` accept any well-formed `trade_pubkey` (`src/api/routes.rs:78-167`).
- Outbound auth to Firebase: service-account JWT-bearer flow only (see FCM section)

**Identity model:**
- Users are identified by Nostr `trade_pubkey` (64 hex chars, validated in `src/api/routes.rs:86-92`)
- Server-side ephemeral Nostr keys generated per relay session (`src/nostr/listener.rs:61`)
- A long-lived `SERVER_PRIVATE_KEY` (secp256k1, hex) is configured for forthcoming Phase 4 token decryption but is not currently exercised by request paths (see `src/crypto/mod.rs`, gated by `#[allow(dead_code)]` in `src/main.rs:13-15`)

## Monitoring & Observability

**Error Tracking:**
- None. No Sentry, Honeycomb, or equivalent SDK is integrated.

**Logs:**
- `log` facade + `env_logger` backend, initialized at `src/main.rs:25`
- Verbosity controlled by `RUST_LOG` (defaults documented in `.env.example`; production uses `debug` per `deploy-fly.sh:42`)
- Logs are written to stdout/stderr; aggregation handled by the deployment platform (Fly.io / Docker)

**Metrics:**
- None. README explicitly lists Prometheus metrics as TODO (`README.md:341-343`).

## CI/CD & Deployment

**Hosting:**
- Primary: Fly.io
  - Manifest: `fly.toml`
  - App name: `mostro-push-server`
  - Region: `gru` (São Paulo)
  - VM: 1 CPU, 512MB
  - HTTPS forced; HTTP/HTTPS service mapped to internal port 8080
  - `auto_stop_machines = 'off'`, `min_machines_running = 1` (warm always-on)
- Alternative: any Docker host (`Dockerfile`, `docker-compose.yml`)

**CI Pipeline:**
- No pipeline detected (no `.github/workflows/`, no `.gitlab-ci.yml`, no `circle.yml`).
- Manual deploy via `deploy-fly.sh` which sets all secrets then runs `flyctl deploy`.

## Environment Configuration

**Required env vars:**
- `NOSTR_RELAYS` - comma-separated WSS relay URLs (no default; `src/config.rs:54`)
- `MOSTRO_PUBKEY` - 64 hex chars; defaults present in `src/config.rs:60-72` if unset
- `SERVER_PRIVATE_KEY` - 64 hex chars; required for future encrypted-token phase, currently has insecure default in `src/config.rs:103-104`
- `FIREBASE_PROJECT_ID` - required when FCM is enabled (default `mostro` at `src/push/fcm.rs:54`)
- `FIREBASE_SERVICE_ACCOUNT_PATH` - filesystem path to service-account JSON; absence disables FCM gracefully (`src/main.rs:67-71`)
- `FCM_ENABLED`, `UNIFIEDPUSH_ENABLED` - toggle each push service (default `true`)
- `SERVER_HOST` (default `0.0.0.0`), `SERVER_PORT` (default `8080`)
- `TOKEN_TTL_HOURS` (default 48), `CLEANUP_INTERVAL_HOURS` (default 1)
- `RATE_LIMIT_PER_MINUTE` (default 60), `BATCH_DELAY_MS` (default 5000), `COOLDOWN_MS` (default 60000)
- `RUST_LOG` (default `info`)

**Secrets location:**
- Local development: `.env` file at repo root (gitignored)
- Production: Fly.io secrets store, set via `deploy-fly.sh`
- Firebase service-account JSON: copied into image from `secrets/` (`Dockerfile:16`) and mounted at `/secrets/<file>.json`; `secrets/` is gitignored (`.gitignore:32`)

## Webhooks & Callbacks

**Incoming HTTP API (`src/api/routes.rs:41-50`):**
- `GET  /api/health` - liveness probe, returns `{"status":"ok"}`
- `GET  /api/status` - server status with token store stats
- `GET  /api/info` - server metadata; currently exposes `encryption_enabled: false`
- `POST /api/register` - body `{ trade_pubkey, token, platform }`; stores plaintext device token (Phase 3)
- `POST /api/unregister` - body `{ trade_pubkey }`; removes mapping

**Incoming Nostr subscription:**
- Persistent WSS subscription to kind 1059 events with `since = now - 60s` filter (`src/nostr/listener.rs:76-83`)
- Recipient resolution by scanning the event's `p` tag (`src/nostr/listener.rs:97-105`)

**Outgoing:**
- `POST` to FCM v1 messages endpoint (per token, with both `notification` and `data` payloads; Android `tag`/`channel_id` and APNs `apns-collapse-id`/`thread-id` set to `mostro-trade`) (`src/push/fcm.rs:168-215`)
- `POST` to UnifiedPush distributor URLs supplied by clients (`src/push/unifiedpush.rs:140-192`); payload `{ "type": "silent_wake", "timestamp": <unix> }`
- `POST` to `https://oauth2.googleapis.com/token` for FCM access-token refresh (`src/push/fcm.rs:132`)

---

*Integration audit: 2026-04-24*
