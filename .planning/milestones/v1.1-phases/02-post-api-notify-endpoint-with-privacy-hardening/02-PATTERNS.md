# Phase 2: POST /api/notify endpoint with privacy hardening - Pattern Map

**Mapped:** 2026-04-25
**Files analyzed:** 10 (3 created, 7 modified)
**Analogs found:** 9 / 10 (1 file has no in-tree analog: `docs/verification/dispute-chat.md`)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| **CREATE** `src/api/notify.rs` | controller + middleware | request-response (handler) + event-driven (spawned dispatch) | `src/api/routes.rs::register_token` (lines 78-137) | exact role, role-match data flow (handler is fire-and-forget vs synchronous CRUD) |
| **CREATE** `src/utils/log_pubkey.rs` | utility | transform (pure fn) | `src/utils/batching.rs` (module shape) + `src/crypto/mod.rs` (keyed-hash usage) | role-match (utility), no exact data-flow analog |
| **CREATE** `docs/verification/dispute-chat.md` | doc / runbook | n/a | none in-tree (no `docs/verification/` exists; closest neighbours are `docs/api.md`, `docs/architecture.md`) | no analog — green-field doc |
| **MODIFY** `src/main.rs` | composition root | startup wiring | `src/main.rs` itself (lines 22-114) — the section being modified | exact (self-analog) |
| **MODIFY** `src/api/routes.rs` | controller wiring | request-response | `src/api/routes.rs::AppState` (lines 36-39) + `configure()` (lines 41-49) | exact (self-analog) |
| **MODIFY** `src/api/mod.rs` | module barrel | n/a | `src/api/mod.rs` (single `pub mod routes;` line) | exact (self-analog) |
| **MODIFY** `src/push/fcm.rs` | service | request-response (HTTP to FCM) + transform (payload builder) | `FcmPush::build_payload_for_token` (lines 168-215) for the new builder; `FcmPush::new` (lines 51-83) for the constructor cascade | exact (sibling fn next to existing builder) |
| **MODIFY** `src/push/unifiedpush.rs` | service | request-response | `UnifiedPushService::new` (lines 28-38) | exact (constructor signature change only) |
| **MODIFY** `src/push/dispatcher.rs` | service | event-driven dispatch | `PushDispatcher::dispatch` (lines 45-77) | exact (sibling method, same backend-selection algorithm) |
| **MODIFY** `Cargo.toml` | manifest | n/a | existing `[dependencies]` block (lines 6-53) | exact (self-analog) |
| **MODIFY** `deploy-fly.sh` | deploy script | n/a | line 42 (the `RUST_LOG="debug"` line being flipped) | exact (single-line edit) |

> Note: `src/utils/mod.rs` is touched only to add `pub mod log_pubkey;` — listed under the modified-files cascade for `src/utils/log_pubkey.rs`, not as its own row.

---

## Pattern Assignments

### CREATE `src/utils/log_pubkey.rs` (utility, transform)

**Analog:** `src/utils/batching.rs` (module shape only — there is no in-tree keyed-hash usage, since `src/crypto/mod.rs` uses raw HKDF, not BLAKE3).

**Module shape pattern** (from `src/utils/batching.rs:1-7`):

```rust
use tokio::time::Instant;

pub struct BatchingManager {
    batch_delay_ms: u64,
    last_sent: Option<Instant>,
    pending_send: Option<tokio::task::JoinHandle<()>>,
}
```

**Mirror as-is:** the "single-purpose helper module under `src/utils/`" convention — one struct or one function per file, no re-exports, registered via `pub mod <name>;` in `src/utils/mod.rs`.

**Net-new content** (no analog, follows RESEARCH § Pattern 3 verbatim):

```rust
//! Salted, truncated pubkey hashing for privacy-safe operator logs.
//!
//! Per Phase 2 D-14 (PRIV-01): used ONLY in the /api/notify handler and its
//! spawned dispatch task. Existing pubkey-prefix logs in src/nostr/listener.rs,
//! src/api/routes.rs, and src/store/mod.rs are intentionally NOT migrated to
//! preserve operator grep-ability through the transition.

/// Salted truncated BLAKE3 keyed-hash of a pubkey, for log correlation.
pub fn log_pubkey(salt: &[u8; 32], pk: &str) -> String {
    let hash = blake3::keyed_hash(salt, pk.as_bytes());
    hash.to_hex()[..8].to_string()
}
```

**Doc-comment style mirror** — see `src/crypto/mod.rs` `///`-style banner comments and the file-level `//!` banner used in `src/api/routes.rs`. Use `//!` for module-level intent + `///` for the public function (matches CONVENTIONS.md "Multi-line `///` doc comments document public API").

**Cascade modification** to `src/utils/mod.rs` (currently `pub mod batching;` — line 1):

```rust
pub mod batching;
pub mod log_pubkey;   // new
```

**Pitfalls:**
- Do NOT import `sha2::Sha256` here even though it is already declared (the user picked BLAKE3 explicitly per D-16; HMAC-SHA256 would work but is the rejected alternative).
- Function returns owned `String` (not `&str`) because `to_hex()` returns an `arrayvec::ArrayString` whose lifetime would not survive the function. The owned-String allocation is one per log line, acceptable.

---

### CREATE `src/api/notify.rs` (controller + middleware, request-response + event-driven)

**Analog:** `src/api/routes.rs::register_token` (lines 78-137).

**Imports pattern** (from `src/api/routes.rs:1-6`):

```rust
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use log::{info, warn};
use std::sync::Arc;

use crate::store::{TokenStore, TokenStoreStats, Platform};
```

**Mirror as-is:** import grouping (actix-web → serde → log → std → crate). `Arc` from `std::sync` (already used in routes.rs).

**Adapt:** add `use serde_json::json;`, `use crate::api::routes::AppState;`, `use crate::utils::log_pubkey::log_pubkey;`, plus middleware imports (`actix_web::dev::{ServiceRequest, ServiceResponse}`, `actix_web::body::MessageBody`, `actix_web::middleware::Next`, `actix_web::http::header::{HeaderName, HeaderValue}`).

**Request DTO pattern** (from `src/api/routes.rs:9-14`):

```rust
#[derive(Deserialize)]
pub struct RegisterTokenRequest {
    pub trade_pubkey: String,
    pub token: String,
    pub platform: String,
}
```

**Mirror as-is:** `#[derive(Deserialize)]` on request body struct, `pub` fields, `String` for hex-encoded values. The new `NotifyRequest` is `{ pub trade_pubkey: String }` only — a single field per OOS-11 / AF-3 (no `sender_pubkey`).

**Validation pattern** (from `src/api/routes.rs:86-93`):

```rust
// Validate trade_pubkey format (should be 64 hex chars)
if req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err() {
    warn!("Invalid trade_pubkey format");
    return HttpResponse::BadRequest().json(RegisterResponse {
        success: false,
        message: "Invalid trade_pubkey format (expected 64 hex characters)".to_string(),
        platform: None,
    });
}
```

**Mirror as-is:** the exact predicate `req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err()` and the `warn!` + `HttpResponse::BadRequest().json(...)` early-return shape.

**Adapt:** the response body type — per RESEARCH Pitfall 5 (lines 677-695), define a local `NotifyError { success: bool, message: String }` in `notify.rs` rather than importing `RegisterResponse`. Same operator-visible JSON shape (minus the optional `platform` field), zero cross-file COMPAT-1 coupling.

**Handler-state extraction pattern** (from `src/api/routes.rs:78-83`):

```rust
async fn register_token(
    state: web::Data<AppState>,
    req: web::Json<RegisterTokenRequest>,
) -> impl Responder {
    info!("Registering token for trade_pubkey: {}...",
        &req.trade_pubkey[..16.min(req.trade_pubkey.len())]);
```

**Mirror as-is:** the `(state: web::Data<AppState>, req: web::Json<...>) -> impl Responder` signature.

**Adapt — DO NOT mirror the log line:** the `&req.trade_pubkey[..16.min(...)]` prefix-truncation is the legacy pattern that D-14 explicitly does NOT migrate retroactively. The new handler uses `log_pubkey(&state.notify_log_salt, &req.trade_pubkey)` instead. This is the load-bearing privacy delta of Phase 2 in this file.

**Net-new — bounded spawn pattern** (no analog in repo; from RESEARCH § Pattern 2 + Code Examples lines 754-814):

```rust
match Arc::clone(&state.semaphore).try_acquire_owned() {
    Ok(permit) => {
        let dispatcher = Arc::clone(&state.dispatcher);
        let token_store = Arc::clone(&state.token_store);
        let salt = Arc::clone(&state.notify_log_salt);
        let pubkey = req.trade_pubkey.clone();
        let task_log_pk = log_pk.clone();

        tokio::spawn(async move {
            let _permit = permit;   // dropped at task end; releases slot.

            if let Some(token) = token_store.get(&pubkey).await {
                match dispatcher.dispatch_silent(&token).await {
                    Ok(outcome) => info!(
                        "notify: dispatched pk={} backend={:?}",
                        task_log_pk, outcome
                    ),
                    Err(e) => warn!(
                        "notify: dispatch failed pk={} err={}",
                        task_log_pk, e
                    ),
                }
            }
            // None case (pubkey not registered): silently no-op.
            // Caller already received 202 (anti-CRIT-2 / anti-CRIT-6).
        });
    }
    Err(_) => {
        warn!("notify: spawn pool saturated, dropping dispatch");
    }
}

// Always 202, regardless of which branch ran above:
HttpResponse::Accepted().json(json!({"accepted": true}))
```

**Net-new — middleware** (no in-tree analog; the project has zero existing middleware. RESEARCH § Pattern 1 verbatim):

```rust
use actix_web::{
    dev::{ServiceRequest, ServiceResponse},
    body::MessageBody,
    middleware::Next,
    Error,
    http::header::{HeaderName, HeaderValue},
};

pub async fn request_id_mw(
    mut req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    // Strip any client-supplied X-Request-Id (privacy: client cannot correlate
    // its own requests with server state).
    req.headers_mut().remove("x-request-id");

    let id = uuid::Uuid::new_v4().to_string();
    let mut res = next.call(req).await?;

    res.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&id).expect("uuid string is always valid header value"),
    );
    Ok(res)
}
```

**Pitfalls observed (from analog read + RESEARCH):**
- `register_token` returns from inside the `match` arm for the platform parsing (lines 109-117). The new handler must NOT do this — D-01 + RESEARCH § Anti-Patterns mandate a single `HttpResponse::Accepted()` return at the bottom of the function. Differentiating return paths becomes an FCM/registration oracle.
- `register_token` writes the full pubkey prefix at INFO level (line 83) — do not copy this into the new handler.
- The spawn closure must own `Arc` clones, not borrow `&state` (RESEARCH Pitfall 4, lines 658-676). `state` is itself `web::Data` (Arc-wrapped), so a careless `move` capture would extend the entire AppState lifetime per spawn.
- Use lowercase `"x-request-id"` consistently — `HeaderName::from_static` panics at startup on uppercase input (RESEARCH Pitfall 7).

---

### CREATE `docs/verification/dispute-chat.md` (doc / runbook, n/a)

**Analog:** none in tree. The closest neighbours (`docs/api.md`, `docs/deployment.md`) are reference docs, not operator runbooks. The bash anti-CRIT-1 grep one-liner has its skeleton in RESEARCH § Code Examples (lines 891-907).

**Net-new content** (per D-17 + global CLAUDE.md "documentation must be professional in tone and formatting", written in Spanish):

Sections to include:
1. Objetivo (one paragraph: verify dispute-chat path end-to-end without a Mostro daemon in the loop).
2. Prerrequisitos (test pubkey, second Nostr client, configured relay, deployed server).
3. Pasos:
   - `POST /api/register` con un test `trade_pubkey` (curl example).
   - Publish a `kind 1059` Gift Wrap addressed to that `trade_pubkey` from a second Nostr client (NOT the Mostro daemon).
   - Verify `flyctl logs | grep "Push sent successfully for event"`.
   - Verify the device receives a silent push.
4. Anti-CRIT-1 grep check (bash one-liner from RESEARCH lines 891-907 with PASS/FAIL exit-status).
5. Limpieza (`POST /api/unregister`).

**Note on directory creation:** `docs/verification/` does not exist yet. Plan must include `mkdir -p docs/verification` (or rely on `git add` + the new file path implicitly creating the dir).

**Pitfalls:**
- Spanish per global CLAUDE.md (CLAUDE.md project file does NOT override; project doc tone is English for `docs/api.md` etc., but D-17 explicitly defers to global = Spanish for runbooks).
- No emojis in the doc body (global CLAUDE.md). The existing `deploy-fly.sh` uses emojis, but those predate the rule and are out of scope here.

---

### MODIFY `src/main.rs` (composition root, startup wiring)

**Analog:** itself (lines 22-114) — Phase 2 extends, does not refactor.

**Existing UnifiedPush + FCM construction pattern** (from `src/main.rs:44-78`):

```rust
// Initialize push services
let mut push_services: Vec<(Arc<dyn PushService>, &'static str)> = Vec::new();

// Keep UnifiedPush service separate for endpoint management
let unifiedpush_service = Arc::new(UnifiedPushService::new(config.clone()));

// Load existing endpoints from disk
if let Err(e) = unifiedpush_service.load_endpoints().await {
    log::error!("Failed to load UnifiedPush endpoints: {}", e);
}

// Initialize FCM service if enabled
if config.push.fcm_enabled {
    info!("Initializing FCM push service");
    let fcm_service = Arc::new(FcmPush::new(config.clone()));
    // ... init flow ...
}

let dispatcher = Arc::new(PushDispatcher::new(push_services));
```

**Mirror as-is:** the `Vec<(Arc<dyn PushService>, &'static str)>` shape (Phase 1 invariant), the `Arc::new(...)` wrap on each service, the `if config.push.<flag>` gate.

**Adapt:** insert `http_client` construction BEFORE `unifiedpush_service` construction; pass `http_client.clone()` as second arg to both `UnifiedPushService::new` and `FcmPush::new`.

**Existing AppState wiring pattern** (from `src/main.rs:91-94, 106-110`):

```rust
let app_state = AppState {
    token_store: token_store.clone(),
};

// ...

HttpServer::new(move || {
    App::new()
        .app_data(web::Data::new(app_state.clone()))
        .configure(api::routes::configure)
})
```

**Mirror as-is:** the `AppState { ... }` literal construction, the `web::Data::new(app_state.clone())` wrap, the `.configure(api::routes::configure)` call. None of these change shape.

**Adapt:** populate the 3 new `AppState` fields (`dispatcher`, `semaphore`, `notify_log_salt`).

**Net-new construction blocks** (no analog; from RESEARCH lines 836-878):

```rust
use std::time::Duration;
use rand::RngCore;
use tokio::sync::Semaphore;

// D-07: shared reqwest::Client with timeouts.
let http_client = Arc::new(
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .expect("reqwest::Client build never fails on default config"),
);

// D-09: notify_log_salt — random per process, in-memory only.
let mut salt_bytes = [0u8; 32];
rand::thread_rng().fill_bytes(&mut salt_bytes);
let notify_log_salt: Arc<[u8; 32]> = Arc::new(salt_bytes);

// D-09: semaphore — bounds spawn pile.
let notify_semaphore: Arc<Semaphore> = Arc::new(Semaphore::new(50));

let app_state = AppState {
    token_store: token_store.clone(),
    dispatcher: dispatcher.clone(),
    semaphore: notify_semaphore.clone(),
    notify_log_salt: notify_log_salt.clone(),
};
```

**API endpoint log lines** (from `src/main.rs:99-104`):

```rust
info!("API endpoints:");
info!("  GET  /api/health     - Health check");
info!("  GET  /api/status     - Server status with token stats");
info!("  GET  /api/info       - Server info");
info!("  POST /api/register   - Register token (plaintext)");
info!("  POST /api/unregister - Unregister token");
```

**Mirror as-is:** the alignment + format. **Adapt:** add `info!("  POST /api/notify     - Trigger silent push (best-effort)");` line.

**Pitfalls observed:**
- `rand::thread_rng()` is already transitively available via `secp256k1`'s `rand-std` feature (RESEARCH line 456). No `Cargo.toml` change for `rand` — it is already declared on `Cargo.toml:48`.
- `tokio::sync::Semaphore` is in tokio's `full` feature, already enabled (`Cargo.toml:13`). No dep change.
- The order matters: `http_client` must be built BEFORE the push-service constructors that consume it. The current code constructs `unifiedpush_service` early (line 48) — insert `http_client` ABOVE that line.

---

### MODIFY `src/api/routes.rs` (controller wiring, request-response)

**Analog:** itself — `AppState` (lines 36-39) and `configure()` (lines 41-49).

**Existing AppState** (from `src/api/routes.rs:36-39`):

```rust
#[derive(Clone)]
pub struct AppState {
    pub token_store: Arc<TokenStore>,
}
```

**Mirror as-is:** `#[derive(Clone)]`, `pub struct AppState`, `pub` fields. **Adapt:** add 3 fields (RESEARCH lines 825-832):

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;
use crate::push::PushDispatcher;

#[derive(Clone)]
pub struct AppState {
    pub token_store: Arc<TokenStore>,        // existing — unchanged
    pub dispatcher: Arc<PushDispatcher>,      // new (D-09)
    pub semaphore: Arc<Semaphore>,            // new (D-09)
    pub notify_log_salt: Arc<[u8; 32]>,       // new (D-09)
}
```

**Existing configure()** (from `src/api/routes.rs:41-49`):

```rust
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/health", web::get().to(health_check))
            .route("/status", web::get().to(status))
            .route("/register", web::post().to(register_token))
            .route("/unregister", web::post().to(unregister_token))
            .route("/info", web::get().to(server_info))
    );
}
```

**Mirror as-is:** the `web::scope("/api")` + chained `.route(...)` shape. The five existing routes stay exactly as they are (COMPAT-1).

**Net-new — one resource with `.wrap(...)`** (per D-13, RESEARCH lines 330-352):

```rust
use actix_web::middleware::from_fn;
use crate::api::notify::{notify_token, request_id_mw};

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/health", web::get().to(health_check))
            .route("/status", web::get().to(status))
            .route("/register", web::post().to(register_token))
            .route("/unregister", web::post().to(unregister_token))
            .route("/info", web::get().to(server_info))
            // CRITICAL: middleware scoped to ONE resource, NOT the scope
            .service(
                web::resource("/notify")
                    .wrap(from_fn(request_id_mw))
                    .route(web::post().to(notify_token))
            )
    );
}
```

**Pitfalls observed:**
- `from_fn` requires `actix-web ≥ 4.9.0` (D-20 / RESEARCH Pitfall 1, lines 622-633). The Cargo.toml bump from `"4.4"` to `"4.9"` is the contractual fix.
- Wrapping the resource (NOT the `/api` scope) is load-bearing. Wrapping the scope adds `X-Request-Id` to ALL endpoints, breaking COMPAT-1 (RESEARCH Anti-Patterns line 584).
- `RegisterResponse`, `RegisterTokenRequest`, `UnregisterTokenRequest`, and the four existing handlers (`health_check`, `status`, `server_info`, `register_token`, `unregister_token`) are UNTOUCHED (D-10, COMPAT-1, OOS-20).

---

### MODIFY `src/api/mod.rs` (module barrel, n/a)

**Analog:** itself.

**Current content** (single line):

```rust
pub mod routes;
```

**Adapt — add one line:**

```rust
pub mod routes;
pub mod notify;   // new
```

**Pitfalls:** none.

---

### MODIFY `src/push/fcm.rs` (service, request-response + transform)

**Analog 1 — constructor cascade:** `FcmPush::new` at lines 51-83.

**Existing constructor** (lines 51-83):

```rust
impl FcmPush {
    pub fn new(config: Config) -> Self {
        // ... service_account loading flow, unchanged ...

        Self {
            client: Client::new(),       // <-- THIS LINE replaced
            service_account,
            cached_token: Arc::new(RwLock::new(None)),
            project_id,
        }
    }
}
```

**Adapt:** signature `(config: Config)` → `(config: Config, client: Arc<reqwest::Client>)`. Field `client: Client` → `client: Arc<Client>`. Field initializer `Client::new()` → `client` (the parameter).

**Mirror as-is:** the body of service_account loading (lines 52-75), `cached_token: Arc::new(RwLock::new(None))`, `project_id` initialization. None of those change.

**Existing field declaration** (lines 43-48):

```rust
pub struct FcmPush {
    client: Client,                   // <-- type changes to Arc<Client>
    service_account: Option<ServiceAccount>,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
    project_id: String,
}
```

**Method-call sites unchanged:** `self.client.post(...)` at lines 131-138 and 236-241 work as-is because `Arc<Client>` derefs to `Client` (RESEARCH line 513).

**Analog 2 — silent payload builder:** existing `build_payload_for_token` at lines 168-215.

**Existing builder** (lines 168-215):

```rust
fn build_payload_for_token(device_token: &str) -> serde_json::Value {
    json!({
        "message": {
            "token": device_token,
            "notification": {
                "title": "Mostro",
                "body": "You have an update on your trade"
            },
            "data": {
                "type": "trade_update",
                "source": "mostro-push-server",
                "timestamp": chrono::Utc::now().timestamp().to_string()
            },
            "android": {
                "priority": "high",
                "notification": {
                    "tag": "mostro-trade",
                    "channel_id": "mostro_notifications",
                    "default_vibrate_timings": true
                }
            },
            "apns": {
                "headers": {
                    "apns-priority": "10",                 // <-- ANTI-PATTERN for silent
                    "apns-collapse-id": "mostro-trade"     // <-- ANTI-PATTERN for chat
                },
                "payload": {
                    "aps": {
                        "alert": { ... },
                        "content-available": 1,
                        "mutable-content": 1,
                        "thread-id": "mostro-trade"
                    }
                }
            }
        }
    })
}
```

**Mirror as-is** in the new sibling fn:
- Outer `json!({"message": {"token": device_token, ...}})` shape.
- `"data": { "type": ..., "source": "mostro-push-server", "timestamp": chrono::Utc::now().timestamp().to_string() }` block.
- `"android": { "priority": "high", ... }` outer shape.

**Net-new (D-05) — `build_silent_payload_for_notify`** (sibling fn, RESEARCH lines 539-569):

```rust
impl FcmPush {
    /// Silent push payload for the /api/notify chat-wake path.
    ///
    /// Data-only (no `alert`, no notification fallback) so iOS does not
    /// throttle the app for high-frequency silent pushes
    /// (apns-priority: 5 + apns-push-type: background per Apple's docs).
    /// Distinct from `build_payload_for_token` (Mostro daemon events at
    /// apns-priority: 10 with an alert fallback). Do NOT merge:
    /// the two paths have fundamentally different frequency profiles.
    fn build_silent_payload_for_notify(device_token: &str) -> serde_json::Value {
        json!({
            "message": {
                "token": device_token,
                "data": {
                    "type": "chat_wake",
                    "source": "mostro-push-server",
                    "timestamp": chrono::Utc::now().timestamp().to_string()
                },
                "android": {
                    "priority": "high"
                },
                "apns": {
                    "headers": {
                        "apns-priority": "5",
                        "apns-push-type": "background"
                        // intentionally NO apns-collapse-id
                    },
                    "payload": {
                        "aps": {
                            "content-available": 1
                            // intentionally NO alert, NO mutable-content, NO thread-id
                        }
                    }
                }
            }
        })
    }
}
```

**Net-new — `send_silent_to_token` method** (per RESEARCH line 575 recommendation; sibling to existing `send_to_token` at lines 220-251). Mirror the existing `send_to_token` body (auth-token fetch, URL construction, POST, status check) but call `Self::build_silent_payload_for_notify(device_token)` instead of `Self::build_payload_for_token(device_token)`. This stays a `pub fn` on `FcmPush`, NOT on the `PushService` trait (UnifiedPush has no per-payload distinction).

**Pitfalls observed during analog read:**
- The existing `build_payload_for_token` at line 198 uses `apns-priority: "10"` with `content-available: 1`. **This is the documented anti-pattern that D-05 separates from** — Apple throttles apps that ship this combination at chat frequency. The existing builder stays untouched because it serves the listener path (low-frequency Mostro daemon events), where the throttling risk is acceptable.
- The existing `apns-collapse-id: "mostro-trade"` is also why the new silent builder explicitly omits it: chat wake-ups must NOT coalesce with trade-update notifications sharing the same collapse-id.
- The `"data"` block uses `"type": "trade_update"` in the existing builder; the new silent builder uses `"type": "chat_wake"` to give the mobile client a switchable case for the inbound payload.
- `Self::build_payload_for_token` at line 232 is called from `send_to_token`. Do NOT touch this call site — Phase 1 listener path keeps using it.

---

### MODIFY `src/push/unifiedpush.rs` (service, request-response)

**Analog:** `UnifiedPushService::new` at lines 28-38.

**Existing constructor** (lines 28-38):

```rust
impl UnifiedPushService {
    pub fn new(config: Config) -> Self {
        let storage_path = PathBuf::from("data/unifiedpush_endpoints.json");

        Self {
            config,
            client: Client::new(),       // <-- THIS LINE replaced
            endpoints: RwLock::new(HashMap::new()),
            storage_path,
        }
    }
}
```

**Existing field** (lines 21-26):

```rust
pub struct UnifiedPushService {
    config: Config,
    client: Client,                              // <-- type changes to Arc<Client>
    endpoints: RwLock<HashMap<String, UnifiedPushEndpoint>>,
    storage_path: PathBuf,
}
```

**Adapt:** signature `(config: Config)` → `(config: Config, client: Arc<reqwest::Client>)`. Field `client: Client` → `client: Arc<Client>`. Field initializer `Client::new()` → `client`.

**Mirror as-is:** `storage_path` initialization, `endpoints: RwLock::new(HashMap::new())`, `config` field. None of those change.

**Method-call sites unchanged:** `self.client.post(...)` at lines 140-144 works as-is via `Arc<Client>` deref.

**Pitfalls:** none — this is a mechanical signature change. The `load_endpoints` / `save_endpoints` / `register_endpoint` / `unregister_endpoint` methods are untouched.

---

### MODIFY `src/push/dispatcher.rs` (service, event-driven dispatch)

**Analog:** existing `PushDispatcher::dispatch` at lines 45-77.

**Existing dispatch** (lines 45-77):

```rust
pub async fn dispatch(
    &self,
    token: &RegisteredToken,
) -> Result<DispatchOutcome, DispatchError> {
    let mut errors: Vec<String> = Vec::new();
    let mut attempted = false;

    for (idx, service) in self.services.iter().enumerate() {
        if !service.supports_platform(&token.platform) {
            continue;
        }
        attempted = true;
        match service
            .send_to_token(&token.device_token, &token.platform)
            .await
        {
            Ok(()) => {
                return Ok(DispatchOutcome::Delivered {
                    backend: self.backend_names[idx],
                });
            }
            Err(e) => {
                errors.push(e.to_string());
            }
        }
    }

    if !attempted {
        Err(DispatchError::NoBackendForPlatform)
    } else {
        Err(DispatchError::AllBackendsFailed { errors })
    }
}
```

**Mirror as-is:** the entire control flow (iteration, `supports_platform` gate, `attempted` flag, `errors` accumulator, terminal `Err` arms). Phase 2 D-22 / RESEARCH Q3 Option A explicitly preserves this algorithm — the only difference is which FCM method is called.

**Net-new — `dispatch_silent` method** (D-22 / Option A from RESEARCH § Pattern 5). Two concrete shapes the planner can pick from (whichever is cleaner; both satisfy D-22):

**Shape A — duplicate the loop, swap one call:**

```rust
pub async fn dispatch_silent(
    &self,
    token: &RegisteredToken,
) -> Result<DispatchOutcome, DispatchError> {
    // Same backend selection algorithm as `dispatch`. Difference: for FCM,
    // route through the silent payload builder (D-05); UnifiedPush has no
    // payload distinction so it goes through `send_to_token` as before.
    //
    // [body mirrors dispatch() lines 45-77, but FCM calls send_silent_to_token]
}
```

**Shape B — extract a private inner helper that takes a per-backend dispatch fn:**

```rust
async fn dispatch_with(
    &self,
    token: &RegisteredToken,
    use_silent: bool,
) -> Result<DispatchOutcome, DispatchError> {
    // Single body, per-iteration branch on use_silent for FCM.
}

pub async fn dispatch(&self, token: &RegisteredToken) -> Result<DispatchOutcome, DispatchError> {
    self.dispatch_with(token, false).await
}
pub async fn dispatch_silent(&self, token: &RegisteredToken) -> Result<DispatchOutcome, DispatchError> {
    self.dispatch_with(token, true).await
}
```

**Note for planner:** D-22 explicitly chose "Option A from RESEARCH Q3" — that means a NEW PUBLIC METHOD `dispatch_silent`, but Shape A vs Shape B (internal duplication vs internal helper) is implementation detail under Claude's discretion. Shape B keeps the algorithm in one place. Shape A is fewer indirection layers. Either satisfies the contract that `dispatch` (the existing method called by `src/nostr/listener.rs:121`) is byte-identical.

**Coupling concern:** the `dispatch_silent` method needs to know which `service` is FCM in order to call its silent path. Two options:
1. Downcast / `Arc::downcast` — fragile, requires `Any` bound.
2. Use the existing `backend_names` array — if `self.backend_names[idx] == "fcm"`, call `send_silent_to_token` instead of `send_to_token`. Requires either (a) extending the trait with an optional `send_silent_to_token` default that delegates to `send_to_token`, or (b) holding a typed `Arc<FcmPush>` reference alongside the `Arc<dyn PushService>` list.

**Recommendation for planner (matches D-22 spirit but is itself plan-time discretion):** add a default-method `send_silent_to_token` on the `PushService` trait that delegates to `send_to_token`, then override it on `FcmPush` to use the silent payload. This avoids `dispatch_silent` needing to know about concrete types and keeps the trait-object dispatch path uniform.

**Trait-extension pattern in `src/push/mod.rs`** (lines 14-23 currently):

```rust
#[async_trait]
pub trait PushService: Send + Sync {
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn supports_platform(&self, platform: &Platform) -> bool;
}
```

**Adapt — add a default method:**

```rust
#[async_trait]
pub trait PushService: Send + Sync {
    async fn send_to_token(...) -> ...;

    /// Silent (data-only, low-priority) variant. Default delegates to
    /// `send_to_token`. FcmPush overrides this with the silent payload
    /// per Phase 2 D-05.
    async fn send_silent_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_to_token(device_token, platform).await
    }

    fn supports_platform(&self, platform: &Platform) -> bool;
}
```

**Cascade:** the two blanket `impl PushService for Arc<...>` blocks in `src/push/mod.rs:27-55` need parallel `send_silent_to_token` delegations:

```rust
async fn send_silent_to_token(
    &self,
    device_token: &str,
    platform: &Platform,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    (**self).send_silent_to_token(device_token, platform).await
}
```

**Pitfalls observed:**
- The `backend_names` array (line 8) holds `&'static str` per backend. The dispatcher cannot easily distinguish "this is FCM" from "this is UnifiedPush" without it. The trait-default-method approach sidesteps this entirely — the dispatcher loop calls `service.send_silent_to_token(...)` uniformly, and only FCM does anything different.
- `src/nostr/listener.rs:121` calls `dispatcher.dispatch(...)` — UNTOUCHED in Phase 2 (D-22 invariant). Verify by grep after planning that listener still imports `dispatch`, not `dispatch_silent`.

---

### MODIFY `Cargo.toml` (manifest, n/a)

**Analog:** existing `[dependencies]` block (lines 6-53).

**Three coordinated changes** (all approved per D-16, D-20, D-21):

```toml
# 1. D-20: bump actix-web (line 8)
actix-web = "4.9"   # was "4.4"

# 2. D-16: add blake3
blake3 = "1"

# 3. D-21: add uuid
uuid = { version = "1", features = ["v4"] }
```

**Mirror as-is:** the existing single-line + comment-grouped style. Group `blake3` near the cryptography deps (lines 43-50) — sits naturally next to `chacha20poly1305`, `hkdf`, `sha2`. Group `uuid` either with the JSON / serde block or in a fresh "# Identifiers" group; planner picks.

**Pitfalls:**
- All three changes are user-pre-approved (D-16, D-20, D-21) per CONTEXT.md. No additional approval needed at plan time.
- The `actix-web` bump from `"4.4"` to `"4.9"` is a floor-shift, not a major-version bump — `Cargo.lock` already resolves to `4.11.0` so no behavioural change is expected. The bump exists purely so the `from_fn` import is contractually guaranteed (RESEARCH Pitfall 1).
- No need to modify `tokio`'s feature flags — `Semaphore` is in `full` (already enabled).
- No need to add `rand` — already at line 48.

---

### MODIFY `deploy-fly.sh` (deploy script, n/a)

**Analog:** itself, line 42.

**Existing line 42:**

```bash
  RUST_LOG="debug"
```

**Adapt — single character changes (one line):**

```bash
  RUST_LOG="info"
```

**Mirror as-is:** the entire surrounding `flyctl secrets set \` block (lines 27-42) — indentation, line continuations, key=value style. Only the value of `RUST_LOG` changes.

**Pitfalls observed:**
- The script has a Spanish comment header (line 3) and emoji-laden echo statements. Out of scope per Phase 2's "no refactor outside scope" — leave as-is.
- The hardcoded `SERVER_PRIVATE_KEY` at line 30 is inert (per user-memory: encryption deactivated in Phase 4 / Phase 3). Do not touch.
- This change is bundled into commit #2 per D-15 + D-19 — not its own commit. Without this flip, the new `log_pubkey()` privacy work is undermined by the still-active `debug!` macros in `src/push/fcm.rs:234` and `src/push/unifiedpush.rs:138` that log token prefixes.

---

## Shared Patterns

### Pattern S1 — `web::Data<AppState>` extraction

**Source:** `src/api/routes.rs:79, 80, 140, 141`
**Apply to:** `src/api/notify.rs::notify_token` (D-12 step 1)

```rust
async fn handler_name(
    state: web::Data<AppState>,
    req: web::Json<RequestType>,
) -> impl Responder {
    // body uses state.* and req.*
}
```

This is the only state-injection idiom in the project. The `web::Data::new(app_state.clone())` call in `src/main.rs:108` provides the matching producer side.

---

### Pattern S2 — `Arc<T>` cloning for cross-task sharing

**Source:** `src/main.rs:38, 78, 83, 84, 87` (existing `dispatcher.clone()`, `token_store.clone()`, etc.)
**Apply to:** spawn closure in `src/api/notify.rs::notify_token`

```rust
let dispatcher = Arc::clone(&state.dispatcher);
let token_store = Arc::clone(&state.token_store);
// then move into spawn
tokio::spawn(async move { /* uses cloned Arcs */ });
```

`Arc::clone(&foo)` and `foo.clone()` are both used in the codebase (`main.rs:38` uses `.clone()`; `main.rs:64` uses `Arc::clone(&...)`). The explicit `Arc::clone(&...)` form is preferred in new code as it makes the cheap-Arc-bump intent visible (vs. accidentally cloning a heavy `T`). Both are valid; planner picks one and stays consistent within `notify.rs`.

---

### Pattern S3 — Hex-pubkey validation guard

**Source:** `src/api/routes.rs:86, 147`
**Apply to:** `src/api/notify.rs::notify_token` (D-12 step 2)

```rust
if req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err() {
    warn!("...invalid trade_pubkey format");
    return HttpResponse::BadRequest().json(/* error body */);
}
```

The `hex::decode(...).is_err()` predicate is the load-bearing check; `len() != 64` is a fast-path short-circuit. The error log is a `warn!`, not `error!` (operator-noise convention).

---

### Pattern S4 — Logging facade levels

**Source:** CLAUDE.md "Logging" section + `src/api/routes.rs:82, 87, 110, 126`
**Apply to:** every log line in `src/api/notify.rs` and the spawned task

| Macro | Use For | Example in repo |
|-------|---------|-----------------|
| `info!` | Lifecycle, normal-path successes | `src/api/routes.rs:82`, `src/main.rs:39` |
| `warn!` | Recoverable problems, validation failures | `src/api/routes.rs:87, 110` |
| `error!` | Operator-attention failures | `src/push/fcm.rs:248`, `src/nostr/listener.rs:132` |
| `debug!` | High-volume diagnostics | `src/push/fcm.rs:234`, `src/store/mod.rs:76` |

Phase 2 specifically:
- `info!` for "request received" + "dispatched ok" lines
- `warn!` for validation 400, semaphore-saturated drop, dispatch failure (per CRIT-6: failures stay log-only, never propagate to caller)
- No `error!` in `notify.rs` — all errors are best-effort and become operator-visible warnings.
- No `debug!` in `notify.rs` per D-15 (production runs at `info`).

---

### Pattern S5 — `serde_json::json!` for inline response bodies

**Source:** `src/api/routes.rs:53, 71-75, 149-167`
**Apply to:** the `202` response body in `notify.rs`

```rust
HttpResponse::Accepted().json(json!({"accepted": true}))
```

The project uses `json!` macro for one-off response shapes and named structs (`#[derive(Serialize)]`) for shapes shared across handlers. The 202 body is a compile-time constant per D-01 — `json!` is the right tool. The 400 body uses a named `NotifyError` struct (per Pattern Pitfall 5) for shape stability.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `docs/verification/dispute-chat.md` | doc / runbook | n/a | No `docs/verification/` directory exists. Closest neighbours (`docs/api.md`, `docs/architecture.md`) are reference docs in English; this is an operator runbook in Spanish. The bash anti-CRIT-1 grep skeleton lives in RESEARCH § Code Examples (lines 891-907) and is the only piece with a concrete pre-existing snippet. The doc body is plan-time prose, not a code-pattern copy. |

---

## Metadata

**Analog search scope:** `src/`, `docs/`, `Cargo.toml`, `deploy-fly.sh`. Read full content of: `src/api/routes.rs`, `src/api/mod.rs`, `src/main.rs`, `src/push/fcm.rs`, `src/push/unifiedpush.rs`, `src/push/dispatcher.rs`, `src/push/mod.rs`, `src/utils/mod.rs`, `src/utils/batching.rs`, `src/store/mod.rs` (top 100 lines), `src/nostr/listener.rs` (lines 60-150), `Cargo.toml`, `deploy-fly.sh`, `docs/api.md` (top). Listed `docs/` directory.

**Files scanned:** 14 source files + 2 directories.

**Pattern extraction date:** 2026-04-25.

**Key invariants preserved by this map:**
- COMPAT-1: existing `RegisterResponse` / `RegisterTokenRequest` / `UnregisterTokenRequest` and the four existing handlers are NOT touched.
- D-22: `PushDispatcher::dispatch` (used by `src/nostr/listener.rs:121`) is byte-identical; Phase 2 adds a sibling `dispatch_silent` method.
- D-14: `log_pubkey()` is applied ONLY to new code paths in `src/api/notify.rs`. Existing prefix-truncation logs in `src/api/routes.rs`, `src/store/mod.rs`, `src/nostr/listener.rs` are intentionally left alone.
- D-05: `build_payload_for_token` (FCM, lines 168-215) stays untouched as the listener-path payload. New silent builder is a sibling fn.
