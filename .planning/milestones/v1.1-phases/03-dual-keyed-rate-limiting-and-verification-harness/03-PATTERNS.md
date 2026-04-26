# Phase 3: Dual-keyed rate limiting and verification harness - Pattern Map

**Mapped:** 2026-04-25
**Files analyzed:** 7 (1 new + 5 modified + 1 test-support module)
**Analogs found:** 7 / 7 (100% in-repo coverage; all patterns already exist for the production code; only `#[actix_web::test]` shape is new)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `src/api/rate_limit.rs` (NEW) | middleware + utility | request-response (middleware) + event-driven (cleanup task) | `src/api/notify.rs` (`request_id_mw`) + `src/store/mod.rs` (`start_cleanup_task`) | exact (split across two analogs by sub-concern) |
| `src/api/notify.rs` (MOD) | controller | request-response | `src/api/notify.rs:49-109` (self — 6-line insert between existing steps 3 and 4) | exact (in-place edit) |
| `src/api/routes.rs` (MOD) | controller wiring | request-response | `src/api/routes.rs:41-63` (self — add 1 field + 1 `.wrap` line) | exact (in-place edit) |
| `src/api/mod.rs` (MOD) | module barrel | n/a | `src/api/mod.rs:1-2` (self — add 1 `pub mod` line) | exact |
| `src/config.rs` (MOD) | config | env-load | `src/config.rs:74-99` (`PushConfig`/`RateLimitConfig` env-with-default pattern) | exact |
| `src/main.rs` (MOD) | binary entry | bootstrap/wiring | `src/main.rs:46-128` (self — add 5 wiring blocks per CONTEXT integration points) | exact |
| `src/api/notify.rs` test block (NEW) | test (handler integration) | request-response | `src/crypto/mod.rs:453-823` (only existing `#[cfg(test)] mod tests`) | role-match only — sync `#[test]` precedent; Phase 3 introduces NEW `#[actix_web::test]` shape |
| `src/api/rate_limit.rs` test block (NEW) | test (middleware integration) | request-response | (same as above) | role-match only — NEW shape |
| `src/api/routes.rs` test block (NEW) | test (regression byte-equality) | request-response | (same as above) | role-match only — NEW shape |
| `StubPushService` test-support (NEW, location at planner discretion) | test double | n/a | `src/push/mod.rs:14-37` (`PushService` trait surface to implement) | exact (trait contract) |

---

## Pattern Assignments

### `src/api/rate_limit.rs` (NEW — middleware + utility)

This file fuses two distinct responsibilities; each has its own analog.

#### Sub-pattern A: per-IP middleware (`per_ip_rate_limit_mw`)

**Analog:** `src/api/notify.rs:117-132` (`request_id_mw`)

**Imports pattern** (lines 1-11 of `notify.rs` — copy verbatim):
```rust
use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header::{HeaderName, HeaderValue},
    middleware::Next,
    web, Error, HttpResponse, Responder,
};
```
For `rate_limit.rs` add: `use std::net::IpAddr;` and `use std::sync::Arc;` and `use governor::{DefaultKeyedRateLimiter, Quota, clock::DefaultClock};`.

**Middleware skeleton** (`notify.rs:117-132`) — copy structure, swap body:
```rust
pub async fn request_id_mw(
    mut req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    req.headers_mut().remove("x-request-id");

    let id = uuid::Uuid::new_v4().to_string();
    let mut res = next.call(req).await?;

    res.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&id)
            .expect("uuid string is always valid header value"),
    );
    Ok(res)
}
```
For `per_ip_rate_limit_mw`: replace the inbound-header-strip + post-call insert with: extract IP via D-10 precedence, read `web::Data<Arc<DefaultKeyedRateLimiter<IpAddr>>>` from `req`, call `.check_key(&ip)`, on `Err(not_until)` short-circuit with `rate_limited_response(retry_after_secs)` (do NOT call `next.call(req)`), on `Ok` proceed with `next.call(req).await`. Per D-19 the `request_id_mw` is the OUTERMOST wrap — do not duplicate its X-Request-Id work here.

**`web::Data` extraction inside `from_fn`** (D-20): the existing handler pattern at `notify.rs:49-52` shows the extraction shape; for `from_fn` middleware, use `req.app_data::<web::Data<Arc<DefaultKeyedRateLimiter<IpAddr>>>>()`. The closest in-tree handler-side analog is in `notify.rs:49-52`:
```rust
pub async fn notify_token(
    state: web::Data<AppState>,
    req: web::Json<NotifyRequest>,
) -> impl Responder {
```
Difference: `from_fn` passes `ServiceRequest`, not extractor types — use `req.app_data::<T>()` lookup, not extractor injection.

#### Sub-pattern B: cleanup task (`start_rate_limit_cleanup_task`)

**Analog:** `src/store/mod.rs:144-158` (`start_cleanup_task`) — D-15 explicitly says "mirror".

**Full pattern to copy** (lines 144-158):
```rust
pub fn start_cleanup_task(store: std::sync::Arc<TokenStore>, interval_hours: u64) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(interval_hours * 3600)
        );

        loop {
            interval.tick().await;
            let removed = store.cleanup_expired().await;
            if removed > 0 {
                warn!("Periodic cleanup removed {} expired tokens", removed);
            }
        }
    });
}
```

Map to Phase 3 (D-15 + D-18):
```rust
pub fn start_rate_limit_cleanup_task(
    limiter: Arc<PerPubkeyLimiter>,
    interval: Duration,
    soft_cap: usize,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            limiter.retain_recent();
            if limiter.len() > soft_cap {
                warn!(
                    "rate-limit pubkey map size exceeded soft cap: {}",
                    limiter.len()
                );
            }
        }
    });
}
```
Differences from analog:
- Interval is `Duration` (already-converted), not `u64 * 3600` — Phase 3 uses seconds-granularity per D-16.
- `cleanup_expired().await` becomes synchronous `retain_recent()` (governor API is sync).
- Soft-cap warn cadence: every tick when over cap (D-18), no throttling.
- Logging: `warn!` (matches `store::start_cleanup_task` line 154 — same level).

#### Sub-pattern C: type alias (D-09)

**Analog:** none in repo for type aliases on external generic types; pattern is simple Rust idiom.
```rust
pub type PerPubkeyLimiter = governor::DefaultKeyedRateLimiter<String>;
```
Place near top of `rate_limit.rs` after imports.

#### Sub-pattern D: `rate_limited_response` helper (D-13 + D-14)

**Analog:** `src/api/notify.rs:55-60` (`HttpResponse::BadRequest().json(...)` shape) for the response-building idiom; `src/api/routes.rs:103-107` for the response-builder + struct pattern (`RegisterResponse`). For Phase 3, use a local minimal struct mirroring `NotifyError` (`notify.rs:34-38`):
```rust
#[derive(Serialize)]
struct NotifyError {
    success: bool,
    message: String,
}
```

Implement (D-13: byte-identical body):
```rust
pub fn rate_limited_response(retry_after_secs: u64) -> HttpResponse {
    HttpResponse::TooManyRequests()
        .insert_header(("Retry-After", retry_after_secs.to_string()))
        .json(serde_json::json!({
            "success": false,
            "message": "rate limited"
        }))
}
```
Use `serde_json::json!` per project convention (`routes.rs:166-169`, `notify.rs:108`) rather than declaring a third response struct — keeps the byte-shape inline with the test expectations in D-25.

---

### `src/api/notify.rs` (MODIFIED — handler insert)

**Analog:** `src/api/notify.rs:49-109` (self).

**Insertion point** (between current line 65 — the `info!("notify: request received pk={}", log_pk);` — and current line 68 — `match Arc::clone(&state.semaphore).try_acquire_owned()`):

The 6-line change per D-12 step 4:
```rust
// D-12 step 4: per-pubkey rate-limit check BEFORE semaphore acquisition.
// Per anti-RL-2 (D-13): byte-identical 429 to the per-IP middleware.
if let Err(not_until) = state.per_pubkey_limiter.check_key(&req.trade_pubkey) {
    let retry_after_secs = not_until
        .wait_time_from(governor::clock::DefaultClock::default().now())
        .as_secs()
        .max(1);
    return rate_limited_response(retry_after_secs);
}
```

**Existing surrounding context** (lines 53-68 — DO NOT modify; insert between current `info!` and current `match`):
```rust
    if req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err() {
        warn!("notify: invalid trade_pubkey format");
        return HttpResponse::BadRequest().json(NotifyError {
            success: false,
            message: "Invalid trade_pubkey format (expected 64 hex characters)"
                .to_string(),
        });
    }

    let log_pk = log_pubkey(&state.notify_log_salt, &req.trade_pubkey);
    info!("notify: request received pk={}", log_pk);

    // <<< INSERT HERE per D-12 step 4 >>>

    match Arc::clone(&state.semaphore).try_acquire_owned() {
```

**New import to add** at top of file:
```rust
use crate::api::rate_limit::rate_limited_response;
```

---

### `src/api/routes.rs` (MODIFIED — AppState + configure)

**Analog:** `src/api/routes.rs:41-63` (self).

**Existing AppState** (lines 41-47) — DO NOT remove or reorder existing fields; ADD ONE field:
```rust
#[derive(Clone)]
pub struct AppState {
    pub token_store: Arc<TokenStore>,
    pub dispatcher: Arc<PushDispatcher>,
    pub semaphore: Arc<Semaphore>,
    pub notify_log_salt: Arc<[u8; 32]>,
    pub per_pubkey_limiter: Arc<PerPubkeyLimiter>,  // <<< NEW per D-09
}
```

**Existing `configure`** (lines 49-63) — modify ONLY the `/notify` resource; per D-19 the LAST `.wrap()` is innermost:
```rust
.service(
    web::scope("/api")
        .route("/health", web::get().to(health_check))
        // ... (other routes UNCHANGED — D-21)
        .service(
            web::resource("/notify")
                .wrap(from_fn(request_id_mw))
                .wrap(from_fn(per_ip_rate_limit_mw))  // <<< NEW per D-19
                .route(web::post().to(notify_token)),
        ),
);
```
Per D-19: `request_id_mw` stays as the FIRST `.wrap()` call so it ends up OUTERMOST (i.e. wraps the rate-limit response too — every 429 must carry `X-Request-Id` per D-25).

**New imports to add**:
```rust
use crate::api::rate_limit::{per_ip_rate_limit_mw, PerPubkeyLimiter};
```

---

### `src/api/mod.rs` (MODIFIED — module barrel)

**Analog:** `src/api/mod.rs:1-2` (self).

**Current contents:**
```rust
pub mod routes;
pub mod notify;
```

**Add ONE line:**
```rust
pub mod rate_limit;
```

---

### `src/config.rs` (MODIFIED — new struct + env-load)

**Analog:** `src/config.rs:74-99` (`PushConfig` and `RateLimitConfig` env-load patterns).

**Existing pattern to replicate** (lines 74-87 — `PushConfig::from_env`):
```rust
push: PushConfig {
    fcm_enabled: env::var("FCM_ENABLED")
        .unwrap_or_else(|_| "true".to_string())
        .parse()?,
    // ...
    batch_delay_ms: env::var("BATCH_DELAY_MS")
        .unwrap_or_else(|_| "5000".to_string())
        .parse()?,
    cooldown_ms: env::var("COOLDOWN_MS")
        .unwrap_or_else(|_| "60000".to_string())
        .parse()?,
},
```

**New struct after `RateLimitConfig`** (around line 39, follow same `#[derive]` pattern):
```rust
#[derive(Debug, Clone, Deserialize)]
pub struct NotifyRateLimitConfig {
    pub per_pubkey_per_min: u32,
    pub per_ip_per_min: u32,
    pub cleanup_interval_secs: u64,
    pub pubkey_limiter_soft_cap: usize,
}
```

**Add field on `Config`** (lines 5-12) — append after `store`:
```rust
pub notify_rate_limit: NotifyRateLimitConfig,
```

**New block inside `Config::from_env`** (after the `store` block, before `Ok(Config { ... })` close at line 113):
```rust
notify_rate_limit: NotifyRateLimitConfig {
    per_pubkey_per_min: {
        let v: u32 = env::var("NOTIFY_RATE_PER_PUBKEY_PER_MIN")
            .map(|s| s.parse())
            .unwrap_or_else(|_| {
                info!("NOTIFY_RATE_PER_PUBKEY_PER_MIN unset, using default 30");
                Ok(30)
            })?;
        if v == 0 {
            return Err("NOTIFY_RATE_PER_PUBKEY_PER_MIN must be > 0, got 0".into());
        }
        v
    },
    per_ip_per_min: {
        let v: u32 = env::var("NOTIFY_RATE_PER_IP_PER_MIN")
            .map(|s| s.parse())
            .unwrap_or_else(|_| {
                info!("NOTIFY_RATE_PER_IP_PER_MIN unset, using default 120");
                Ok(120)
            })?;
        if v == 0 {
            return Err("NOTIFY_RATE_PER_IP_PER_MIN must be > 0, got 0".into());
        }
        v
    },
    cleanup_interval_secs: env::var("NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS")
        .unwrap_or_else(|_| "60".to_string())
        .parse()?,
    pubkey_limiter_soft_cap: env::var("NOTIFY_PUBKEY_LIMITER_SOFT_CAP")
        .unwrap_or_else(|_| "100000".to_string())
        .parse()?,
},
```
Differences from the analog (`PushConfig`):
- D-03 requires `info!` log when an env var is unset and the default is used. The vanilla `unwrap_or_else(|_| "30".to_string()).parse()?` shape doesn't allow that distinction (it can't tell "unset" from "set to 30"). Use the `env::var(...).map(...).unwrap_or_else(|_| { info!(...); Ok(default) })` shape above.
- D-04 requires explicit `> 0` validation on the two `u32` rate fields. Plain `parse::<u32>()` would only reject negatives (which fail to parse anyway) and non-numerics — not zero. Hence the explicit `if v == 0` check.
- The two non-rate fields (`cleanup_interval_secs`, `pubkey_limiter_soft_cap`) follow the vanilla `PushConfig` shape since D-03/D-04 only apply to the two rate fields.

**New import** at top of `config.rs`:
```rust
use log::info;
```
(Currently `config.rs` does no logging — first time the module imports `log`.)

---

### `src/main.rs` (MODIFIED — wiring)

**Analog:** `src/main.rs:46-128` (self).

**Existing semaphore-construction line** (line 108) — DO NOT remove:
```rust
let notify_semaphore: Arc<Semaphore> = Arc::new(Semaphore::new(50));
```

**Insert AFTER line 108, BEFORE the Nostr listener spawn (line 111)** — per CONTEXT integration point 1+2+3:
```rust
// D-09: per-pubkey limiter shared with /api/notify handler via AppState.
let per_pubkey_limiter: Arc<PerPubkeyLimiter> = Arc::new(governor::RateLimiter::keyed(
    governor::Quota::per_minute(
        std::num::NonZeroU32::new(config.notify_rate_limit.per_pubkey_per_min)
            .expect("validated > 0 in Config::from_env"),
    )
    .allow_burst(std::num::NonZeroU32::new(10).unwrap()),
));

// D-20: per-IP limiter shared via app_data (NOT in AppState — different key type).
let per_ip_limiter: Arc<governor::DefaultKeyedRateLimiter<std::net::IpAddr>> =
    Arc::new(governor::RateLimiter::keyed(
        governor::Quota::per_minute(
            std::num::NonZeroU32::new(config.notify_rate_limit.per_ip_per_min)
                .expect("validated > 0 in Config::from_env"),
        )
        .allow_burst(std::num::NonZeroU32::new(30).unwrap()),
    ));

// D-15: cleanup task mirrors store::start_cleanup_task.
api::rate_limit::start_rate_limit_cleanup_task(
    per_pubkey_limiter.clone(),
    Duration::from_secs(config.notify_rate_limit.cleanup_interval_secs),
    config.notify_rate_limit.pubkey_limiter_soft_cap,
);
```

**Modify AppState construction** (lines 122-128) — add ONE field:
```rust
let app_state = AppState {
    token_store: token_store.clone(),
    dispatcher: dispatcher.clone(),
    semaphore: notify_semaphore.clone(),
    notify_log_salt: notify_log_salt.clone(),
    per_pubkey_limiter: per_pubkey_limiter.clone(),  // <<< NEW
};
```

**Modify HttpServer closure** (lines 141-145) — add `app_data` for per-IP limiter:
```rust
HttpServer::new(move || {
    App::new()
        .app_data(web::Data::new(app_state.clone()))
        .app_data(web::Data::new(per_ip_limiter.clone()))  // <<< NEW per D-20
        .configure(api::routes::configure)
})
```

Note: `per_ip_limiter` must be cloned BEFORE entering the `HttpServer::new` closure (the closure is `Fn`, so each call needs its own clone) — same idiom already used for `app_state.clone()` above.

**New import** at top of `main.rs`:
```rust
use api::rate_limit::PerPubkeyLimiter;
```

---

### Test blocks (NEW — `#[cfg(test)] mod tests` per file)

**Analog:** `src/crypto/mod.rs:453-823` is the ONLY existing `#[cfg(test)] mod tests` in the codebase. CRITICAL: that block uses sync `#[test]` exclusively. Phase 3 introduces `#[actix_web::test]` (and possibly `#[tokio::test]` for `tokio::time::pause`/`advance`) — the planner must flag this as a NEW test shape, not a copy of the existing crypto-module test idiom.

#### Test imports skeleton (replicate structure of `crypto/mod.rs:453-456`)
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use std::sync::Arc;
    // additional imports per file
}
```
Pattern source: lines 453-456 of `crypto/mod.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
```
The `#[cfg(test)] mod tests { use super::*; ... }` shape is the conserved part — Phase 3 keeps that, swaps the body to async actix tests.

#### Test app factory pattern (NEW shape — no in-repo analog)

Recommended (planner's discretion per D-29 last bullet) — define a `make_test_app()` helper inside each test module:
```rust
async fn make_test_app() -> impl actix_web::dev::Service<...> {
    let stub = Arc::new(StubPushService::new(vec![Platform::Android]));
    let dispatcher = Arc::new(PushDispatcher::new(vec![
        (stub.clone() as Arc<dyn PushService>, "stub"),
    ]));
    let token_store = Arc::new(TokenStore::new(48, Arc::new([0u8; 32])));
    let semaphore = Arc::new(Semaphore::new(50));
    let per_pubkey_limiter: Arc<PerPubkeyLimiter> = /* with test quota */;
    let per_ip_limiter = /* with test quota */;
    let state = AppState { /* fields */ };

    test::init_service(
        App::new()
            .app_data(web::Data::new(state))
            .app_data(web::Data::new(per_ip_limiter))
            .configure(crate::api::routes::configure),
    ).await
}
```

#### `StubPushService` test double (D-23)

**Analog:** `src/push/mod.rs:14-37` (`PushService` trait — must implement this contract).

**Trait surface to satisfy** (lines 14-37 of `push/mod.rs`):
```rust
#[async_trait]
pub trait PushService: Send + Sync {
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

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

**Stub structure per D-23**:
```rust
pub(crate) struct StubPushService {
    pub calls: Arc<tokio::sync::Mutex<Vec<(String, Platform)>>>,
    pub supports: Vec<Platform>,
    pub fail: bool,
}

#[async_trait::async_trait]
impl PushService for StubPushService {
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.calls.lock().await.push((device_token.to_string(), platform.clone()));
        if self.fail {
            Err("stub forced failure".into())
        } else {
            Ok(())
        }
    }
    // send_silent_to_token uses default delegation
    fn supports_platform(&self, platform: &Platform) -> bool {
        self.supports.contains(platform)
    }
}
```

Location: D-23 says "shared `pub(crate)` test helper module" with the alternative "src/api/test_support.rs gated by `#[cfg(test)]`". Planner's discretion (D-29) — both are valid; recommendation is to put it in `src/api/rate_limit.rs` inside the same `#[cfg(test)] mod tests` block IF only that file uses it, or split to `src/api/test_support.rs` (also `#[cfg(test)]`) if `notify.rs` and `routes.rs` test blocks both consume it. The latter avoids duplication.

#### Time-control pattern (D-27)

**Analog:** none in repo. Phase 3 introduces:
```rust
#[actix_web::test]
async fn test_retain_recent_reduces_len() {
    tokio::time::pause();
    // ... populate limiter ...
    tokio::time::advance(Duration::from_secs(120)).await;
    limiter.retain_recent();
    assert!(limiter.len() < 10);
}
```
Planner caveat (per D-27): verify whether `governor`'s `MonotonicClock` interacts with `tokio::time::pause`. If it doesn't, the `retain_recent` test may need a real `tokio::time::sleep(Duration::from_secs(2)).await` — flag this as an investigation item during planning.

#### Byte-equality regression (D-26)

**Analog:** `src/api/routes.rs:147-151` (the actual JSON body produced by `register_token`):
```rust
HttpResponse::Ok().json(RegisterResponse {
    success: true,
    message: "Token registered successfully".to_string(),
    platform: Some(platform.to_string()),
})
```

When serialized, the on-the-wire body is exactly:
```
{"success":true,"message":"Token registered successfully","platform":"android"}
```

D-26 test fixture (inline JSON literal, no `insta` dependency):
```rust
let body_str = std::str::from_utf8(&body).unwrap();
assert_eq!(body_str, r#"{"success":true,"message":"Token registered successfully","platform":"android"}"#);
```
Field ordering invariant: serde_json preserves struct field order; the order in `RegisterResponse` (`routes.rs:33-39`) is `success, message, platform` — the test fixture must match exactly. If the fixture is wrong, the test fails byte-equality, not field-presence.

---

## Shared Patterns

### Shared Pattern 1: `unwrap_or_else(|_| "<default>".to_string()).parse()?` env-load

**Source:** `src/config.rs:74-99` (every existing `Config` field).
**Apply to:** Two of four new env vars (`NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS`, `NOTIFY_PUBKEY_LIMITER_SOFT_CAP`).
**Skip for:** Two rate vars (per D-03 + D-04) — those need the `info!`-on-default + zero-rejection variant shown above.

### Shared Pattern 2: `Arc<T>` shared into `tokio::spawn`

**Source:** `src/main.rs:46-128` (every shared resource: `token_store`, `dispatcher`, `notify_semaphore`, `notify_log_salt`).
**Apply to:** Both new limiters (`per_pubkey_limiter` in AppState, `per_ip_limiter` via `app_data`).
**Excerpt** (`main.rs:46-49`):
```rust
let token_store = Arc::new(TokenStore::new(
    config.store.token_ttl_hours,
    notify_log_salt.clone(),
));
```
Same `Arc::new(...)` then `.clone()` per consumer idiom — `governor::RateLimiter::keyed(...)` returns the limiter directly; wrap in `Arc::new(...)` exactly as `TokenStore::new` is wrapped.

### Shared Pattern 3: privacy-safe logging via `log_pubkey()`

**Source:** `src/utils/log_pubkey.rs:19-22` + every existing log site (`store/mod.rs:64`, `routes.rs:96-97`, `notify.rs:64-65`).
**Apply to:** All new log lines that touch a pubkey. Per CONTEXT lines 209: "Phase 3's new log lines (rate-limit warn, soft-cap warn) MUST NOT include the pubkey at all (RL-2 + soft-cap is aggregate cardinality, not per-key)." So Phase 3's logging is even stricter than the shared pattern — `log_pubkey` is the upper bound; Phase 3 stays well below that, emitting only aggregate counts and `info!`/`warn!` lines without any per-request pubkey reference.

### Shared Pattern 4: HTTP response builder + `serde_json::json!`

**Source:** `src/api/notify.rs:108`, `src/api/routes.rs:166-169`.
**Apply to:** `rate_limited_response` helper (D-14 — body shape `{"success":false,"message":"rate limited"}`).
**Excerpt** (`routes.rs:175-178`):
```rust
HttpResponse::Ok().json(serde_json::json!({
    "success": true,
    "message": "Token unregistered successfully"
}))
```
Mirror exactly for the 429 body, swapping `Ok()` for `TooManyRequests()` and adding the `Retry-After` header via `.insert_header(...)` before `.json(...)`.

### Shared Pattern 5: `RwLock<HashMap<...>>` style in-memory state

**Source:** `src/store/mod.rs:33-37` (`TokenStore` shape).
**Apply to:** N/A — `governor`'s `DefaultKeyedRateLimiter` already encapsulates the `DashMap`-backed state (D-09 rationale "no wrapper struct"). This pattern is INTENTIONALLY not replicated in Phase 3.

### Shared Pattern 6: middleware-via-`from_fn` wrapping a single resource

**Source:** `src/api/routes.rs:57-61`:
```rust
.service(
    web::resource("/notify")
        .wrap(from_fn(request_id_mw))
        .route(web::post().to(notify_token)),
),
```
**Apply to:** D-19 stack ordering — add `.wrap(from_fn(per_ip_rate_limit_mw))` AFTER `request_id_mw`. Per Actix wrap-ordering: LAST `.wrap()` is INNERMOST. So `request_id_mw` runs first on inbound, last on outbound — guaranteeing every response (including 429s emitted by `per_ip_rate_limit_mw`) carries `X-Request-Id`.

---

## No Analog Found

| File / Concern | Reason | Mitigation |
|----------------|--------|------------|
| `#[actix_web::test]` async test functions | Repo only has sync `#[test]` in `src/crypto/mod.rs`. No precedent for `actix_web::test::init_service`, `test::call_service`, `test::TestRequest`, `test::read_body`. | Planner cites actix-web docs directly (4.x test module). The shape is well-documented; risk is in the ergonomics of building `AppState` for tests, not in the test harness itself. |
| `tokio::time::pause()` / `advance()` | Repo has zero `#[tokio::test]` precedent. | D-27 is explicit: try `tokio::time::pause`; fall back to a real ~2s sleep for the `retain_recent` test if `governor`'s `MonotonicClock` doesn't honor virtual time. Planner flags this as an investigation item. |
| `from_fn` middleware that short-circuits (returns response WITHOUT calling `next.call(req)`) | `request_id_mw` always calls `next.call(req)`. | Pattern is documented in actix-web 4.x `middleware::from_fn` docs; manual return of `Ok(req.into_response(rate_limited_response(...).map_into_boxed_body()))` is the standard idiom. Planner cites actix-web 4.4+ release notes confirming `from_fn` short-circuit support. |
| `req.app_data::<web::Data<T>>()` lookup inside a `from_fn` middleware | Existing `request_id_mw` doesn't read app data. | Pattern is in actix-web docs for `ServiceRequest::app_data`. Trivial but new to this repo. |
| `governor::RateLimiter::keyed`, `check_key`, `retain_recent`, `len`, `Quota::per_minute().allow_burst()` | `governor` declared in `Cargo.toml:41` but never imported anywhere in `src/`. First use. | Planner consults `governor = "0.6.3"` docs.rs. CONTEXT canonical_refs confirms 0.6 vs 0.10 API parity for our usage. |

---

## Metadata

**Analog search scope:** `src/api/`, `src/store/`, `src/config.rs`, `src/main.rs`, `src/push/`, `src/utils/`, `src/crypto/mod.rs:453-823` (test block).
**Files scanned:** 9 (`api/mod.rs`, `api/routes.rs`, `api/notify.rs`, `store/mod.rs`, `config.rs`, `main.rs`, `push/mod.rs`, `utils/log_pubkey.rs`, `Cargo.toml` + crypto test header).
**Files not scanned (out of phase scope per CONTEXT line 234-237):** `src/nostr/listener.rs`, `src/push/{fcm,unifiedpush,dispatcher}.rs`, `src/utils/batching.rs`, `src/crypto/mod.rs` body (only the test header at lines 453-456 was load-bearing).
**Pattern extraction date:** 2026-04-25.
