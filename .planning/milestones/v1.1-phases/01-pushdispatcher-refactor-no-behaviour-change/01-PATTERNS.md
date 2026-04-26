# Phase 1: PushDispatcher refactor (no behaviour change) - Pattern Map

**Mapped:** 2026-04-24
**Files analyzed:** 6 (1 new + 5 modified)
**Analogs found:** 6 / 6 (all in-tree)

> All analogs live inside the same crate. This is a structural refactor of an existing
> Rust binary; there are no greenfield modules. Every "new" file is modeled directly on
> a sibling that already implements the same role.

---

## File Classification

| File | Status | Role | Data Flow | Closest Analog | Match Quality |
|------|--------|------|-----------|----------------|---------------|
| `src/push/dispatcher.rs` | NEW | service / coordinator | request-response (in-process fan-out over backends) | `src/push/unifiedpush.rs` (sibling concrete service in same module) + Q1 sketch in `.planning/research/ARCHITECTURE.md` lines 126-153 | role-match (Rust struct + `impl` + custom error enum) |
| `src/push/mod.rs` | MODIFIED | barrel / trait surface | n/a | itself (existing `pub mod` + `pub use` + `#[async_trait]` trait) | exact (in-place edit) |
| `src/push/fcm.rs` | MODIFIED | concrete push backend | request-response (HTTPS to FCM v1) | itself (cascade of D-09 + D-10) | exact |
| `src/push/unifiedpush.rs` | MODIFIED | concrete push backend | request-response (HTTPS to UnifiedPush distributor) | itself (cascade of D-09 + D-10) | exact |
| `src/main.rs` | MODIFIED | binary entry point / wiring | startup-once construction | itself (existing `Vec<Box<dyn PushService>>` build site at lines 46-79) | exact |
| `src/nostr/listener.rs` | MODIFIED | event-driven dispatcher (caller of `PushDispatcher`) | streaming (Nostr subscription -> async event loop) | itself (existing inline iteration loop at lines 119-135) | exact |

---

## Pattern Assignments

### NEW: `src/push/dispatcher.rs` (service / coordinator)

**Primary analog:** `src/push/unifiedpush.rs` for module shape, error idioms, struct + `impl` layout.
**Secondary analog:** `.planning/research/ARCHITECTURE.md` Q1 (lines 126-153) for the `dispatch` method skeleton (verbatim Rust sketch).
**Tertiary analog:** `src/crypto/mod.rs` lines 173-204 for the `Display` + `std::error::Error` hand-written enum pattern that `DispatchError` follows.

#### Imports pattern

Copy the import-grouping convention from `src/push/unifiedpush.rs:1-12` (external crates first, then `std`, then `crate::`, then `super::`):

```rust
use log::{debug, error}; // optional - dispatcher itself emits no logs per D-07; keep imports lean
use std::sync::Arc;

use crate::push::PushService;
use crate::store::{Platform, RegisteredToken};
```

Note D-07: dispatcher emits NO log lines. The `log` import above is shown for completeness but should be omitted unless an internal helper actually uses it. Prefer:

```rust
use std::sync::Arc;

use crate::push::PushService;
use crate::store::RegisteredToken;
```

#### Struct + constructor pattern

Mirror `UnifiedPushService::new` (`src/push/unifiedpush.rs:21-38`) — plain `pub struct`, single `impl`, constructor returns `Self` (no `Result`, since Phase 1 does no validation):

```rust
pub struct PushDispatcher {
    services: Arc<[Arc<dyn PushService>]>,
}

impl PushDispatcher {
    pub fn new(services: Vec<Arc<dyn PushService>>) -> Self {
        Self {
            services: services.into(), // Vec<T> -> Arc<[T]>
        }
    }
}
```

The `Vec<T> -> Arc<[T]>` collapse uses the stdlib `From<Vec<T>> for Arc<[T]>` impl (free, no `unsafe`, single allocation). This is the exact shape proposed in `.planning/research/ARCHITECTURE.md:131-135`.

#### Core pattern: `dispatch` method (lifted from `src/nostr/listener.rs:119-135`)

Iteration protocol replicated **byte-for-byte** per D-04:

```rust
pub async fn dispatch(
    &self,
    token: &RegisteredToken,
) -> Result<DispatchOutcome, DispatchError> {
    let mut errors: Vec<String> = Vec::new();
    let mut attempted = false;

    for service in self.services.iter() {
        if !service.supports_platform(&token.platform) {
            continue;
        }
        attempted = true;
        match service.send_to_token(&token.device_token, &token.platform).await {
            Ok(()) => {
                return Ok(DispatchOutcome::Delivered {
                    backend: backend_name_for(service),
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

Notes for the planner:
- The loop body matches the existing listener semantics: skip non-matching, attempt first matching, **break on first `Ok(())`** (the `return` statement is the equivalent of the existing `break`).
- D-07 forbids `info!`/`error!`/`debug!` inside this method; the listener (caller) keeps the existing log lines.
- The `backend_name_for(service)` helper is at Claude's discretion (D-72 of CONTEXT - "internal helper functions are at Claude's discretion"). Two options worth considering:
  - Add a method to the `PushService` trait: `fn name(&self) -> &'static str` (cleanest, but expands trait surface — possibly out of scope for D-09's "tighten only").
  - Keep a parallel `Vec<&'static str>` of backend names alongside `Arc<[Arc<dyn PushService>]>` populated by `main.rs` at construction. Less elegant but zero trait churn.
  - The planner picks; both honor D-05's contract that `Delivered` carries `&'static str` ("fcm" / "unifiedpush").

#### `DispatchOutcome` enum (per D-05)

```rust
pub enum DispatchOutcome {
    Delivered { backend: &'static str },
}
```

(One variant today; reserved as an enum because Phase 2 may add `Queued`/`Skipped` semantics for the always-202 OPEN-1 resolution.)

#### `DispatchError` enum pattern

Copy the manual `Display` + `std::error::Error` impl pattern from `src/crypto/mod.rs:173-204` (`CryptoError`):

```rust
#[derive(Debug)]
pub enum DispatchError {
    NoBackendForPlatform,
    AllBackendsFailed { errors: Vec<String> },
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::NoBackendForPlatform =>
                write!(f, "no push backend supports this platform"),
            DispatchError::AllBackendsFailed { errors } =>
                write!(f, "all push backends failed: [{}]", errors.join("; ")),
        }
    }
}

impl std::error::Error for DispatchError {}
```

`#[derive(Debug)]` matches the `CryptoError` pattern (`src/crypto/mod.rs:173`). The hand-written `Display` + empty `impl std::error::Error` matches lines 187-204 of the same file. No `thiserror` is used in this codebase — sticking with the established style.

#### Visibility pattern

`pub struct`, `pub fn new`, `pub async fn dispatch`. Internal helpers (e.g., `backend_name_for`) stay private — matches the convention noted in `.planning/codebase/CONVENTIONS.md:46` ("Internal helpers default to private; e.g., `save_endpoints` in `src/push/unifiedpush.rs`").

---

### MODIFIED: `src/push/mod.rs` (barrel + trait surface)

**Analog:** the existing file itself (lines 1-23 for the trait, lines 25-63 for the blanket impls, plus the existing `pub mod` / `pub use` block at lines 4-8).

#### Add `dispatcher` to the barrel (D-01)

Existing structure to mirror (`src/push/mod.rs:4-8`):

```rust
pub mod fcm;
pub mod unifiedpush;

pub use fcm::FcmPush;
pub use unifiedpush::UnifiedPushService;
```

Phase 1 extends to:

```rust
pub mod dispatcher;
pub mod fcm;
pub mod unifiedpush;

pub use dispatcher::{DispatchError, DispatchOutcome, PushDispatcher};
pub use fcm::FcmPush;
pub use unifiedpush::UnifiedPushService;
```

Alphabetical ordering of `pub mod` / `pub use` is consistent with the existing layout (`fcm` before `unifiedpush`).

#### Tighten trait signature (D-09)

**Before** (`src/push/mod.rs:12-23`):

```rust
#[async_trait]
pub trait PushService: Send + Sync {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>>;

    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error>>;

    fn supports_platform(&self, platform: &Platform) -> bool;
}
```

**After** (D-09 tightens to `Send + Sync`, D-10 deletes `send_silent_push`):

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

The `Send + Sync` bound is already used in production code: `connect_and_listen` (`src/nostr/listener.rs:57`) and `FcmPush::init` (`src/push/fcm.rs:86`) and `FcmPush::get_access_token` (`src/push/fcm.rs:95`) all return `Result<_, Box<dyn std::error::Error + Send + Sync>>`. D-09 brings the trait in line.

#### Update blanket `Arc<>` impls

**Before** (`src/push/mod.rs:25-63`) — two blanket impls, three methods each.
**After** — same two blanket impls, **two** methods each (delegated). Pattern stays identical:

```rust
#[async_trait]
impl PushService for Arc<UnifiedPushService> {
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        (**self).send_to_token(device_token, platform).await
    }

    fn supports_platform(&self, platform: &Platform) -> bool {
        (**self).supports_platform(platform)
    }
}

#[async_trait]
impl PushService for Arc<FcmPush> {
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        (**self).send_to_token(device_token, platform).await
    }

    fn supports_platform(&self, platform: &Platform) -> bool {
        (**self).supports_platform(platform)
    }
}
```

The `(**self)` deref-then-deref pattern is preserved verbatim from existing lines 29, 37, 41, 49, 57, 61.

---

### MODIFIED: `src/push/fcm.rs` (concrete backend cascade)

**Analog:** itself. D-09 + D-10 cascade only.

#### Delete dead method (D-10)

Remove lines 220-266 (`send_silent_push` impl). The trait method no longer exists per D-10, so no impl is needed.

#### Tighten `send_to_token` return type (D-09)

**Before** (`src/push/fcm.rs:268-300`):

```rust
async fn send_to_token(
    &self,
    device_token: &str,
    platform: &Platform,
) -> Result<(), Box<dyn std::error::Error>> {
    let auth_token = self.get_access_token().await
        .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;
    // ... rest unchanged
}
```

**After** — drop the `.map_err` workaround on line 274 (it was bridging `Send + Sync` -> non-`Send + Sync`; with D-09 the bound matches and `?` propagates directly):

```rust
async fn send_to_token(
    &self,
    device_token: &str,
    platform: &Platform,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let auth_token = self.get_access_token().await?;
    // ... rest unchanged (lines 276-300)
}
```

The body from line 276 onward (`fcm_url` construction, payload build, HTTPS POST, status check, `info!` / `error!` lines, `Err(format!(...).into())`) is unchanged. `format!(...).into()` already produces a `Box<dyn Error + Send + Sync>` because `String: Send + Sync`, so the `Err(...)` line at the bottom (currently line 298) keeps working without modification.

The same `.map_err` removal applies inside the deleted `send_silent_push` (line 222) — moot once the method is gone.

---

### MODIFIED: `src/push/unifiedpush.rs` (concrete backend cascade)

**Analog:** itself. D-09 + D-10 cascade only.

#### Delete dead method (D-10)

Remove lines 127-163 (`send_silent_push` impl).

#### Tighten `send_to_token` return type (D-09)

**Before** (`src/push/unifiedpush.rs:165-193`):

```rust
async fn send_to_token(
    &self,
    device_token: &str,
    _platform: &Platform,
) -> Result<(), Box<dyn std::error::Error>> {
    // ... body
}
```

**After** — body unchanged, signature only:

```rust
async fn send_to_token(
    &self,
    device_token: &str,
    _platform: &Platform,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // ... body unchanged
}
```

`UnifiedPushService::send_to_token` does not currently use a `.map_err` workaround (it uses `.await?` on `reqwest::Client::post(...).send()` which already returns a `Send + Sync` error). No body change required, only the signature on line 169.

---

### MODIFIED: `src/main.rs` (wiring)

**Analog:** itself. Lines 46-90 are the construction site.

#### Drop `tokio::sync::Mutex` import (D-14)

**Before** (`src/main.rs:1-4`):

```rust
use actix_web::{web, App, HttpServer};
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;
```

**After**:

```rust
use actix_web::{web, App, HttpServer};
use log::info;
use std::sync::Arc;
```

(Verify no other `Mutex` use remains in `main.rs`. Current code uses `Mutex` only at line 79.)

#### Update the `use push::...;` line to surface `PushDispatcher`

**Before** (`src/main.rs:20`):

```rust
use push::{PushService, FcmPush, UnifiedPushService};
```

**After**:

```rust
use push::{FcmPush, PushDispatcher, PushService, UnifiedPushService};
```

(Alphabetised by Rust convention, matches the brace-import style noted in `.planning/codebase/CONVENTIONS.md:60`.)

#### Build `Vec<Arc<dyn PushService>>` instead of `Vec<Box<dyn PushService>>` (D-13)

**Before** (`src/main.rs:46`):

```rust
let mut push_services: Vec<Box<dyn PushService>> = Vec::new();
```

**After**:

```rust
let mut push_services: Vec<Arc<dyn PushService>> = Vec::new();
```

#### Collapse `Box::new(Arc::clone(&svc))` to `Arc::clone(&svc) as Arc<dyn PushService>` (D-13)

**Before** (`src/main.rs:65`):

```rust
push_services.push(Box::new(Arc::clone(&fcm_service)));
```

**After**:

```rust
push_services.push(Arc::clone(&fcm_service) as Arc<dyn PushService>);
```

**Before** (`src/main.rs:76`):

```rust
push_services.push(Box::new(Arc::clone(&unifiedpush_service)));
```

**After**:

```rust
push_services.push(Arc::clone(&unifiedpush_service) as Arc<dyn PushService>);
```

The blanket `impl PushService for Arc<FcmPush>` and `impl PushService for Arc<UnifiedPushService>` from `src/push/mod.rs:25-63` are what makes the `as Arc<dyn PushService>` coercion work. After Phase 1 those blanket impls still exist (they just lose `send_silent_push`). No new trait machinery is required.

#### Replace `Arc::new(Mutex::new(...))` with `Arc::new(PushDispatcher::new(...))` (D-14)

**Before** (`src/main.rs:79`):

```rust
let push_services = Arc::new(Mutex::new(push_services));
```

**After**:

```rust
let dispatcher = Arc::new(PushDispatcher::new(push_services));
```

(Variable rename from `push_services` to `dispatcher` is recommended for grep clarity — the old `push_services` binding referred to the lock-wrapped vector; the new binding is the dispatcher object.)

#### Pass `dispatcher` into `NostrListener::new` (D-15)

**Before** (`src/main.rs:82-86`):

```rust
let nostr_listener = NostrListener::new(
    config.clone(),
    push_services.clone(),
    token_store.clone(),
).expect("Failed to initialize Nostr listener - check MOSTRO_PUBKEY");
```

**After**:

```rust
let nostr_listener = NostrListener::new(
    config.clone(),
    dispatcher.clone(),
    token_store.clone(),
).expect("Failed to initialize Nostr listener - check MOSTRO_PUBKEY");
```

The `.expect("Failed to initialize Nostr listener - check MOSTRO_PUBKEY")` line stays unchanged. D-12 keeps `MOSTRO_PUBKEY` validation in place.

#### `AppState` is NOT extended (D-16)

`src/main.rs:93-95` (`AppState { token_store: token_store.clone() }`) is **untouched** in Phase 1. The dispatcher field on `AppState` belongs to Phase 2 — Phase 1 deliberately keeps that seam closed.

---

### MODIFIED: `src/nostr/listener.rs` (caller of dispatcher)

**Analog:** itself. The structural change is the lift of lines 119-135 into the dispatcher; the listener becomes a one-line caller plus `match` on the outcome.

#### Drop `tokio::sync::Mutex` import (D-15)

**Before** (`src/nostr/listener.rs:1-10`):

```rust
use log::{info, error, warn, debug};
use nostr_sdk::prelude::*;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

use crate::config::Config;
use crate::push::PushService;
use crate::store::TokenStore;
```

**After** — drop `tokio::sync::Mutex` and `crate::push::PushService` (no longer used directly), add `crate::push::PushDispatcher` and `crate::push::{DispatchError, DispatchOutcome}` for the match arms:

```rust
use log::{info, error, warn, debug};
use nostr_sdk::prelude::*;
use std::str::FromStr;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

use crate::config::Config;
use crate::push::{DispatchError, DispatchOutcome, PushDispatcher};
use crate::store::TokenStore;
```

#### Field type change (D-15)

**Before** (`src/nostr/listener.rs:12-17`):

```rust
pub struct NostrListener {
    config: Config,
    push_services: Arc<Mutex<Vec<Box<dyn PushService>>>>,
    token_store: Arc<TokenStore>,
    mostro_pubkey: String,
}
```

**After**:

```rust
pub struct NostrListener {
    config: Config,
    dispatcher: Arc<PushDispatcher>,
    token_store: Arc<TokenStore>,
    mostro_pubkey: String,
}
```

#### Constructor signature (D-15)

**Before** (`src/nostr/listener.rs:20-40`):

```rust
pub fn new(
    config: Config,
    push_services: Arc<Mutex<Vec<Box<dyn PushService>>>>,
    token_store: Arc<TokenStore>,
) -> Result<Self, Box<dyn std::error::Error>> {
    // MOSTRO_PUBKEY validation (lines 25-32) — UNCHANGED per D-12
    Ok(Self {
        config,
        push_services,
        token_store,
        mostro_pubkey,
    })
}
```

**After**:

```rust
pub fn new(
    config: Config,
    dispatcher: Arc<PushDispatcher>,
    token_store: Arc<TokenStore>,
) -> Result<Self, Box<dyn std::error::Error>> {
    // MOSTRO_PUBKEY validation (lines 25-32) — UNCHANGED per D-12
    Ok(Self {
        config,
        dispatcher,
        token_store,
        mostro_pubkey,
    })
}
```

Lines 25-32 (the `mostro_pubkey.len() != 64` check and the `XOnlyPublicKey::from_str` call) are **explicitly untouched** per D-12.

#### Capture for the closure (line 87)

**Before** (`src/nostr/listener.rs:86-87`):

```rust
let token_store = self.token_store.clone();
let push_services = self.push_services.clone();
```

**After**:

```rust
let token_store = self.token_store.clone();
let dispatcher = self.dispatcher.clone();
```

#### Add anti-CRIT-1 block comment above `Filter::new()` (D-11)

**Before** (`src/nostr/listener.rs:73-79`):

```rust
// Create filter for kind 1059 (Gift Wrap) events
// Note: We don't filter by author because Gift Wrap uses ephemeral keys
// The actual sender (Mostro) is encrypted inside. We filter by 'p' tag later.
let since = Timestamp::now() - Duration::from_secs(60);
let filter = Filter::new()
    .kinds(vec![Kind::Custom(1059)])
    .since(since);
```

**After** — replace lines 73-75 with the expanded block comment from D-11. The existing 3-line comment is preserved in spirit but extended to call out CRIT-1 explicitly:

```rust
// DO NOT add .authors(...) to this Filter. Two reasons:
//  1. Gift Wrap (NIP-59, kind 1059) wraps each event with an EPHEMERAL outer key.
//     The outer pubkey is never the Mostro daemon — filtering by author would drop everything.
//  2. Admin DMs in disputes are sent directly user-to-user, NOT through the Mostro daemon.
//     A mostro_pubkey author filter would silently drop every dispute notification.
// See PROJECT.md anti-requirement OOS-19 / PITFALLS CRIT-1.
let since = Timestamp::now() - Duration::from_secs(60);
let filter = Filter::new()
    .kinds(vec![Kind::Custom(1059)])
    .since(since);
```

This is the **highest-leverage location** for the guard (D-11 rationale): a future contributor reading `Filter::new()` sees the warning before they "fix" the dormant `MOSTRO_PUBKEY` field by applying it as a filter.

#### Replace inline iteration loop with `dispatcher.dispatch(...)` (D-04, D-06)

**Before** (`src/nostr/listener.rs:118-135`):

```rust
// Send push notification to the specific device
let services = push_services.lock().await;
for service in services.iter() {
    if service.supports_platform(&registered_token.platform) {
        match service.send_to_token(
            &registered_token.device_token,
            &registered_token.platform,
        ).await {
            Ok(_) => {
                info!("Push sent successfully for event {}", event.id);
                break; // Only need one service to succeed
            }
            Err(e) => {
                error!("Failed to send push: {}", e);
            }
        }
    }
}
```

**After** — single dispatch call + match. **Per D-08**, the log shape is preserved exactly: same `info!` "Push sent successfully for event {}" message on success, same `error!` "Failed to send push: {}" message on failure (no event id added to the error line in Phase 1; event id was not in the original error line either). Per D-07, the dispatcher itself emits no log lines:

```rust
// Dispatch via PushDispatcher (lock-free; iteration protocol owned by dispatcher)
match dispatcher.dispatch(&registered_token).await {
    Ok(DispatchOutcome::Delivered { backend: _ }) => {
        info!("Push sent successfully for event {}", event.id);
    }
    Err(DispatchError::NoBackendForPlatform) => {
        // Preserve existing observable behaviour: today's loop simply
        // exits silently when no service supports the platform.
        // Phase 2's /api/notify handler will distinguish this case.
    }
    Err(DispatchError::AllBackendsFailed { errors }) => {
        for err in errors {
            error!("Failed to send push: {}", err);
        }
    }
}
```

D-08 alignment notes:
- The current loop emits one `error!` per failed backend (line 131 inside the `for` loop runs once per failing service). The new code emits one `error!` per element of `errors`, preserving log multiplicity.
- The current loop is silent when no service `supports_platform` returns true (the `if` is just skipped). The new `NoBackendForPlatform` arm is also silent. Match.
- The truncated `&trade_pubkey[..16]` log lines at lines 108, 112-116, 137 are **untouched** per D-08.

---

## Shared Patterns

### Module barrel + `pub use` re-exports

**Source:** `src/push/mod.rs:4-8`, `src/nostr/mod.rs:1-3`
**Apply to:** `src/push/mod.rs` extension for the new `dispatcher` module.

```rust
pub mod dispatcher;
pub use dispatcher::{DispatchError, DispatchOutcome, PushDispatcher};
```

Documented in `.planning/codebase/CONVENTIONS.md:142-147` ("Modules expose public types via `pub use` re-exports at the module root for ergonomic access").

### Hand-written `Display` + `std::error::Error` enum

**Source:** `src/crypto/mod.rs:173-204` (`CryptoError`)
**Apply to:** `DispatchError` in `src/push/dispatcher.rs`.

Pattern:
1. `#[derive(Debug)]` on the enum.
2. `impl std::fmt::Display for X { fn fmt(...) { match self { ... } } }`.
3. Empty `impl std::error::Error for X {}`.

No `thiserror` is used in this codebase — sticking to the established hand-written style. (PITFALLS MIN-7 / "no thiserror" note in research; consistent with `CONVENTIONS.md` line 73 "Custom error enum: implements `Display` and `std::error::Error` manually".)

### `#[async_trait]` on trait + blanket `Arc<>` impls

**Source:** `src/push/mod.rs:12-63`
**Apply to:** Cascade D-09 + D-10 changes inside the same file.

The blanket `impl PushService for Arc<UnifiedPushService>` and `impl PushService for Arc<FcmPush>` are what makes `Arc::clone(&svc) as Arc<dyn PushService>` work in `main.rs`. After D-10 they shrink (no `send_silent_push`); after D-09 their `send_to_token` return type tightens. Same shape, fewer methods.

### `Box<dyn std::error::Error + Send + Sync>` return type

**Source:** `src/push/fcm.rs:86, 95` (`init`, `get_access_token`); `src/nostr/listener.rs:57` (`connect_and_listen`)
**Apply to:** Tightened `PushService::send_to_token` (D-09) and the cascade in `fcm.rs:268`, `unifiedpush.rs:165`.

Documented in `.planning/codebase/CONVENTIONS.md:67-70` ("Boxed trait objects are the dominant return type: `Result<T, Box<dyn std::error::Error>>` and `Result<T, Box<dyn std::error::Error + Send + Sync>>`"). D-09 collapses everything to the `+ Send + Sync` form to remove the `.map_err` workarounds at `fcm.rs:222, 274`.

### Logging convention at the listener boundary

**Source:** `src/nostr/listener.rs:108, 112-116, 127, 131, 137` (existing `info!` / `error!` / `debug!` lines in the event-handling closure)
**Apply to:** The post-refactor listener match arms.

Per D-07 the dispatcher emits **no** log lines. Per D-08 the listener preserves the existing log shape exactly:
- `info!("Push sent successfully for event {}", event.id)` — kept verbatim on `Delivered`.
- `error!("Failed to send push: {}", e)` — kept verbatim on `AllBackendsFailed` (one line per error in the `errors` vec, preserving today's per-failure cardinality).
- `debug!("No registered token for {}...", ...)` at line 137 — UNCHANGED.
- `info!("Event recipient (p tag): {}...", ...)` at line 108 — UNCHANGED.
- `info!("MATCH! Found registered token...", ...)` at lines 112-116 — UNCHANGED.

The pubkey-hashing helper PRIV-01 / `log_pubkey()` is **explicitly deferred to Phase 2** per D-08; today's truncation (`&trade_pubkey[..16.min(trade_pubkey.len())]`) stays.

### Concurrency: `Arc<...>` shared state, no Mutex

**Source:** `src/main.rs:36, 39` (`Arc<TokenStore>`); `src/store/mod.rs:30-31` (`RwLock<HashMap<...>>` inside `TokenStore`)
**Apply to:** `Arc<PushDispatcher>` shared between `main.rs` and `NostrListener` via `dispatcher.clone()`.

Documented in `.planning/codebase/CONVENTIONS.md:151-154` ("`Arc<TokenStore>` ... passed into background tasks ... internal state uses `tokio::sync::RwLock` for read-heavy maps"). Phase 1 specifically **drops** the `tokio::sync::Mutex` from this pattern (CRIT-5 / D-02): the dispatcher holds `Arc<[Arc<dyn PushService>]>` which is `Clone + Send + Sync` without any lock, since the slice is immutable after construction.

---

## No Analog Found

| File | Role | Reason |
|------|------|--------|
| _(none)_ | _(none)_ | Every Phase 1 file has an in-tree analog. The new `src/push/dispatcher.rs` follows the `unifiedpush.rs` / `fcm.rs` shape (struct + `impl` + tighten error type) plus the `crypto/mod.rs` enum-error idiom. No greenfield patterns. |

---

## Cross-Reference: Decisions to Patterns

| Decision | Pattern Section | File:Line(s) of Analog |
|----------|-----------------|------------------------|
| D-01 (new module + barrel re-export) | "Add `dispatcher` to the barrel" | `src/push/mod.rs:4-8` |
| D-02 (`Arc<[Arc<dyn>]>`, no Mutex) | "Struct + constructor pattern" | `.planning/research/ARCHITECTURE.md:131-135` |
| D-03 (single `dispatch` method) | "Core pattern: `dispatch` method" | `.planning/research/ARCHITECTURE.md:137-152` |
| D-04 (iteration protocol) | "Core pattern: `dispatch` method" | `src/nostr/listener.rs:119-135` (lift source) |
| D-05 (`DispatchOutcome` / `DispatchError` enums) | "`DispatchOutcome` enum", "`DispatchError` enum pattern" | `src/crypto/mod.rs:173-204` |
| D-06 (caller logs, not dispatcher) | "Logging convention at the listener boundary" | `src/nostr/listener.rs:127, 131` |
| D-07 (no log lines in dispatcher) | "Imports pattern" (lean imports), "`dispatch` method" | n/a (negative constraint) |
| D-08 (no log shape change in Phase 1) | "Logging convention at the listener boundary" | `src/nostr/listener.rs:108, 112-116, 137` |
| D-09 (tighten `send_to_token` return) | "Tighten trait signature", "Tighten `send_to_token` return type" (fcm/unifiedpush) | `src/push/fcm.rs:86, 95`; `src/nostr/listener.rs:57` |
| D-10 (delete `send_silent_push`) | "Tighten trait signature" (delete method), "Update blanket `Arc<>` impls", "Delete dead method" (fcm + unifiedpush) | `src/push/mod.rs:14, 28-31, 48-51`; `fcm.rs:220-266`; `unifiedpush.rs:127-163` |
| D-11 (anti-CRIT-1 block comment) | "Add anti-CRIT-1 block comment above `Filter::new()`" | `src/nostr/listener.rs:73-79` |
| D-12 (leave `MOSTRO_PUBKEY` alone) | "Constructor signature" (preserve lines 25-32) | `src/nostr/listener.rs:25-32`; `src/config.rs:60-72` |
| D-13 (`Vec<Arc<dyn>>` in main) | "Build `Vec<Arc<dyn PushService>>`...", "Collapse `Box::new(Arc::clone(...))`..." | `src/main.rs:46, 65, 76` |
| D-14 (Arc-wrap dispatcher; drop Mutex import) | "Drop `tokio::sync::Mutex` import" (main), "Replace `Arc::new(Mutex::new(...))`..." | `src/main.rs:4, 79` |
| D-15 (listener takes `Arc<PushDispatcher>`) | "Field type change", "Constructor signature", "Capture for the closure", "Drop `tokio::sync::Mutex` import" (listener) | `src/nostr/listener.rs:5, 14, 22, 36, 87` |
| D-16 (do NOT add to AppState in Phase 1) | "`AppState` is NOT extended" | `src/main.rs:93-95` (untouched) |

---

## Metadata

**Analog search scope:**
- `src/push/` (sibling concrete services for the new `dispatcher.rs`)
- `src/crypto/` (`CryptoError` enum pattern for `DispatchError`)
- `src/nostr/listener.rs` (lift source for the dispatch loop)
- `src/main.rs` (wiring site)
- `src/store/mod.rs` (`RegisteredToken`, `Platform` consumed by reference)
- `.planning/research/ARCHITECTURE.md` (Q1 dispatcher Rust sketch)
- `.planning/codebase/CONVENTIONS.md` (naming, error, import, module conventions)

**Files scanned:** 7 source files + 4 planning artifacts
**Pattern extraction date:** 2026-04-24
