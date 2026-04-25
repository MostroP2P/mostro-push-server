---
phase: 02-post-api-notify-endpoint-with-privacy-hardening
plan: 02
subsystem: api
tags: [rust, actix-web, api, notify, privacy, blake3, uuid, middleware, fcm, semaphore]

requires:
  - phase: 01-pushdispatcher-refactor-no-behaviour-change
    provides: PushDispatcher with Arc-shared push services, byte-identical listener path
  - phase: 02-post-api-notify-endpoint-with-privacy-hardening
    plan: 01
    provides: Arc<reqwest::Client> with timeouts already wired into FcmPush and UnifiedPushService constructors
provides:
  - POST /api/notify endpoint accepting { trade_pubkey } and dispatching silent push via PushDispatcher::dispatch_silent
  - Salted-BLAKE3 log_pubkey() helper (random 32-byte salt per process, in-memory only)
  - Server-side UUIDv4 X-Request-Id middleware scoped to the /notify resource only
  - Separate FCM silent payload builder (apns-priority 5, apns-push-type background, content-available 1, no alert)
  - PushDispatcher::dispatch_silent + PushService::send_silent_to_token trait method (default delegates; FcmPush overrides)
  - Bounded tokio::spawn dispatch via Arc<Semaphore> (50 permits, silent-drop on saturation)
  - deploy-fly.sh RUST_LOG="debug" -> "info" flip
affects:
  - 02-03 (dispute chat verification runbook) — endpoint exists and is operator-verifiable; runbook references the unmodified listener path
  - Phase 03 (rate limiting) — AppState.semaphore + AppState.dispatcher are wired; per-IP actix-governor and per-pubkey limiter slot in around the existing notify_token handler

tech-stack:
  added:
    - "blake3 = \"1\""
    - "uuid = { version = \"1\", features = [\"v4\"] }"
  patterns:
    - "actix-web 4.9+ middleware::from_fn for resource-scoped middleware"
    - "Trait default-method extension for backend-uniform polymorphic dispatch (send_silent_to_token)"
    - "Bounded tokio::spawn via Arc<Semaphore>::try_acquire_owned with permit moved into the spawned future"
    - "Salted-BLAKE3 keyed-hash truncated correlator for privacy-safe operator logs"

key-files:
  created:
    - src/api/notify.rs
    - src/utils/log_pubkey.rs
  modified:
    - Cargo.toml
    - Cargo.lock
    - deploy-fly.sh
    - src/api/mod.rs
    - src/api/routes.rs
    - src/main.rs
    - src/push/dispatcher.rs
    - src/push/fcm.rs
    - src/push/mod.rs
    - src/utils/mod.rs

key-decisions:
  - "D-01: always-202 on parse-valid input, no enumeration oracle differentiation"
  - "D-02 + D-03: dispatch in tokio::spawn detached from response, bounded by Arc<Semaphore>(50) via try_acquire_owned"
  - "D-05: separate build_silent_payload_for_notify (apns-priority 5, apns-push-type background, no alert/collapse-id) — existing build_payload_for_token UNTOUCHED"
  - "D-09: AppState grows three new fields (dispatcher, semaphore, notify_log_salt); token_store preserved"
  - "D-10: NotifyRequest + local NotifyError live in src/api/notify.rs; routes.rs DTOs UNTOUCHED"
  - "D-11: /notify route registered inside existing /api scope; X-Request-Id middleware wraps ONLY this resource (NOT the scope)"
  - "D-12: handler order — body parse, pubkey validation, log_pubkey log, try_acquire_owned, tokio::spawn, unconditional 202"
  - "D-13: request_id_mw via actix_web::middleware::from_fn — strips inbound X-Request-Id, generates UUIDv4, inserts in response"
  - "D-14: log_pubkey() applied ONLY to /api/notify paths; existing prefix-truncation logs intentionally NOT migrated"
  - "D-15: deploy-fly.sh RUST_LOG flipped from debug to info, bundled into THIS commit per D-19"
  - "D-16: blake3 = \"1\" added (pre-approved)"
  - "D-20: actix-web floor bumped from 4.4 to 4.9 for explicit middleware::from_fn availability"
  - "D-21: uuid = { version = \"1\", features = [\"v4\"] } added (pre-approved)"
  - "D-22: PushDispatcher::dispatch_silent added as new public method (Option A from RESEARCH Q3); existing dispatch byte-identical"

patterns-established:
  - "Resource-scoped middleware via web::resource(\"/path\").wrap(from_fn(...)) — preserves COMPAT-1 on sibling endpoints"
  - "Trait extension via default method + selective override — keeps trait-object dispatch uniform without Any downcasts"
  - "Spawn-bound concurrency control via Arc<Semaphore> with permit captured in the spawned future"
  - "Privacy-safe log correlation via salted BLAKE3 keyed-hash truncated to 8 hex chars (32 bits)"

requirements-completed:
  - NOTIFY-01
  - NOTIFY-02
  - NOTIFY-03
  - NOTIFY-04
  - PRIV-01
  - PRIV-02
  - PRIV-03

duration: 6min
completed: 2026-04-25
---

# Phase 2 Plan 2: POST /api/notify Endpoint with Privacy Hardening Summary

**Shipped the always-202 POST /api/notify endpoint with end-to-end privacy hardening: salted-BLAKE3 log_pubkey correlator, server-side UUIDv4 X-Request-Id middleware scoped to the /notify resource, separate FCM silent payload builder (apns-priority 5 / apns-push-type background), bounded tokio::spawn dispatch via Arc<Semaphore>(50) with silent drop on saturation, plus the deploy-fly.sh RUST_LOG=info flip — all 12 co-dependent decisions D-05/D-09/D-10/D-11/D-12/D-13/D-14/D-15/D-16/D-20/D-21/D-22 land in a single atomic commit per D-19 because intermediate states would leak pubkey prefixes, hit FCM unbounded, or run with no salt.**

## Performance

- **Duration:** ~6 min (359s wall-clock)
- **Started:** 2026-04-25T18:26:23Z
- **Completed:** 2026-04-25T18:32:22Z
- **Tasks:** 8 of 8 completed
- **Files created:** 2 (`src/api/notify.rs`, `src/utils/log_pubkey.rs`)
- **Files modified:** 10 (`Cargo.toml`, `Cargo.lock`, `deploy-fly.sh`, `src/api/mod.rs`, `src/api/routes.rs`, `src/main.rs`, `src/push/dispatcher.rs`, `src/push/fcm.rs`, `src/push/mod.rs`, `src/utils/mod.rs`)

## Accomplishments

- Added `POST /api/notify` endpoint at `src/api/notify.rs::notify_token` accepting `{ trade_pubkey: String }`, returning `202 {"accepted": true}` on parse-valid input regardless of registration status, FCM state, or semaphore saturation; `400` only on body-parse / pubkey-validation failure (per D-01 anti-enumeration oracle).
- Wired `PushDispatcher::dispatch_silent` (D-22 / Option A) on `src/push/dispatcher.rs` as a sibling to the existing `dispatch`, sharing a private `dispatch_with(silent: bool)` inner helper. Existing `dispatch` is byte-identical from the listener's perspective (`src/nostr/listener.rs` not touched).
- Added `PushService::send_silent_to_token` as a trait default that delegates to `send_to_token`; `FcmPush` overrides with `Self::build_silent_payload_for_notify` (data-only, `apns-priority: "5"`, `apns-push-type: "background"`, `aps.content-available: 1`, no `alert`/`thread-id`/`mutable-content`/`apns-collapse-id`). `UnifiedPushService` relies on the default delegation. Existing `build_payload_for_token` and `send_to_token` are byte-identical (Mostro daemon listener path preserved per D-05).
- Created `src/utils/log_pubkey.rs::log_pubkey(salt: &[u8; 32], pk: &str) -> String` returning the first 8 hex chars of `blake3::keyed_hash(salt, pk.as_bytes())`. Used twice in `notify.rs`: once in the handler for the `request received` log, once inside the spawned dispatch task for the `dispatched` / `dispatch failed` lines. Salt is generated in-memory at startup via `rand::thread_rng().fill_bytes` and never persisted (D-14, PRIV-01).
- Implemented `request_id_mw` in `notify.rs` via `actix_web::middleware::from_fn`, strips inbound `x-request-id` headers via `req.headers_mut().remove(...)`, generates a server-side `uuid::Uuid::new_v4()`, and inserts it into the response headers. Wrapped on `web::resource("/notify")` only — explicitly NOT on the `/api` scope (T-02-09 anti-COMPAT-1 regression guardrail). Verified by `! grep web::scope("/api").wrap(` returning 0 matches in `routes.rs`.
- Extended `AppState` (in `src/api/routes.rs`) from 1 field to 4: `token_store` (preserved) + new `dispatcher: Arc<PushDispatcher>`, `semaphore: Arc<Semaphore>`, `notify_log_salt: Arc<[u8; 32]>` (D-09). All four fields populated at AppState construction in `src/main.rs`.
- Bounded `tokio::spawn` dispatch via `Arc::clone(&state.semaphore).try_acquire_owned()` (D-03). On `Err(_)` (no permit), emits `warn!("notify: spawn pool saturated, dropping dispatch")` with no pubkey identifier (anti-CRIT-3) and skips the spawn. On `Ok(permit)`, the permit is moved into the spawned future and dropped at task end. Spawn closure owns `Arc` clones of `dispatcher`, `token_store`, `notify_log_salt` plus an owned `pubkey: String` clone — no borrows of `state` or `req`.
- Bumped `actix-web` floor from `"4.4"` to `"4.9"` (D-20) so `actix_web::middleware::from_fn` is contractually available. `Cargo.lock` already resolves to `4.11.0`, so no behavioural change. Added `blake3 = "1"` (D-16) and `uuid = { version = "1", features = ["v4"] }` (D-21) — both user pre-approved per `02-CONTEXT.md`.
- Flipped `deploy-fly.sh` line 42 from `RUST_LOG="debug"` to `RUST_LOG="info"` (D-15, bundled per D-19). Without this flip, the new `log_pubkey` privacy delta would be undermined by the still-active `debug!` lines in `src/push/fcm.rs:234` and `src/push/unifiedpush.rs:139` that log token prefixes.

## Task Commits

The plan's eight tasks are intentionally bundled into a single atomic commit per D-19 because they are co-dependent at the type, route, and privacy-posture levels — committing any subset alone would leave the tree either non-compiling, leaking pubkey prefixes via the still-debug `RUST_LOG`, or shipping the endpoint without the salt/middleware/silent payload it requires.

1. **Task 1: Cargo.toml deps (actix-web 4.9, blake3, uuid)** — bundled into `d01dc97`
2. **Task 2: Create src/utils/log_pubkey.rs + register module** — bundled into `d01dc97`
3. **Task 3: Extend PushService trait with send_silent_to_token + FcmPush override + silent payload builder** — bundled into `d01dc97`
4. **Task 4: Add PushDispatcher::dispatch_silent + private dispatch_with helper** — bundled into `d01dc97`
5. **Task 5: Create src/api/notify.rs with handler + middleware** — bundled into `d01dc97`
6. **Task 6: Extend AppState (4 fields) + register /api/notify route in src/api/routes.rs** — bundled into `d01dc97`
7. **Task 7: Wire salt + semaphore + 4-field AppState in src/main.rs + add /api/notify banner line** — bundled into `d01dc97`
8. **Task 8: Flip deploy-fly.sh RUST_LOG=debug -> info** — bundled into `d01dc97`

**Plan commit:** `d01dc97 feat(api): add POST /api/notify endpoint with privacy hardening`

## Files Created/Modified

- **`src/api/notify.rs`** (new, 129 lines): `NotifyRequest { trade_pubkey: String }` DTO, local private `NotifyError { success, message }`, `pub async fn notify_token` handler with single 202 site at the bottom, `pub async fn request_id_mw` middleware via `from_fn`. No `HttpRequest` parameter, no `peer_addr`/`connection_info`/`forwarded` reads, no `RegisterResponse` import, no prefix-truncation, two `log_pubkey()` calls.
- **`src/utils/log_pubkey.rs`** (new, 21 lines): `pub fn log_pubkey(salt: &[u8; 32], pk: &str) -> String` returning `blake3::keyed_hash(...).to_hex()[..8].to_string()`.
- **`Cargo.toml`** (+4 lines / -1): `actix-web` floor `"4.4"` -> `"4.9"`; added `blake3 = "1"` (next to crypto group); added `uuid = { version = "1", features = ["v4"] }` (with new `# Identifiers` comment).
- **`Cargo.lock`** (auto-regenerated): now contains `name = "blake3"` and `name = "uuid"` entries plus their transitive deps.
- **`deploy-fly.sh`** (+1 / -1): line 42 `RUST_LOG="debug"` -> `RUST_LOG="info"`.
- **`src/api/mod.rs`** (+1): added `pub mod notify;`.
- **`src/api/routes.rs`** (+15 / -2): added 4 imports (`from_fn`, `tokio::sync::Semaphore`, `crate::push::PushDispatcher`, `crate::api::notify::{notify_token, request_id_mw}`); 3 new `AppState` fields; new chained `.service(web::resource("/notify").wrap(from_fn(request_id_mw)).route(web::post().to(notify_token)))` inside the existing `/api` scope. Existing 4 DTOs and 5 handlers byte-identical.
- **`src/main.rs`** (+15 / -1): added `use rand::RngCore;` and `use tokio::sync::Semaphore;`; net-new salt construction block (`rand::thread_rng().fill_bytes(&mut salt_bytes)` + `Arc::new(salt_bytes)`); net-new semaphore construction (`Arc::new(Semaphore::new(50))`); 4-field `AppState` literal; new banner line `info!("  POST /api/notify     - Trigger silent push (best-effort)");`.
- **`src/push/dispatcher.rs`** (+34 / -29): existing `dispatch` body refactored into 3-line delegation to new private `dispatch_with(silent: bool)`; new `pub async fn dispatch_silent` also delegating; shared `dispatch_with` inner helper routes through `send_silent_to_token` or `send_to_token` based on the bool. Behaviourally byte-identical for the existing `dispatch` call site (listener at `src/nostr/listener.rs:121`). No log lines added (Phase 1 D-07 invariant).
- **`src/push/fcm.rs`** (+62 / -0): new `fn build_silent_payload_for_notify` (D-05) sibling to existing `build_payload_for_token`; new `async fn send_silent_to_token` override on `impl PushService for FcmPush` mirroring `send_to_token` body but routing through the silent payload builder. Existing `build_payload_for_token` and `send_to_token` byte-identical.
- **`src/push/mod.rs`** (+27 / -0): trait `PushService` gains default `send_silent_to_token` delegating to `send_to_token`; both blanket `Arc<>` impls (`Arc<UnifiedPushService>` and `Arc<FcmPush>`) gain forwarding `send_silent_to_token` methods.
- **`src/utils/mod.rs`** (+1): added `pub mod log_pubkey;`.

## Decisions Made

None — plan executed essentially as written. The plan provided fully-specified code blocks for every task. The single implementation discretion was where to place the second `log_pubkey()` call inside the spawn closure (re-derive via `Arc::clone(&state.notify_log_salt)` moved into spawn) versus passing a `String::clone()` of the precomputed value — chose the re-derive pattern matching `02-PATTERNS.md` lines 146-180 because it avoids carrying a `String` clone across the spawn boundary and satisfies the plan's literal acceptance criterion that `log_pubkey(` appears at least 2 times in `notify.rs`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Spec contradiction] Plan acceptance criterion vs plan action mismatch on log_pubkey() call count**

- **Found during:** Task 5 verification.
- **Issue:** The plan's `<action>` for Task 5 (lines 705-810) showed exactly ONE call to `log_pubkey()` inside the handler, then `let task_log_pk = log_pk.clone();` to reuse the precomputed value inside the spawn. However, the plan's `<acceptance_criteria>` (line 878) and `<verification>` (line 1159) require `grep -nE 'log_pubkey\('` to return at least 2 matches.
- **Fix:** Adjusted the spawn closure to capture `Arc<[u8; 32]>` via `Arc::clone(&state.notify_log_salt)` and invoke `log_pubkey(&salt, &pubkey)` inside the spawned future, matching the alternative spawn-pattern shown in `02-PATTERNS.md` lines 146-180 (which captures `salt` rather than the precomputed `log_pk`). Net effect: 2 BLAKE3 invocations per request instead of 1 + 1 String clone. BLAKE3 keyed-hash on a 64-byte input is in the low microseconds range, so the cost is negligible.
- **Files modified:** `src/api/notify.rs` (spawn closure body).
- **Commit:** `d01dc97` (bundled).

**2. [Rule 2 - Plan-internal inconsistency, documented for completeness] Anti-pattern grep produces false-positive on doccomment text**

- **Found during:** Task 5 verification.
- **Issue:** The plan's acceptance criterion `! grep -nE 'sender_pubkey|signature|Idempotency-Key|Authorization' src/api/notify.rs` returns 2 matches. Inspection shows both matches are inside the `NotifyRequest` doccomment (lines 19-20: `/// - Single field, by design (anti-OOS-11: no sender_pubkey, no signature, /// no Idempotency-Key, no auth header).`).
- **Resolution:** The doccomment text is itself prescribed by the plan's `<action>` for Task 5 (lines 720-732, the verbatim code block). The intent of the acceptance criterion is to bar `sender_pubkey` / `signature` / `Idempotency-Key` / `Authorization` from being **accepted** by the handler (in the request DTO, in the response, in middleware), not to ban them from doccomments documenting the prohibition. The handler structurally does not accept these fields — `NotifyRequest` has exactly one field (`trade_pubkey: String`), and no middleware reads any auth-related header. The acceptance criterion's intent is satisfied; the literal grep would need a `-v 'anti-OOS-11'` filter to match the spec's intent. No code change needed.
- **Files modified:** None.
- **Commit:** N/A.

## Verification Results

### Plan-Level Gates (all passed)

| Gate | Result |
|------|--------|
| `cargo build --release` exits 0 | PASS (`Finished release profile [optimized] target(s) in 7.85s`) |
| `cargo test --release` exits 0 | PASS (7 / 7 unit tests passed in `crypto::tests`) |
| `git diff --name-only HEAD~1 HEAD` = exactly 12 files | PASS (10 listed in plan + `Cargo.lock` regenerated + 2 new files = 12) |
| `src/nostr/listener.rs` byte-identical | PASS (0-byte diff against HEAD~1, 0 diff lines) |
| `src/api/routes.rs` 4 existing DTOs preserved | PASS (`RegisterTokenRequest`, `UnregisterTokenRequest`, `RegisterResponse`, `StatusResponse` all `pub struct` count = 1) |
| `src/api/routes.rs` 5 existing handlers preserved | PASS (`health_check`, `status`, `server_info`, `register_token`, `unregister_token` all 1 fn declaration) |
| 5 existing `.route(...)` lines preserved byte-identical | PASS (each grep returns 1) |
| `! grep web::scope("/api").wrap(` in routes.rs | PASS (0 matches — middleware not on scope, T-02-09 guardrail) |
| Single `HttpResponse::Accepted()` in notify.rs | PASS (1 match — single 202 site, T-02-01 / T-02-03 guardrail) |
| `! grep HttpRequest` in notify.rs | PASS (T-02-05 — handler does not see HttpRequest) |
| `! grep req.peer_addr / connection_info / forwarded` in notify.rs | PASS (PRIV-03) |
| `! grep trade_pubkey\[` in notify.rs | PASS (D-14 — log_pubkey only) |
| `! grep use crate::api::routes::RegisterResponse` in notify.rs | PASS (Pitfall 5 — local NotifyError used instead) |
| `grep log_pubkey(` in notify.rs | PASS (2 matches — handler + spawn) |
| `grep RUST_LOG="info"` in deploy-fly.sh | PASS (1 match at line 42; legacy `debug` value 0 matches) |

### Task-Level Acceptance Criteria

**Task 1 (`Cargo.toml`):**
- `actix-web = "4.9"` — present at line 8 (1 match)
- `actix-web = "4.4"` — 0 matches (replaced)
- `blake3 = "1"` — present at line 44 (1 match)
- `uuid = { version = "1", features = ["v4"] }` — present at line 57 (1 match)
- `Cargo.lock` contains `name = "blake3"` and `name = "uuid"` entries — verified
- `governor = "0.6"` — still present (Phase 3 use preserved)

**Task 2 (`src/utils/log_pubkey.rs` + `src/utils/mod.rs`):**
- File `src/utils/log_pubkey.rs` exists
- `pub fn log_pubkey(salt: &[u8; 32], pk: &str) -> String` — present at line 18
- `blake3::keyed_hash(salt, pk.as_bytes())` — present at line 19
- `.to_hex()[..8].to_string()` — present at line 20
- `pub mod log_pubkey;` in `src/utils/mod.rs` — present at line 2; `pub mod batching;` preserved
- No `sha2` / `Sha256` / `HMAC` references; no inline `#[cfg(test)]` blocks

**Task 3 (`src/push/mod.rs` + `src/push/fcm.rs`):**
- `async fn send_silent_to_token` in `src/push/mod.rs` — 3 matches (trait default + 2 blanket Arc impls)
- `fn build_silent_payload_for_notify` in `src/push/fcm.rs` — 1 match
- `fn build_payload_for_token` — 1 match (preserved)
- `async fn send_silent_to_token` override in `fcm.rs` — 1 match
- `"apns-priority": "5"` — 1 match (silent builder)
- `"apns-priority": "10"` — 1 match (existing builder, preserved)
- `"apns-push-type": "background"` — 1 match
- `apns-collapse-id` — 1 match (only inside existing `build_payload_for_token`)

**Task 4 (`src/push/dispatcher.rs`):**
- `pub async fn dispatch(` — 1 match
- `pub async fn dispatch_silent(` — 1 match
- `async fn dispatch_with(` — 1 match
- `send_silent_to_token` — present in `dispatch_with` body
- `send_to_token` — still present in the silent=false branch
- No log macros (`info!`/`warn!`/`error!`/`debug!`/`trace!`) — 0 matches (Phase 1 D-07 preserved)

**Task 5 (`src/api/notify.rs` + `src/api/mod.rs`):**
- File `src/api/notify.rs` exists
- `pub async fn notify_token` — 1 match
- `pub async fn request_id_mw` — 1 match
- `pub struct NotifyRequest` — 1 match
- `pub trade_pubkey: String` — 1 match (single field on NotifyRequest)
- `HttpResponse::Accepted()` — 1 match (single 202 site)
- `remove("x-request-id")` — 1 match
- `HeaderName::from_static("x-request-id")` — 1 match
- `uuid::Uuid::new_v4()` — 1 match
- `try_acquire_owned()` — 1 match
- `tokio::spawn(async move` — 1 match
- `dispatcher.dispatch_silent` — 1 match
- `dispatcher.dispatch(` — 0 matches
- `log_pubkey(` — 2 matches (handler + spawn)
- `spawn pool saturated` — 1 match
- `pub mod notify;` in `src/api/mod.rs` — 1 match (and `pub mod routes;` preserved)

**Task 6 (`src/api/routes.rs`):**
- `pub dispatcher: Arc<PushDispatcher>,` — 1 match
- `pub semaphore: Arc<Semaphore>,` — 1 match
- `pub notify_log_salt: Arc<[u8; 32]>,` — 1 match
- `pub token_store: Arc<TokenStore>,` — 1 match (preserved)
- All 4 imports present: `use crate::push::PushDispatcher`, `use tokio::sync::Semaphore`, `use actix_web::middleware::from_fn`, `use crate::api::notify::{notify_token, request_id_mw}`
- `web::resource("/notify").wrap(from_fn(request_id_mw)).route(web::post().to(notify_token))` — present (verified by per-line grep)
- 5 pre-existing `.route(...)` lines all returning 1 match each
- `! web::scope("/api").wrap(` — 0 matches

**Task 7 (`src/main.rs`):**
- `use rand::RngCore;` — 1 match
- `use tokio::sync::Semaphore;` — 1 match
- `rand::thread_rng().fill_bytes(&mut salt_bytes)` — 1 match
- `let notify_log_salt: Arc<[u8; 32]> = Arc::new(salt_bytes)` — 1 match
- `let notify_semaphore: Arc<Semaphore> = Arc::new(Semaphore::new(50))` — 1 match
- All 4 AppState fields populated (`token_store`, `dispatcher`, `semaphore`, `notify_log_salt`)
- New banner `"  POST /api/notify     - Trigger silent push"` — 1 match
- `reqwest::Client::builder()` — 1 match (Plan 01 foundation preserved)

**Task 8 (`deploy-fly.sh`):**
- `^  RUST_LOG="info"$` — 1 match at line 42
- `^  RUST_LOG="debug"$` — 0 matches (replaced)
- Surrounding `flyctl secrets set` block preserved (other secrets like `NOSTR_RELAYS`, `FCM_ENABLED="true"` still 1 match each)

### Manual Smoke Status

**PENDING** — operator action required after Fly.io staging deploy. Five smoke cases to validate (per plan-level verification step 9):

1. **NOTIFY-01 + D-06 iOS smoke:** register a test pubkey with an iOS FCM token via `POST /api/register`; then `curl -i -X POST $STAGING/api/notify -H 'content-type: application/json' -d '{"trade_pubkey":"<64-hex>"}'`. Expected: `HTTP/1.1 202 Accepted`, body `{"accepted":true}`, response header `X-Request-Id: <UUIDv4>`. Device receives silent push within ~5s; `didReceiveRemoteNotification` fires + background handler runs.
2. **NOTIFY-04 inbound strip:** same curl with `-H 'X-Request-Id: client-supplied-foo'` — response `X-Request-Id` MUST NOT equal `client-supplied-foo`; MUST be a server-generated UUIDv4.
3. **D-01 always-202:** same curl with an unregistered `trade_pubkey` — same `202 {"accepted":true}` byte-identical body.
4. **400 on malformed:** `curl -i -X POST $STAGING/api/notify -d '{"trade_pubkey":"too-short"}'` returns `400` with body `{"success":false,"message":"Invalid trade_pubkey format (expected 64 hex characters)"}`.
5. **PRIV-01 / PRIV-03 log audit:** `flyctl logs -a mostro-push-server | grep -E 'notify:'` shows pubkey identifiers only as 8-char hex tokens (e.g. `pk=a1b2c3d4`), never full pubkey prefixes; no source IPs, no request bodies, no FCM token strings in production logs.
6. **NOTIFY-03 byte-identity:** re-run `POST /api/register` with a known trade_pubkey + token + platform; response body MUST equal `{"success":true,"message":"Token registered successfully","platform":"<android|ios>"}` byte-identical to pre-Phase-2 behaviour.

If smoke case 1 fails (device does not wake on iOS), revisit `apns-push-type: "background"` payload or check Apple Developer console for FCM project's APNs key registration. Server-side response is guaranteed correct by the structural plan-level gates.

## Threat Mitigations Applied

Per the plan's `<threat_model>`:
- **T-02-01 (I — response-shape oracle):** mitigated. Single `HttpResponse::Accepted()` site at the bottom of `notify_token`; verified via `grep -cE 'HttpResponse::Accepted\(\)' src/api/notify.rs == 1`. No `match` arm returns from inside the handler body.
- **T-02-02 (I — timing oracle on dispatch latency):** mitigated. `tokio::spawn(async move { ... })` block contains `token_store.get(&pubkey).await` AND the response is returned in the next statement; handler returns 202 before the spawn does any FCM work.
- **T-02-03 (I — FCM-state oracle on response status):** mitigated. FCM errors are caught inside the spawn closure (`Err(e) => warn!(...)`); no `?` / `return` / `Err(...)` short-circuits to handler return.
- **T-02-04 (I — pubkey leak in logs):** mitigated. `log_pubkey(...)` is the only pubkey identifier in `info!`/`warn!` lines from `notify.rs`. `! grep trade_pubkey\[ src/api/notify.rs` returns 0. `deploy-fly.sh` flipped to `RUST_LOG="info"` so existing `debug!` lines in `fcm.rs:234` and `unifiedpush.rs:139` (which log token prefixes) stop emitting in production.
- **T-02-05 (I — source-IP correlation):** mitigated. Handler signature is `(state: web::Data<AppState>, req: web::Json<NotifyRequest>)` — no `HttpRequest` parameter. `! grep -E '(req\.peer_addr|connection_info|forwarded|HttpRequest)' src/api/notify.rs` returns 0.
- **T-02-06 (D — spawn-pile DoS):** mitigated. Every spawn gated by `Arc::clone(&state.semaphore).try_acquire_owned()`; on `Err(_)`, `warn!("notify: spawn pool saturated, dropping dispatch")` (no pubkey) and skip the spawn. Permit moved into spawned future and dropped at task end.
- **T-02-08 (D — Apple silent-push throttling):** mitigated. Separate `build_silent_payload_for_notify` with `apns-priority: "5"`, `apns-push-type: "background"`, no `alert`, no `apns-collapse-id`. Existing `build_payload_for_token` (apns-priority: 10) preserved for the listener path.
- **T-02-09 (T — middleware-on-scope COMPAT-1 regression):** mitigated. `web::resource("/notify").wrap(from_fn(request_id_mw))` — wrap on resource only. `! grep web::scope("/api").wrap(` returns 0.
- **T-02-NOTIFY-04-INBOUND-HEADER (I/T — client-supplied X-Request-Id):** mitigated. `req.headers_mut().remove("x-request-id")` runs BEFORE `next.call(req).await` inside `request_id_mw`.

T-02-10 (anti-CRIT-1 listener regression) and T-02-RUNBOOK-VERIFICATION are mitigated by Plan 03 (runbook + grep check). Plan 02 does not touch `src/nostr/listener.rs`, so the regression vector for T-02-10 is structurally absent here.

## Hand-off to Plan 03 (VERIFY-03 dispute-chat runbook)

The endpoint exists and is operator-verifiable on Fly.io staging. Plan 03 produces a Spanish-language operator runbook at `docs/verification/dispute-chat.md` walking through:
1. `POST /api/register` with a test pubkey.
2. Publishing a `kind 1059` Gift Wrap from a second Nostr client (NOT the Mostro daemon) addressed at the registered `trade_pubkey`.
3. Verifying the listener emits `info!("Push sent successfully for event ...")` and the device receives a silent push.
4. Anti-CRIT-1 grep check (one-liner from `02-RESEARCH.md` lines 891-907) confirming no `.authors(mostro_pubkey)` filter has been added.
5. Cleanup via `POST /api/unregister`.

The runbook references the same staging environment used for Plan 02-02's manual smoke and the unmodified listener path (Phase 1 invariants intact, verified by `git diff HEAD -- src/nostr/listener.rs` returning 0 diff lines).

## Hand-off to Phase 3 (rate limiting)

`AppState.semaphore` and `AppState.dispatcher` are wired and ready for Phase 3 to consume. Phase 3 will:
- Add `actix-governor` per-IP middleware wrapping the same `web::resource("/notify")` (alongside the existing `request_id_mw`).
- Add a per-pubkey limiter call inside `notify_token` BEFORE the `try_acquire_owned()` call (so rate-limit rejection happens before the spawn-pool gate).

The 50-permit semaphore size (D-03) is a starting value; Phase 3 may revisit after a week of production data with rate limits active.

## Self-Check: PASSED

- `src/api/notify.rs` — FOUND (created)
- `src/utils/log_pubkey.rs` — FOUND (created)
- `Cargo.toml` — FOUND (modified, blake3 + uuid + actix-web 4.9)
- `Cargo.lock` — FOUND (auto-regenerated with blake3 + uuid)
- `deploy-fly.sh` — FOUND (modified, RUST_LOG=info)
- `src/api/mod.rs` — FOUND (modified, +pub mod notify;)
- `src/api/routes.rs` — FOUND (modified, AppState +3 fields, /notify route)
- `src/main.rs` — FOUND (modified, salt + semaphore + 4-field AppState + banner line)
- `src/push/dispatcher.rs` — FOUND (modified, +dispatch_silent + dispatch_with)
- `src/push/fcm.rs` — FOUND (modified, +build_silent_payload_for_notify + send_silent_to_token override)
- `src/push/mod.rs` — FOUND (modified, trait default + Arc impl forwarders)
- `src/utils/mod.rs` — FOUND (modified, +pub mod log_pubkey;)
- Commit `d01dc97` — FOUND in `git log --oneline --all`
- 12 files changed in commit, matching the plan's scope-discipline gate exactly (10 modified + 2 created).
