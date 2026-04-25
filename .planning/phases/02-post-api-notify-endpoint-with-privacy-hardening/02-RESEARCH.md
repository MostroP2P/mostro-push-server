# Phase 2: `POST /api/notify` endpoint with privacy hardening - Research

**Researched:** 2026-04-25
**Domain:** Actix-web 4.x request middleware, tokio bounded-spawn, BLAKE3 keyed hashing, FCM v1 silent push payload, reqwest shared client hygiene
**Confidence:** HIGH for codebase claims and crate-version pins (verified against `Cargo.lock`); HIGH for FCM/Apple silent-push semantics (verified against published vendor docs); MEDIUM for the `from_fn` middleware migration path because `from_fn` post-dates the literal `actix-web = "4.4"` line in `Cargo.toml` but Cargo has resolved the dependency to `4.11.0` via `^` semver — flagged below.

## Summary

This is a **bundled hardening + endpoint phase**, not a greenfield surface. The locked decisions in CONTEXT.md (D-01..D-19) leave the planner with no architectural choices on the response contract, dispatch semantics, semaphore size, payload split, middleware scoping, or commit grain. The research surface is therefore narrow: confirm the **exact crate-version-specific API shapes** the planner will write into PLAN.md task steps, and surface any landmine that could prevent those decisions from being executed cleanly.

Five concrete findings shape the plan:

1. **`actix-web 4.11.0` is resolved in `Cargo.lock`** even though `Cargo.toml` says `"4.4"` (caret-semver). This means `actix_web::middleware::from_fn` (added in `4.9.0`) is **available without bumping `Cargo.toml`**, but the planner must NOT assume it's available without re-verifying the lockfile remains at `>= 4.9.0`. There is a recommended belt-and-suspenders option: pin `Cargo.toml` to `actix-web = "4.9"` to make the requirement explicit, but **that needs the user's explicit approval per global CLAUDE.md** (no dep version bumps without approval). If the user declines the bump, the alternative is the manual `Transform + Service` pattern (~80 lines of trait impl), still scoped to the single `/api/notify` resource. Recommendation: surface this as a plan-time question, not an unilateral decision.

2. **`uuid` is NOT in `Cargo.lock`**, neither directly nor transitively. NOTIFY-04 requires UUIDv4 generation in the middleware. CONTEXT.md pre-approves only `blake3` as a new dependency. The planner must either (a) ask the user to approve `uuid = { version = "1", features = ["v4"] }`, or (b) generate the request-id from `rand::thread_rng()` (already a transitive dep via `secp256k1`'s `rand-std` feature) as 16 random bytes formatted as a UUIDv4 hex string. Option (b) avoids a new dep but reinvents a wheel and is less reviewable. Recommendation: ask the user.

3. **`blake3 = "1"` is the stable line** (latest `1.8.4` per crates.io). `blake3::keyed_hash(key: &[u8; 32], input: &[u8]) -> Hash` is exactly the API CONTEXT.md D-14 specifies. `Hash::to_hex()` returns `arrayvec::ArrayString<{N}>` which `Deref`s to `&str` — slice `&hex[0..8]` works directly. No feature flags needed; default features are sufficient.

4. **FCM v1 silent push for iOS requires three header/payload elements together**: `apns-priority: "5"` (header), `apns-push-type: "background"` (header, FCM v1 will silently drop without it), and `aps.content-available: 1` (payload). MUST omit `alert` and `mutable-content`. The existing `build_payload_for_token` at `src/push/fcm.rs:165-215` violates all three for the silent-push use case (sets `apns-priority: "10"`, includes `alert`, no `apns-push-type`). D-05's separate-builder decision is the correct fix — the existing builder is sized for low-frequency Mostro daemon events and must NOT be modified.

5. **Tokio `Semaphore::try_acquire_owned()` returns `Result<OwnedSemaphorePermit, TryAcquireError>`** and requires the semaphore to be wrapped in `Arc<Semaphore>` (CONTEXT.md D-09 already says this). The owned-permit pattern is documented as the canonical way to bound `tokio::spawn` — the permit is `Send + 'static`, so it moves into the spawn closure cleanly and drops when the future completes (releasing one permit back to the pool).

**Primary recommendation:** Three-commit phase per D-19, with the planner addressing **two open questions before commit 2 begins**: (Q1) whether to bump `actix-web` in `Cargo.toml` to `"4.9"` for explicit `from_fn` support (vs. relying on `Cargo.lock` resolving to `4.11.0`), and (Q2) whether to add `uuid` as a new dep or hand-roll UUIDv4 from `rand`. Both are user-approval gates, not Claude's discretion. Everything else is mechanically derivable from CONTEXT.md.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Response Contract & Dispatch Semantics (OPEN-1 + OPEN-2 resolved)**

- **D-01: Always-`202 Accepted`.** The endpoint returns `202 { "accepted": true }` on ALL dispatch paths — registered pubkey dispatched, registered pubkey FCM-failed, pubkey not registered. Compile-time-constant JSON body. Exceptions: `429` (rate-limit, Phase 3) and `400` (parse / pubkey-validation failure). No other status codes. Rationale: PITFALLS CRIT-2 + CRIT-6 + RL-2.
- **D-02: Dispatch in `tokio::spawn` detached from the response.** Handler returns `202` immediately; FCM happens in a spawned task. Handler p99 < 50 ms regardless of FCM state.
- **D-03: Bound the spawn pile with `tokio::sync::Semaphore` — 50 permits.** Spawned task acquires permit before `dispatcher.dispatch`. On no permit: silent drop, no log line that encodes dispatch success/failure at request level, no 503. Semaphore owned by `AppState` as `Arc<Semaphore>`.
- **D-04: Mobile team coordination — decide now, document, communicate later.** Always-202 is locked here; mobile-team coordination handled separately by user/orchestrator.

**iOS Silent Push Payload (OPEN-5 resolved)**

- **D-05: Separate `build_silent_payload_for_notify()` in `src/push/fcm.rs`.** Existing `build_payload_for_token` (lines 165-215) UNTOUCHED — continues to serve listener path. New builder is data-only (no `alert`, no `title`/`body`), `android.priority: "high"`, `apns.headers.apns-priority: "5"`, `apns.headers.apns-push-type: "background"`, `apns.payload.aps.content-available: 1`, omits `apns-collapse-id`. Called only from `/api/notify` dispatch path.
- **D-06: Manual smoke on staging with a real iOS device.** Documented in SUMMARY.md after Phase 2 deploy. No automated iOS test in this phase.

**Outbound Client Hygiene**

- **D-07: Single shared `reqwest::Client` built in `main.rs`.** `.connect_timeout(Duration::from_secs(2))`, `.timeout(Duration::from_secs(5))`, `.pool_idle_timeout(Duration::from_secs(90))`. `Arc<reqwest::Client>` passed to `FcmPush::new(config, client)` and `UnifiedPushService::new(config, client)`.
- **D-08: Constructor breaking change is acceptable.** `FcmPush::new` and `UnifiedPushService::new` go from `(config)` to `(config, client)`. `main.rs:46-79` rewired. No external consumers exist.

**Endpoint Wiring (NOTIFY-01..04)**

- **D-09: `AppState` grows three new fields:** `dispatcher: Arc<PushDispatcher>`, `semaphore: Arc<Semaphore>`, `notify_log_salt: Arc<[u8; 32]>` (in-memory, random per process). Existing `token_store: Arc<TokenStore>` stays. Handler reads all four via `web::Data<AppState>`.
- **D-10: New types in a new file `src/api/notify.rs`.** `NotifyRequest { trade_pubkey: String }` and the response type live there, NOT in `src/api/routes.rs`. Existing DTOs UNTOUCHED (COMPAT-1 / OOS-20).
- **D-11: Route registration.** `src/api/routes.rs::configure` extended with `.route("/notify", web::post().to(notify::notify_token))` inside the existing `/api` scope. X-Request-Id middleware (D-13) wraps ONLY this resource.
- **D-12: Handler order of operations:**
  1. `web::Json<NotifyRequest>` body parse (serde rejects malformed → automatic 400).
  2. Validate `trade_pubkey` is 64 hex chars → 400 with same error body shape on failure.
  3. `info!` log using `log_pubkey()`.
  4. Try `Semaphore::try_acquire_owned`. If fail, log `warn!("notify: spawn pool saturated, dropping dispatch")` (no pubkey), skip to step 6.
  5. `tokio::spawn` future that holds permit, looks up via `TokenStore::get`, calls `dispatcher.dispatch(&token)` if present, logs outcome via `log_pubkey()`. Spawn closure owns `Arc` clones; no handler-state references.
  6. Return `HttpResponse::Accepted().json(json!({"accepted": true}))`.

**Observability & Privacy Hardening**

- **D-13: X-Request-Id middleware scoped to `/api/notify` only.** Generates UUIDv4 server-side per request, ignores any inbound `X-Request-Id` from client, inserts into response headers. Wrapped on single notify resource via `web::resource("/notify").wrap(...).route(...)`. ID NOT exposed to handler via extensions in Phase 2. All other endpoints UNTOUCHED.
- **D-14: `log_pubkey()` helper applied ONLY to new `/api/notify` handler and new spawned task.** Lives in new module `src/utils/log_pubkey.rs` (or similar; naming is Claude's discretion). Signature: `fn log_pubkey(salt: &[u8; 32], pk: &str) -> String` returning first 8 hex chars of `BLAKE3::keyed_hash(salt, pk.as_bytes())`. Salt random in-memory per process, never persisted. Existing prefix-truncation logs in listener/routes/store STAY — no retroactive migration.
- **D-15: `deploy-fly.sh` flips `RUST_LOG="debug"` → `"info"`.** Bundled into commit #2 with the handler — hard-bundle per CRIT-3 + DEPLOY-1.
- **D-16: Cargo.toml dependency addition: `blake3`.** User pre-approved this in discussion. Defaults are fine.

**Dispute Chat Verification Runbook (VERIFY-03)**

- **D-17: `docs/verification/dispute-chat.md`** is the single deliverable for VERIFY-03. Manual runbook in Spanish, covers register → publish kind 1059 from second client → verify push → grep-check anti-CRIT-1 (`.authors(mostro_pubkey)` not present in listener filter).
- **D-18: No test code for dispute chat path in Phase 2.** Manual only.

**Commit Grain**

- **D-19: 2-3 commits.**
  1. `feat(push): add shared reqwest Client with timeouts` — D-07 + D-08.
  2. `feat(api): add POST /api/notify endpoint with privacy hardening` — D-09..D-16 all together (co-dependent).
  3. `docs: add dispute chat verification runbook` — D-17 standalone.
  `deploy-fly.sh` `RUST_LOG` flip goes in commit #2, NOT separate.

### Claude's Discretion

- Exact file paths for new modules (`src/api/notify.rs`, `src/utils/log_pubkey.rs`) — names can shift for consistency.
- Exact Semaphore overflow log level (`warn!` vs `debug!`).
- Exact 400 response body shape — match existing `RegisterResponse { success, message, platform: None }` OR define lean error body in `notify.rs`. Claude picks whichever preserves existing shapes.
- Whether to use `Semaphore::try_acquire` vs `try_acquire_owned` — owned is typically needed for spawn; plan chooses.
- 32-byte salt initialization strategy (`rand::thread_rng().fill`, `OnceCell`, etc.).
- `Cargo.toml` position and feature flags for `blake3`.

### Deferred Ideas (OUT OF SCOPE)

- Rate limiting (LIMIT-01..06) — entire Phase 3.
- Integration test suite (VERIFY-01, VERIFY-02) — entire Phase 3.
- Retroactive migration of existing pubkey-prefix logs to `log_pubkey()` — future observability milestone.
- iOS APNs-direct backend without FCM — OOS-08, never.
- Context propagation of X-Request-Id into handler logs (via `HttpRequest::extensions_mut()`) — future phase.
- OS-level Semaphore tuning (the 50 permits number) — review after a week of Phase 3 production data.

</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| **NOTIFY-01** | `POST /api/notify` endpoint that accepts `{ "trade_pubkey": "<64-hex>" }`, validates, dispatches via `PushDispatcher`. | Standard Stack (`actix-web 4.11`, locked-resolved), Architecture Patterns (handler skeleton, `web::Json<NotifyRequest>`, validation copy-paste from `routes.rs:86`), Code Examples (full handler shape with `tokio::spawn` + semaphore). |
| **NOTIFY-02** | Endpoint matches mobile-team wire contract from `CHAT_NOTIFICATIONS_PLAN.md` Phase 4, with deviation (always-202) communicated separately. | D-01 + D-04 lock the contract; research confirms always-202 is the privacy-correct choice (CRIT-2 + CRIT-6) and matches the structurally-feasible response from D-02's spawn-detached dispatch. |
| **NOTIFY-03** | Existing `/api/register`, `/api/unregister`, `/api/health`, `/api/info`, `/api/status` request/response shapes byte-identical. | Phase 1 SUMMARY confirms no changes to `routes.rs` shipped in Phase 1. CONCERNS section "Untouched in Phase 2" + COMPAT-1 prevention. New types isolated in `src/api/notify.rs` (D-10). |
| **NOTIFY-04** | `X-Request-Id` middleware generates server-side UUIDv4 per request, ignores inbound header, exposes on response. | Architecture Patterns (`actix-web from_fn` since 4.9.0, resolved 4.11.0 in lockfile), Code Examples (middleware skeleton with `req.headers_mut()` strip + `res.headers_mut().insert` UUIDv4). UUIDv4 generation crate landmine — see Open Questions. |
| **PRIV-01** | `log_pubkey(pk)` helper using salted truncated BLAKE3, sole sanctioned form in new endpoint logs. | Standard Stack (`blake3 = "1"`), Code Examples (`keyed_hash(salt, pk.as_bytes()).to_hex()[..8]`). D-14 scopes application to new endpoint only. |
| **PRIV-02** | `deploy-fly.sh` sets `RUST_LOG="info"` (down from `"debug"`). | D-15 single-line edit; bundled into commit #2 per DEPLOY-1. |
| **PRIV-03** | `notify_token` never logs source IP, request body, response body, FCM/UnifiedPush token strings. | D-12 step 3 + D-14 enforce; handler order-of-operations explicitly excludes IP/token logging. |
| **VERIFY-03** | Manual runbook at `docs/verification/dispute-chat.md` walks operator through dispute-chat verification, includes anti-CRIT-1 grep. | D-17 + D-18; doc-only deliverable, written in Spanish. Code Examples section provides the grep one-liner the runbook reproduces. |

</phase_requirements>

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| HTTP request acceptance + body parse + validation | API / Backend (`src/api/notify.rs` handler) | — | Endpoint is server-internal; mobile clients are the only callers. No browser/SSR/CDN involvement. |
| UUIDv4 generation per response | API / Backend (`actix-web` middleware) | — | Generated server-side for privacy (client-supplied IDs are stripped, D-13). Lives in middleware scoped to single resource. |
| Salted BLAKE3 pubkey hashing | API / Backend (helper module + handler call sites) | — | Pure-Rust deterministic compute, no I/O. Salt held in `AppState` (process-memory only). |
| Spawn-bounding (Semaphore) | API / Backend (`AppState` field, handler entry) | — | tokio runtime lives in the API process; semaphore bounds in-flight FCM tasks. |
| FCM silent push payload construction | API / Backend (`src/push/fcm.rs::build_silent_payload_for_notify`) | — | Server-side JSON serialization; consumed by FCM v1 endpoint. |
| Outbound HTTPS to FCM v1 / UnifiedPush | API / Backend (existing concrete services via shared `reqwest::Client`) | External (Google FCM, UnifiedPush distributors) | Server is the egress origin; external services are dependencies. |
| Token lookup (`TokenStore::get`) | Database / Storage (in-memory `RwLock<HashMap>` in `src/store/mod.rs`) | — | Read-only from notify handler (D-12 step 5, OOS-21). No mutation from `/api/notify`. |
| Dispute-chat verification (kind 1059 listener path) | API / Backend (existing `src/nostr/listener.rs`, UNTOUCHED in Phase 2) | External (Nostr relays) | Phase 2 only documents this path; runbook is doc-tier deliverable. |

**Why this matters here:** Every capability lives on the API/Backend tier. Phase 2 has zero browser/SSR/CDN/database-server involvement — the only "external" tiers are Google FCM and Nostr relays, which are dependencies, not owners. This map's value is **negative**: it confirms there is no temptation to push any of this work to a different tier (e.g., no client-side hashing, no edge-cached UUID generation), and confirms `/api/notify` is the correct surface for all eight phase requirements.

## Standard Stack

### Core (already declared in Cargo.toml — no change)

| Library | Declared | Resolved (Cargo.lock) | Purpose | Why Standard |
|---------|----------|----------------------|---------|--------------|
| `actix-web` | `"4.4"` | **`4.11.0`** | HTTP server + routing + middleware (`from_fn`, `web::resource`, `wrap`, `web::Data`, `web::Json`, `HttpResponse::Accepted`) | Project's existing framework. The `4.11.0` resolution is critical — `from_fn` exists since `4.9.0`, so no manual `Transform + Service` boilerplate needed. `[VERIFIED: Cargo.lock line 'name = "actix-web"' / 'version = "4.11.0"'; CITED: docs.rs/actix-web/latest/actix_web/middleware/fn.from_fn.html]` |
| `tokio` | `"1.35"` features `["full"]` | **`1.48.0`** | Async runtime, `Semaphore`, `tokio::spawn`, `tokio::sync::Mutex`/`RwLock` (already in use). The `"full"` feature flag includes `sync` (Semaphore lives there) — no Cargo change. | `[VERIFIED: Cargo.lock line 'name = "tokio"' / 'version = "1.48.0"'; CITED: docs.rs/tokio/latest/tokio/sync/struct.Semaphore.html — try_acquire_owned available]` |
| `reqwest` | `"0.11"` features `["json"]` | **`0.11.27`** | Outbound HTTPS to FCM and UnifiedPush. `ClientBuilder` exposes `.connect_timeout`, `.timeout`, `.pool_idle_timeout`. `Client` is internally `Arc`-wrapped (cheap to `.clone()`); wrapping in `Arc<Client>` per CONTEXT.md D-07 is for **trait-object compatibility**, not for cloning cost. | `[VERIFIED: Cargo.lock line 'name = "reqwest"' / 'version = "0.11.27"'; CITED: docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html]` |
| `serde` + `serde_json` | `"1.0"` | (current) | `#[derive(Deserialize)]` on `NotifyRequest`, `serde_json::json!` for the 202 body. Existing project pattern. | `[VERIFIED: Cargo.toml]` |
| `log` | `"0.4"` | (current) | `info!` / `warn!` macros for the new endpoint. Existing project pattern. | `[VERIFIED: Cargo.toml]` |
| `hex` | `"0.4"` | (current) | Pubkey hex-decode validation (reuse exact pattern from `src/api/routes.rs:86`). Already declared. | `[VERIFIED: Cargo.toml; CITED: src/api/routes.rs:86]` |

### New (one approved by user, two open questions)

| Library | Version | Purpose | Status |
|---------|---------|---------|--------|
| `blake3` | `"1"` (resolves to `1.8.4` per crates.io as of 2026-04) | Salted-keyed pubkey hashing for `log_pubkey()` (D-14, D-16, PRIV-01) | **APPROVED in CONTEXT.md D-16.** Default features sufficient; no `no_std`, no `rayon`, no `digest`-trait needed. `[CITED: crates.io/crates/blake3 — version 1.8.4 latest; docs.rs/blake3/latest/blake3/fn.keyed_hash.html]` |
| `uuid` | `"1"` features `["v4"]` (resolves to `1.x`) | UUIDv4 generation for `X-Request-Id` middleware (NOTIFY-04, D-13) | **NOT YET APPROVED.** Not in `Cargo.lock` (verified: 0 hits for `name = "uuid"`). Requires user approval per global CLAUDE.md. See Open Questions. `[VERIFIED: Cargo.lock — no uuid entry]` |
| `actix-web` version pin bump (`"4.4"` → `"4.9"`) | — | Make `from_fn` requirement explicit in `Cargo.toml` rather than implicit via lockfile resolution | **NOT YET APPROVED.** Not strictly required (lockfile already resolves to `4.11.0`), but defensive against a future `cargo update` that downgrades. See Open Questions. |

### Alternatives Considered (rejected per CONTEXT.md or research)

| Instead of | Could Use | Why Rejected |
|------------|-----------|--------------|
| `blake3 = "1"` | `sha2` (already declared) | Slower for keyed-MAC use case; would need explicit HMAC construction. CONTEXT.md user picked `blake3` for purpose-built keyed-hash API. |
| `uuid = "1"` | `rand::thread_rng()` 16-byte fill, manual hex format | Hand-rolling UUIDv4 from raw bytes is ~10 lines but reinvents a wheel and isn't reviewable as "this is a UUIDv4". `rand` IS already a transitive dep (via `secp256k1`'s `rand-std` feature). Surface as user choice. |
| `actix_web::middleware::from_fn` (4.9+) | Manual `Transform + Service` impl (~80 lines of trait boilerplate) | Works on any actix-web 4.x, including 4.0-4.8. Only required if user rejects pinning ≥ 4.9 AND we want to be defensive against future `cargo update` resolving down to a pre-4.9 version. Not currently necessary because lockfile is at 4.11.0. |
| `actix_web::middleware::DefaultHeaders` | — | Adds static headers only; cannot generate per-request UUIDv4. Wrong tool. |
| `actix-web-lab` (separate crate) | — | `from_fn` graduated FROM `actix-web-lab` INTO `actix-web` core in 4.9.0. Adding it is redundant when 4.11.0 is already resolved. |
| Sharing `build_payload_for_token` for silent push (parameter-driven) | — | **REJECTED in D-05.** User explicitly chose split builder for clarity and to keep listener path's `apns-priority: "10"` unchanged. |

**Installation (commit #2 of D-19, after open questions resolved):**

```toml
# Cargo.toml — add to [dependencies] section
blake3 = "1"
# uuid = { version = "1", features = ["v4"] }   # ONLY IF user approves Q2
# actix-web = "4.9"                              # ONLY IF user approves Q1 explicit pin
```

**Version verification commands the planner should run before writing PLAN.md tasks:**

```bash
# Verify blake3 latest
cargo search blake3 --limit 1
# Verify uuid latest (if approved)
cargo search uuid --limit 1
# Confirm actix-web is still resolved >= 4.9 in lockfile
grep -A1 'name = "actix-web"' Cargo.lock | head -2
```

`[VERIFIED: as of 2026-04-25, blake3 1.8.4 is current; actix-web 4.11.0 is resolved in Cargo.lock]`

## Architecture Patterns

### System Architecture Diagram

```
                Mobile client (sender — User A)
                         │
                         │  POST /api/notify { "trade_pubkey": "<64-hex>" }
                         │  (NO auth, NO sender identification — OOS-10/11)
                         ▼
                Fly.io Edge Proxy (TLS termination)
                         │  (Fly-Client-IP injected — but UNUSED in Phase 2;
                         │   Phase 3 wires this for rate limiting)
                         ▼
                Actix-web HttpServer (src/main.rs)
                         │
                         ├─→ /api/health, /info, /status, /register, /unregister
                         │   (UNTOUCHED — D-13 middleware does NOT wrap these)
                         │
                         └─→ /api/notify  ◄─── X-Request-Id middleware (D-13)
                                  │           generates UUIDv4 server-side,
                                  │           strips inbound X-Request-Id,
                                  │           inserts into response headers
                                  ▼
                         notify_token handler (src/api/notify.rs)
                                  │
                                  │  1. web::Json<NotifyRequest> parse → 400 if malformed
                                  │  2. validate trade_pubkey (64 hex chars) → 400 if bad
                                  │  3. info!("notify request", log_pubkey(salt, pk))
                                  │  4. semaphore.try_acquire_owned()
                                  │       │
                                  │       ├─ Ok(permit) ─→ tokio::spawn(...)
                                  │       │                       │
                                  │       │                       │  (background task,
                                  │       │                       │   detached from response)
                                  │       │                       ▼
                                  │       │              token_store.get(pubkey)
                                  │       │                       │
                                  │       │                       ├─ Some(t) → dispatcher.dispatch(&t)
                                  │       │                       │                  │
                                  │       │                       │                  │  Phase 1 component
                                  │       │                       │                  │  (Arc<[Arc<dyn PushService>]>)
                                  │       │                       │                  ▼
                                  │       │                       │           build_silent_payload_for_notify()
                                  │       │                       │           POST FCM v1 / UnifiedPush
                                  │       │                       │                  │
                                  │       │                       │                  ▼
                                  │       │                       │           info!("dispatch outcome",
                                  │       │                       │                 log_pubkey(...))
                                  │       │                       │           (permit drops on task end)
                                  │       │                       │
                                  │       │                       └─ None → silently no-op
                                  │       │                                 (D-01: still 202 to caller)
                                  │       │
                                  │       └─ Err(NoPermits) ─→ warn!("spawn pool saturated")
                                  │                            (no pubkey logged; CRIT-3)
                                  │
                                  ▼
                         5. ALWAYS HttpResponse::Accepted()
                            .json({"accepted": true})
                            (D-01: no body variation by registration state, FCM state, or
                             permit availability — anti-oracle CRIT-2 + CRIT-6)
                                  │
                                  ▼
                         X-Request-Id middleware (response phase)
                                  │  inserts X-Request-Id: <uuid-v4> header
                                  ▼
                         Mobile client receives 202 + header
                         (no echo of trade_pubkey, no FCM state oracle)
```

**Key flow invariants** the diagram encodes:

- **Two paths converge on `PushDispatcher`** — the existing Nostr-listener path (UNTOUCHED in Phase 2) and the new notify path. Dispatch logic lives in one place.
- **Response is decoupled from dispatch** — the `tokio::spawn` arrow leaves the request lifecycle. Cancellation of the request (client disconnect) does NOT cancel the spawned dispatch; the permit owns the task lifetime.
- **Response is a constant** — every arrow leading to "202 + header" carries the same JSON body regardless of upstream state.
- **Other endpoints have NO middleware-added arrow** — the X-Request-Id middleware is scoped to one resource, not the `/api` scope.

### Recommended Project Structure (Phase 2 deltas only)

```
src/
├── api/
│   ├── mod.rs           # add `pub mod notify;`
│   ├── routes.rs        # extend AppState (3 new fields), add 1 .route() line
│   └── notify.rs        # NEW — NotifyRequest, notify_token handler, RequestId middleware
├── push/
│   ├── mod.rs           # UNTOUCHED (Phase 1 already exposed PushDispatcher)
│   ├── fcm.rs           # ADD build_silent_payload_for_notify() sibling fn;
│   │                     # CHANGE FcmPush::new(config) → FcmPush::new(config, client)
│   ├── unifiedpush.rs   # CHANGE UnifiedPushService::new(config) → (config, client)
│   └── dispatcher.rs    # UNTOUCHED
├── utils/
│   ├── mod.rs           # add `pub mod log_pubkey;`
│   └── log_pubkey.rs    # NEW — fn log_pubkey(salt, pk) -> String
└── main.rs              # construct shared reqwest::Client, salt, Semaphore;
                          # wire 4-field AppState; pass client to constructors
```

**File count delta:** 2 new files (`src/api/notify.rs`, `src/utils/log_pubkey.rs`), 1 new doc (`docs/verification/dispute-chat.md`), 5 modified files (`src/api/routes.rs`, `src/api/mod.rs`, `src/push/fcm.rs`, `src/push/unifiedpush.rs`, `src/utils/mod.rs`, `src/main.rs`, `Cargo.toml`, `deploy-fly.sh`). No file deletions.

### Pattern 1: actix-web `from_fn` middleware scoped to one resource

**What:** Generate UUIDv4 per response, ignore client-supplied `X-Request-Id`, insert generated ID into response headers. Wrapped on a single `web::resource("/notify")`, NOT the `/api` scope.

**When to use:** Per CONTEXT.md D-13, exactly here — privacy-scoped correlation that must NOT leak to other endpoints.

**Source:** `[CITED: docs.rs/actix-web/4.11/actix_web/middleware/fn.from_fn.html]` + `[CITED: docs.rs/actix-web/4.11/actix_web/struct.Resource.html#method.wrap]` `[VERIFIED: from_fn added in actix-web 4.9.0; lockfile resolves to 4.11.0]`

**Skeleton (planner translates this directly into a task action):**

```rust
// src/api/notify.rs
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
    // its own requests with server state)
    req.headers_mut().remove("x-request-id");

    // Generate server-side UUIDv4
    let id = uuid::Uuid::new_v4().to_string();   // <-- if user approves uuid dep

    let mut res = next.call(req).await?;

    // Insert into response headers
    res.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&id).expect("uuid string is always valid header value"),
    );
    Ok(res)
}
```

**Wiring in `src/api/routes.rs::configure`:**

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

`web::resource(...).wrap(...)` is the documented per-resource scoping idiom. `[CITED: docs.rs/actix-web/4.11/actix_web/struct.Resource.html#method.wrap — "Resource does not inherit its parent's default service"]`

### Pattern 2: tokio Semaphore-bounded `tokio::spawn`

**What:** Acquire `OwnedSemaphorePermit` BEFORE spawning; permit moves into spawn closure; permit drops when future completes (releasing one slot back).

**When to use:** Always, when spawning detached background work whose count must be bounded. CONTEXT.md D-03 mandates 50 permits.

**Source:** `[CITED: docs.rs/tokio/latest/tokio/sync/struct.Semaphore.html#method.try_acquire_owned]` `[VERIFIED: tokio 1.48.0 in Cargo.lock; try_acquire_owned in tokio::sync since at least 1.0]`

**Construction in `src/main.rs`:**

```rust
use tokio::sync::Semaphore;
use std::sync::Arc;

let notify_semaphore: Arc<Semaphore> = Arc::new(Semaphore::new(50));
```

**Acquisition + spawn in handler (`notify_token`):**

```rust
// In handler, after validation + log:
match Arc::clone(&state.semaphore).try_acquire_owned() {
    Ok(permit) => {
        let dispatcher = Arc::clone(&state.dispatcher);
        let token_store = Arc::clone(&state.token_store);
        let salt = Arc::clone(&state.notify_log_salt);
        let pubkey = req.trade_pubkey.clone();

        tokio::spawn(async move {
            // permit is moved in; will drop at end of this async block,
            // releasing the semaphore slot.
            let _permit = permit;

            if let Some(token) = token_store.get(&pubkey).await {
                match dispatcher.dispatch(&token).await {
                    Ok(outcome) => {
                        info!(
                            "notify dispatch ok pk={} outcome={:?}",
                            log_pubkey(&salt, &pubkey),
                            outcome,
                        );
                    }
                    Err(e) => {
                        // Per CRIT-6: log via log_pubkey, never propagate to caller
                        // (caller already received 202)
                        warn!(
                            "notify dispatch err pk={} err={}",
                            log_pubkey(&salt, &pubkey),
                            e,
                        );
                    }
                }
            }
            // None case: silently no-op (D-01 anti-oracle: caller saw 202 already)
        });
    }
    Err(_) => {
        // No permit available. CRIT-3 + D-12 step 4: log without pubkey.
        warn!("notify: spawn pool saturated, dropping dispatch");
    }
}

// Always 202, regardless of which branch ran above:
HttpResponse::Accepted().json(serde_json::json!({"accepted": true}))
```

**Critical detail:** `try_acquire_owned` requires `&Arc<Semaphore>`. This is why `AppState.semaphore: Arc<Semaphore>` (D-09) — the field IS the Arc, and `Arc::clone(&state.semaphore).try_acquire_owned()` is the call shape. Don't try to call `try_acquire_owned()` on a borrowed `Semaphore`; the API requires an owned `Arc` so the permit can hold a strong reference.

### Pattern 3: BLAKE3 keyed hash for `log_pubkey()`

**What:** `BLAKE3::keyed_hash(&salt[u8;32], pk.as_bytes())` produces a `Hash`; `to_hex()` returns `arrayvec::ArrayString` which `Deref`s to `&str`; slice `[..8]` for the operator-friendly short ID.

**When to use:** Every log line in `src/api/notify.rs` and the spawned dispatch task that references a pubkey. Per D-14, NOT used in any other module.

**Source:** `[CITED: docs.rs/blake3/latest/blake3/fn.keyed_hash.html]` + `[CITED: docs.rs/blake3/latest/blake3/struct.Hash.html#method.to_hex — returns ArrayString, Derefs to str]`

**Module skeleton (`src/utils/log_pubkey.rs`):**

```rust
//! Salted, truncated pubkey hashing for privacy-safe operator logs.
//!
//! Per Phase 2 D-14 (PRIV-01): used ONLY in the /api/notify handler and its
//! spawned dispatch task. Existing pubkey-prefix logs in src/nostr/listener.rs,
//! src/api/routes.rs, and src/store/mod.rs are intentionally NOT migrated to
//! preserve operator grep-ability through the transition.

/// Salted truncated BLAKE3 keyed-hash of a pubkey, for log correlation.
///
/// Returns the first 8 lowercase hex chars of `BLAKE3::keyed_hash(salt, pk)`.
/// 8 hex chars = 32 bits; collision-free for the registered pubkey set
/// (in-memory map, single process). Salt is random per process and held only
/// in memory — never persisted, never logged. Comparing log lines across
/// process restarts is intentionally impossible.
pub fn log_pubkey(salt: &[u8; 32], pk: &str) -> String {
    let hash = blake3::keyed_hash(salt, pk.as_bytes());
    hash.to_hex()[..8].to_string()
}
```

**Salt initialization in `src/main.rs` (after `Config::from_env`):**

```rust
use rand::RngCore;   // rand is already a transitive dep via secp256k1's rand-std feature

let mut salt_bytes = [0u8; 32];
rand::thread_rng().fill_bytes(&mut salt_bytes);
let notify_log_salt: Arc<[u8; 32]> = Arc::new(salt_bytes);
```

**Why `Arc<[u8; 32]>` and not `Arc<Vec<u8>>`:** The fixed-size array is exactly the type `keyed_hash` accepts. No bounds-check on every call. CONTEXT.md D-09 specifies `Arc<[u8; 32]>` precisely for this reason.

### Pattern 4: Shared `reqwest::Client` with timeouts

**What:** Single `reqwest::Client` built in `main.rs` with explicit timeouts. Cloned (cheaply — internally Arc-wrapped) into both push services.

**When to use:** Always — the existing `Client::new()` per service in `fcm.rs:78` and `unifiedpush.rs:34` are CONCERNS-flagged (lines 134-137) and CRIT-5 mitigation requires the timeouts to land before commit #2 wires the spawn pattern.

**Source:** `[CITED: docs.rs/reqwest/0.11/reqwest/struct.ClientBuilder.html]` `[VERIFIED: reqwest 0.11.27 in Cargo.lock; .connect_timeout, .timeout, .pool_idle_timeout all on ClientBuilder in 0.11.x]`

**Construction in `src/main.rs`:**

```rust
use std::time::Duration;
use std::sync::Arc;

let http_client = reqwest::Client::builder()
    .connect_timeout(Duration::from_secs(2))
    .timeout(Duration::from_secs(5))
    .pool_idle_timeout(Duration::from_secs(90))
    .build()
    .expect("reqwest::Client build never fails on default config");

let http_client = Arc::new(http_client);
```

**Note on `Arc` wrapping:** `reqwest::Client` is **already internally `Arc`-wrapped** (its `Clone` impl is cheap — bumps the inner Arc refcount). `[CITED: docs.rs/reqwest/0.11/reqwest/struct.Client.html — "The Client holds a connection pool internally, so it is advised that you create one and reuse it. ... Cloning the Client is cheap"]`

The `Arc<Client>` wrap in CONTEXT.md D-07 is a **convention choice** to make the sharing explicit in field types and to allow `Arc::clone` syntax everywhere — NOT a performance optimization. Either `client: Client` or `client: Arc<Client>` works. The planner should use `Arc<Client>` for consistency with the rest of `AppState`.

**Constructor cascade (D-08):**

```rust
// src/push/fcm.rs (BEFORE):
impl FcmPush {
    pub fn new(config: Config) -> Self {
        // ...
        Self { client: Client::new(), ... }
    }
}

// src/push/fcm.rs (AFTER):
impl FcmPush {
    pub fn new(config: Config, client: Arc<reqwest::Client>) -> Self {
        // ...
        Self { client, ... }    // field type changes from `Client` to `Arc<Client>`
    }
}
```

The internal `self.client.post(...)` calls work unchanged because `Arc<Client>` derefs to `Client`. No method-call site changes inside `fcm.rs` or `unifiedpush.rs` — only the constructor signature and the field type.

### Pattern 5: FCM v1 silent push payload for `/api/notify`

**What:** Data-only message (no `notification`), `android.priority: "high"`, `apns.headers.apns-priority: "5"`, `apns.headers.apns-push-type: "background"`, `apns.payload.aps.content-available: 1`. **No `alert`, no `mutable-content`, no `apns-collapse-id`.**

**When to use:** Only from `/api/notify` dispatch path. The existing `build_payload_for_token` (`src/push/fcm.rs:165-215`) keeps serving the listener path UNCHANGED.

**Source:** `[CITED: developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns — apns-priority: 5 + apns-push-type: background required for silent content-available: 1 pushes]` `[CITED: firebase.google.com/docs/cloud-messaging/concept-options — FCM v1 android.priority "high" semantics]`

**Skeleton (sibling to existing builder in `src/push/fcm.rs`):**

```rust
impl FcmPush {
    /// Silent push payload for the /api/notify chat-wake path.
    ///
    /// Data-only (no `alert`, no notification fallback) so iOS does not
    /// throttle the app for high-frequency silent pushes
    /// (apns-priority: 5 + apns-push-type: background per Apple's docs).
    /// Android keeps priority: "high" — the documented escape hatch from
    /// Doze / App Standby for data-only messages.
    ///
    /// Distinct from `build_payload_for_token` (which serves Mostro daemon
    /// events at apns-priority: 10 with an alert fallback). Do NOT merge:
    /// the two paths have fundamentally different frequency profiles
    /// (chat = continuous, daemon events = sporadic).
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
                        // intentionally NO apns-collapse-id — chat wake-ups must
                        // not coalesce with Mostro trade-update notifications
                        // sent by build_payload_for_token
                    },
                    "payload": {
                        "aps": {
                            "content-available": 1
                            // intentionally NO alert, NO mutable-content,
                            // NO thread-id — privacy/throttling discipline
                        }
                    }
                }
            }
        })
    }
}
```

**Wiring:** Phase 2 needs a new `send_to_token`-like path that uses the silent builder. **Open design point for the planner:** does `FcmPush` get a second method `send_silent_to_token` parallel to the existing `send_to_token`, or does the dispatcher gain awareness of "chat vs daemon" call sites?

**Recommendation:** Add `FcmPush::send_silent_to_token(&self, device_token, platform)` as a new public method on `FcmPush` (NOT on the trait — UnifiedPush has no per-payload distinction; its silent payload is already minimal in `unifiedpush.rs:133-136`). The notify spawned task calls `dispatcher.dispatch(...)` if we want the existing fan-out, OR a new `dispatcher.dispatch_silent(...)` method. The cleanest split given Phase 1's PushDispatcher API:

- **Option A:** `PushDispatcher::dispatch_silent(&self, token: &RegisteredToken)` mirrors the existing `dispatch` but calls `send_silent_to_token` for FCM and `send_to_token` for UnifiedPush. Adds one method to `PushDispatcher`.
- **Option B:** Add a `silent: bool` parameter to `PushDispatcher::dispatch`. Trait surface stays identical; FcmPush's `send_to_token` branches internally.

**Both are within Claude's discretion** (CONTEXT.md leaves implementation shape open as long as the existing `build_payload_for_token` is untouched and the silent path uses the new builder). Option A is more discoverable; Option B requires fewer new symbols. Plan-phase should pick one and document the rationale.

### Anti-Patterns to Avoid

- **Apply middleware at `App` or `/api` scope level:** Breaks NOTIFY-03 (other endpoints would gain `X-Request-Id` header). Wrap only the resource. Already addressed by D-13; mentioned here for verification-step coverage.
- **Differentiate response by registration status / FCM outcome:** Anti-CRIT-2, anti-CRIT-6. The handler must return `HttpResponse::Accepted().json(...)` from a single statement at the bottom of the function — **not** from inside a `match` arm.
- **Hold `RwLock` across `await`:** Anti-CONC-2. The handler must call `state.token_store.get(&pubkey).await` (which internally drops the lock before returning, per `src/store/mod.rs:85-88`) and use the returned `RegisteredToken` afterwards. Do NOT reach into `state.token_store.tokens` directly.
- **Mutate `TokenStore` from notify handler:** Anti-OOS-21 / CONC-3. No `last-notified-at`, no per-pubkey counters, no any write.
- **Add `MOSTRO_PUBKEY` filter to listener:** Anti-CRIT-1 / OOS-19. Phase 2 does NOT touch `src/nostr/listener.rs`. The runbook (D-17) reminds reviewers.
- **Log full `trade_pubkey` or its prefix in new code paths:** Anti-CRIT-3 / PRIV-03. New code uses `log_pubkey(salt, pk)` exclusively.
- **Reuse `apns-priority: "10"` or include `alert` in the silent builder:** Anti-FCM-1. Apple throttles apps that ship `apns-priority: "10"` + `content-available: 1` together.
- **Spawn without bounding:** Anti-CONC-1. Every `tokio::spawn` in the handler must be gated by a `try_acquire_owned`.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| UUIDv4 generation | Manual byte-fill from `rand::thread_rng()` + custom hex format with version/variant nibbles | `uuid = "1"` features `["v4"]` (after user approval) — `uuid::Uuid::new_v4().to_string()` | The variant/version nibbles in UUIDv4 are easy to get wrong; `uuid::Uuid::new_v4()` is reviewable as "this is a UUIDv4". Reviewer fatigue alone justifies the dep. **Open Question — needs user approval**. |
| Keyed hash for `log_pubkey` | HMAC-SHA256 from existing `sha2` (already declared) | `blake3::keyed_hash` (approved D-16) | BLAKE3's keyed mode is purpose-built for MAC use; HMAC adds a layer of construction (inner/outer pad) that's easy to typo. CONTEXT.md user picked BLAKE3 explicitly. |
| Bounded background-task pool | Manual `AtomicUsize` counter + check-then-spawn pattern | `tokio::sync::Semaphore` with `try_acquire_owned` | The check-then-spawn pattern has a TOCTOU race (between checking and spawning, another caller can acquire the slot). Semaphore is atomic-by-design. Already in tokio `full` — no Cargo change. |
| Custom `KeyExtractor` for actix-governor | (out of scope) | (Phase 3 territory) | Phase 2 has zero rate-limiting; this row is here as a marker that Phase 3 will need it. |
| Atomic file write for `unifiedpush_endpoints.json` | (already exists in current code) | Existing `fs::rename(temp, target)` pattern in `src/push/unifiedpush.rs:73-83` | Phase 2 doesn't touch persistence. Listed for completeness. |
| Custom retry/backoff for FCM | Manual sleep loop | (defer to a future "outbound-hardening" milestone) | Phase 2 is "best-effort dispatch" by D-01 + FCM-2 contract. Retries become observable timing oracles unless very carefully bounded — out of scope. |

**Key insight:** The phase ships **one new helper crate** (`blake3`, approved) and **maybe one more** (`uuid`, pending). Everything else uses crates already declared. The discipline of "use what's there" is consistent with COMPAT-1 and the project's "no deps without approval" rule.

## Runtime State Inventory

> Phase 2 is a **greenfield endpoint** + **bundled hygiene fixes**, NOT a rename / refactor / migration. There is no string rename, no datastore key change, no service registration update.

| Category | Items Found | Action Required |
|----------|-------------|------------------|
| Stored data | None — verified by reviewing `src/store/mod.rs` (in-memory `RwLock<HashMap>`), `src/push/unifiedpush.rs:30` (atomic JSON file with no schema change). The new `notify_log_salt` is in-memory only and explicitly never persisted (D-14). | None |
| Live service config | None — verified by reviewing `fly.toml` (no service-name change), Fly.io secrets (`deploy-fly.sh:27-42` — only `RUST_LOG` value flips, key name unchanged). | None — single-line `RUST_LOG="debug"` → `"info"` in `deploy-fly.sh:42` is a config-value edit, not a name change. Bundled into commit #2 per D-15. |
| OS-registered state | None — verified: no Windows / launchd / systemd / pm2 registrations. The Fly.io VM only runs the binary directly. | None |
| Secrets / env vars | No new env vars in Phase 2 (CONTEXT.md "code_context > Untouched in Phase 2" confirms `src/config.rs` not modified). The `notify_log_salt` is generated in-process, not loaded from env. | None |
| Build artifacts | None — verified: no `pyproject.toml`, no `egg-info`, no compiled binaries pinned to a specific name. `Cargo.lock` will gain entries for `blake3` (and possibly `uuid`); this is a normal `cargo build` outcome, not a stale-artifact concern. | None — `cargo build --release` regenerates everything cleanly. |

**Nothing found in any category** — this is a strictly additive phase for runtime state. The two state additions (`notify_log_salt`, `Semaphore`) live **only in process memory** by explicit design (D-09 + D-14), so process restart resets them with no migration concern.

## Common Pitfalls

### Pitfall 1: `from_fn` not present in the resolved `actix-web` version

**What goes wrong:** The planner writes a task action that imports `actix_web::middleware::from_fn`. After a `cargo update` (or fresh checkout on a different machine where the lockfile resolves differently), `actix-web` resolves to `4.4.x..4.8.x` and `from_fn` is missing. Compilation fails.

**Why it happens:** `Cargo.toml` says `"4.4"` (caret semver = `^4.4`), so any `4.x.y` ≥ 4.4 is acceptable. The current `Cargo.lock` resolves to `4.11.0` because that was the latest 4.x at lock-update time. A future `cargo update` could re-resolve, but in practice it stays current. The risk is theoretical but real for fresh checkouts.

**How to avoid:**
- **Option A (preferred, requires user approval):** Bump `Cargo.toml` to `actix-web = "4.9"` to make the floor explicit. This counts as a dep-version change → needs user approval.
- **Option B:** Leave `"4.4"` and rely on the lockfile. Add a comment in `src/api/notify.rs` near the `from_fn` import explaining the dependency on resolution ≥ 4.9.
- **Option C (most robust, no approval needed):** Implement the middleware manually with `Transform + Service` traits. Works on any `actix-web 4.x`. ~80 lines of boilerplate but zero version-resolution risk.

**Warning signs:** `cargo build` error `unresolved import 'actix_web::middleware::from_fn'`. `cargo tree | grep actix-web` shows version below 4.9.

### Pitfall 2: `uuid` not declared, planner forgets to add it

**What goes wrong:** `notify.rs` calls `uuid::Uuid::new_v4()`. Build fails: `unresolved import 'uuid'`.

**Why it happens:** CONTEXT.md D-16 only pre-approves `blake3`. UUIDv4 is needed for NOTIFY-04 / D-13 but the dep itself was not on the user's discussion radar.

**How to avoid:**
- The planner MUST surface the `uuid` dep as a question to the user **before commit #2 begins**.
- If user approves: add `uuid = { version = "1", features = ["v4"] }` to `Cargo.toml` in commit #1 or commit #2 (planner picks; commit #2 is more cohesive since it's used by the middleware).
- If user rejects: hand-roll UUIDv4 from `rand` (already a transitive dep). Reviewable burden is higher.

**Warning signs:** Plan task says "import `uuid`" without any task to update `Cargo.toml`.

### Pitfall 3: `tokio::sync::Semaphore::try_acquire_owned` called on a non-Arc Semaphore

**What goes wrong:** `state.semaphore.try_acquire_owned()` (where `state.semaphore: Semaphore`) fails to compile because `try_acquire_owned` requires `Arc<Self>`, not `&Self`.

**Why it happens:** Tokio's API distinguishes `try_acquire` (returns `SemaphorePermit<'_>` borrowing the semaphore) from `try_acquire_owned` (returns `OwnedSemaphorePermit` holding a strong Arc reference). The owned variant is the one you need for `tokio::spawn`, but the call site MUST start with an `Arc<Semaphore>`.

**How to avoid:** Field type is `Arc<Semaphore>` (D-09 already says this). Call shape is `Arc::clone(&state.semaphore).try_acquire_owned()` — note the explicit `Arc::clone` to get an owned `Arc` to call the method on. (Alternative: store a `&Arc<Semaphore>` reference — but the explicit clone is more idiomatic in handler context.)

**Warning signs:** Compiler error `the method 'try_acquire_owned' exists for struct 'Semaphore', but its trait bounds were not satisfied: required for 'Self' to implement 'Sized'` or similar.

### Pitfall 4: Spawned closure captures handler-state references instead of Arc clones

**What goes wrong:** The `tokio::spawn` future borrows `&state` or borrows from `&req`. Compiler error: `borrowed value does not live long enough`. Or worse: it compiles because `state` is `web::Data` which is itself Arc-wrapped, but the spawn closure now holds a strong ref to the entire `AppState` — including the `Arc<Semaphore>` and the `Arc<TokenStore>` — for the lifetime of the spawn, which can extend beyond worker lifetimes and confuse drop ordering.

**Why it happens:** Reflexive Rust capture semantics — `move` into spawn captures everything mentioned by name. Spawning closure must explicitly clone only what it needs.

**How to avoid:** Per D-12 step 5: "spawn closure owns `Arc` clones of dispatcher + token_store; no references to the handler state". Concretely:

```rust
let dispatcher = Arc::clone(&state.dispatcher);
let token_store = Arc::clone(&state.token_store);
let salt = Arc::clone(&state.notify_log_salt);
let pubkey = req.trade_pubkey.clone();          // owned String, not &str
// Now move into spawn:
tokio::spawn(async move { /* uses dispatcher, token_store, salt, pubkey only */ });
```

**Warning signs:** Code reviewer sees `state` or `req` mentioned inside `tokio::spawn(async move { ... })`.

### Pitfall 5: `RegisterResponse` reused for 400 path → response shape drift

**What goes wrong:** Planner picks "use `RegisterResponse` for the 400 case for operator consistency" (one of the discretion options in CONTEXT.md). A future refactor of `RegisterResponse` (out of Phase 2 scope but still possible) silently changes the `/api/notify` 400 shape too. COMPAT-1 protected `RegisterResponse`'s shape against incidental refactor in Phase 2 — but if `notify.rs` imports the type, COMPAT-1 protection is now load-bearing for both endpoints.

**Why it happens:** "Reuse for consistency" is reflexively appealing; the cross-file coupling cost is invisible.

**How to avoid:** Define a small lean error body in `src/api/notify.rs`:

```rust
#[derive(Serialize)]
struct NotifyError {
    success: bool,        // always false in 400 path
    message: String,
}
```

Same operator-visible shape as `RegisterResponse` minus the optional `platform` field. Zero cross-file coupling. **Recommendation: define new type in `notify.rs`.**

**Warning signs:** `src/api/notify.rs` has `use crate::api::routes::RegisterResponse;`.

### Pitfall 6: Salt initialized inside a request handler, not at startup

**What goes wrong:** Each request gets a different salt. `log_pubkey()` becomes useless for log correlation across requests for the same pubkey.

**Why it happens:** Reflexive "make it lazy" thinking. Or `OnceCell` mis-initialization where the first call sets it.

**How to avoid:** Per D-09: salt is generated in `main.rs` BEFORE `HttpServer::new(...)`, then placed in `AppState`. Single salt for the entire process lifetime. Restarting the process generates a new salt — that's the explicit privacy property, not a bug.

**Warning signs:** Salt construction code lives anywhere except `main.rs`. `OnceCell::new()` for the salt.

### Pitfall 7: Stripping the wrong header name (case-sensitivity / canonicalization)

**What goes wrong:** Middleware does `req.headers_mut().remove("X-Request-Id")` (capital-cased), but actix-web's `HeaderMap` is case-insensitive — and the canonical form is lowercase. The `remove` actually works (case-insensitive), but the mental model is fragile.

**Why it happens:** HTTP header names are case-insensitive per RFC 7230 §3.2, but `HeaderMap::remove` accepts any case and canonicalizes internally. The risk isn't a bug — it's reviewer confusion when the literal in code differs from the literal Apple/Google docs use.

**How to avoid:** Use lowercase `"x-request-id"` consistently in code (matches what `HeaderName::from_static` accepts at compile time). Use the title-case form in user-facing docs.

**Warning signs:** Mixed casing in the same file. `HeaderName::from_static("X-Request-Id")` (will panic at startup — `from_static` requires lowercase).

## Code Examples

Verified patterns the planner can reference directly in PLAN.md task actions:

### Full handler skeleton (`src/api/notify.rs::notify_token`)

```rust
// Source: synthesizes CONTEXT.md D-12 + Pattern 2 + Pattern 3 verified above
use actix_web::{web, HttpResponse, Responder};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::api::routes::AppState;
use crate::utils::log_pubkey::log_pubkey;

#[derive(Deserialize)]
pub struct NotifyRequest {
    pub trade_pubkey: String,
}

#[derive(Serialize)]
struct NotifyError {
    success: bool,
    message: String,
}

/// Sender-triggered silent push to the device registered for `trade_pubkey`.
///
/// Privacy contract:
/// - Always returns 202 on parse-valid input. Never differentiates registered
///   vs unregistered pubkeys (anti-CRIT-2 enumeration oracle).
/// - 400 only on JSON parse failure or pubkey-validation failure.
/// - Dispatch happens in a tokio::spawn detached from the response, bounded
///   by Arc<Semaphore> with 50 permits (anti-CRIT-6 + anti-CONC-1).
/// - Best-effort: FCM 200 means "Google accepted", not "device woke" (FCM-2).
pub async fn notify_token(
    state: web::Data<AppState>,
    req: web::Json<NotifyRequest>,
) -> impl Responder {
    // Step 2 (D-12): validate pubkey format. Reuses the exact pattern from
    // src/api/routes.rs:86 for operator consistency.
    if req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err() {
        warn!("notify: invalid trade_pubkey format");
        return HttpResponse::BadRequest().json(NotifyError {
            success: false,
            message: "Invalid trade_pubkey format (expected 64 hex characters)".to_string(),
        });
    }

    // Step 3 (D-12): structured log via log_pubkey only.
    let log_pk = log_pubkey(&state.notify_log_salt, &req.trade_pubkey);
    info!("notify: request received pk={}", log_pk);

    // Step 4 (D-12): bounded spawn via Semaphore.
    match Arc::clone(&state.semaphore).try_acquire_owned() {
        Ok(permit) => {
            let dispatcher = Arc::clone(&state.dispatcher);
            let token_store = Arc::clone(&state.token_store);
            let salt = Arc::clone(&state.notify_log_salt);
            let pubkey = req.trade_pubkey.clone();
            let task_log_pk = log_pk.clone();

            // Step 5 (D-12): detached dispatch.
            tokio::spawn(async move {
                let _permit = permit;   // dropped at task end; releases slot.

                // CONC-2-safe: get() drops the RwLock before returning.
                if let Some(token) = token_store.get(&pubkey).await {
                    // NOTE: dispatcher here uses the silent-payload path.
                    // See Pattern 5 — exact dispatch shape (Option A vs B)
                    // is plan-time choice.
                    match dispatcher.dispatch(&token).await {
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
                // Caller already received 202 (anti-CRIT-2 anti-CRIT-6).
                // No log line — that would be an oracle.
            });
        }
        Err(_) => {
            // No permit available. Pubkey NOT in this log line (anti-CRIT-3).
            warn!("notify: spawn pool saturated, dropping dispatch");
        }
    }

    // Step 6 (D-12): always 202 on parse-valid input.
    HttpResponse::Accepted().json(json!({"accepted": true}))
}
```

### `AppState` extension (`src/api/routes.rs:36-39`)

```rust
// Source: CONTEXT.md D-09 verbatim
use std::sync::Arc;
use tokio::sync::Semaphore;
use crate::push::PushDispatcher;

#[derive(Clone)]
pub struct AppState {
    pub token_store: Arc<TokenStore>,        // existing
    pub dispatcher: Arc<PushDispatcher>,      // new (D-09)
    pub semaphore: Arc<Semaphore>,            // new (D-09)
    pub notify_log_salt: Arc<[u8; 32]>,       // new (D-09)
}
```

### `main.rs` construction site (D-07, D-08, D-09 wiring)

```rust
// Source: synthesizes CONTEXT.md D-07/D-08/D-09 + Pattern 4 + Pattern 3 salt init
use std::sync::Arc;
use std::time::Duration;
use rand::RngCore;
use tokio::sync::Semaphore;

// (existing config + token_store + cleanup task code stays here, untouched)

// D-07: shared reqwest::Client with timeouts.
let http_client = Arc::new(
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .pool_idle_timeout(Duration::from_secs(90))
        .build()
        .expect("reqwest::Client build never fails on default config"),
);

// D-08: pass client into push services (signature change).
let unifiedpush_service = Arc::new(UnifiedPushService::new(config.clone(), http_client.clone()));
// ... existing load_endpoints, FCM init flow ...
// fcm_service constructed via FcmPush::new(config.clone(), http_client.clone())

// (existing dispatcher build via PushDispatcher::new(...) stays — Phase 1 component)

// D-09: notify_log_salt — random per process, in-memory only, never persisted.
let mut salt_bytes = [0u8; 32];
rand::thread_rng().fill_bytes(&mut salt_bytes);
let notify_log_salt: Arc<[u8; 32]> = Arc::new(salt_bytes);

// D-09: semaphore — bounds spawn pile.
let notify_semaphore: Arc<Semaphore> = Arc::new(Semaphore::new(50));

// D-09: 4-field AppState.
let app_state = AppState {
    token_store: token_store.clone(),
    dispatcher: dispatcher.clone(),
    semaphore: notify_semaphore.clone(),
    notify_log_salt: notify_log_salt.clone(),
};

// (existing HttpServer::new(...) stays the same)
```

### `deploy-fly.sh` flip (D-15 — single-line edit)

```bash
# src/deploy-fly.sh, line 42 BEFORE:
  RUST_LOG="debug"

# AFTER (commit #2):
  RUST_LOG="info"
```

### Anti-CRIT-1 grep one-liner for the runbook (D-17)

```bash
# Verify no .authors(...) filter has crept into the listener.
# Expected output: a single match — the comment block from Phase 1's D-11 — and
# nothing else. Matches inside src/nostr/listener.rs that are NOT comments fail
# the anti-requirement.
grep -n '\.authors(' src/nostr/listener.rs

# Bash exit-status check the runbook can use:
if grep -nE '^\s*[^/].*\.authors\(' src/nostr/listener.rs; then
    echo "FAIL: .authors() filter present in listener — anti-CRIT-1 violated"
    exit 1
else
    echo "PASS: no active .authors() filter"
fi
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Manual `impl Transform + impl Service` for ad-hoc middleware | `actix_web::middleware::from_fn` (async fn signature) | actix-web 4.9.0 (2024) | Eliminates ~80 lines of trait boilerplate per middleware. Phase 2 NOTIFY-04 directly benefits. `[CITED: docs.rs/actix-web/4.11/actix_web/middleware/fn.from_fn.html — graduated from actix-web-lab into core]` |
| `actix-governor` 0.5 `KeyExtractor::extract` returning `Result<Self::Key, ()>` | (Phase 3 territory — not Phase 2) | actix-governor 0.5 → 0.6 | Mentioned for context — OPEN-4 in Phase 3 reopens this. |
| `apns-priority: "10"` for `content-available: 1` silent pushes | `apns-priority: "5"` + `apns-push-type: "background"` (FCM v1 mandatory pairing) | Apple iOS 13 (2019); FCM v1 added explicit `apns-push-type` requirement ~2020 | The current `build_payload_for_token` in fcm.rs:165-215 still uses the old pattern. Acceptable for low-frequency Mostro events; would be wrong for chat. D-05's separate-builder is the fix. `[CITED: developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns]` |
| `reqwest::Client::new()` per service | Single `reqwest::Client` shared via `Arc` (or via `Client::clone`) | Always (since reqwest 0.10) | Cited as best practice in reqwest docs since 0.10. CONCERNS.md flags the current per-service `Client::new()` at lines 134-137. D-07 fixes. |
| `BLAKE3::hash(input)` (un-keyed) for log identifiers | `BLAKE3::keyed_hash(salt, input)` for MAC-style log identifiers | BLAKE3 1.0 (2020) — keyed mode was day-1 | The keyed-vs-un-keyed choice is privacy-relevant: un-keyed allows anyone with the input to reproduce the hash; keyed-with-secret-salt requires the salt. CONTEXT.md D-14 specifies keyed. |

**Deprecated / outdated for this phase:**

- **Manual UUIDv4 byte-fill from `rand`**: works but uses up reviewer attention; `uuid = "1"` is the conventional choice in 2026 Rust. Surface as Open Question (Q2).
- **HMAC-SHA256 from `sha2` for `log_pubkey`**: would work, but BLAKE3 keyed-hash has been the recommended primitive for new code since 2020. CONTEXT.md user already chose BLAKE3.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | The 50-permit semaphore size is correct for Fly.io's 25-connection cap × ~5x oversubscription buffer. | Standard Stack (Pattern 2) | If too low: legitimate dispatches get dropped silently (no caller-visible error per D-03, but missed pushes on real device). If too high: at peak load, 50 in-flight FCM tasks each holding a `reqwest` connection saturates the 512MB Fly machine's open-FD budget. **`[ASSUMED]`** — CONTEXT.md D-03 picks 50, marked "tunable". Risk acceptable per CONTEXT.md "Deferred Ideas — review after a week of production data with Phase 3's rate limits active". |
| A2 | The `apns-collapse-id` omission from the silent builder is correct for chat (vs. the existing builder's `"mostro-trade"`). | Pattern 5 (Code Examples) | If wrong: rapid-fire chat wakes coalesce on Apple's side, dropping intermediate notifications. CONTEXT.md D-05 specifies omission with the rationale "chat wake-ups must not coalesce with Mostro trade-update notifications". **`[CITED: Apple APNs docs say apns-collapse-id is optional and unsetting it means each notification is delivered independently]`** but the practical effect under chat-frequency load needs the iOS smoke test (D-06) to confirm. |
| A3 | `reqwest::Client::clone()` is "cheap" because the Client is internally `Arc`-wrapped. | Pattern 4 | None — extensively documented and verified. **`[CITED: docs.rs/reqwest/0.11/reqwest/struct.Client.html]`** |
| A4 | UUIDv4 is the right ID format for `X-Request-Id` (vs. ULID, KSUID, snowflake). | Pattern 1 | None — NOTIFY-04 in REQUIREMENTS.md explicitly says "UUIDv4". **`[CITED: REQUIREMENTS.md NOTIFY-04]`** |
| A5 | The 8-hex-char (32-bit) truncation of BLAKE3 keyed-hash is collision-free for the project's pubkey set size. | Pattern 3 | If pubkey set grows past ~10k entries, birthday-paradox collisions become possible (2^16 ≈ 65k). For the current Mostro user set this is fine; for v2.0+ scale it might become a concern. **`[ASSUMED]`** — CONTEXT.md D-14 specifies 8 chars; risk noted in CONTEXT.md "Deferred Ideas" implicitly via the retroactive-migration deferral. |
| A6 | `actix-web 4.11.0` will remain the resolved version through Phase 2 development without an unintended `cargo update` regressing to a pre-4.9 version. | Standard Stack | If `cargo update` runs and resolution changes, `from_fn` import breaks. Mitigation: bump `Cargo.toml` to `"4.9"` (Open Question Q1) OR document the constraint in `notify.rs`. **`[VERIFIED: Cargo.lock at HEAD]`** but **`[ASSUMED]`** for forward stability. |

**If this table contained no rows:** all claims would be verified or cited. Six assumptions remain — five are minor design choices made in CONTEXT.md (deferring detailed risk analysis to a future tuning milestone), one (A6) is a verified-now-but-future-fragile lockfile fact. None block planning.

## Open Questions

These need user resolution **before commit #2 begins** (commit #1 is just `reqwest::Client` hygiene, doesn't touch middleware or hashing).

### Q1. Bump `actix-web` to `"4.9"` in `Cargo.toml`?

- **What we know:** `Cargo.lock` resolves to `4.11.0`; `from_fn` exists since `4.9.0`. Per global CLAUDE.md, no dep version bumps without approval.
- **What's unclear:** Whether the user wants the explicit pin (defensive) or is OK relying on the lockfile (works today, fragile if `cargo update` ever resolves down).
- **Options:**
  1. Bump `Cargo.toml` to `"4.9"` (1 line edit). Most defensive. Needs user approval.
  2. Leave `"4.4"`, add a comment in `src/api/notify.rs` explaining the requirement. No approval needed; assumes lockfile stays current.
  3. Hand-roll middleware via `Transform + Service` traits. Works on any 4.x. ~80 lines of boilerplate. No approval needed.
- **Recommendation:** **Option 1** if user approves; otherwise **Option 2**. Option 3 is a fallback only if user rejects the bump AND wants belt-and-suspenders.

### Q2. Add `uuid = "1"` features `["v4"]` as a new dep?

- **What we know:** `uuid` is NOT in `Cargo.lock` (verified). NOTIFY-04 / D-13 require UUIDv4 generation.
- **What's unclear:** Whether the user prefers a small new dep or hand-rolling from `rand` (already transitive).
- **Options:**
  1. Add `uuid = { version = "1", features = ["v4"] }`. Reviewable; conventional. Needs user approval.
  2. Hand-roll: 16 bytes from `rand::thread_rng()`, format with `format!("{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}", ...)` setting version/variant nibbles per RFC 4122. ~10 lines. Doesn't need approval but adds reviewer burden.
- **Recommendation:** **Option 1**. The `uuid` crate is ubiquitous and the manual path is exactly the kind of detail CRIT-style reviewers miss.

### Q3. `PushDispatcher` API shape for silent dispatch (Option A vs B in Pattern 5)?

- **What we know:** D-05 mandates the new `build_silent_payload_for_notify` exists and is used only by `/api/notify`. CONTEXT.md leaves the dispatch wiring shape under Claude's discretion.
- **What's unclear:** Whether `PushDispatcher::dispatch_silent` (Option A — new method) or `PushDispatcher::dispatch(token, silent: bool)` (Option B — flag parameter) is preferred.
- **Recommendation:** **Option A** (`dispatch_silent`). More discoverable, no behavioral overload of the existing `dispatch` method (which the listener path keeps calling unchanged). The internal implementation can share an inner helper to avoid duplication. Plan-phase decides.

## Environment Availability

> Phase 2 has external dependencies but they are mostly already present and verified. Listed for completeness.

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain | All build | ✓ | 1.75+ (project min); 1.83 in Dockerfile | — |
| `cargo` | Build | ✓ | (bundled with rustc) | — |
| `actix-web` 4.9+ in lockfile | NOTIFY-04 middleware via `from_fn` | ✓ | 4.11.0 (resolved) | Manual `Transform + Service` impl (Pitfall 1, Option C) |
| `tokio` 1.x with `full` features | Semaphore | ✓ | 1.48.0 (resolved) | — |
| `reqwest` 0.11.x | FCM + UnifiedPush HTTP | ✓ | 0.11.27 (resolved) | — |
| `blake3` (new) | `log_pubkey` helper | ✗ (to add in commit #2) | will resolve to `1.8.4` | — (approved, no fallback needed) |
| `uuid` (potential new) | X-Request-Id middleware | ✗ | — | Hand-roll from `rand` (Open Question Q2) |
| `cargo build --release` | Compile | ✓ | (verified passing in Phase 1 SUMMARY) | — |
| Fly.io account + flyctl | Deploy (D-15 + D-06 manual smoke) | (operator concern) | — | — |
| Real iOS device + FCM-registered test pubkey | D-06 manual smoke | (operator concern) | — | — |
| Second Nostr client (e.g., nostore, Damus) | D-17 runbook publishes test kind 1059 event | (operator concern) | — | — |

**Missing dependencies with no fallback:** None for development. Operator-side dependencies (real iOS device, Nostr client) for D-06 and D-17 are deferred to operator action.

**Missing dependencies with fallback:** `uuid` — see Open Questions Q2.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Built-in `cargo test` (Rust 2021 edition + tokio runtime via `#[tokio::test]` attribute) |
| Config file | None — Cargo defaults |
| Quick run command | `cargo build --release` (the Phase 1 SUMMARY's primary gate; under 30s for incremental) |
| Full suite command | `cargo test --release` (currently no-op — repo has zero `#[cfg(test)]` modules with assertions) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| NOTIFY-01 | `POST /api/notify` accepts valid body, dispatches via `PushDispatcher` | manual-only (Phase 2) → integration in Phase 3 | `cargo build --release` (compile check); manual curl on Fly.io staging | n/a — manual only |
| NOTIFY-02 | Wire contract matches mobile-team plan (modulo D-01 always-202) | manual coordination | (out-of-band — user/orchestrator confirms with mobile team) | n/a |
| NOTIFY-03 | Existing endpoints byte-identical | manual diff against pre-Phase-2 fixture (planned) | `git diff main -- src/api/routes.rs` shows only `AppState` extension + 1 new `.route()` line + import additions | n/a |
| NOTIFY-04 | UUIDv4 in `X-Request-Id` response header on `/api/notify` only | manual smoke + curl | `curl -i -X POST http://staging/api/notify -d '{"trade_pubkey":"<64-hex>"}'` → check `X-Request-Id:` header present | n/a |
| PRIV-01 | `log_pubkey()` is the only sanctioned form in new endpoint logs | manual grep on resulting code | `! grep -nE '(info\|warn\|error\|debug)!.*trade_pubkey\[' src/api/notify.rs` | n/a |
| PRIV-02 | `RUST_LOG="info"` in deploy script | manual diff | `grep 'RUST_LOG=' deploy-fly.sh` returns `RUST_LOG="info"` | n/a |
| PRIV-03 | No source IP / token / body in handler logs | manual grep + code review | `! grep -nE '(req\.peer_addr\|connection_info\|forwarded)' src/api/notify.rs` | n/a |
| VERIFY-03 | Runbook at `docs/verification/dispute-chat.md` exists, contains anti-CRIT-1 grep | manual presence check | `test -f docs/verification/dispute-chat.md` + `grep -q '\.authors(' docs/verification/dispute-chat.md` | n/a |

### Sampling Rate

- **Per task commit:** `cargo build --release` (compile + clippy-clean).
- **Per wave merge:** `cargo build --release` + the manual grep checks tabulated above.
- **Phase gate:** All NOTIFY-* / PRIV-* / VERIFY-03 manual checks PASS + Fly.io staging deploy + D-06 iOS smoke + D-17 runbook walkthrough.

### Wave 0 Gaps

- [ ] **No `tests/` directory or `#[cfg(test)]` modules with real assertions exist in the repo.** This is a known property of the project — VERIFY-01 / VERIFY-02 in Phase 3 establish the integration-test harness with `actix_web::test::init_service`. Phase 2 explicitly defers automated coverage per CONTEXT.md "Deferred Ideas".
- [ ] **No mock `PushService` impl exists.** Phase 3 will introduce one (`NoopPush` per PITFALLS TEST-1). Phase 2 cannot exercise the spawn-and-dispatch path without it; the iOS device smoke (D-06) is the only end-to-end signal.
- [ ] **No frozen pre-Phase-2 fixture** for `RegisterResponse` / `UnregisterTokenRequest` byte-identity check. The COMPAT-1 protection is enforced by **code-level discipline + diff review** (Phase 1 SUMMARY's anti-requirement check methodology).

**Why automated coverage is deferred to Phase 3:** Phase 2's manual checks suffice because:

1. The handler logic is genuinely small (~50 lines). Reviewer + compile-pass catch the bulk of regressions.
2. The privacy-relevant invariants (anti-oracle, anti-pubkey-leak, anti-IP-leak) are **structural**: they're either present or absent in the code, not behavioral. `grep` catches them more reliably than a test that has to provoke the negative case.
3. The end-to-end path requires a real FCM service account and a real iOS device — both operator-side resources, not unit-testable. D-06 + D-17 capture this.
4. **Phase 3 closes the gap** with VERIFY-01 (in-process integration suite via `actix_web::test::init_service`) — explicitly traced in REQUIREMENTS.md and ROADMAP.md.

**Nyquist gap to flag for Phase 3:** Phase 2 ships **8 requirements with 0 automated tests**. Phase 3's VERIFY-01 must cover at minimum: NOTIFY-01 (registered → 202), NOTIFY-04 (X-Request-Id header present + ignored when client-supplied), PRIV-01 (log lines do not contain `trade_pubkey[..16]`-shaped substrings), PRIV-03 (no peer-IP in logs). Otherwise Phase 2's manual-only check vector remains the only safety net.

## Project Constraints (from CLAUDE.md)

The project's `CLAUDE.md` and global `CLAUDE.md` impose the following directives that PLAN.md tasks MUST honor:

- **No new dependencies without explicit approval.** `blake3` is approved (CONTEXT.md D-16). `uuid` is NOT approved — Open Question Q2. `actix-web` version bump is NOT approved — Open Question Q1.
- **Privacy hard-rules (project CLAUDE.md):** server never learns sharedKeys, peer-to-peer relationships, or sender identity. Every Phase 2 anti-requirement (OOS-10..OOS-21) maps to one of these invariants.
- **Backwards compatibility:** existing `/api/register`, `/api/unregister`, `/api/health`, `/api/info`, `/api/status` contracts must not change. NOTIFY-03 is the explicit codification.
- **Deployment cap:** single Fly.io machine, 512MB RAM, 25-connection cap. The 50-permit Semaphore (D-03) and 5s reqwest timeout (D-07) respect this — at peak, 50 in-flight FCM POSTs × ~16KB heap each ≈ 800KB; well within budget.
- **Anti-requirement (project CLAUDE.md):** No Mostro-daemon author filter on the Nostr listener. Phase 2 does NOT touch `src/nostr/listener.rs`. The runbook (D-17) reinforces.
- **Language:** code, comments, commit messages, branch names in English. Conversation in Spanish. The runbook (D-17) is in Spanish per global CLAUDE.md.
- **No emojis** in code, logs, CLI output, commit messages, or documentation.
- **Conventional Commits.** Phase 1 used `refactor(push):` — Phase 2 follows D-19's `feat(push):`, `feat(api):`, `docs:` prefixes.
- **Commit messages: NO `Co-Authored-By: Claude` trailer** in this repo (per project memory). Phase 1's commit `a43aa49` confirms this — verify with `git log -1`.

## Sources

### Primary (HIGH confidence)

- `Cargo.lock` (project file) — resolved versions for `actix-web` (4.11.0), `tokio` (1.48.0), `reqwest` (0.11.27); confirmed absence of `uuid` and `blake3`.
- `Cargo.toml` (project file) — declared dependency versions.
- `src/push/dispatcher.rs` (project file) — Phase 1 PushDispatcher API surface (`Arc<[Arc<dyn PushService>]>`, structured `DispatchOutcome`/`DispatchError`, no internal logging per D-07).
- `src/api/routes.rs` (project file) — existing `AppState`, `configure`, validation pattern at line 86, response shape patterns.
- `src/store/mod.rs` (project file) — `TokenStore::get` async method that drops the `RwLock` before returning (CONC-2-safe).
- `src/push/fcm.rs` (project file) — existing `build_payload_for_token` at lines 165-215, `send_to_token` impl, `reqwest::Client::new()` per-service pattern (CONCERNS-flagged).
- `src/push/unifiedpush.rs` (project file) — existing constructor + `Client::new()` + atomic-write persistence pattern.
- `src/main.rs` (project file) — current construction site (lines 22-114) for `AppState`, push services list, `PushDispatcher`, `NostrListener`.
- `src/push/mod.rs` (project file) — current `PushService` trait surface (Phase 1 tightened to `Box<dyn Error + Send + Sync>`).
- `deploy-fly.sh:42` (project file) — current `RUST_LOG="debug"` value (D-15 flips to `"info"`).
- `.planning/phases/01-pushdispatcher-refactor-no-behaviour-change/01-CONTEXT.md` and `01-01-SUMMARY.md` — Phase 1 decisions still in force; PushDispatcher API actually shipped.
- `.planning/phases/02-post-api-notify-endpoint-with-privacy-hardening/02-CONTEXT.md` — 19 user-locked decisions for this phase.
- `.planning/REQUIREMENTS.md` — NOTIFY-01..04, PRIV-01..03, VERIFY-03 specifications.
- `.planning/research/PITFALLS.md` — CRIT-1..6, CONC-1..3, FCM-1..2, COMPAT-1, DEPLOY-1, RL-2 (carrying over).
- [docs.rs/blake3/latest/blake3/fn.keyed_hash.html](https://docs.rs/blake3/latest/blake3/fn.keyed_hash.html) — `keyed_hash(key: &[u8; 32], input: &[u8]) -> Hash` signature.
- [docs.rs/blake3/latest/blake3/struct.Hash.html](https://docs.rs/blake3/latest/blake3/struct.Hash.html) — `to_hex()` returns `ArrayString`, `Deref`s to `&str`, slicable.
- [docs.rs/tokio/latest/tokio/sync/struct.Semaphore.html](https://docs.rs/tokio/latest/tokio/sync/struct.Semaphore.html) — `Semaphore`, `try_acquire_owned`, `OwnedSemaphorePermit`.
- [docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html](https://docs.rs/reqwest/latest/reqwest/struct.ClientBuilder.html) — `ClientBuilder` methods (`connect_timeout`, `timeout`, `pool_idle_timeout`).
- [docs.rs/reqwest/latest/reqwest/struct.Client.html](https://docs.rs/reqwest/latest/reqwest/struct.Client.html) — `Client` is internally `Arc`-wrapped, cheap to clone.
- [docs.rs/actix-web/latest/actix_web/middleware/fn.from_fn.html](https://docs.rs/actix-web/latest/actix_web/middleware/fn.from_fn.html) — `from_fn` middleware helper signature.
- [docs.rs/actix-web/latest/actix_web/struct.Resource.html](https://docs.rs/actix-web/latest/actix_web/struct.Resource.html) — `Resource::wrap` per-resource middleware scoping.
- [crates.io/crates/blake3](https://crates.io/crates/blake3) — version 1.8.4 latest as of 2026-04-25.
- [Apple Developer Documentation — Pushing background updates to your app](https://developer.apple.com/documentation/usernotifications/pushing-background-updates-to-your-app) — `apns-priority: 5` + `apns-push-type: background` requirement for `content-available: 1` silent pushes.
- [Firebase Cloud Messaging — Set Android message priority](https://firebase.google.com/docs/cloud-messaging/android-message-priority) — `android.priority: "high"` semantics for data-only messages and Doze-bypass.

### Secondary (MEDIUM confidence)

- [actix-web GitHub CHANGES.md](https://github.com/actix/actix-web/blob/main/CHANGES.md) — `from_fn` graduated from `actix-web-lab` in actix-web 4.9.0 (verified via web search; the actual changelog page was not fetched directly but the conclusion appeared in multiple search results).
- WebSearch results corroborating Apple's silent-push throttling guidance.
- WebSearch results on `wrap_fn` closure-based middleware (alternative path; not chosen because `from_fn` is cleaner when available).

### Tertiary (LOW confidence)

- The exact memory footprint per `OwnedSemaphorePermit` (~bytes); the 800KB estimate at peak in "Project Constraints" is a rough order-of-magnitude check, not a measurement. Acceptable risk for Phase 2.
- The collision-resistance of 8-hex-char BLAKE3 truncation at the project's eventual user-set scale (A5). Currently verified only against birthday-paradox math, not measured.

## Metadata

**Confidence breakdown:**

- **Standard stack:** HIGH — every dep verified against `Cargo.lock`; new deps (`blake3` approved, `uuid` pending) verified absent.
- **Architecture:** HIGH — Phase 1 PushDispatcher actually exists (`src/push/dispatcher.rs`) and matches Phase 2's seam expectations; CONTEXT.md decisions are mechanically translatable into the patterns documented.
- **Pitfalls:** HIGH for the seven specific pitfalls documented (each grounded in Cargo.lock, vendor docs, or PITFALLS.md cross-refs); MEDIUM for the assumption that Phase 1's runtime-smoke status remains green (operator hasn't yet confirmed per Phase 1 SUMMARY).
- **FCM payload semantics:** HIGH — verified against both Apple and FCM v1 vendor docs.
- **Lockfile stability:** MEDIUM — `4.11.0` resolution is stable as of HEAD but a future `cargo update` could shift; flagged in Pitfall 1 and Open Question Q1.

**Research date:** 2026-04-25
**Valid until:** 2026-05-25 (30 days; phase is well-bounded and dependencies are stable). Re-verify the `actix-web` lockfile resolution if any `Cargo.lock` change lands before Phase 2 ships.
