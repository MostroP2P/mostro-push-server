# Phase 2: `POST /api/notify` endpoint with privacy hardening - Context

**Gathered:** 2026-04-24
**Status:** Ready for planning

<domain>
## Phase Boundary

Add a new `POST /api/notify` HTTP endpoint that accepts a `{ "trade_pubkey": "<64-hex>" }` body and fires a silent push to the device registered for that pubkey via the `PushDispatcher` built in Phase 1. Ship the endpoint with privacy hardening bundled in: a salted-BLAKE3 `log_pubkey()` helper used from day one by the new handler, an `X-Request-Id` middleware scoped to the endpoint, and a `deploy-fly.sh` flip from `RUST_LOG="debug"` to `"info"`. Plus two bundle-along hygiene fixes the new endpoint would be unsafe without: a shared `reqwest::Client` with outbound timeouts, and a separate FCM payload builder for silent pushes with `apns-priority: 5` + `apns-push-type: background`.

This phase is also VERIFY-03: a manual runbook documenting how an operator verifies end-to-end that admin DMs (sent directly user-to-user, NOT through the Mostro daemon) reach registered devices via the existing Nostr-listener path. No production code for that — a doc file that reminds reviewers the `.authors(mostro_pubkey)` anti-fix is forbidden.

</domain>

<decisions>
## Implementation Decisions

### Response Contract & Dispatch Semantics (OPEN-1 + OPEN-2 resolved)

- **D-01: Always-`202 Accepted`.** The endpoint returns `202 { "accepted": true }` on ALL dispatch paths — registered pubkey dispatched, registered pubkey FCM-failed, pubkey not registered. The response body is a compile-time-constant JSON — no echo of `trade_pubkey`, no request-id in the body (that lives in the header, D-10), no timestamp. Exceptions: `429 Too Many Requests` only for rate-limit rejections (Phase 3 wires those), and `400 Bad Request` only for body parse failures / pubkey validation failures (`trade_pubkey` length !=64 or not hex). No other status codes.
  Rationale: PITFALLS CRIT-2 (no pubkey-enumeration oracle via 200/404 differentiation) + CRIT-6 (no FCM-state oracle via propagated errors) + RL-2 (rate-limit decision must not depend on registration status).
- **D-02: Dispatch in `tokio::spawn` detached from the response.** The handler (a) parses + validates the body, (b) returns `202` immediately, (c) passes the work to a `tokio::spawn`ed task that calls `dispatcher.dispatch(...)`. The response never awaits FCM. Handler p99 target: under 50 ms regardless of FCM state.
  Rationale: closes the timing-channel oracle (latency == hit) and protects the 25-connection Fly cap (DEPLOY-2).
- **D-03: Bound the spawn pile with `tokio::sync::Semaphore` — 50 permits.** The spawned task acquires a permit (`try_acquire`) before calling `dispatcher.dispatch`. If no permit is available, the task drops silently — no log line that encodes dispatch success/failure at request level, no 503 back to the caller (the 202 already fired). The semaphore is owned by `AppState` as `Arc<Semaphore>`.
  Rationale: PITFALLS CONC-1 (unbounded `tokio::spawn` from HTTP handler leaks futures under sustained load). Silent-drop over 503 is the privacy-safer overflow behaviour per CRIT-6.
- **D-04: Mobile team coordination — decide now, document, communicate later.** The mobile team's `CHAT_NOTIFICATIONS_PLAN.md` Phase 4 is not yet merged; their client call site is still TBD. We lock the contract as always-202 here, document it in CONTEXT.md + the handler doccomment, and communicate the deviation to the mobile team before they implement. If they can't accept always-202, the response contract can be adjusted in a localized handler change without touching the dispatch strategy (D-02 + D-03 still hold).

### iOS Silent Push Payload (OPEN-5 resolved)

- **D-05: Separate `build_silent_payload_for_notify()` in `src/push/fcm.rs`.** The existing `build_payload_for_token` (lines 165-215) stays UNTOUCHED and continues to serve the listener path (low-frequency Mostro daemon events). The new builder is data-only (no `alert`, no `title`/`body`), sets FCM `android.priority: "high"`, FCM `apns.headers.apns-priority: "5"`, FCM `apns.headers.apns-push-type: "background"`, FCM `apns.payload.aps.content-available: 1`, and omits `apns-collapse-id` (chat wake-ups must not coalesce with Mostro trade-update notifications). The new builder is called only from the new `/api/notify` dispatch path.
  Rationale: PITFALLS FCM-1. Apple explicitly deprecates `apns-priority: 10` for silent `content-available: 1` pushes; sustained high-priority silent traffic flags the app for throttling.
- **D-06: Manual smoke on staging with a real iOS device.** The milestone's operator verifies after deploy: register a test pubkey with an iOS FCM token, call `POST /api/notify`, confirm `didReceiveRemoteNotification` fires on device and background handler runs. Document in SUMMARY.md. No automated iOS test — the server-side integration suite (VERIFY-01 in Phase 3) uses a stub `PushService` and cannot validate Apple's delivery decision.

### Outbound Client Hygiene (NEW — bundle into Phase 2)

- **D-07: Single shared `reqwest::Client` built in `main.rs`.** Construct once at startup with `.connect_timeout(Duration::from_secs(2))`, `.timeout(Duration::from_secs(5))`, `.pool_idle_timeout(Duration::from_secs(90))`. Pass `Arc<reqwest::Client>` to both `FcmPush::new(config, client)` and `UnifiedPushService::new(config, client)` — constructor signatures change.
  Rationale: PITFALLS CRIT-5 (shared-client + timeouts protects `/api/notify` from FCM-hang self-DoS, closes CONCERNS item at `CONCERNS.md:134-137`, prepares for D-02/D-03 spawn-and-bound).
- **D-08: Constructor breaking change is acceptable.** `FcmPush::new` and `UnifiedPushService::new` go from `(config)` to `(config, client)`. `main.rs:46-79` is rewired to pass the client. No external consumer of these constructors exists — they are all constructed in `main.rs`.

### Endpoint Wiring (NOTIFY-01..04)

- **D-09: `AppState` grows three new fields:** `dispatcher: Arc<PushDispatcher>`, `semaphore: Arc<Semaphore>`, `notify_log_salt: Arc<[u8; 32]>` (the BLAKE3 salt used by `log_pubkey()`, loaded at startup from a random-initialized `OnceCell` — NOT from env, NOT persisted). The existing `token_store: Arc<TokenStore>` field stays. Handler reads all four via `web::Data<AppState>`.
- **D-10: New types in a new file `src/api/notify.rs`.** `NotifyRequest { trade_pubkey: String }` and the response type live in `src/api/notify.rs`, NOT in `src/api/routes.rs`. `RegisterResponse`, `RegisterTokenRequest`, `UnregisterTokenRequest`, and the routes::AppState struct in `src/api/routes.rs` are UNTOUCHED (COMPAT-1 / OOS-20).
- **D-11: Route registration.** `src/api/routes.rs::configure` is extended with `.route("/notify", web::post().to(notify::notify_token))` inside the existing `/api` scope. The X-Request-Id middleware (D-13) wraps ONLY this one resource, not the scope.
- **D-12: Handler order of operations** (inside `notify_token`):
  1. `web::Json<NotifyRequest>` body parse (serde rejects malformed → automatic 400).
  2. Validate `trade_pubkey` is 64 hex chars (reuse pattern from `register_token` at `src/api/routes.rs:86`) → 400 with the same error body shape on failure.
  3. `info!` log using `log_pubkey()` — structured, opaque pubkey identifier only.
  4. Try to acquire a `Semaphore` permit (`try_acquire_owned`). If fail, log `warn!("notify: spawn pool saturated, dropping dispatch")` (no pubkey in this line), skip to step 6.
  5. `tokio::spawn` a future that: holds the permit, looks up the token in `TokenStore::get`, if present calls `dispatcher.dispatch(&token)` using the new silent payload builder (D-05), logs outcome via `log_pubkey()`. The spawn closure owns `Arc` clones of dispatcher + token_store; no references to the handler state.
  6. Return `HttpResponse::Accepted().json(json!({"accepted": true}))`.

### Observability & Privacy Hardening

- **D-13: X-Request-Id middleware scoped to `/api/notify` only.** Implemented as a small `actix_web::middleware` that generates a UUIDv4 server-side per request, ignores any inbound `X-Request-Id` header from the client (privacy — the client cannot correlate its own requests with server state), and inserts the generated ID into the response headers. Wrapped on the single notify resource via `web::resource("/notify").wrap(RequestIdMiddleware).route(...)`. The ID is NOT exposed to `notify_token` via request extensions in Phase 2 (handler uses its own per-log opaque correlator via `log_pubkey()` + a short random suffix). Every other endpoint (`/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister`) stays UNTOUCHED — no new headers, no middleware (COMPAT-1).
- **D-14: `log_pubkey()` helper applied ONLY to the new `/api/notify` handler and the new spawned dispatch task.** Lives in a new small module `src/utils/log_pubkey.rs` (or similar; naming is Claude's discretion), implemented as `fn log_pubkey(salt: &[u8; 32], pk: &str) -> String` returning the first 8 hex chars of `BLAKE3::keyed_hash(salt, pk.as_bytes())`. The salt is generated once at startup (random, in-memory only, regenerated per process). Existing logs in `src/nostr/listener.rs` (lines ~108, 115-116, 137), `src/api/routes.rs` (register/unregister handlers), and `src/store/mod.rs` (TokenStore log lines) KEEP their current `&trade_pubkey[..16]` prefix-truncation shape — NOT migrated. Rationale: operators that grep production logs by hex prefix today do not break; retroactive migration is deferred to a future observability milestone.
- **D-15: `deploy-fly.sh` flips `RUST_LOG` from `"debug"` to `"info"`.** Bundled into the same commit (or PR) as the handler — hard-bundle per CRIT-3 + DEPLOY-1. Shipping `/api/notify` while production still logs at `debug` amplifies the token-prefix leakage in `src/push/fcm.rs:283` + `src/push/unifiedpush.rs:176`, negating D-14.
- **D-16: Cargo.toml dependency addition: `blake3`.** Required for `log_pubkey()`. Small pure-Rust crate, single version line added under `[dependencies]`. This IS a new dependency and requires explicit user approval per global CLAUDE.md — the user has pre-approved this decision in this discussion by selecting BLAKE3 as the hash primitive. Alternative (`sha2` already declared) would work but BLAKE3 is faster and purpose-built for keyed hashing.

### Dispute Chat Verification Runbook (VERIFY-03)

- **D-17: `docs/verification/dispute-chat.md` is the single deliverable for VERIFY-03.** A single markdown file that walks an operator through (1) registering a test pubkey via `POST /api/register`, (2) publishing a `kind 1059` Gift Wrap from a second Nostr client (simulating an admin DM sent DIRECTLY user-to-user — NOT via the Mostro daemon) addressed at the registered `trade_pubkey` on a configured relay, (3) verifying the listener emits `info!("Push sent successfully for event ...")` and the device receives a silent push, (4) confirming the `.authors(mostro_pubkey)` anti-fix has NOT been added to the listener filter (grep check included in the runbook). Written in Spanish per global CLAUDE.md.
- **D-18: No test code for dispute chat path in Phase 2.** The runbook is manual. VERIFY-01 in Phase 3 will cover `/api/notify` server-side via stub PushService, but the dispute chat path (Nostr listener → `PushDispatcher`) is covered by Phase 1's refactor verification (DISPATCH-02 proved by manual smoke) + this runbook.

### Commit Grain

- **D-19: Recommended grain — 2-3 commits in this phase.**
  1. `feat(push): add shared reqwest Client with timeouts` — D-07 + D-08 reqwest hygiene (resolve CONCERNS item, prepare for endpoint). Constructor breaking changes cascade through `FcmPush::new`, `UnifiedPushService::new`, `main.rs`.
  2. `feat(api): add POST /api/notify endpoint with privacy hardening` — Everything else: D-09..D-16 all land together because they are co-dependent (handler needs salt needs helper needs dep; middleware needs handler). Includes the `src/push/fcm.rs` silent builder (D-05) because it's called from the handler, not the listener.
  3. `docs: add dispute chat verification runbook` — VERIFY-03 / D-17 standalone doc commit.
  The `deploy-fly.sh` RUST_LOG flip (D-15) goes in commit #2, NOT a separate commit — bundle hard.
  Splitting commit #2 finer than this would ship an endpoint that leaks pubkey prefixes (without D-14 helper), or hits FCM without timeouts (without D-07 dep), or has no salt (incomplete). Those aren't valid intermediate states.

### Claude's Discretion

- Exact file paths for the new modules (`src/api/notify.rs`, `src/utils/log_pubkey.rs` — names can shift for consistency with existing conventions).
- Exact Semaphore overflow log level (`warn!` vs `debug!`) — plan-phase decides.
- Exact response body shape for the `400` case — match existing `RegisterResponse { success, message, platform: None }` structure for operator consistency, OR define a lean error body in `notify.rs` if refactoring would risk COMPAT-1. Claude picks whichever preserves existing shapes.
- Whether to use `tokio::sync::Semaphore::try_acquire` vs `try_acquire_owned` — owned variant is typically needed for spawn; plan chooses.
- The 32-byte salt initialization strategy (`rand::thread_rng().fill`, `OnceCell`, etc.) as long as it's random in-memory per process and never persisted.
- Cargo.toml dependency position and feature flags for `blake3` — defaults are fine.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project / milestone scope (mandatory)

- `.planning/PROJECT.md` — privacy invariants (lines 68-71, 84-89), anti-requirements OOS-10..OOS-21 (including the new relevant ones: OOS-10 no auth on /api/notify, OOS-16 no Idempotency-Key, OOS-17 no CORS, OOS-18 no 200/404 differentiation — the last is D-01's justification)
- `.planning/REQUIREMENTS.md` — NOTIFY-01..04, PRIV-01..03, VERIFY-03 are the 8 REQ-IDs assigned to this phase. OPEN-1, OPEN-2, OPEN-5 resolved here (D-01..D-06). OPEN-6 resolved in Phase 1.
- `.planning/ROADMAP.md` — Phase 2 success criteria (6 items) the planner must satisfy

### Phase 1 artifacts (predecessor context)

- `.planning/phases/01-pushdispatcher-refactor-no-behaviour-change/01-CONTEXT.md` — Phase 1 decisions still in force (trait `+ Send + Sync`, structured `DispatchOutcome` / `DispatchError`, caller-side logging, dispatcher emits no log lines)
- `.planning/phases/01-pushdispatcher-refactor-no-behaviour-change/01-01-SUMMARY.md` — what actually landed (reviews the reconciliation of `Vec<(Arc<dyn>, &'static str)>` tuple and the intentional `field 'backend' is never read` warning)
- `src/push/dispatcher.rs` — the existing dispatcher that Phase 2 consumes. Read before writing the spawn closure in D-12.

### Research outputs (mandatory)

- `.planning/research/SUMMARY.md` — § "OPEN-1" / "OPEN-2" / "OPEN-5" discussions; § "Suggested Phase Shape / Phase 2"
- `.planning/research/ARCHITECTURE.md` — § Q2 (where does the rate limiter live — relevant for Phase 3, BUT note the split middleware-vs-handler reasoning which informs D-11 scoping); § Q5 (which CONCERNS to fix, CRIT-5 Mutex already done, reqwest timeouts here at D-07)
- `.planning/research/PITFALLS.md` — CRIT-2 (anti-enumeration → D-01), CRIT-3 (logging hygiene → D-14 + D-15), CRIT-6 (anti-FCM-state-oracle → D-01 + D-02), CONC-1 (spawn bound → D-03), CONC-2 (no RwLock across await in handler — relevant when writing D-12 step 5), CONC-3 (no TokenStore mutation from handler — relevant when writing D-12), FCM-1 (iOS payload → D-05), FCM-2 (best-effort guarantee — must appear in runbook + handler doccomment), COMPAT-1 (no Register* DTO refactor → D-10), DEPLOY-1 (RUST_LOG bundle → D-15)

### Codebase analysis (read for current state)

- `.planning/codebase/ARCHITECTURE.md` — § "HTTP API Layer" (`AppState` is currently `{ token_store }` — D-09 extends it to 4 fields); § "Push Service Layer" (the two concrete services + the blanket `Arc<>` impls)
- `.planning/codebase/CONVENTIONS.md` — module naming (`notify.rs` lives in `src/api/` alongside `routes.rs`), response shape conventions, `Box<dyn Error[+ Send + Sync]>` return style
- `.planning/codebase/CONCERNS.md` — § "reqwest::Client::new() per service" (lines 134-137 — D-07 resolves); § "Trade pubkey logged at INFO level" (lines 114-117 — D-14 partially mitigates, full retroactive migration deferred)

### External / cross-repo (informational — authoritative for contract coordination)

- `mobile/docs/plans/CHAT_NOTIFICATIONS_PLAN.md` — Phase 4 section. The server deviates from the literal `200/404/429` written there (we pick always-202). The deviation is documented in D-04; the orchestrator/user will communicate to the mobile team.

### Anti-requirements to keep present in mind while planning

- OOS-19 / PITFALLS CRIT-1 — no `.authors(mostro_pubkey)` filter. Phase 1 added the block comment above `Filter::new()`; Phase 2 does NOT touch `src/nostr/listener.rs`. Runbook (D-17) reminds reviewers.
- OOS-10 / AF-1 — no auth on `/api/notify`. Handler body accepts `{ trade_pubkey }` only, no signature, no JWT, no sender identification.
- OOS-11 / AF-3 — no `sender_pubkey` field anywhere in the request. `NotifyRequest` is `{ trade_pubkey: String }`, period.
- OOS-12 / AF-4 — no storage or registration of `sharedKey`. `TokenStore` stays keyed only on `tradeKey`.
- OOS-13 / AF-5 — no persistent log of `(timestamp, source IP, trade_pubkey)` tuples. D-12 step 3 logs only `log_pubkey()` output, never IP.
- OOS-14 / AF-2/AF-8/AF-9 — no content forwarding, no push customization, no routing hints. D-05 payload is data-only, empty body.
- OOS-15 / AF-10 — no webhook/delivery-receipt back to sender.
- OOS-16 / D-2 — no `Idempotency-Key` header. Not implemented, not accepted.
- OOS-17 / D-4 — no CORS. Not adding `actix-cors` to `Cargo.toml`.
- OOS-18 / AF-7 — no differentiation between registered and not registered. D-01 enforces this with always-202.
- OOS-20 / COMPAT-1 — no refactor of `RegisterResponse` / `RegisterTokenRequest` / `UnregisterTokenRequest`. D-10 + D-11 keep the new types in `src/api/notify.rs` fully isolated.
- OOS-21 / CONC-3 — no `TokenStore` mutation from the notify handler. D-12 reads only.
- Phase 3 boundary — no rate-limiting middleware in Phase 2. The handler does NOT check `RATE_LIMIT_PER_MINUTE` or any governor limiter. Phase 3 adds LIMIT-01..06 around this endpoint. Phase 2's handler just returns 202 unconditionally.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`Arc<PushDispatcher>`** at `src/push/dispatcher.rs` — D-09 wires it into `AppState`. The dispatcher is already `Send + Sync` (trait bound from Phase 1 D-09 applied to `PushService`), so it can be cloned into the spawn closure.
- **`TokenStore::get`** at `src/store/mod.rs:85-88` — async, returns `Option<RegisteredToken>` by clone. Already drops the `RwLock` before returning (CONC-2 safe). Handler uses this verbatim.
- **Pubkey validation pattern** at `src/api/routes.rs:86` — `req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err()`. D-12 step 2 copies this exactly.
- **`RegisterResponse` shape** at `src/api/routes.rs:29-34` — `{ success: bool, message: String, platform: Option<Platform> }`. D-12's 400 path reuses this shape for consistency (omit `platform`).
- **`hex` crate** — already a dependency; used by the validation pattern above.

### Established Patterns

- **`actix-web` scope + route**: `cfg.service(web::scope("/api").route("/notify", web::post().to(handler)))`. D-11 adds one more `.route` inside the existing scope.
- **`web::Data<AppState>`**: every handler extracts shared state via the `AppState` clone. D-12 mirrors this exactly.
- **`#[derive(Deserialize)]` request DTOs + `#[derive(Serialize)]` response DTOs**: used on all existing handlers. D-10's `NotifyRequest` follows the same derive pattern.
- **`info!` / `warn!` / `error!` / `debug!`** macros from `log` facade. Handler uses `info!` for normal path, `warn!` for semaphore saturation or 400 validation failures.
- **`Arc::clone(&foo)`** for sharing across spawn: the same pattern used in `main.rs:79+` for the existing spawn into `nostr_listener.start()`.
- **`tokio::sync::Semaphore`** is NOT currently used anywhere in the repo — it's in the tokio `full` feature flag so no dep change needed (only `blake3` does).

### Integration Points

- **`src/main.rs:46-95`** — the construction site. Phase 2 adds `blake3` salt generation, `Arc<Semaphore>` construction, shared `reqwest::Client` construction, and passes all three into `AppState` (D-07 + D-09).
- **`src/api/routes.rs:36-39, 41-49`** — `AppState` struct + `configure()` function. D-09 extends the struct (3 new fields); D-11 adds one route line.
- **`src/api/mod.rs`** — adds `pub mod notify;` (D-10).
- **`src/push/fcm.rs:165-215`** — existing payload builder. D-05 adds a SEPARATE new function; existing function UNTOUCHED.
- **`src/push/fcm.rs` + `src/push/unifiedpush.rs` constructors** — D-07 changes the constructor signature (one new arg: `Arc<reqwest::Client>`). Small cascade.
- **`deploy-fly.sh:42`** — D-15 flips `RUST_LOG`. Single-line edit.

### Untouched in Phase 2

- `src/nostr/listener.rs` — Phase 1 already refactored this file; Phase 2 does NOT touch it again. The anti-CRIT-1 comment block at lines 72-77 (Phase 1) is the enforcement for dispute chat.
- `src/store/`, `src/crypto/`, `src/config.rs` (no new env vars in Phase 2 — all runtime values are derived from Args-only `AppState`), `src/utils/batching.rs`, `fly.toml`, `secrets/`.
- Existing DTOs in `src/api/routes.rs` (`RegisterResponse`, `RegisterTokenRequest`, `UnregisterTokenRequest`).
- `/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister` handlers and their response shapes.

</code_context>

<specifics>
## Specific Ideas

- User explicitly chose the privacy-safer options at every Area 1 turn (always-202 over 200/404, tokio::spawn + Semaphore over inline await). This is a high-privacy-posture phase; the planner should not second-guess and propose 200/404 "for consistency with other endpoints".
- User chose Area 2 separate builder (D-05) — do NOT reuse `build_payload_for_token` for silent pushes. The planner must not propose "simplify by sharing the builder". The existing builder is sized for Mostro events (low-frequency); the new one is for chat (high-frequency, Apple-throttling-sensitive).
- User chose Area 3 full bundle (D-07 + D-08) — shared client + constructor breaking change. The planner must not propose "add timeouts but keep two clients" as a compromise; the user explicitly rejected that option.
- User chose Area 4 new-only PRIV-01 (D-14) — explicit that operators' existing grep-ability matters. The planner must NOT retroactively migrate listener logs even if it would be "more consistent".
- User chose Area 4 scoped X-Request-Id (D-13) — global was explicitly rejected to preserve COMPAT-1 on existing endpoint headers.

</specifics>

<deferred>
## Deferred Ideas

- **Rate limiting** (LIMIT-01..06). Entire Phase 3. Phase 2's handler returns 202 unconditionally; Phase 3 wraps the endpoint with `actix-governor` per-IP middleware + adds per-pubkey handler-level check.
- **Integration test suite** (VERIFY-01, VERIFY-02). Entire Phase 3. Phase 2 ships with manual smoke only (D-06 + D-17).
- **Retroactive migration of existing pubkey-prefix logs to `log_pubkey()`**. Future observability milestone (per Area 4 user choice on D-14).
- **iOS APNs-direct backend (without FCM)**. Explicitly Out of Scope in PROJECT.md (OOS-08). iOS continues delivering via FCM.
- **Context propagation of the X-Request-Id into the handler logs** (via `actix_web::HttpRequest::extensions_mut()`). Phase 2 generates the ID in the middleware and sets the header only; handler logs use its own BLAKE3 short-code. A future phase can unify them if operator feedback requires.
- **OS-level semaphore tuning** (the 50 permits number). Review after a week of production data with Phase 3's rate limits active.

</deferred>

---

*Phase: 02-post-api-notify-endpoint-with-privacy-hardening*
*Context gathered: 2026-04-24*
