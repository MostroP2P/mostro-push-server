# Phase 3: Dual-keyed rate limiting and verification harness - Context

**Gathered:** 2026-04-25
**Status:** Ready for planning

<domain>
## Phase Boundary

Add dual-keyed rate limiting on top of the `POST /api/notify` endpoint shipped in Phase 2 (always-202 contract preserved): a per-IP middleware (Fly-Client-IP keyed) wrapping the `/notify` resource, and a per-`trade_pubkey` `governor` keyed limiter checked inside the handler before the existing `Semaphore::try_acquire`. Both limits configurable via two new env vars (`NOTIFY_RATE_PER_PUBKEY_PER_MIN`, `NOTIFY_RATE_PER_IP_PER_MIN`), with periodic `retain_recent` cleanup and a soft-cap warn for active key-bombing detection. Ship with an in-process integration test suite (`actix_web::test::init_service` against a real `governor` middleware and a stub `PushService`) covering the 6 mandatory TEST-1 scenarios from SC #6 plus 4 additional regressions.

This phase deliberately does NOT add `actix-governor` to `Cargo.toml`: every published version is GPL-3.0-or-later, incompatible with the project's MIT license. The per-IP middleware is hand-rolled using `actix_web::middleware::from_fn` (the same pattern already in use for `request_id_mw` from Phase 2), backed by `governor = "0.6"` (already declared, MIT licensed, no new dependency required).

</domain>

<decisions>
## Implementation Decisions

### Rate & Burst Tuning (OPEN-3 resolved)

- **D-01: Per-pubkey: `30 req/min`, burst `10`.** Aligns with PITFALLS RL-3 chat back-and-forth profile (10-message bursts followed by sustained ~1 every 2s). Configurable at runtime via `NOTIFY_RATE_PER_PUBKEY_PER_MIN`; the burst is a separate compile-time constant (10) that does NOT have an env override in this phase — keeps the env surface minimal per LIMIT-04 wording. Rationale: PROJECT.md's `~5/min` (line 35) was sized informally for non-chat traffic; PITFALLS RL-3 is the chat-aware number.
- **D-02: Per-IP: `120 req/min`, burst `30`.** Aligns with PITFALLS RL-3 NAT-aware sizing. Configurable at runtime via `NOTIFY_RATE_PER_IP_PER_MIN`; burst is a separate compile-time constant (30). Per-IP is the coarse anti-flood backstop; per-pubkey does the privacy/abuse-relevant work.
- **D-03: Compile-time defaults + `info!` log when env unset.** If `NOTIFY_RATE_PER_PUBKEY_PER_MIN` is absent, use the D-01 default (30) and log `info!("NOTIFY_RATE_PER_PUBKEY_PER_MIN unset, using default 30")`. Same shape for `NOTIFY_RATE_PER_IP_PER_MIN`. Lets `cargo run` work locally without a `.env` while keeping the chosen value visible in production logs.
- **D-04: Panic at startup on invalid env values.** If `NOTIFY_RATE_PER_*_PER_MIN` parses to `0` or a negative integer, `Config::from_env()` returns `Err("NOTIFY_RATE_PER_PUBKEY_PER_MIN must be > 0, got 0")` and `main.rs` panics. Consistent with the existing `parse()?` pattern. Never silently fall back to a default after a typo. `0` is NOT a kill switch; emergencies use `flyctl secrets set` with a high number.

### actix-governor Disposition (OPEN-4 resolved)

- **D-05: Do NOT add `actix-governor` to `Cargo.toml`.** Every published version (0.2.0 through 0.10.0, last release 2025-10-12) is GPL-3.0-or-later. The project is MIT licensed. Adding a GPL-3.0 dependency would force the distributed binary to GPL-3.0-or-later, an unintended re-licensing. Verified against `crates.io` API metadata.
- **D-06: Hand-rolled per-IP middleware over `governor` directly.** Use `actix_web::middleware::from_fn` (same pattern as `request_id_mw` at `src/api/notify.rs:117`). Internally call `governor::DefaultKeyedRateLimiter<IpAddr>::check_key(&ip)`. ~50 LoC of middleware code. No new dependency, no license issue.
- **D-07: Keep `governor = "0.6"` (do NOT bump to 0.10).** `governor = "0.6"` is already declared and counts as approved. The keyed-limiter API surface needed by this phase (`RateLimiter::keyed(quota)`, `check_key`, `retain_recent`, `len`) is functionally identical between 0.6.3 and 0.10.4. Bumping has no incremental benefit and adds churn (hashbrown 0.16 + web-time 1.1 transitively).
- **D-08: Module location `src/api/rate_limit.rs`.** Re-exported via `src/api/mod.rs`. Houses `FlyClientIpKeyExtractor` (or equivalent helper), `per_ip_rate_limit_mw`, the `PerPubkeyLimiter` type alias (D-09), `start_rate_limit_cleanup_task`, and the `#[cfg(test)] mod tests` block for rate-limit-specific scenarios.
- **D-09: Type alias `pub type PerPubkeyLimiter = governor::DefaultKeyedRateLimiter<String>;`** declared in `src/api/rate_limit.rs`. AppState gets one new field: `per_pubkey_limiter: Arc<PerPubkeyLimiter>`. No wrapper struct — `governor` already encapsulates the state, and the soft-cap check lives in the cleanup task (D-13), not inline.
- **D-10: IP key extraction precedence (CRIT-4 anti-fix).**
  1. `Fly-Client-IP` header (Fly's edge-injected canonical client-IP; never client-passthrough).
  2. Rightmost segment of `X-Forwarded-For` (Fly appends real client IP last; never leftmost — that's attacker-controlled).
  3. `req.peer_addr().ip()` (local dev, non-Fly deployments).
  If all three fail → return `500 Internal Server Error` with body `{"success": false, "message": "internal error"}` (D-11). Fail closed: in production Fly always populates `Fly-Client-IP`, so a missing IP signals a misconfigured deployment, not legitimate traffic.
- **D-11: 500 on IP extraction failure.** Privacy-safer than fail-open (no rate limiter would let attackers bypass per-IP entirely). Anti-pattern: sharing one global bucket for IP-less requests creates cross-contamination with legitimate traffic.

### Order of Operations Inside `notify_token` (anti-RL-2)

- **D-12: Order locked.**
  1. `web::Json<NotifyRequest>` body parse → `400` if malformed (serde-automatic).
  2. Validate `trade_pubkey` is 64 hex chars (mirrors `src/api/routes.rs:101` and the existing `src/api/notify.rs:54`) → `400` on failure.
  3. Per-IP middleware already ran outside the handler; nothing to do here.
  4. **Per-pubkey limiter check** via `state.per_pubkey_limiter.check_key(&req.trade_pubkey)` → `429` if exhausted (D-14).
  5. `Arc::clone(&state.semaphore).try_acquire_owned()` → silent drop on saturation (Phase 2 D-03 invariant; warn log without pubkey).
  6. `tokio::spawn` → `token_store.get(&pubkey)` → `dispatcher.dispatch_silent(&token)` → log via `log_pubkey()`. `None` case silently no-ops (no oracle log line).
  7. `HttpResponse::Accepted().json(json!({"accepted": true}))` always returned for parse-valid input.
  Rationale: per-pubkey check BEFORE `try_acquire_owned` so an attacker exhausting their per-pubkey quota does not consume semaphore permits that legitimate traffic needs (RL-2 + CONC-1 interaction).

### 429 Response Shape (anti-RL-2 oracle)

- **D-13: 429 body byte-identical between per-IP and per-pubkey 429s.** Both produce `HTTP/1.1 429 Too Many Requests` with body `{"success": false, "message": "rate limited"}` and header `Retry-After: <seconds>` computed from `not_until.wait_time_from(DefaultClock::default().now())` (rounded up to whole seconds). No echo of `trade_pubkey`, no source identifier, no differentiation between "rate-limit-by-IP" vs "rate-limit-by-pubkey". Verified by D-25 integration test asserting byte equality of both response bodies. Privacy rationale: CRIT-2 + RL-2 — a sender must not learn whether the recipient is registered, and an attacker must not learn which limiter triggered (would reveal whether the pubkey is being targeted by them alone or by many sources).
- **D-14: Per-pubkey 429 path inside the handler builds the same response shape as the per-IP middleware.** Implemented as a small helper `fn rate_limited_response(retry_after_secs: u64) -> HttpResponse` in `src/api/rate_limit.rs`, called from both the middleware (per-IP) and the handler (per-pubkey).

### Cleanup Task & Soft-cap (LIMIT-05 + LIMIT-06)

- **D-15: `start_rate_limit_cleanup_task(limiter: Arc<PerPubkeyLimiter>, interval: Duration, soft_cap: usize)` in `src/api/rate_limit.rs`.** Mirror of `store::start_cleanup_task` (`src/store/mod.rs:140-153`). Spawns a tokio task running an `interval.tick().await` loop that calls `limiter.retain_recent()` then checks `limiter.len() > soft_cap`, logging `warn!("rate-limit pubkey map size exceeded soft cap: {}", limiter.len())` when crossed. main.rs calls `start_rate_limit_cleanup_task(per_pubkey_limiter.clone(), Duration::from_secs(cleanup_interval_secs), soft_cap)` after constructing the limiter.
- **D-16: Cleanup interval default `60s`, configurable via `NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS`.** Same env-or-default pattern as D-03. The constant `RATE_LIMIT_CLEANUP_INTERVAL_DEFAULT_SECS = 60` lives in `src/api/rate_limit.rs`.
- **D-17: Soft-cap default `100_000`, configurable via `NOTIFY_PUBKEY_LIMITER_SOFT_CAP`.** Constant `PUBKEY_LIMITER_SOFT_CAP_DEFAULT = 100_000` in `src/api/rate_limit.rs`. ~13 MB at `governor`'s ~128 bytes per active key — sized for the 512 MB Fly machine with comfortable headroom (token store + dispatcher state + reqwest pool consume the rest).
- **D-18: Warn cadence: every cleanup tick when `limiter.len() > cap`.** No throttling, no once-per-incident suppression. The cleanup loop runs every 60s; if the cap stays exceeded across multiple ticks (e.g. active key-bombing), the operator sees a warn line every 60s — exactly the signal needed. If sustained noise becomes a problem, throttle in a future observability milestone (deferred).

### Middleware Wiring & Composition

- **D-19: Middleware stack on `/api/notify` (outermost first).**
  ```
  web::resource("/notify")
      .wrap(from_fn(request_id_mw))      // outermost: sets X-Request-Id on EVERY response, including 429s
      .wrap(from_fn(per_ip_rate_limit_mw)) // inner: 429 if per-IP exhausted, BEFORE body parse
      .route(web::post().to(notify_token))
  ```
  Per Actix's `.wrap()` ordering, the LAST `.wrap()` call is innermost. So request flow: `request_id_mw → per_ip_rate_limit_mw → notify_token → per_ip_rate_limit_mw (resp) → request_id_mw (resp)`. This guarantees every response (200/202/400/429/500) carries an `X-Request-Id` header.
- **D-20: Per-IP middleware accepts `Arc<DefaultKeyedRateLimiter<IpAddr>>` via `web::Data` extraction inside `from_fn`.** Same pattern as the handler reading `web::Data<AppState>`. The per-IP limiter is constructed in `main.rs` and added to the App via `app_data(web::Data::new(per_ip_limiter.clone()))`. Kept separate from the per-pubkey limiter because the key types differ (`IpAddr` vs `String`).
- **D-21: Apply rate limiting ONLY to `/api/notify` (LIMIT-03 + DEPLOY-3 enforcement).** Do NOT wrap the `/api` scope. `/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister` MUST remain unrate-limited by this milestone's middleware. Verified by D-26 integration test (1000-burst against /api/health → 1000× 200).

### Test Suite Design (VERIFY-01 + VERIFY-02)

- **D-22: Tests co-located in `#[cfg(test)] mod tests` per source file.**
  - `src/api/notify.rs` — handler-side tests (registered hit, unregistered miss, malformed body, X-Request-Id header).
  - `src/api/rate_limit.rs` — middleware + limiter tests (per-IP 429, per-pubkey 429, 429 byte-equality, retain_recent cleanup, soft-cap warn).
  - `src/api/routes.rs` — register/unregister/health/info/status byte-identical regression (VERIFY-02).
  No `tests/` integration directory — that would require restructuring as a library crate (`lib.rs`), out of scope.
- **D-23: Stub `PushService` lives in a shared `pub(crate)` test helper module.** Implementation skeleton:
  ```rust
  // src/api/rate_limit.rs (or a new src/api/test_support.rs gated by #[cfg(test)])
  pub(crate) struct StubPushService {
      pub calls: Arc<Mutex<Vec<(String, Platform)>>>,
      pub supports: Vec<Platform>,
      pub fail: bool,
  }
  ```
  Implements `PushService` recording every `send_to_token` and `send_silent_to_token` call into `calls`. `supports` controls which platforms the stub matches (lets a test exercise `NoBackendForPlatform`). `fail` flips both methods to `Err("stub forced failure")` for error-path tests. Tests assert `stub.calls.lock().await.len()` and contents.
- **D-24: 6 mandatory TEST-1 scenarios from SC #6 (REQUIRED).**
  1. Registered pubkey + valid body → 202, stub recorded one call with the registered platform.
  2. Unregistered (but format-valid) pubkey → 202, stub recorded zero calls.
  3. Malformed body (non-hex pubkey, wrong length, missing field) → 400 with `RegisterResponse`-like body shape (matches `src/api/notify.rs:34-38` `NotifyError`).
  4. Per-pubkey 429 boundary: hit `/api/notify` 31 times for the same pubkey within one minute → at least one 429.
  5. Per-IP 429 boundary: hit `/api/notify` 121 times with `Fly-Client-IP: 1.2.3.4` within one minute → at least one 429.
  6. `/api/register` byte-identical regression — see D-27.
- **D-25: 4 additional regression tests (REQUIRED in addition to D-24).**
  - **`/api/health` 1000-burst** (anti-DEPLOY-3): 1000 GETs against `/api/health` from the same simulated `Fly-Client-IP` → assert all 1000 return 200. Closes the Fly-health-check-restart-loop oracle.
  - **`X-Request-Id` header asserted** (NOTIFY-04 regression): every `/api/notify` response (200/202/400/429) carries an `x-request-id` header parseable as UUIDv4. Inbound `X-Request-Id: spoofed-by-client` is overwritten server-side.
  - **429 byte-equality between per-IP and per-pubkey** (anti-RL-2 oracle): trigger per-IP 429 in one test, per-pubkey 429 in another, capture both bodies, `assert_eq!(body_ip, body_pubkey)`. Locks the byte-identity invariant structurally.
  - **`retain_recent` reduces `limiter.len()`** (LIMIT-05 plumbing): construct limiter with quota allowing infrequent traffic, populate ~10 keys with `check_key`, advance the test clock past the GCRA window (or sleep — see D-28), call `retain_recent`, assert `limiter.len() < 10`. Validates the cleanup loop's plumbing against the real `governor` API.
- **D-26: VERIFY-02 byte-identical fixture for `/api/register` via inline JSON literal.** Test in `src/api/routes.rs#[cfg(test)] mod tests`:
  ```rust
  let req = test::TestRequest::post().uri("/api/register")
      .set_json(json!({"trade_pubkey": "<64-hex>", "token": "test_fcm_token", "platform": "android"}));
  let resp = test::call_service(&app, req.to_request()).await;
  let body = test::read_body(resp).await;
  let body_str = std::str::from_utf8(&body).unwrap();
  assert_eq!(body_str, r#"{"success":true,"message":"Token registered successfully","platform":"android"}"#);
  ```
  Same fixture pattern for `/api/unregister`, `/api/health`, `/api/info`, `/api/status`. No new dependency (`insta` would be overkill for ~5-line JSON), no `tests/fixtures/` directory.
- **D-27: Time-sensitive tests use `tokio::time::pause()` + `tokio::time::advance()`** rather than real `tokio::time::sleep`. Avoids flaky tests on slow CI / loaded dev machines. The `governor` crate uses the standard clock by default — verify at plan time whether `governor`'s `MonotonicClock` interacts cleanly with tokio's paused time, or whether the `retain_recent` test needs a real short sleep (~2s acceptable for a once-only test).

### `Config` Struct Extensions

- **D-28: New struct `NotifyRateLimitConfig` in `src/config.rs`.**
  ```rust
  pub struct NotifyRateLimitConfig {
      pub per_pubkey_per_min: u32,        // NOTIFY_RATE_PER_PUBKEY_PER_MIN, default 30
      pub per_ip_per_min: u32,            // NOTIFY_RATE_PER_IP_PER_MIN, default 120
      pub cleanup_interval_secs: u64,     // NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS, default 60
      pub pubkey_limiter_soft_cap: usize, // NOTIFY_PUBKEY_LIMITER_SOFT_CAP, default 100_000
  }
  ```
  Added to `Config` as `pub notify_rate_limit: NotifyRateLimitConfig`. The bursts (10 per-pubkey, 30 per-IP) are compile-time constants in `src/api/rate_limit.rs`, NOT env-overridable in this phase — keeps the env surface to the four LIMIT-04 mandates.
- **D-29: Existing `RATE_LIMIT_PER_MINUTE` env var and `RateLimitConfig` struct UNTOUCHED.** Per LIMIT-04. The `RateLimitConfig.max_per_minute` field stays declared but unused; cleanup is deferred.

### Commit Grain

- **D-30: Recommended grain — 2 commits in this phase.**
  1. `feat(api): add per-IP and per-pubkey rate limiting to /api/notify` — D-05..D-21 + D-28: new module `src/api/rate_limit.rs`, AppState extension, middleware wiring, env-var loading, cleanup task. Bundles together because the per-IP middleware and the per-pubkey handler check are co-dependent on the AppState shape and the order of operations.
  2. `test(api): add integration tests for /api/notify and /api/register` — D-22..D-27: all new `#[cfg(test)] mod tests` blocks. Doc-only commits would be useful here but the test code itself IS verifiable proof; no separate doc.

  Splitting commit #1 finer than this would ship an endpoint with one limiter wired and the other dangling — a regressed privacy posture (per-IP without per-pubkey leaks recipient state under flood; per-pubkey without per-IP fails to bound aggregate traffic).

### Claude's Discretion

- Exact internal helper function signatures inside `src/api/rate_limit.rs` (e.g. `extract_client_ip(req: &ServiceRequest) -> Result<IpAddr, ()>` vs `Option<IpAddr>` vs custom error type) — pick whatever composes cleanly with `from_fn`.
- Whether to use a custom error type for the IP extraction failure path or the existing `actix_web::error::ErrorInternalServerError` macro for D-11.
- The exact UUIDv4 assertion in D-25 (`uuid::Uuid::parse_str(&header).is_ok()` vs regex match) — both are valid.
- Logging level for the per-IP 429 path: `debug!` (high cardinality) vs `warn!` (noisy under attack) vs no log at all (minimum signal). Default to `debug!` to avoid log spam under attack; planner picks if a strong reason emerges.
- Whether the cleanup task uses `tokio::time::interval` (default) or `tokio::time::interval_at` for jittered start.
- Exact arrangement of test helper functions (e.g. `make_test_app()` factory, `register_test_pubkey()` helper) — at planner's discretion to balance DRY and locality.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project / milestone scope (mandatory)

- `.planning/PROJECT.md` — privacy invariants (lines 67-71, 84-89), anti-requirements OOS-10..OOS-21 (notably OOS-13 — no persistent log of source-IP-to-pubkey tuples; the rate-limiter state stays in-memory).
- `.planning/REQUIREMENTS.md` — LIMIT-01..06, VERIFY-01, VERIFY-02 are the 8 REQ-IDs assigned to this phase. OPEN-3 and OPEN-4 resolved here (D-01..D-08).
- `.planning/ROADMAP.md` — Phase 3 success criteria (6 items) the planner must satisfy. SC #6 enumerates the 6 mandatory TEST-1 scenarios (D-24).

### Phase 1 + 2 artifacts (predecessor context — locked decisions still in force)

- `.planning/phases/01-pushdispatcher-refactor-no-behaviour-change/01-CONTEXT.md` — `PushDispatcher` shape, `Arc<[Arc<dyn PushService>]>` lock-free reads, anti-CRIT-1 comment block above `Filter::new()`.
- `.planning/phases/02-post-api-notify-endpoint-with-privacy-hardening/02-CONTEXT.md` — always-`202` contract (D-01), `tokio::spawn` + `Arc<Semaphore>(50)` (D-02 + D-03), separate FCM silent payload `apns-priority: 5` (D-05), shared `reqwest::Client` with timeouts (D-07), `log_pubkey()` helper + `notify_log_salt` in AppState (D-09 + D-14), X-Request-Id middleware scoped to `/notify` (D-13), `RUST_LOG="info"` flip (D-15), `dispatch_silent` method on `PushDispatcher` (D-22).
- `src/api/notify.rs` — handler that Phase 3 wraps with the per-pubkey check (D-12). Order of operations preserved.
- `src/api/routes.rs` — `AppState` structure that grows ONE new field in this phase (D-09). Existing fields untouched.

### Research outputs (mandatory)

- `.planning/research/SUMMARY.md` — § "OPEN-3" / "OPEN-4" discussions; § "Suggested Phase Shape / Phase 3"; convergence rows on the rate-limiter wiring.
- `.planning/research/ARCHITECTURE.md` — § Q2 "Where does the rate limiter live" (split middleware-vs-handler reasoning → D-12 + D-19); § Q3 "Per-pubkey limiter shape" (governor keyed limiter API → D-09); § Q4 "Per-IP KeyExtractor for Fly.io" (IP precedence → D-10).
- `.planning/research/PITFALLS.md` — CRIT-2 (anti-enumeration → D-13), CRIT-3 (logging hygiene; already locked in Phase 2 by `log_pubkey` migration), CRIT-4 (Fly-Client-IP / rightmost-XFF → D-10), RL-1 (governor key-bombing + retain_recent → D-15..D-17), RL-2 (rate-limit-decision independence from registration → D-12 + D-13), RL-3 (burst sizing → D-01 + D-02), CONC-1 (semaphore + spawn order → D-12), TEST-1 (six mandatory test scenarios → D-24), DEPLOY-3 (middleware scoping → D-21), MIN-3 (Fly-Client-IP not present locally → D-10 fallback to peer_addr).

### Codebase analysis (read for current state)

- `.planning/codebase/ARCHITECTURE.md` — § "HTTP API Layer" (current `AppState` shape post-Phase 2 = `{ token_store, dispatcher, semaphore, notify_log_salt }`; Phase 3 adds `per_pubkey_limiter`).
- `.planning/codebase/CONVENTIONS.md` — module naming (`rate_limit.rs` lives in `src/api/` alongside `notify.rs` and `routes.rs`), test conventions (co-located `#[cfg(test)] mod tests`).
- `.planning/codebase/CONCERNS.md` — § "RATE_LIMIT_PER_MINUTE config unused" — partially resolved here (we leave it untouched per LIMIT-04, but it remains documented as future-cleanup); § zero integration tests dissolves naturally with VERIFY-01/02.
- `.planning/codebase/TESTING.md` — current test patterns (only `src/crypto/mod.rs` has tests; uses `#[test]` synchronous; no `#[tokio::test]` precedent — Phase 3 introduces both `#[actix_web::test]` and `tokio::time::pause()`).

### External / standards (informational — verify against current docs at plan time)

- Apple APNs documentation on `apns-priority: 5` for silent pushes (already locked in Phase 2 D-05; reaffirmed here as the silent payload Phase 3 dispatches).
- Fly.io documentation on `Fly-Client-IP` header injection at the edge proxy (CRIT-4 trust-model anchor).
- `governor` crate `0.6.3` docs.rs: `RateLimiter::keyed(quota)`, `check_key(&K)`, `retain_recent()`, `len()`. API confirmed identical to `0.10.x` for our usage; if the planner finds an API drift (e.g. method renames in 0.6.3 vs the inline sketch above), the plan adjusts and `0.6.3` stays — do NOT silently bump.
- `mobile/docs/plans/CHAT_NOTIFICATIONS_PLAN.md` Phase 4 — the response contract Phase 3 honors. Always-202 for non-rate-limited, 400 for malformed, 429 for rate-limited (mobile expects to see 429 and back off).

### Anti-requirements to keep present in mind while planning

- **OOS-13 / AF-5** — no persistent log of `(timestamp, source IP, target trade_pubkey)` tuples. The rate-limiter state is `governor`'s in-memory `DashMap`; never serialized, never logged at INFO/DEBUG.
- **OOS-18 / AF-7** — no differentiation between registered and not registered. D-13 enforces 429 byte-identical regardless of which limiter triggered, regardless of registration. D-25 verifies structurally.
- **OOS-19 / CRIT-1** — no `.authors(mostro_pubkey)` filter. Phase 1 added the comment block; Phase 3 does NOT touch `src/nostr/listener.rs`.
- **OOS-20 / COMPAT-1** — no refactor of `RegisterResponse` / `RegisterTokenRequest` / `UnregisterTokenRequest`. D-26 verifies byte-identity structurally.
- **OOS-21 / CONC-3** — no `TokenStore` mutation from the notify path. Per-pubkey limiter is a SEPARATE structure; the `TokenStore::get` call on the spawn side stays read-only.
- **License invariant (NEW)** — the project is MIT. Any new dependency must be MIT, Apache-2.0, BSD, or compatible. GPL/LGPL are forbidden. D-05 enforces this for `actix-governor`; future-phase reviewers must apply the same lens to any additions.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`actix_web::middleware::from_fn`** is already in use at `src/api/routes.rs:1` and `src/api/notify.rs:117` (`request_id_mw`). The per-IP middleware reuses this pattern verbatim — no new middleware abstraction needed.
- **`store::start_cleanup_task`** at `src/store/mod.rs:140-153` — exemplar pattern for `start_rate_limit_cleanup_task` (D-15). `tokio::spawn` with `interval.tick().await` loop. Match the same shape.
- **Pubkey validation** at `src/api/routes.rs:101` (and replicated at `src/api/notify.rs:54`) — `req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err()`. The per-pubkey limiter MUST be checked AFTER this validation (D-12) so attackers can't populate the keyspace with garbage.
- **`AppState`** at `src/api/routes.rs:41-47` — already holds 4 fields (`token_store`, `dispatcher`, `semaphore`, `notify_log_salt`). Phase 3 adds ONE more (`per_pubkey_limiter`), keeping the struct flat.
- **`web::Data<AppState>` extraction** in handlers — same pattern as `notify_token`. The per-IP middleware uses `web::Data<Arc<DefaultKeyedRateLimiter<IpAddr>>>` for its limiter (the per-IP limiter is intentionally NOT in AppState — different key type, different middleware lifetime).
- **`log_pubkey()`** at `src/utils/log_pubkey.rs` (Phase 2) — already used by `notify_token`. Phase 3's new log lines (rate-limit warn, soft-cap warn) MUST NOT include the pubkey at all (RL-2 + soft-cap is aggregate cardinality, not per-key).
- **`hex` crate** — already a dependency; reuse for any new validation paths.

### Established Patterns

- **Module naming:** `src/api/notify.rs` (Phase 2), `src/api/routes.rs` (existing). Phase 3 adds `src/api/rate_limit.rs` — same convention. Re-export via `src/api/mod.rs`.
- **Config loading:** `Config::from_env()` in `src/config.rs:53-115`. New struct `NotifyRateLimitConfig` (D-28) follows the same `unwrap_or_else(|_| "<default>".to_string()).parse()?` shape used by every existing field.
- **Test organization:** `#[cfg(test)] mod tests` co-located. Currently only `src/crypto/mod.rs:453-823` has tests — Phase 3 introduces async `#[actix_web::test]` (new shape, but documented in actix-web docs).
- **Logging:** plain English `info!`/`warn!`/`debug!`/`error!`. New rate-limit logs use `warn!` for soft-cap exceeded and `info!` for "default value used at startup". `debug!` for per-IP 429 (planner's discretion).

### Integration Points

- **`src/main.rs:46-128`** — the construction site. Phase 3 adds:
  1. `let per_pubkey_limiter = Arc::new(governor::RateLimiter::keyed(Quota::per_minute(...).allow_burst(...)));` after the `Semaphore` construction (around line 108).
  2. `let per_ip_limiter = Arc::new(governor::RateLimiter::keyed(Quota::per_minute(...).allow_burst(...)));` likewise.
  3. `start_rate_limit_cleanup_task(per_pubkey_limiter.clone(), Duration::from_secs(...), soft_cap)` after the cleanup-task spawn for tokens.
  4. `app_state.per_pubkey_limiter = per_pubkey_limiter.clone();` in the AppState construction.
  5. `app_data(web::Data::new(per_ip_limiter.clone()))` in the HttpServer closure.
- **`src/api/routes.rs:41-47`** — `AppState` struct: ONE new field (`per_pubkey_limiter: Arc<PerPubkeyLimiter>`). Existing fields untouched.
- **`src/api/routes.rs:49-63`** — `configure()`: extend the `/notify` resource wrap stack (D-19). Existing `request_id_mw` wrap preserved as outermost.
- **`src/api/notify.rs:49-109`** — `notify_token` handler: insert the per-pubkey check between step 3 (existing `info!` log) and step 4 (existing `try_acquire_owned`). 6-line change.
- **`src/api/mod.rs`** — add `pub mod rate_limit;`.
- **`src/config.rs`** — add `NotifyRateLimitConfig` struct + `notify_rate_limit` field on `Config` + 4 new env vars in `Config::from_env`.

### Untouched in Phase 3

- `src/nostr/listener.rs` — Phase 1 territory; Phase 3 does NOT touch the listener path. The Nostr-driven flow is NOT rate-limited (no per-IP since it's not HTTP, no per-pubkey since dispatch volume is governed by relay traffic).
- `src/store/`, `src/crypto/`, `src/utils/log_pubkey.rs`, `src/utils/batching.rs`, `src/push/*` — no changes.
- Existing endpoints: `/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister` — no middleware applied, no shape changes (LIMIT-03 + COMPAT-1 + D-21 + D-26).
- `Cargo.toml` — no new dependencies (D-05 forbids `actix-governor`; D-07 keeps `governor = "0.6"`).
- `deploy-fly.sh`, `fly.toml` — Phase 2 already flipped `RUST_LOG="info"`; no further changes here. The new env vars (`NOTIFY_RATE_PER_PUBKEY_PER_MIN`, etc.) are OPTIONAL — defaults work for production, operators set them only to override. Updating `deploy-fly.sh` to set explicit values is a Claude-discretion item for the planner.

</code_context>

<specifics>
## Specific Ideas

- User explicitly chose PITFALLS RL-3 numbers (30/min burst 10 per-pubkey, 120/min burst 30 per-IP) over PROJECT.md informal numbers. Planner MUST use these; do NOT propose tighter limits "for safety" without evidence — the chat back-and-forth profile is the documented rationale.
- User explicitly rejected adding `actix-governor` because of GPL-3.0 incompatibility with the project's MIT license. The planner MUST NOT propose `actix-governor` as a "simpler" alternative — it would re-license the binary. Hand-rolled middleware over `governor` directly is the locked path.
- User chose fail-closed (500) on IP extraction failure, NOT fail-open. Planner MUST preserve this semantic. A future "trust toggle" env var (e.g. `TRUST_FLY_CLIENT_IP=true|false`) is deferred — current default is "trust if Fly is in front, fall back to peer_addr otherwise, 500 if both miss".
- User chose all 4 additional regression tests beyond the mandatory 6. Planner MUST include them; they are not optional.
- Burst sizing (10 per-pubkey, 30 per-IP) is a compile-time constant, NOT env-overridable. The four env vars (`NOTIFY_RATE_PER_PUBKEY_PER_MIN`, `NOTIFY_RATE_PER_IP_PER_MIN`, `NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS`, `NOTIFY_PUBKEY_LIMITER_SOFT_CAP`) are the COMPLETE Phase 3 env surface — do NOT add more.
- The user does NOT want `actix-governor` even if a future MIT-licensed fork or v1.0 ships. Switching is a separate, future decision; Phase 3 ships hand-rolled.

</specifics>

<deferred>
## Deferred Ideas

- **Per-IP-per-pubkey composite key limiter** — cited as a possibility in research but not in this milestone's scope. Single-axis limiters cover the threat model documented in PITFALLS.
- **Burst-size env override** (`NOTIFY_RATE_PER_PUBKEY_BURST` etc.) — deferred to keep env surface minimal. If post-rollout traffic data shows burst is the wrong knob, future cleanup phase can add it.
- **Throttled soft-cap warning** (warn once per 5min instead of every cleanup tick) — deferred to a future observability milestone. Current 60s cadence is acceptable for a soft-cap signal.
- **Metrics endpoint exposing `notify_429_ip_total` / `notify_429_pubkey_total`** — Future Requirement F-02 in REQUIREMENTS.md. Not in this milestone.
- **CI / GitHub Actions** running the new integration suite on PR — Out-of-Scope OOS-06. The README will get a one-liner reminder to `cargo test --all` before push; CI is its own milestone.
- **Trust toggle for `Fly-Client-IP`** — `TRUST_FLY_CLIENT_IP=true|false` env var. Useful for non-Fly deployments that want to opt out of header trust. Phase 3 defaults to "trust the header IF present, fall back otherwise" without an explicit toggle. Add later if a non-Fly operator surfaces.
- **`tower_governor` adapter for Actix** — explored at discussion time; would require Tower-to-Actix translation glue, more code than the hand-rolled middleware. Re-evaluate only if `governor` itself becomes unavailable.
- **Switching to `actix-governor` if it ever re-licenses to MIT/Apache** — possible future cleanup. Track the upstream issue; revisit only if/when the license changes.
- **Future cleanup of unused `RateLimitConfig.max_per_minute` field + `RATE_LIMIT_PER_MINUTE` env var** — out of scope per LIMIT-04 anti-touch. Belongs in a config-cleanup milestone after this one.
- **Bump `governor` 0.6 → 0.10** — no incremental benefit for this phase. Future maintenance milestone.

</deferred>

---

*Phase: 03-dual-keyed-rate-limiting-and-verification-harness*
*Context gathered: 2026-04-25*
