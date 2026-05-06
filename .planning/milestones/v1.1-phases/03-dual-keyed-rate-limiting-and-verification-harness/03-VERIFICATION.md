---
phase: 03-dual-keyed-rate-limiting-and-verification-harness
verified: 2026-04-26T00:22:19Z
status: passed
score: 6/6 success criteria verified
overrides_applied: 0
---

# Phase 03: Dual-Keyed Rate Limiting and Verification Harness — Verification Report

**Phase Goal:** Sustained `POST /api/notify` traffic from a single client cannot exhaust the server or flood any one recipient, the new endpoint's wiring is exercised by an in-process integration suite that catches regressions before deploy, and the rate-limiting layer never affects any endpoint other than `/api/notify`.

**Verified:** 2026-04-26T00:22:19Z
**Status:** passed
**Re-verification:** No — initial verification

---

## Build and Test Results

**`cargo test --bin mostro-push-backend`:** 31 passed; 0 failed; 0 ignored — GREEN

**`cargo build --release`:** Finished `release` profile [optimized] — SUCCESS

Both required commands pass without error.

---

## Goal Achievement

### Observable Truths (Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Sustained `POST /api/notify` with fixed `Fly-Client-IP` eventually returns 429; rotating `X-Forwarded-For` from same TCP peer cannot bypass | VERIFIED | `per_ip_rate_limit_mw` in `src/api/rate_limit.rs:87-135` uses `extract_client_ip` (lines 55-74): precedence is `Fly-Client-IP` > rightmost-XFF > `peer_addr()`. Test `per_ip_burst_exhaustion_returns_429` and `rightmost_xff_used_when_fly_client_ip_missing` pass. |
| 2 | Sustained `POST /api/notify` for same `trade_pubkey` from many distinct IPs returns 429; 429 shape byte-identical regardless of pubkey registration (anti-RL-2 oracle) | VERIFIED | Per-pubkey check in `notify_token` (`src/api/notify.rs:72-78`) uses `rate_limited_response` helper shared with per-IP middleware. Test `rate_limited_429_body_byte_identical_per_ip_vs_per_pubkey` asserts exact byte equality (`{"success":false,"message":"rate limited"}`). Test `per_pubkey_burst_exhaustion_returns_429` passes. |
| 3 | `/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister` NOT subject to rate-limiting; 1000-burst on `/api/health` returns 1000 successes | VERIFIED | `configure()` in `src/api/routes.rs:51-69` wraps only `web::resource("/notify")` with `per_ip_rate_limit_mw`. Other routes are in the outer `web::scope("/api")` without the middleware. Tests `health_endpoint_not_rate_limited_1000_burst` (1000 GETs) and `other_endpoints_not_rate_limited_under_burst` (50 each for `/api/info`, `/api/status`, `/api/register`) all pass. |
| 4 | Quotas configurable via `NOTIFY_RATE_PER_PUBKEY_PER_MIN` and `NOTIFY_RATE_PER_IP_PER_MIN`; existing `RATE_LIMIT_PER_MINUTE` untouched | VERIFIED | `NotifyRateLimitConfig` in `src/config.rs:44-49` reads both new env vars. `RATE_LIMIT_PER_MINUTE` feeds `RateLimitConfig::max_per_minute` at line 106, separate struct, unchanged. Zero-value rejection tests (`rejects_zero_per_pubkey_rate`, `rejects_zero_per_ip_rate`) pass. |
| 5 | Per-pubkey limiter map bounded by periodic `retain_recent` + `warn!` when size crosses configurable soft cap (default ~100k) | VERIFIED | `start_rate_limit_cleanup_task` in `src/api/rate_limit.rs:159-174` calls `limiter.retain_recent()` every tick and routes through `check_soft_cap` which emits `warn!("rate-limit pubkey map size exceeded soft cap: {}", n)`. Spawned in `src/main.rs:138-142` with `config.notify_rate_limit.pubkey_limiter_soft_cap` (env var `NOTIFY_PUBKEY_LIMITER_SOFT_CAP`, default 100000). Tests `retain_recent_reduces_len_with_fake_clock`, `check_soft_cap_fires_above_cap`, `check_soft_cap_fires_for_real_limiter_above_cap` pass. |
| 6 | In-process integration suite covers six TEST-1 scenarios and runs green on `cargo test` | VERIFIED | 31 tests pass. Six VERIFY-01 scenarios covered: (1) registered hit → `notify_registered_pubkey_dispatches`; (2) unregistered miss → `notify_unregistered_pubkey_no_dispatch`; (3) malformed body → `notify_malformed_body_returns_400`; (4) per-pubkey 429 → `per_pubkey_burst_exhaustion_returns_429`; (5) per-IP 429 → `per_ip_burst_exhaustion_returns_429`; (6) `/api/register` byte-identical regression → `register_success_body_is_byte_identical`. |

**Score:** 6/6 success criteria verified

---

### Required Artifacts

| Artifact | Purpose | Status | Details |
|----------|---------|--------|---------|
| `src/api/rate_limit.rs` | Per-IP middleware + per-pubkey limiter type + cleanup task | VERIFIED | 598 lines; substantive; imported and used in `routes.rs` and `main.rs` |
| `src/api/notify.rs` | notify handler + `request_id_mw` middleware | VERIFIED | 303 lines; substantive; imported in `routes.rs` |
| `src/api/routes.rs` | `configure()` wires the notify resource with both middlewares | VERIFIED | Middleware order confirmed: `per_ip_rate_limit_mw` registered first (innermost), `request_id_mw` registered second (outermost) — correct per actix-web 4 reverse-wrap semantics |
| `src/api/test_support.rs` | `StubPushService`, `make_test_components`, `build_test_actix_app`, `seed_hex_pubkey` | VERIFIED | 187 lines; substantive; used by all test modules |
| `src/api/mod.rs` | Module declaration exposing all submodules | VERIFIED | Declares `routes`, `notify`, `rate_limit`, `test_support` (cfg(test)) |
| `src/config.rs` | `NotifyRateLimitConfig` with 4 new env vars | VERIFIED | `per_pubkey_per_min`, `per_ip_per_min`, `cleanup_interval_secs`, `pubkey_limiter_soft_cap` — all wired through to `main.rs` |
| `src/main.rs` | Limiter construction + cleanup task spawn + `AppState` wiring | VERIFIED | Lines 113-142: per-pubkey and per-IP limiters constructed from config, cleanup task spawned, limiters registered in `app_data` and `AppState` |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `notify_token` handler | `PerPubkeyLimiter` | `state.per_pubkey_limiter.check_key()` | WIRED | `src/api/notify.rs:72` — check happens after pubkey validation, before semaphore |
| `per_ip_rate_limit_mw` | `PerIpLimiter` | `req.app_data::<web::Data<Arc<PerIpLimiter>>>()` | WIRED | `src/api/rate_limit.rs:92-93` — pulled from app_data, fail-closed on None |
| `/api/notify` resource | both middlewares | `web::resource("/notify").wrap(...)` | WIRED | `src/api/routes.rs:60-67` — scoped strictly to `/notify`, other routes bypass |
| `start_rate_limit_cleanup_task` | `per_pubkey_limiter` | `Arc::clone` in `main.rs:138-142` | WIRED | Cleanup task runs in background; same `Arc` instance as the one in `AppState` |
| `rate_limited_response` helper | both 429 paths | shared function call | WIRED | `src/api/rate_limit.rs:39-46` called from middleware (line 130) and `notify_token` (line 77) — byte-identical by construction |
| `request_id_mw` (outermost) | per-IP 429 response | middleware wrap order | WIRED | `request_id_mw` registered second → executes first in actix-web 4 → `x-request-id` present on BOTH 429 paths. Confirmed by `x_request_id_present_on_both_429_paths` test. WR-01 fix in commit `6573733` intact. |

---

### Data-Flow Trace (Level 4)

Rate limiting is a control-flow concern, not a data-rendering concern. The limiters hold in-memory GCRA state (no external data source). The cleanup task calls `retain_recent()` which operates purely on the governor internal state. Level 4 data-flow tracing is not applicable to this phase's artifacts — the "data" flowing through is HTTP request metadata (IP, pubkey string) verified present by the tests themselves.

---

### Behavioral Spot-Checks

Tests serve as the behavioral verification layer for this phase. All 31 in-process tests run against a real governor middleware (not mocked), making them equivalent to behavioral spot-checks.

| Behavior | Verification | Result |
|----------|-------------|--------|
| Per-IP 429 after burst exhaustion | `per_ip_burst_exhaustion_returns_429` (actix_web::test) | PASS |
| Per-pubkey 429 after burst exhaustion | `per_pubkey_burst_exhaustion_returns_429` (actix_web::test) | PASS |
| 429 body byte-identical between both paths | `rate_limited_429_body_byte_identical_per_ip_vs_per_pubkey` | PASS |
| `x-request-id` present on both 429 paths | `x_request_id_present_on_both_429_paths` | PASS |
| Rightmost XFF used when Fly-Client-IP absent | `rightmost_xff_used_when_fly_client_ip_missing` | PASS |
| 1000-burst on /api/health returns 1000x 200 | `health_endpoint_not_rate_limited_1000_burst` | PASS |
| `retain_recent` evicts stale keys (FakeRelativeClock) | `retain_recent_reduces_len_with_fake_clock` | PASS |
| Soft-cap warn fires above threshold, not at/below | `check_soft_cap_fires_above_cap` + `check_soft_cap_does_not_fire_at_or_below_cap` | PASS |
| Config rejects NOTIFY_RATE_PER_PUBKEY_PER_MIN=0 | `rejects_zero_per_pubkey_rate` | PASS |
| Config rejects NOTIFY_RATE_PER_IP_PER_MIN=0 | `rejects_zero_per_ip_rate` | PASS |

---

### Requirements Coverage

| Requirement | Description | Status | Evidence |
|-------------|-------------|--------|----------|
| LIMIT-01 | Per-source-IP rate limit on `/api/notify` via `Fly-Client-IP` / rightmost-XFF / `peer_addr()` | SATISFIED | `extract_client_ip` + `per_ip_rate_limit_mw` in `rate_limit.rs`; test `rightmost_xff_used_when_fly_client_ip_missing` |
| LIMIT-02 | Per-`trade_pubkey` rate limit inside `notify_token` handler | SATISFIED | `state.per_pubkey_limiter.check_key()` in `notify.rs:72`; test `per_pubkey_burst_exhaustion_returns_429` |
| LIMIT-03 | Rate-limiting middleware applied ONLY to `/api/notify`; other endpoints unaffected | SATISFIED | `web::resource("/notify").wrap(...)` scoped route in `routes.rs:59-68`; 1000-burst health test + 50-burst other-endpoints test |
| LIMIT-04 | Quotas configurable via `NOTIFY_RATE_PER_PUBKEY_PER_MIN` and `NOTIFY_RATE_PER_IP_PER_MIN`; `RATE_LIMIT_PER_MINUTE` untouched | SATISFIED | `NotifyRateLimitConfig` in `config.rs:44-49`; zero-rejection tests; `RATE_LIMIT_PER_MINUTE` feeds unchanged `RateLimitConfig` |
| LIMIT-05 | Periodic `retain_recent` on per-pubkey limiter to bound map cardinality | SATISFIED | `start_rate_limit_cleanup_task` in `rate_limit.rs:159-174`; `main.rs:138-142`; `retain_recent_reduces_len_with_fake_clock` test |
| LIMIT-06 | `warn!` logged when per-pubkey map size crosses configurable soft cap | SATISFIED | `check_soft_cap` helper in `rate_limit.rs:143-147`; warn at line 170; configured from `NOTIFY_PUBKEY_LIMITER_SOFT_CAP` (default 100000) |
| VERIFY-01 | In-process integration suite covering six TEST-1 scenarios | SATISFIED | 10 tests across `notify.rs` and `rate_limit.rs` cover all six scenarios against real governor middleware; all pass |
| VERIFY-02 | Regression test verifies existing endpoint responses are byte-identical | SATISFIED | 7 tests in `routes.rs` cover `/api/register` (success + malformed), `/api/unregister` (success + not-found), `/api/health`, `/api/info`, `/api/status`; all assert exact byte content |

Coverage: 8/8 Phase 3 requirements satisfied.

---

### WR-01 Fix Confirmation

The code review finding WR-01 (middleware order causing per-IP 429 to lack `x-request-id`) has been fixed in commit `6573733`.

**Before fix (review finding):**
```
.wrap(from_fn(request_id_mw))        // registered first → innermost (wrong)
.wrap(from_fn(per_ip_rate_limit_mw)) // registered second → outermost (wrong)
```

**After fix (current code, `src/api/routes.rs:65-66`):**
```
.wrap(from_fn(per_ip_rate_limit_mw)) // registered first → innermost
.wrap(from_fn(request_id_mw))        // registered second → outermost
```

The comment at `routes.rs:61-64` correctly documents the actix-web 4 reverse-wrap semantics and the intent. Test `x_request_id_present_on_both_429_paths` in `rate_limit.rs` verifies both paths carry a valid UUIDv4 `x-request-id`. This test passes in the current codebase.

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `src/config.rs` | 70 | Dead variable `let mostro_pubkey` (WR-02 from review) | Warning | Pre-existing issue; compiler emits `unused variable` warning; does not affect Phase 3 functionality |
| `src/api/routes.rs` | 128 | User-supplied `platform` string logged verbatim (WR-03 from review) | Warning | Pre-existing issue noted in review as non-blocking; log injection risk but not a Phase 3 regression |

Both findings were flagged in `03-REVIEW.md` as WR-02 and WR-03. Per verification instructions, these are pre-existing/non-blocking and are not counted as Phase 3 gaps. No new anti-patterns were introduced by Phase 3 code.

The `RATE_LIMIT_CLEANUP_INTERVAL_DEFAULT_SECS` and `PUBKEY_LIMITER_SOFT_CAP_DEFAULT` constants in `rate_limit.rs` are unused (compiler warns) — these are informational defaults defined but not consumed since the values come from config. Not a functional gap.

---

### Human Verification Required

None. All success criteria are verifiable programmatically via the in-process test suite. The test suite itself IS the VERIFY-01 requirement; it runs green. No manual smoke test (real device + FCM) is required for this phase because the dispatch layer was validated in Phase 2 and Phase 3 only adds the rate-limiting wrapper around the existing dispatch path.

---

## Gaps Summary

No gaps. All six success criteria are fully verified:

- Per-IP rate limiting is implemented, correctly keyed on `Fly-Client-IP` > rightmost-XFF > peer_addr, and scoped exclusively to `/api/notify`.
- Per-pubkey rate limiting is implemented inside the handler with byte-identical 429 responses to the per-IP path (anti-RL-2 oracle).
- Other endpoints are provably unaffected (1000-burst health test passes).
- Both new env vars are wired through Config to the limiter constructors; `RATE_LIMIT_PER_MINUTE` is untouched.
- The per-pubkey limiter cleanup task is spawned in `main.rs` with configurable interval and soft-cap, using `retain_recent()` + `warn!` per LIMIT-05/06.
- The in-process test suite (31 tests, all green) covers all six TEST-1 scenarios and the VERIFY-02 byte-identical regression fixtures.

The WR-01 middleware order fix (commit `6573733`) is in place and verified by test.

---

_Verified: 2026-04-26T00:22:19Z_
_Verifier: Claude (gsd-verifier)_
