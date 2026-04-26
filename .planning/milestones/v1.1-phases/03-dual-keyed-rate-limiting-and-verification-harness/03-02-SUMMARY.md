---
phase: 03-dual-keyed-rate-limiting-and-verification-harness
plan: "02"
subsystem: api/testing
tags:
  - testing
  - integration-tests
  - actix-web
  - governor
  - regression
dependency_graph:
  requires:
    - "03-01 (rate_limit.rs wiring — PerPubkeyLimiter, PerIpLimiter, check_soft_cap, AppState)"
    - "governor = 0.6 (FakeRelativeClock, HashMapStateStore)"
    - "uuid = 1 (v4 feature — already declared)"
  provides:
    - "StubPushService test double (D-23) with Arc<Mutex<Vec<(String, Platform)>>> call recording"
    - "make_app_state() + build_test_actix_app() factory pair for in-process actix test apps"
    - "make_test_components() convenience constructor"
    - "seed_hex_pubkey(n) — deterministic 64-hex pubkey rotation for per-IP boundary tests"
    - "21 passing tests covering VERIFY-01, VERIFY-02, D-24 #1-6, D-25 regressions"
  affects:
    - "src/api/mod.rs (added #[cfg(test)] pub mod test_support)"
    - "src/api/notify.rs (added #[cfg(test)] mod tests)"
    - "src/api/rate_limit.rs (extended existing #[cfg(test)] mod tests)"
    - "src/api/routes.rs (added #[cfg(test)] mod tests)"
tech_stack:
  added: []
  patterns:
    - "actix_web::test as atest alias — avoids #[test] attribute shadowing by actix_web::test module"
    - "governor::clock::FakeRelativeClock + RateLimiter::new with explicit NoOpMiddleware<<FakeRelativeClock as Clock>::Instant> fourth generic (D-27 resolution)"
    - "build_test_actix_app(TestAppComponents) factory — avoids annotating the opaque actix_http::Request type without a direct dep"
    - "tokio::task::yield_now() loop for tokio::spawn completion (no sleep, no time::pause)"
key_files:
  created:
    - src/api/test_support.rs
  modified:
    - src/api/mod.rs
    - src/api/notify.rs
    - src/api/rate_limit.rs
    - src/api/routes.rs
decisions:
  - "actix_web::test aliased as atest in test modules — importing 'test' shadows the #[test] built-in attribute causing E0277 on sync test functions"
  - "RateLimiter type annotation with FakeRelativeClock requires explicit 4th generic: NoOpMiddleware<<FakeRelativeClock as Clock>::Instant>; omitting it causes QuantaInstant/Nanos mismatch under quanta feature"
  - "make_test_app() redesigned to return TestAppComponents + build_test_actix_app() instead of impl Service<actix_http::Request,...> — actix_http is a transitive dep not directly accessible without adding it to Cargo.toml"
  - "No new Cargo.toml entries — all required types (actix_web::test, governor::clock::FakeRelativeClock, uuid) were already pulled"
metrics:
  duration_secs: 739
  completed_date: "2026-04-25"
  tasks_completed: 4
  files_changed: 5
---

# Phase 03 Plan 02: In-process integration test suite — Summary

**One-liner:** 21 co-located tests covering the full `/api/notify` wiring end-to-end (handler + governor middleware + StubPushService), VERIFY-02 byte-identical fixtures for 5 unchanged endpoints, and 4 locked regressions (D-25): 1000-burst `/api/health`, X-Request-Id overwrite, 429 byte-equality (non-tautological both halves), and retain_recent with FakeRelativeClock.

---

## What Was Built

Four commits implement VERIFY-01 + VERIFY-02 + SC #6 + D-25 regressions.

### Task 1 — `src/api/test_support.rs` (new, ~160 LoC) + `src/api/mod.rs` (1 line)

- `StubPushService` implementing the `PushService` trait, recording every `send_to_token` call into `Arc<Mutex<Vec<(String, Platform)>>>` (D-23).
- `make_app_state(stub)` — synchronous factory returning `(AppState, Arc<PerIpLimiter>)` with fresh governor limiters, a random 32-byte log salt, and an `Arc<PushDispatcher>` backed by the stub.
- `TestAppComponents` struct + `make_test_components()` + `build_test_actix_app(c)` — avoids annotating the opaque `actix_http::Request` type returned by `test::init_service` (which is not re-exported by `actix_web`) without adding `actix-http` as a direct dependency.
- `make_test_app!` macro wrapping the `init_service` call for single-expression test setup.
- `seed_hex_pubkey(n: u64) -> String` — canonical source of the pubkey-rotation pattern used across per-IP boundary tests.
- `TEST_PUBKEY` + `TEST_PUBKEY_2` — 64-hex constants; `TEST_PUBKEY_2` is the canonical "unregistered but format-valid" fixture.
- Module gated `#[cfg(test)] pub mod test_support;` in `src/api/mod.rs`; absent from release builds.

### Task 2 — `src/api/notify.rs` (4 tests added)

- `notify_registered_pubkey_dispatches` (D-24 #1): pre-registers via `make_app_state`, sends POST, asserts 202 + stub recorded 1 call with `test_fcm_token` + `Platform::Android`.
- `notify_unregistered_pubkey_no_dispatch` (D-24 #2): asserts 202 (anti-CRIT-2) + stub records zero calls.
- `notify_malformed_body_returns_400` (D-24 #3): 3 sub-cases (short pubkey, non-hex 64-char, missing field).
- `notify_x_request_id_always_uuidv4_and_overwrites_client_value` (D-25 NOTIFY-04): header present on both 202 and 400, client-supplied value overwritten, server value parses as UUIDv4.

### Task 3 — `src/api/rate_limit.rs` (6 tests added, Plan 01's 2 retained = 8 total)

- `per_ip_burst_exhaustion_returns_429` (D-24 #5): rotates pubkey via `seed_hex_pubkey(i)`, asserts first 429 at `iter >= IP_BURST` (structurally proves per-IP path, not per-pubkey).
- `per_pubkey_burst_exhaustion_returns_429` (D-24 #4): rotates IPs, asserts first 429 at `iter <= PUBKEY_BURST`.
- `rate_limited_429_body_byte_identical_per_ip_vs_per_pubkey` (D-25 byte-equality): both halves non-tautological with independent iteration-boundary assertions; final `assert_eq!(body_ip, body_pk)` + body shape locked to `{"success":false,"message":"rate limited"}`.
- `retain_recent_reduces_len_with_fake_clock` (D-25 LIMIT-05): `FakeRelativeClock` + `clock.advance(120s)` — no OS time, no `tokio::time::pause` (D-27 resolution).
- `check_soft_cap_fires_for_real_limiter_above_cap` (D-25 LIMIT-06): real `PerPubkeyLimiter` with 5 keys; above-cap fires with `n=5`; boundary (`soft_cap == len`) does not fire.
- `rightmost_xff_used_when_fly_client_ip_missing` (anti-CRIT-4): no `Fly-Client-IP`, 3-segment XFF, rightmost `3.3.3.3` is the rate-limit key; structural assertion `iter >= IP_BURST`.

### Task 4 — `src/api/routes.rs` (9 tests added)

- VERIFY-02 byte-identical fixtures: `/api/register` success + malformed, `/api/unregister` not-found + success, `/api/health`, `/api/info`, `/api/status`. All inline `r#"..."#` literals — no `insta` dep, no `tests/fixtures/` dir.
- `health_endpoint_not_rate_limited_1000_burst`: 1000x GET returns 200 — closes DEPLOY-3 oracle structurally.
- `other_endpoints_not_rate_limited_under_burst`: 50-request sweep across `/api/info`, `/api/status`, `/api/register` — closes LIMIT-03 scope invariant.

---

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `actix_web::test` module shadows `#[test]` attribute**

- **Found during:** Task 3 (`cargo test --no-run`)
- **Issue:** Importing `use actix_web::{...test...}` inside `mod tests` makes the identifier `test` refer to the actix module. Sync test functions annotated `#[test]` got E0277 "the async keyword is missing" because the `#[actix_web::test]` macro (which requires `async fn`) was applied instead of the stdlib `#[test]`.
- **Fix:** Aliased the import: `use actix_web::{...test as atest...}`. All `test::` call sites updated to `atest::`.
- **Files modified:** `src/api/rate_limit.rs`, `src/api/routes.rs`, `src/api/notify.rs`

**2. [Rule 1 - Bug] `RateLimiter::new` with `FakeRelativeClock` requires explicit 4th generic**

- **Found during:** Task 3 (`cargo test --no-run`)
- **Issue:** The plan annotated `RateLimiter<String, HashMapStateStore<String>, FakeRelativeClock>` without the 4th generic. Rust inferred `NoOpMiddleware<QuantaInstant>` (the default) instead of `NoOpMiddleware<Nanos>` (the `FakeRelativeClock` instant type), causing E0277 trait bound failure.
- **Fix:** Annotated the full type: `RateLimiter<String, HashMapStateStore<String>, FakeRelativeClock, governor::middleware::NoOpMiddleware<<FakeRelativeClock as Clock>::Instant>>`. Pattern matches governor's own test suite in `src/state/keyed.rs:276-285`.
- **Files modified:** `src/api/rate_limit.rs`

**3. [Rule 1 - Bug] `make_test_app()` return type required `actix_http::Request` not accessible without direct dep**

- **Found during:** Task 1 (`cargo check --tests`)
- **Issue:** `actix_web::test::init_service` returns `impl Service<actix_http::Request, ...>`. The plan's `impl Service<ServiceRequest, ...>` annotation was wrong; `actix_http` is a transitive dep not directly usable without `Cargo.toml` entry, and `actix_http::Request` is not re-exported by `actix_web`.
- **Fix:** Redesigned `make_test_app()` into a factory pair: `make_test_components() -> TestAppComponents` + `build_test_actix_app(c) -> App<impl ServiceFactory<...>>`. Each test calls `test::init_service(build_test_actix_app(c))` inline, letting Rust infer the opaque `impl Service<Request, ...>` type. No new dependency added.
- **Files modified:** `src/api/test_support.rs`

---

## Test Results

| Suite | Tests | Result |
|-------|-------|--------|
| `api::notify::tests::` | 4 | PASS |
| `api::rate_limit::tests::` | 8 | PASS |
| `api::routes::tests::` | 9 | PASS |
| `config::tests::` | 2 | PASS |
| `crypto::tests::` | 7 | PASS |
| **Total** | **30** | **PASS** |

---

## Must-Haves Verified

| Requirement | Status |
|-------------|--------|
| 6 TEST-1 scenarios (D-24 #1-6) | PASS — notify×3, rate_limit×2, routes×1 |
| 4 D-25 regressions (1000-health, X-Request-Id, 429-byte-eq, retain_recent) | PASS |
| 429 body byte-equality both halves non-tautological | PASS — `body_ip_iter >= IP_BURST`, `body_pk_iter <= PUBKEY_BURST` |
| `retain_recent` uses FakeRelativeClock, no tokio::time::pause | PASS |
| Per-IP tests rotate pubkey via seed_hex_pubkey | PASS — 3 tests carry inline comment |
| check_soft_cap against real PerPubkeyLimiter | PASS — above-cap + boundary |
| VERIFY-02 inline fixtures, no insta dep | PASS |
| Zero new Cargo.toml entries | PASS |
| All tests co-located in #[cfg(test)] mod tests | PASS (D-22) |
| cargo build --release exits 0 | PASS |

---

## Known Stubs

None — all production paths exercised by tests are wired. `StubPushService` is test-only.

---

## Self-Check: PASSED

Files confirmed on disk:
- `src/api/test_support.rs` — FOUND
- `src/api/notify.rs` (#[cfg(test)] block) — FOUND
- `src/api/rate_limit.rs` (extended tests block) — FOUND
- `src/api/routes.rs` (#[cfg(test)] block) — FOUND

Commits confirmed in git log:
- `4a1fb30` feat(03-02): add test_support module — FOUND
- `18198d9` test(03-02): add notify handler tests — FOUND
- `56c5104` test(03-02): extend rate_limit tests — FOUND
- `227a8b5` test(03-02): add routes byte-identical VERIFY-02 fixtures — FOUND

`cargo test` 30/30 PASS. `cargo build --release` exit 0.
