---
phase: 03-dual-keyed-rate-limiting-and-verification-harness
plan: "01"
subsystem: api/rate-limiting
tags:
  - rate-limiting
  - governor
  - actix-web
  - middleware
  - privacy
dependency_graph:
  requires:
    - "02-03 (notify endpoint + AppState shape)"
    - "governor = 0.6 (already declared in Cargo.toml)"
  provides:
    - "PerPubkeyLimiter type alias and per-pubkey enforcement in notify_token"
    - "PerIpLimiter type alias and per_ip_rate_limit_mw middleware"
    - "rate_limited_response helper (byte-identical 429 body, D-13)"
    - "NotifyRateLimitConfig with four env-overridable fields"
    - "start_rate_limit_cleanup_task (LIMIT-05)"
    - "check_soft_cap helper (LIMIT-06, unit-testable)"
  affects:
    - "src/api/notify.rs (per-pubkey check inserted at D-12 step 4)"
    - "src/api/routes.rs (AppState extended, /notify double-wrapped)"
    - "src/main.rs (limiter construction, cleanup task, app_data)"
tech_stack:
  added: []
  patterns:
    - "governor::DefaultKeyedRateLimiter<K> keyed limiter (first use in codebase)"
    - "from_fn middleware that short-circuits with BoxBody (new shape)"
    - "Mutex-serialized env-mutating unit tests (no serial_test dev-dep)"
key_files:
  created:
    - src/api/rate_limit.rs
  modified:
    - src/api/mod.rs
    - src/api/notify.rs
    - src/api/routes.rs
    - src/config.rs
    - src/main.rs
decisions:
  - "D-05: actix-governor NOT added (GPL-3.0 vs project MIT)"
  - "D-06: hand-rolled per_ip_rate_limit_mw over governor directly"
  - "D-09: PerPubkeyLimiter = DefaultKeyedRateLimiter<String> in AppState"
  - "D-10: Fly-Client-IP > rightmost-XFF > peer_addr IP precedence"
  - "D-11: 500 fail-closed on IP extraction failure"
  - "D-12: per-pubkey check after log_pk, before try_acquire_owned"
  - "D-13: byte-identical 429 body via shared rate_limited_response"
  - "D-19: request_id_mw outermost, per_ip_rate_limit_mw innermost"
  - "D-20: per-IP limiter via app_data, NOT in AppState (key type IpAddr)"
  - "D-21: middleware applied ONLY to /api/notify (LIMIT-03 + DEPLOY-3)"
  - "D-28: NotifyRateLimitConfig with four fields on Config"
  - "D-29: bursts are compile-time constants, not env-overridable"
  - "Rule 1 (Auto-fix): added governor::clock::Clock import to notify.rs — governor 0.6 requires the Clock trait in scope for .now() on QuantaClock"
  - "Rule 2 (Auto-add): added Mutex-serialized ENV_MUTEX in config tests — env-mutating tests race without a serialization lock; no serial_test dep needed"
metrics:
  duration_secs: 421
  completed_date: "2026-04-25"
  tasks_completed: 3
  files_changed: 6
---

# Phase 03 Plan 01: Dual-keyed rate limiting wiring — Summary

**One-liner:** Per-IP (120/min burst 30) and per-pubkey (30/min burst 10) `governor::DefaultKeyedRateLimiter` enforcement on `/api/notify` only, with hand-rolled `from_fn` middleware, byte-identical 429 responses, and a periodic `retain_recent` cleanup task.

---

## What Was Built

Three commits implement LIMIT-01 through LIMIT-06 and D-01 through D-29:

### Task 1 — `src/api/rate_limit.rs` (new, 200 LoC) + `src/api/mod.rs` (1 line)

- `PerPubkeyLimiter` and `PerIpLimiter` type aliases over `governor::DefaultKeyedRateLimiter<K>`.
- `PUBKEY_BURST = 10` and `IP_BURST = 30` compile-time constants (D-29 — not env-overridable).
- `rate_limited_response(retry_after_secs)` — shared 429 builder, byte-identical body `{"success":false,"message":"rate limited"}` plus `Retry-After` header (D-13, D-14).
- `extract_client_ip` — `Fly-Client-IP` → rightmost `X-Forwarded-For` segment → `peer_addr()` precedence (D-10, CRIT-4). Returns `None` only when all three fail.
- `per_ip_rate_limit_mw` — `from_fn` middleware; fail-closed 500 on missing IP (D-11); 429 on quota exhaustion; passes through with `BoxBody` on both branches.
- `check_soft_cap<F: FnOnce(usize)>` — synchronous helper routing the soft-cap warn through a closure; unit-testable without spawning a real interval loop (LIMIT-06).
- `start_rate_limit_cleanup_task(limiter, interval, soft_cap)` — mirrors `store::start_cleanup_task`; calls `retain_recent()` then `check_soft_cap` every tick (D-15, D-18).
- Two `check_soft_cap` unit tests co-located in `#[cfg(test)] mod tests`.

### Task 2 — `src/config.rs` (105 lines added)

- `NotifyRateLimitConfig` struct with four fields.
- `notify_rate_limit` field appended to `Config` (existing fields untouched, LIMIT-04).
- `Config::from_env` extended: `info!` log when env vars are absent (D-03); explicit `must be > 0` rejection for the two rate fields (D-04).
- Two co-located `#[cfg(test)]` tests using `Mutex`-serialized env mutation (no new dev-dep).

### Task 3 — `src/api/routes.rs`, `src/api/notify.rs`, `src/main.rs`

- `AppState` gains `per_pubkey_limiter: Arc<PerPubkeyLimiter>` as fifth field.
- `/api/notify` resource gains `.wrap(from_fn(per_ip_rate_limit_mw))` after `request_id_mw`; all other routes remain unwrapped (D-21).
- `notify_token` inserts per-pubkey limiter check between `info!` log and `try_acquire_owned` (D-12), returning `rate_limited_response(...)` on exhaustion (D-13).
- `main.rs` constructs both limiters, spawns the cleanup task, logs the resolved quota/burst/cleanup/soft-cap, adds `per_ip_limiter` via `app_data`.

---

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `governor::clock::Clock` trait import missing in `notify.rs`**

- **Found during:** Task 3 (`cargo check`)
- **Issue:** `governor 0.6.3` uses `QuantaClock` as `DefaultClock`; the `.now()` method is gated behind the `Clock` trait. Without `use governor::clock::Clock` in `notify.rs`, the compiler emits `E0599: no method named 'now' found for struct QuantaClock`.
- **Fix:** Added `use governor::clock::Clock;` to `src/api/notify.rs` imports.
- **Files modified:** `src/api/notify.rs`
- **Commit:** e964170

**2. [Rule 2 - Missing critical functionality] `ENV_MUTEX` serialization in config tests**

- **Found during:** Task 2 (first test run without `--test-threads=1`)
- **Issue:** `rejects_zero_per_ip_rate` failed intermittently because cargo's default parallel test runner let `rejects_zero_per_pubkey_rate` set `NOTIFY_RATE_PER_PUBKEY_PER_MIN=0` before `rejects_zero_per_ip_rate` read it, causing the wrong branch to trigger. The plan acknowledges this race and suggests `serial_test` (which would require a new dev-dep, prohibited).
- **Fix:** Added `static ENV_MUTEX: Mutex<()>` inside the `#[cfg(test)] mod tests` block; each test acquires the lock before mutating env and releases it on drop — no new dependency, no `--test-threads=1` flag required.
- **Files modified:** `src/config.rs`
- **Commit:** 5e262ee

---

## Startup Log (sample with defaults)

```
INFO  mostro_push_backend > Rate limiters initialized (per-pubkey 30/min burst 10; per-IP 120/min burst 30; cleanup 60s; soft cap 100000)
```

---

## Grep Guards (all pass)

```
! grep -rn "actix-governor|actix_governor" .            # PASS (D-05 license invariant)
! grep -n "\.split(',').next()" src/api/rate_limit.rs   # PASS (CRIT-4 leftmost-XFF anti-fix)
grep -c "\.wrap(" src/api/routes.rs                     # → 2 (request_id_mw + per_ip_rate_limit_mw)
grep -c "fn check_soft_cap" src/api/rate_limit.rs       # → 1 definition; 2 test uses (correct)
grep -c "if len > soft_cap" src/api/rate_limit.rs       # → 1 (only inside check_soft_cap)
grep -c "rsplit(',')" src/api/rate_limit.rs             # → 1 (rightmost-XFF guard)
```

---

## Test Results

| Test | Result |
|------|--------|
| `api::rate_limit::tests::check_soft_cap_fires_above_cap` | PASS |
| `api::rate_limit::tests::check_soft_cap_does_not_fire_at_or_below_cap` | PASS |
| `config::tests::rejects_zero_per_pubkey_rate` | PASS |
| `config::tests::rejects_zero_per_ip_rate` | PASS |
| All 11 binary tests | PASS |

---

## Pointer to Plan 02

Plan 02 (`03-02-PLAN.md`) delivers the integration test suite for the wiring built here:

- 6 mandatory TEST-1 scenarios (D-24): registered hit, unregistered miss, malformed body, per-pubkey 429 boundary, per-IP 429 boundary, `/api/register` byte-identical regression.
- 4 additional regressions (D-25): `/api/health` 1000-burst, `X-Request-Id` on every response, 429 byte-equality between per-IP and per-pubkey, `retain_recent` plumbing test.
- `StubPushService` test double (D-23).
- The `check_soft_cap` helper defined in Plan 01 will be used in Plan 02's `check_soft_cap_fires_for_real_limiter_above_cap` test against a real `PerPubkeyLimiter`.

---

## Self-Check: PASSED

All files created/modified exist on disk. All three task commits (b3fdef0, 5e262ee, e964170) confirmed in git log. `cargo build --release` exits 0. All 11 tests pass.
