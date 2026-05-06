---
phase: 01-pushdispatcher-refactor-no-behaviour-change
plan: 01
subsystem: push-dispatch
tags:
  - rust
  - refactor
  - push
  - dispatcher
  - nostr-listener
requirements:
  - DISPATCH-01
  - DISPATCH-02
dependency_graph:
  requires:
    - existing-PushService-trait
    - existing-Nostr-listener
    - existing-FcmPush-impl
    - existing-UnifiedPushService-impl
  provides:
    - PushDispatcher
    - DispatchOutcome
    - DispatchError
    - lock-free-services-list
  affects:
    - src/push/mod.rs (trait surface tightened)
    - src/main.rs (wiring)
    - src/nostr/listener.rs (caller updated)
tech_stack:
  added: []
  patterns:
    - Arc<[T]> immutable slice instead of Mutex<Vec<T>>
    - Hand-written Display + std::error::Error enum (CryptoError pattern)
    - Side-table backend-name index alongside Arc<[Arc<dyn PushService>]>
key_files:
  created:
    - src/push/dispatcher.rs
  modified:
    - src/push/mod.rs
    - src/push/fcm.rs
    - src/push/unifiedpush.rs
    - src/main.rs
    - src/nostr/listener.rs
decisions:
  - D-01..D-16 from 01-CONTEXT.md applied verbatim
  - Single atomic commit (per CONTEXT.md "Claude's Discretion") covering all 6 files
metrics:
  duration_seconds: 416
  duration_human: "6m 56s"
  tasks_completed: 6
  files_changed: 6
  insertions: 120
  deletions: 138
  net_lines: -18
  completed_date: "2026-04-25"
commits:
  - a43aa49: "refactor(push): extract PushDispatcher and replace Mutex with Arc<[Arc<dyn>]>"
---

# Phase 1 Plan 1: PushDispatcher refactor (no behaviour change) Summary

Pure structural refactor that lifts the inline push-dispatch loop out of `src/nostr/listener.rs` into a new `PushDispatcher` component (`src/push/dispatcher.rs`), replaces the `Arc<Mutex<Vec<Box<dyn PushService>>>>` runtime container with a lock-free `Arc<[Arc<dyn PushService>]>` immutable slice, and adds a structurally-visible anti-CRIT-1 comment block above the Nostr `Filter::new()` site to prevent a future contributor from "fixing" the dormant `MOSTRO_PUBKEY` field by applying it as a filter (which would silently drop dispute admin DMs and ephemeral-keyed Gift Wrap events). Bundles two trait-surface hygiene items along the way (D-09 tighten `PushService::send_to_token` to `Box<dyn Error + Send + Sync>`; D-10 delete unused `send_silent_push`). Mostro daemon -> silent push flow remains byte-identical at the observable level.

## Files

### Created

- `src/push/dispatcher.rs` (78 lines) — `PushDispatcher`, `DispatchOutcome::Delivered { backend: &'static str }`, `DispatchError::{NoBackendForPlatform, AllBackendsFailed { errors: Vec<String> }}` with hand-written `Display` + empty `impl std::error::Error` (CryptoError pattern). Constructor accepts `Vec<(Arc<dyn PushService>, &'static str)>` to keep service/name index alignment trivially correct. `dispatch(&RegisteredToken)` replicates the listener's prior iteration protocol byte-for-byte: skip non-matching, attempt first matching, return `Ok(Delivered)` on first `Ok(())`, return `Err(NoBackendForPlatform)` if nothing was attempted, return `Err(AllBackendsFailed { errors })` if at least one matching backend was attempted and all failed. Zero log lines (D-07).

### Modified

- `src/push/mod.rs` (-9 net lines) — Added `pub mod dispatcher;` and re-exports for `DispatchError`, `DispatchOutcome`, `PushDispatcher`. Tightened `PushService::send_to_token` return type to `Result<(), Box<dyn std::error::Error + Send + Sync>>` (D-09). Deleted `send_silent_push` from the trait and both blanket `Arc<>` impls (D-10).

- `src/push/fcm.rs` (-49 net lines) — Deleted `send_silent_push` impl (lines 220-266 in the prior version). Tightened `send_to_token` return type per D-09. Dropped the `.map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })` workaround on the `get_access_token().await` line; with the bound aligned, `?` propagates directly.

- `src/push/unifiedpush.rs` (-37 net lines) — Deleted `send_silent_push` impl (lines 127-163 in the prior version). Tightened `send_to_token` return type per D-09 (body unchanged; `reqwest`'s `?` already returned a `Send + Sync` error).

- `src/main.rs` (~6 lines net delta) — Dropped `use tokio::sync::Mutex;`. Extended `use push::{...}` to import `PushDispatcher`. Built `Vec<(Arc<dyn PushService>, &'static str)>` tagged with `"fcm"` / `"unifiedpush"` backend names. Replaced `Arc::new(Mutex::new(push_services))` with `Arc::new(PushDispatcher::new(push_services))` and renamed the binding to `dispatcher`. Passed `dispatcher.clone()` into `NostrListener::new`. `AppState` untouched (D-16, must-not #3).

- `src/nostr/listener.rs` (-9 net lines) — Dropped `use tokio::sync::Mutex;` and `use crate::push::PushService;`. Imported `crate::push::{DispatchError, DispatchOutcome, PushDispatcher}`. Field changed from `push_services: Arc<Mutex<Vec<Box<dyn PushService>>>>` to `dispatcher: Arc<PushDispatcher>`; constructor signature updated accordingly. `MOSTRO_PUBKEY` validation block (lines 25-32) preserved verbatim per D-12. Replaced the existing 3-line filter comment above `Filter::new()` with the explicit anti-CRIT-1 block citing NIP-59 ephemeral keys, admin DMs, and `OOS-19` / `CRIT-1`. Updated closure capture from `push_services.clone()` to `self.dispatcher.clone()`. Replaced the inline iteration loop (lines 119-135 of the prior version) with a single `dispatcher.dispatch(&registered_token).await` followed by a match on `DispatchOutcome` / `DispatchError`; existing `info!("Push sent successfully for event {}", event.id)` and per-backend `error!("Failed to send push: {}", err)` log lines preserved verbatim per D-08. The `&trade_pubkey[..16]` truncation logs at lines 108, 112-116, 137 are unchanged.

## Decisions

All 16 implementation decisions D-01 through D-16 from `01-CONTEXT.md` were applied verbatim. Highlights:

- **D-02 / D-14:** Lock-free reads. Services list is built once at startup and stored as `Arc<[Arc<dyn PushService>]>`; never mutated at runtime. Removes the `tokio::sync::Mutex` from the dispatch hot path entirely (CRIT-5 in PITFALLS).
- **D-04:** Iteration protocol replicated byte-for-byte from the prior listener loop — same skip / attempt-first / break-on-success semantics. The new code emits one `error!` per failed backend (preserving today's per-failure cardinality) and is silent when no service supports the platform (matching the prior `if`-skip behaviour).
- **D-05:** `DispatchOutcome` is enum-shaped (one variant today: `Delivered { backend }`) and `DispatchError` distinguishes "no backend matched" from "all matching backends failed" — Phase 2's `/api/notify` handler can map these to different HTTP status codes without a richer error layer later.
- **D-07:** Dispatcher emits zero log lines. The caller (listener today, `/api/notify` tomorrow) owns the log surface so it can attach context like `event.id` or `request_id` without churn inside the dispatcher.
- **D-08:** No log shape change in this phase. The PRIV-01 hash-based `log_pubkey()` helper and the `RUST_LOG=info` deploy flip are bundled into Phase 2 alongside the new endpoint to keep privacy-posture changes atomic with the new external surface.
- **D-09 + D-10:** Bundled into the same edit pass through `src/push/mod.rs` since we were already touching the file. Drops the `.map_err` workaround at the prior `fcm.rs:274` and shrinks the trait surface to the two methods actually called at runtime.
- **D-11:** Anti-CRIT-1 block comment lives above `Filter::new()` — the highest-leverage location for the guard. A future contributor reading the filter sees the explicit ban before they "fix" the dormant `MOSTRO_PUBKEY` validation by applying it as a filter.
- **D-12:** `MOSTRO_PUBKEY` field on `NostrConfig`, the validation in `NostrListener::new`, and `.env.example` are intentionally untouched. A future cleanup milestone may revisit deletion vs `#[allow(dead_code)]`.
- **D-16:** `AppState` is NOT extended. The dispatcher exists, is owned by `main.rs`, and is shared with the listener via `Arc::clone(...)` at startup. Phase 2 wires it into `AppState.dispatcher: Arc<PushDispatcher>` alongside the new endpoint.

## Verification

### Plan-level must_haves (5/5 hold)

1. **`cargo build --release` exits 0** — verified. Build completes in ~95s with 19 preexisting warnings (none in modified files except a benign `field 'backend' is never read` in `dispatcher.rs` — Phase 2 will read it).
2. **No `tokio::sync::Mutex` wraps the push-services list anywhere in `src/`** — verified via `! grep -rE "Arc<Mutex<Vec<(Box|Arc)<dyn PushService>>>>" src/` and `! grep -E "use tokio::sync::Mutex;" src/main.rs src/nostr/listener.rs`.
3. **Listener no longer inlines the iteration loop** — verified: single `dispatcher.dispatch(&registered_token).await` call, no `push_services.lock().await`, no `for service in services.iter()`.
4. **Anti-CRIT-1 block comment present above `Filter::new()`** — contains "DO NOT add .authors(", references NIP-59 ephemeral keys, admin DMs being direct, and cites both `OOS-19` and `CRIT-1`. Zero `.authors(...)` calls in code (the only match is inside the warning comment itself, which is intentional).
5. **Manual smoke test on staging** — DEFERRED to operator. Procedure documented in `01-01-PLAN.md` `<verification>` block item 5. Expected behaviour: a Mostro-daemon Gift Wrap event addressed at a registered `trade_pubkey` produces the same `info!("Push sent successfully for event {}", event.id)` log and reaches the registered device. Operator must fill in PASS / FAIL after Fly.io staging deploy.

### Negative anti-requirement checks (11/11 hold)

| Must-not # | Check | Result |
|------------|-------|--------|
| 1 | No `.authors(...)` calls in `src/nostr/` (other than comment) | PASS |
| 2 | `RegisterResponse` / `RegisterTokenRequest` / `UnregisterTokenRequest` shapes unchanged | PASS — `git diff` shows 0 changes in `src/api/routes.rs` |
| 3 | `AppState` unchanged | PASS — `src/api/routes.rs` not modified |
| 4 | No `log_pubkey` helper, no BLAKE3 references | PASS |
| 5 | `MOSTRO_PUBKEY` config field + listener validation untouched | PASS — `src/config.rs` not modified; `listener.rs:25-32` validation block preserved verbatim |
| 6 | Out-of-scope files unchanged (`src/store/`, `src/api/`, `src/config.rs`, `src/crypto/`, `src/utils/`, `Cargo.toml`, `Cargo.lock`, `deploy-fly.sh`, `fly.toml`) | PASS — `git diff main --name-only` for these paths is empty |
| 7 | No new `#[cfg(test)]` modules or test scaffolding | PASS |
| 8 | No new `tokio::spawn` in listener event handler | PASS |
| 9 | No `Cargo.toml` change | PASS |
| 10 | Dispatcher emits no log lines | PASS — `! grep -qE "info!|warn!|error!|debug!|trace!" src/push/dispatcher.rs` |
| 11 | No `name()` method on `PushService` trait | PASS — backend names live in a parallel `Arc<[&'static str]>` side-table populated by `main.rs` |

### File-list invariant

`git diff --name-only HEAD~1 HEAD` returns exactly:
- `src/main.rs`
- `src/nostr/listener.rs`
- `src/push/dispatcher.rs`
- `src/push/fcm.rs`
- `src/push/mod.rs`
- `src/push/unifiedpush.rs`

Six files. Matches `<files_modified>` in the plan exactly.

## Manual smoke test

**Status: PENDING (operator to fill in)**

Procedure (from `01-01-PLAN.md` `<verification>` item 5):

1. Deploy `feat/fcm-for-p2p-chat` (with commit `a43aa49`) to staging Fly.io.
2. Confirm a known mobile test client is registered (`POST /api/register` with a known `trade_pubkey`).
3. Trigger a Mostro-daemon Gift Wrap event addressed at that `trade_pubkey`.
4. Within ~30s, inspect Fly logs for `Push sent successfully for event ...`.
5. Confirm the test device receives the silent push.

```bash
flyctl logs -a mostro-push-server | grep -E "(Push sent successfully|Failed to send push)"
```

**Pre/post comparison expectation:** identical operator-visible log lines before and after the refactor, identical reconnection-on-error behaviour (5s sleep on clean close, 10s on errors per `src/nostr/listener.rs:42-55`), identical `MOSTRO_PUBKEY` startup validation behaviour.

## Deviations from Plan

**None — plan executed exactly as written.**

Notes on the build verification:

- `cargo clippy --release -- -D warnings` reports preexisting errors in `src/crypto/mod.rs` (out of scope per must-not #6). `cargo build --release` (the gate the plan enforces) passes cleanly.
- One new clippy warning was introduced: `field 'backend' is never read` in `src/push/dispatcher.rs:12`. This is **intentional and reserved**: per D-05 the `DispatchOutcome::Delivered { backend: &'static str }` variant carries the backend identifier so Phase 2's `/api/notify` handler can include it in response logs. Today's listener intentionally ignores it via `Delivered { backend: _ }` per D-08 (no log shape change in Phase 1). The warning is benign and will be resolved when Phase 2 reads the field.
- One verify regex in Task 4 (`! grep -E "Result<\(\), Box<dyn std::error::Error>>" src/push/unifiedpush.rs`) matches preexisting non-trait helpers (`load_endpoints`, `save_endpoints`, `register_endpoint`, `unregister_endpoint`) that the plan explicitly forbids modifying ("Do NOT modify ... `load_endpoints`, `save_endpoints`, the `UnifiedPushEndpoint` struct"). The intent of the verify (D-09 cascade on the trait method) is satisfied: line 131 `send_to_token` has `Box<dyn std::error::Error + Send + Sync>`. No code change made — preserving the helpers honors must-not #6 and D-09's "tighten only" stance on the trait surface.

## Authentication gates

None encountered.

## Phase 2 hand-off

The dispatcher exists at `src/push/dispatcher.rs`; it is **not yet wired into `AppState`**. Phase 2 wires it via `AppState.dispatcher: Arc<PushDispatcher>` together with the new `POST /api/notify` endpoint. The `DispatchError` variants (`NoBackendForPlatform` vs `AllBackendsFailed`) are the seam Phase 2 will use to map dispatch outcomes to HTTP status codes (likely `404` vs `502` if OPEN-1 lands on the differentiated contract; both fold to `202` if it lands on always-`202`).

## Self-Check: PASSED

**Files verified to exist:**

- FOUND: `src/push/dispatcher.rs`
- FOUND: `src/push/mod.rs` (modified)
- FOUND: `src/push/fcm.rs` (modified)
- FOUND: `src/push/unifiedpush.rs` (modified)
- FOUND: `src/main.rs` (modified)
- FOUND: `src/nostr/listener.rs` (modified)

**Commit verified:**

- FOUND: `a43aa49` — `refactor(push): extract PushDispatcher and replace Mutex with Arc<[Arc<dyn>]>`
