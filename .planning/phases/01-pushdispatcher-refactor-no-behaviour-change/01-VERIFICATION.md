---
phase: 01-pushdispatcher-refactor-no-behaviour-change
verified: 2026-04-24T00:00:00Z
status: human_needed
score: 4/5 must-haves verified (1 deferred to operator smoke test)
overrides_applied: 0
human_verification:
  - test: "Manual smoke test on Fly.io staging — Mostro daemon Gift Wrap (kind 1059) addressed at a registered trade_pubkey produces a silent push to the registered device with the same observable behaviour as pre-refactor"
    expected: "info!(\"Push sent successfully for event {}\", event.id) log appears in Fly logs within ~30s of the triggering event; the test device receives a silent push; reconnection-on-error cadence unchanged (5s clean close, 10s on error)"
    why_human: "Requires Fly.io staging deploy, a registered mobile test client, triggering a real Mostro-daemon Gift Wrap event, and observing a silent push on a real device — cannot be verified programmatically from the repo"
---

# Phase 1: PushDispatcher refactor — Verification Report

**Phase Goal:** The push-dispatch path is owned by a single reusable component callable by both the existing Nostr listener and the upcoming HTTP notify handler, with the Mutex-serialised delivery bottleneck removed and the existing Mostro daemon push flow unchanged.

**Verified:** 2026-04-24
**Status:** human_needed (4/5 automatable must-haves VERIFIED; 1 must-have is operator-action smoke test)
**Re-verification:** No — initial verification.

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `cargo build --release` succeeds after the refactor | VERIFIED | Build finished `Finished release profile [optimized] target(s)`; 19 pre-existing warnings, no new errors. One benign `field 'backend' is never read` in `src/push/dispatcher.rs:12` — intentional and reserved for Phase 2 per D-05/D-08 |
| 2 | No `tokio::sync::Mutex` wraps the push-services list anywhere in `src/` | VERIFIED | `grep -rn 'tokio::sync::Mutex' src/` returns no hits; `grep -rnE 'Arc<Mutex<Vec<(Box\|Arc)<dyn PushService>>>>' src/` returns no hits |
| 3 | Listener no longer inlines the iteration loop — single call into `dispatcher.dispatch(...)` | VERIFIED | `src/nostr/listener.rs:121` is the single dispatch call, followed by a match on `DispatchOutcome` / `DispatchError` (lines 122-135). No `services.iter()`, no `.lock().await` |
| 4 | Anti-CRIT-1 block comment present above `Filter::new()` in `listener.rs` | VERIFIED | `src/nostr/listener.rs:72-77` — references NIP-59 ephemeral keys, admin DMs being direct user-to-user, and cites `PROJECT.md OOS-19 / PITFALLS CRIT-1`. Hard ban on `.authors(...)` is explicit |
| 5 | Mostro daemon Gift Wrap → silent push still works after refactor (staging smoke) | HUMAN NEEDED | Operator action — see human_verification section. Procedure documented in `01-01-SUMMARY.md` §"Manual smoke test" |

**Score:** 4/5 automatable truths verified. Item 5 is the documented operator smoke test (consistent with the phase plan that labels this as operator action, not executor action).

### Roadmap Success Criteria Mapping

The ROADMAP Phase 1 section defines 4 Success Criteria. Mapping to verified truths:

| Roadmap SC | Phase Goal Concern | Status | Evidence |
|------------|--------------------|--------|----------|
| SC-1: Mostro daemon kind-1059 event → silent push unchanged | Truth #5 | HUMAN NEEDED | Operator smoke test on staging |
| SC-2: No `tokio::sync::Mutex` on the services list; `Arc<[Arc<dyn PushService>]>` | Truth #2 + artifact `dispatcher.rs` | VERIFIED | `PushDispatcher.services: Arc<[Arc<dyn PushService>]>` at `src/push/dispatcher.rs:7` |
| SC-3: Listener calls into `PushDispatcher` instead of inlining the loop | Truth #3 | VERIFIED | `src/nostr/listener.rs:121` single `dispatch(...)` call |
| SC-4: Dormant `MOSTRO_PUBKEY` either removed OR annotated with anti-`.authors` comment | Truth #4 | VERIFIED | Annotation chosen (D-12). Anti-CRIT-1 block comment at `listener.rs:72-77`; dormant validation preserved at `listener.rs:26-31` |

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/push/dispatcher.rs` | `PushDispatcher`, `DispatchOutcome::Delivered { backend: &'static str }`, `DispatchError::{NoBackendForPlatform, AllBackendsFailed { errors: Vec<String> }}`, hand-written `Display` + `impl Error`, single `async dispatch(&RegisteredToken)`, no log macros | VERIFIED | All present at lines 6-78. `services: Arc<[Arc<dyn PushService>]>` at line 7; parallel `backend_names: Arc<[&'static str]>` at line 8 (coherent reconciliation of D-02 + D-05 "backend name" requirement — avoids a `name()` method on the trait, noted in SUMMARY as must-not #11). No log macros (negative grep returns empty) |
| `src/push/mod.rs` | `pub mod dispatcher`; `pub use dispatcher::{...}`; trait tightened to `+ Send + Sync` bound; `send_silent_push` deleted from trait and both blanket `Arc<>` impls | VERIFIED | Lines 4, 8, 15-23. Both blanket impls (27-55) use `Box<dyn std::error::Error + Send + Sync>` and no `send_silent_push` method |
| `src/push/fcm.rs` | `FcmPush::send_to_token` signature updated; `send_silent_push` impl removed; `.map_err Box<dyn Error>` workaround dropped | VERIFIED | `send_to_token` at line 220 has the `+ Send + Sync` bound; `?` propagates directly through `get_access_token().await?` (line 225) and `response.text().await?` (line 247). `grep -n 'send_silent_push' src/push/fcm.rs` returns empty. No `Box<dyn std::error::Error>` workaround remains |
| `src/push/unifiedpush.rs` | `UnifiedPushService::send_to_token` signature updated; `send_silent_push` impl removed | VERIFIED | `send_to_token` at line 127 has `+ Send + Sync` bound. `grep -n 'send_silent_push' src/push/unifiedpush.rs` returns empty. Persistence helpers (`load_endpoints`, `save_endpoints`, `register_endpoint`, `unregister_endpoint`) intentionally preserved with their existing `Box<dyn std::error::Error>` signature per plan's "Do NOT modify" guard |
| `src/main.rs` | `Vec<Arc<dyn PushService>>` (or tuple form); `Arc::new(PushDispatcher::new(...))`; `tokio::sync::Mutex` import dropped; `AppState` unchanged | VERIFIED | Line 45 builds `Vec<(Arc<dyn PushService>, &'static str)>` (tuple form with backend names — documented coherent reconciliation of D-13/D-14 with D-05's backend-name requirement). Line 78 `Arc::new(PushDispatcher::new(push_services))`. Line 83 passes `dispatcher.clone()` into `NostrListener::new`. `grep -n '^use tokio::sync::Mutex' src/main.rs` returns empty. `AppState` at `src/api/routes.rs:37-39` is unchanged — no `dispatcher` field |
| `src/nostr/listener.rs` | Field type `Arc<PushDispatcher>`; constructor accepts `Arc<PushDispatcher>`; closure captures `dispatcher`; inline loop replaced with single `dispatch(...).await` + match; `tokio::sync::Mutex` import dropped; anti-CRIT-1 block comment above `Filter::new()` | VERIFIED | Field at line 13. Constructor at lines 19-23. Closure capture at line 89. Single `dispatch(&registered_token).await` at line 121 + match at 122-135. No `tokio::sync::Mutex` import. Anti-CRIT-1 block at lines 72-77 citing OOS-19/CRIT-1 |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `src/main.rs` | `PushDispatcher` | `Arc::new(PushDispatcher::new(push_services))` | WIRED | `src/main.rs:78` matches pattern `Arc::new\(PushDispatcher::new` |
| `src/main.rs` | `src/nostr/listener.rs` | `dispatcher.clone()` passed into `NostrListener::new` | WIRED | `src/main.rs:81-85` — `NostrListener::new(config.clone(), dispatcher.clone(), token_store.clone())` |
| `src/nostr/listener.rs` | `src/push/dispatcher.rs` | `self.dispatcher.dispatch(&registered_token).await` | WIRED | Closure at line 89 clones `self.dispatcher`; call at line 121 `dispatcher.dispatch(&registered_token).await` |
| `src/push/mod.rs` | `src/push/dispatcher.rs` | `pub mod dispatcher; pub use dispatcher::{...};` | WIRED | Lines 4 (`pub mod dispatcher;`) and 8 (`pub use dispatcher::{DispatchError, DispatchOutcome, PushDispatcher};`) |

### Data-Flow Trace (Level 4)

N/A — this is a structural refactor with no data/state rendering. The "data" flowing is `RegisteredToken` from `token_store.get(...)` into `dispatcher.dispatch(...)` and then into the concrete `PushService::send_to_token` impls — all pre-existing wiring, verified at the key-link level above.

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `cargo build --release` exits 0 | `cargo build --release` | `Finished release profile [optimized] target(s)` | PASS |
| Dispatcher emits no log lines | `grep -nE 'info!\|warn!\|error!\|debug!\|trace!' src/push/dispatcher.rs` | empty | PASS |
| No `.authors(...)` code in `src/nostr/` | `grep -nE '\.authors\(' src/nostr/` | 1 hit — inside the anti-CRIT-1 block comment (expected) | PASS |
| `send_silent_push` is gone from source | `grep -rn 'send_silent_push' src/` | empty | PASS |
| `tokio::sync::Mutex` fully removed from src/ | `grep -rn 'tokio::sync::Mutex' src/` | empty | PASS |
| `log_pubkey` helper NOT introduced (Phase 2 job) | `grep -rn 'log_pubkey' src/` | empty | PASS |
| No BLAKE3 references | `grep -rn 'BLAKE3' src/` | empty | PASS |
| Out-of-scope files untouched | `git diff bf38f36..HEAD -- src/api/ src/store/ src/crypto/ src/utils/ src/config.rs Cargo.toml Cargo.lock deploy-fly.sh fly.toml` | empty | PASS |
| `AppState` has no `dispatcher` field (D-16) | `grep -n 'dispatcher' src/api/routes.rs` | empty | PASS |
| Runtime end-to-end push delivery | (Requires Fly.io staging deploy) | N/A | SKIP — routed to human verification |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| DISPATCH-01 | 01-01-PLAN | Push dispatch logic is extracted into a single `PushDispatcher` component that owns an immutable `Arc<[Arc<dyn PushService>]>` (no `Mutex`), exposes one async `dispatch(token)` method, and is callable by both the existing Nostr listener and the new HTTP notify handler | SATISFIED | `PushDispatcher` at `src/push/dispatcher.rs:6` with `services: Arc<[Arc<dyn PushService>]>`. Single async `dispatch(&self, token: &RegisteredToken)` method at lines 45-77. "Callable by both" is achieved structurally: dispatcher is owned by `main.rs` (line 78) and passed into the listener via `Arc::clone`; Phase 2 will attach `Arc<PushDispatcher>` to `AppState` without any change to the dispatcher itself |
| DISPATCH-02 | 01-01-PLAN | After the refactor, the existing Nostr-listener → silent-push flow for Mostro daemon events continues to work end-to-end with no observable behaviour change | SATISFIED (pending operator smoke) | Structural preservation verified: iteration protocol byte-for-byte in `dispatcher.rs:49-70` (skip non-matching, attempt-first, break on first Ok) matches the prior listener loop. Log shape preserved per D-08 (`&trade_pubkey[..16]` truncation at listener.rs:110, 115-116, 137; `info!("Push sent successfully for event {}", event.id)` at line 123; per-backend `error!("Failed to send push: {}", err)` at line 132). `MOSTRO_PUBKEY` startup validation unchanged at listener.rs:26-31. End-to-end runtime confirmation is operator action (human_verification) |

Requirements covered: 2/2. No orphaned requirements — ROADMAP.md assigns exactly DISPATCH-01 and DISPATCH-02 to Phase 1, and both are mapped.

### Anti-Patterns Found

None. The scan across all 6 modified files returned no blockers. Two notes:

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `src/push/dispatcher.rs` | 12 | Compiler warning `field 'backend' is never read` on `DispatchOutcome::Delivered { backend }` | NOTE | Intentional per D-05 + D-08 — the `backend` identifier is carried forward for Phase 2's `/api/notify` handler which will log it. Today's listener uses `backend: _` to preserve D-08's "no log shape change". Documented in SUMMARY §"Deviations from Plan" as reserved for Phase 2. |
| `src/nostr/listener.rs` | 72 | `.authors(` string inside a comment | NOTE (false positive) | The only `.authors(` match in `src/nostr/` is inside the anti-CRIT-1 block comment warning against adding `.authors(...)` — this is the intentional guardrail. No actual code calls `.authors(...)`. |

### Git / Commit Grain

| Commit | Message | Notes |
|--------|---------|-------|
| `a43aa49` | `refactor(push): extract PushDispatcher and replace Mutex with Arc<[Arc<dyn>]>` | Refactor commit — 6 source files. No `Co-Authored-By` trailer (project memory requirement honoured) |
| `500732a` | `docs(01-01): complete PushDispatcher refactor plan` | SUMMARY + ROADMAP + REQUIREMENTS + STATE updates. No `Co-Authored-By` trailer |

Two commits, both clean. Commit grain matches plan's recommended shape.

### Anti-Requirement Compliance

All roadmap-level anti-requirements and Phase 1 must-not clauses checked:

| Anti-req | Check | Result |
|----------|-------|--------|
| OOS-19 / CRIT-1 | No `.authors(mostro_pubkey)` in Nostr filter code | PASS — only the warning comment mentions it |
| OOS-20 / COMPAT-1 | `RegisterResponse` / `RegisterTokenRequest` / `UnregisterTokenRequest` shapes unchanged | PASS — `src/api/routes.rs` not in diff |
| D-12 | `MOSTRO_PUBKEY` config field + listener-startup validation preserved verbatim | PASS — `src/config.rs` not in diff; `listener.rs:26-31` preserved |
| D-16 | `AppState` does NOT have a `dispatcher` field | PASS — `AppState` at `src/api/routes.rs:37-39` unchanged |
| Phase 1 scope | `src/store/`, `src/api/`, `src/config.rs`, `src/crypto/`, `src/utils/`, `Cargo.toml`, `Cargo.lock`, `deploy-fly.sh`, `fly.toml` untouched | PASS — `git diff bf38f36..HEAD` on these paths is empty |
| PRIV-01 deferral | No `log_pubkey` helper introduced in Phase 1 | PASS |
| No BLAKE3 | No BLAKE3 references | PASS |
| D-10 | `send_silent_push` deleted from trait and both concrete impls | PASS — `grep -rn 'send_silent_push' src/` empty |
| Commit trailer | No `Co-Authored-By: Claude` trailer | PASS on both commits |
| Dependencies | `Cargo.toml` / `Cargo.lock` unchanged | PASS |

### Human Verification Required

One item deferred to operator action (documented in SUMMARY §"Manual smoke test"):

#### 1. Staging smoke test — Mostro daemon → silent push

**Test:** Deploy commit `a43aa49` to Fly.io staging. Register a known mobile test client via `POST /api/register`. Trigger a Mostro-daemon Gift Wrap (`kind 1059`) event addressed at the registered `trade_pubkey`. Observe Fly logs and the test device.

**Expected:**
- Within ~30s of the triggering event, Fly logs show `Push sent successfully for event <event_id>`
- The test device receives the silent push (Android via FCM or UnifiedPush; iOS via FCM/APNs bridge)
- Reconnection cadence on transient relay errors remains 5s on clean close, 10s on error (matches pre-refactor behaviour at `listener.rs:42-55`)
- `MOSTRO_PUBKEY` startup validation still rejects a misconfigured pubkey on boot

**Why human:** Requires a Fly.io staging deploy, a registered mobile test client, a real Mostro-daemon event, and inspection of a silent push on a physical device. Cannot be simulated from the repo without a mock relay + mock FCM harness (which is Phase 3's VERIFY-01 work, not Phase 1's).

**Command for operator:**
```bash
flyctl logs -a mostro-push-server | grep -E "(Push sent successfully|Failed to send push)"
```

### Gaps Summary

No blocking gaps. All automatable must-haves (4/4) and both requirements (DISPATCH-01, DISPATCH-02) are satisfied. The one outstanding item is an operator-action staging smoke test that is documented in both the plan (`<verification>` block item 5) and the summary (§"Manual smoke test"). The verifier does not block on this per the phase's own definition of operator vs. executor action.

### Coherent Reconciliations (documented deviations that are NOT gaps)

1. **`PushDispatcher::new` signature accepts `Vec<(Arc<dyn PushService>, &'static str)>` instead of plain `Vec<Arc<dyn PushService>>`.** D-05 requires `DispatchOutcome::Delivered { backend: &'static str }` (the backend name), and D-13/D-14 require the services list be built in `main.rs`. Rather than add a `name()` method to `PushService` (which would widen the trait surface, violating D-10's spirit of shrinking it) or hardcode names inside the dispatcher (which would couple dispatcher to concrete backend identities), the executor tagged each service with its backend name at the call site in `main.rs:64, 75` and stored a parallel `Arc<[&'static str]>` inside `PushDispatcher`. This preserves D-02's "no Mutex/RwLock around the list" (both are built once, frozen after). Documented in plan must-not #11 and SUMMARY "Deviations" section. Accepted.

2. **Benign compiler warning `field 'backend' is never read` in `dispatcher.rs:12`.** Phase 1 intentionally ignores the `backend` discriminator in the listener (`backend: _` at `listener.rs:122`) per D-08's "no log shape change" constraint. Phase 2's `/api/notify` handler will read this field to include backend identity in request-id-scoped logs. The warning is reserved and will self-resolve in Phase 2. Non-blocking.

---

*Verified: 2026-04-24*
*Verifier: Claude (gsd-verifier)*
