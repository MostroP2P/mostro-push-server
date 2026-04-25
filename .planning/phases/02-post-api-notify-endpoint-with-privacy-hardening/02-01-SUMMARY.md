---
phase: 02-post-api-notify-endpoint-with-privacy-hardening
plan: 01
subsystem: push
tags: [rust, reqwest, hygiene, push, foundation, timeouts]

requires:
  - phase: 01-pushdispatcher-refactor-no-behaviour-change
    provides: PushDispatcher trait + Arc-shared push services topology, untouched in this plan
provides:
  - Single shared Arc<reqwest::Client> with explicit outbound timeouts (connect 2s, total 5s, pool idle 90s)
  - FcmPush::new and UnifiedPushService::new now take Arc<reqwest::Client> as their second argument
  - Resolution of CONCERNS.md "reqwest::Client::new() per service" item
affects:
  - 02-02 (POST /api/notify endpoint) — Arc<http_client> is now in scope at main.rs for any future construction site
  - Outbound dispatch path for both FCM and UnifiedPush

tech-stack:
  added: []
  patterns:
    - "Constructor-cascade injection of shared reqwest::Client via Arc<reqwest::Client>"

key-files:
  created: []
  modified:
    - src/main.rs
    - src/push/fcm.rs
    - src/push/unifiedpush.rs

key-decisions:
  - "D-07: shared reqwest::Client built once at startup with connect_timeout=2s, timeout=5s, pool_idle_timeout=Some(90s)"
  - "D-08: constructor breaking change for FcmPush::new and UnifiedPushService::new is acceptable — no external consumers exist outside main.rs"

patterns-established:
  - "Shared HTTP client injection: construct once in main.rs, wrap in Arc<reqwest::Client>, pass via Arc::clone(&http_client) to each service constructor"

requirements-completed: []

duration: 4min
completed: 2026-04-25
---

# Phase 2 Plan 1: Shared reqwest Client with Timeouts Summary

**Constructed a single Arc<reqwest::Client> at startup with explicit connect/total/pool-idle timeouts and cascaded the constructor signature change through FcmPush::new and UnifiedPushService::new — outbound calls to FCM and UnifiedPush are now bounded so a hung remote endpoint cannot saturate tokio worker threads under sustained load.**

## Performance

- **Duration:** ~4 min (234s wall-clock)
- **Started:** 2026-04-25T18:17:25Z
- **Completed:** 2026-04-25T18:21:19Z
- **Tasks:** 3 of 3 completed
- **Files modified:** 3 (src/main.rs, src/push/fcm.rs, src/push/unifiedpush.rs)

## Accomplishments

- Constructed a single shared `Arc<reqwest::Client>` in `src/main.rs` with `connect_timeout=Duration::from_secs(2)`, `timeout=Duration::from_secs(5)`, `pool_idle_timeout=Some(Duration::from_secs(90))` — bounds outbound HTTP traffic per Phase 2 D-07.
- Changed `FcmPush::new(config)` to `FcmPush::new(config, client: Arc<reqwest::Client>)`; field `client: Client` became `client: Arc<reqwest::Client>`. Internal `self.client.post(...)` call sites unchanged because `Arc<Client>` derefs to `Client`.
- Changed `UnifiedPushService::new(config)` to `UnifiedPushService::new(config, client: Arc<reqwest::Client>)`; same field type change. Persistence helpers (`load_endpoints`, `save_endpoints`, `register_endpoint`, `unregister_endpoint`) and the `PushService` trait impl untouched.
- Plan 1 commit ships zero behavioural change to either dispatch path; the existing Mostro daemon → silent push flow remains byte-identical (Phase 1 invariants `src/nostr/listener.rs`, `src/push/dispatcher.rs`, `src/push/mod.rs` are byte-for-byte unchanged).

## Task Commits

The plan's three tasks are intentionally bundled into a single atomic commit because they cross-depend at the type level — committing any subset alone would leave the tree in a non-compiling state (the constructor signature change in `fcm.rs` requires the new call site in `main.rs`, and vice-versa). The plan's `<verification>` section specifies this single commit message verbatim.

1. **Task 1: Update FcmPush constructor to accept Arc<reqwest::Client>** — bundled into `56a1a6d`
2. **Task 2: Update UnifiedPushService constructor to accept Arc<reqwest::Client>** — bundled into `56a1a6d`
3. **Task 3: Wire shared reqwest::Client in main.rs and pass to constructors** — bundled into `56a1a6d`

**Plan commit:** `56a1a6d feat(push): add shared reqwest Client with timeouts`

## Files Created/Modified

- `src/main.rs` (+12 / -2 effective): added `use std::time::Duration;`, constructed `Arc<reqwest::Client>` block before push-service instantiation, updated both `UnifiedPushService::new` and `FcmPush::new` call sites to pass `Arc::clone(&http_client)`.
- `src/push/fcm.rs` (+3 / -3 effective, plus a one-byte trailing-whitespace cleanup on line 54): field `client: Client` → `client: Arc<reqwest::Client>`; constructor signature `(config: Config)` → `(config: Config, client: Arc<reqwest::Client>)`; `Self { client: Client::new(), ... }` → `Self { client, ... }`.
- `src/push/unifiedpush.rs` (+3 / -2): added `use std::sync::Arc;`; field type and constructor signature changes mirror `fcm.rs`.

## Decisions Made

None — plan executed exactly as written. Followed D-07 and D-08 verbatim from `02-CONTEXT.md`. The only minor implementation choice was preserving the `Arc<reqwest::Client>` literal type spelling (rather than `Arc<Client>` which would be valid Rust but would not satisfy the plan's literal grep acceptance criteria).

## Deviations from Plan

None — plan executed exactly as written.

## Verification Results

### Plan-Level Gates (all passed)

| Gate | Result |
|------|--------|
| `cargo build --release` exits 0 | PASS (`Finished release profile [optimized] target(s) in 20.41s`) |
| `cargo test --release` exits 0 | PASS (7 / 7 unit tests passed in `crypto::tests`) |
| `git diff --name-only HEAD~1 HEAD` = exactly 3 files | PASS (`src/main.rs`, `src/push/fcm.rs`, `src/push/unifiedpush.rs`) |
| `src/nostr/listener.rs` byte-identical | PASS (0-byte diff against HEAD~1) |
| `src/push/dispatcher.rs` byte-identical | PASS (0-byte diff against HEAD~1) |
| `src/push/mod.rs` byte-identical | PASS (0-byte diff against HEAD~1) |
| `src/api/routes.rs` byte-identical (COMPAT-1) | PASS (0-byte diff against HEAD~1) |
| `Cargo.toml` byte-identical | PASS (0-byte diff against HEAD~1) |
| `deploy-fly.sh` byte-identical (RUST_LOG flip lives in Plan 02) | PASS (0-byte diff against HEAD~1) |

### Task-Level Acceptance Criteria

**Task 1 (`src/push/fcm.rs`):**
- `pub fn new(config: Config, client: Arc<reqwest::Client>) -> Self` — present at line 51 (1 match)
- `client: Arc<reqwest::Client>,` field — present at line 44 (1 match)
- `client: Client::new()` — 0 matches
- `client: Client,` (legacy) — 0 matches
- `fn build_payload_for_token` — still present at line 168 (untouched per D-05 invariant)
- `fn send_to_token` — still present at line 220 (untouched in this plan)

**Task 2 (`src/push/unifiedpush.rs`):**
- `pub fn new(config: Config, client: Arc<reqwest::Client>) -> Self` — present at line 30 (1 match)
- `client: Arc<reqwest::Client>,` field — present at line 24 (1 match)
- `use std::sync::Arc;` — added at line 7
- `client: Client::new()` — 0 matches
- `fn load_endpoints` / `fn save_endpoints` / `pub struct UnifiedPushEndpoint` — all unchanged

**Task 3 (`src/main.rs`):**
- `use std::time::Duration;` — added at line 4
- `reqwest::Client::builder()` — line 49 (1 match)
- `.connect_timeout(Duration::from_secs(2))` — line 50 (1 match)
- `.timeout(Duration::from_secs(5))` — line 51 (1 match)
- `.pool_idle_timeout(Some(Duration::from_secs(90)))` — line 52 (1 match)
- `UnifiedPushService::new(config.clone(), Arc::clone(&http_client))` — line 61 (1 match)
- `FcmPush::new(config.clone(), Arc::clone(&http_client))` — line 71 (1 match)

### Manual Smoke Status

**PENDING** — operator action required after Fly.io staging deploy.

Recommended smoke procedure (from plan-level verification step 7):
- Re-run the dispute-chat verification from Phase 1 `01-01-SUMMARY.md` (publish a `kind 1059` Gift Wrap addressed at a registered `trade_pubkey` from a second Nostr client, confirm registered device receives push, confirm `flyctl logs | grep "Push sent successfully for event"`).
- Expected: byte-identical observable behaviour vs. pre-Plan-1.
- If a registered device stops receiving Mostro daemon events after this plan ships, the timeouts may be too tight: revisit `Duration::from_secs(5)` and consider relaxing to 10s. Such a follow-up would be a single-line tuning change.

## Threat Mitigations Applied

Per the plan's `<threat_model>`:
- **T-02-07 (D — DoS via outbound hang):** mitigated. All three timeout setters present in `src/main.rs` with the exact values from D-07.
- **T-02-CRIT-5-CONCERNS (D — unbounded per-service Clients):** mitigated. Two independent `Client::new()` allocations replaced by one shared `Arc<reqwest::Client>`. Pool footprint is now a single bounded pool.
- **T-02-PHASE-1-REGRESSION (T/R — observable-behaviour drift):** verified. Phase 1 listener path files (`src/nostr/listener.rs`, `src/push/dispatcher.rs`, `src/push/mod.rs`) and the existing endpoint files (`src/api/routes.rs`) all show 0-byte diffs against HEAD~1.

## Hand-off to Plan 02

`Arc<reqwest::Client>` is now bound to `http_client` in `src/main.rs` immediately after the token-store cleanup-task initialization (around line 49). Plan 02 can `Arc::clone(&http_client)` for any future constructor that needs an outbound HTTP client without reconstructing one. No further wiring needed for the shared-client foundation.

## Self-Check: PASSED

- `src/main.rs` — FOUND (modified)
- `src/push/fcm.rs` — FOUND (modified)
- `src/push/unifiedpush.rs` — FOUND (modified)
- Commit `56a1a6d` — FOUND in `git log --oneline --all`
- 3 files changed in commit, matching the plan's scope-discipline gate exactly.
