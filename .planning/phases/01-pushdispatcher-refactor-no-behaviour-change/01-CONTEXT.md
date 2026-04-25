# Phase 1: PushDispatcher refactor (no behaviour change) - Context

**Gathered:** 2026-04-24
**Status:** Ready for planning

<domain>
## Phase Boundary

Extract the inline push-dispatch loop from `src/nostr/listener.rs:119-135` into a reusable `PushDispatcher` component owned by `main.rs`. Replace the runtime container `Arc<Mutex<Vec<Box<dyn PushService>>>>` with `Arc<[Arc<dyn PushService>]>` (immutable after init, lock-free reads). After the refactor, the existing Mostro-daemon → silent-push flow must produce byte-identical observable behaviour.

This phase is intentionally a **pure structural refactor**. Behaviour change, logging change, new endpoints, rate limiting, and privacy-hardening helpers all belong to later phases.

</domain>

<decisions>
## Implementation Decisions

### Dispatch Component Surface

- **D-01:** New module `src/push/dispatcher.rs` re-exported via `src/push/mod.rs`. Owns the services list and the iteration protocol.
- **D-02:** Dispatcher holds `services: Arc<[Arc<dyn PushService>]>`. The list is built once in `main.rs` and never mutated at runtime — no `Mutex`, no `RwLock` around it.
- **D-03:** Single async method on the dispatcher: `dispatch(&self, token: &RegisteredToken) -> Result<DispatchOutcome, DispatchError>`.
- **D-04:** Iteration protocol replicates the listener's current behaviour exactly: iterate `services`, skip those whose `supports_platform(&token.platform)` is `false`, call `send_to_token(&token.device_token, &token.platform)` on the first matching service, break on first `Ok(())`.
- **D-05:** Return type is **structured enums**, not a bare `Result<(), Box<dyn Error>>`:
  - `DispatchOutcome::Delivered { backend: &'static str }` — the backend that succeeded (`"fcm"` or `"unifiedpush"`).
  - `DispatchError::NoBackendForPlatform` — no service in the list reports `supports_platform = true` for the token's platform.
  - `DispatchError::AllBackendsFailed { errors: Vec<String> }` — at least one matching backend was attempted, all failed; collected error strings (lossy, but stable).
  Rationale: the structured form lets Phase 2's `/api/notify` handler distinguish "no backend" from "backend error" without adding a richer error layer later. Phase 1 callers (the Nostr listener) ignore the distinction and log uniformly.

### Caller / Logging Contract

- **D-06:** **Caller logs**, not the dispatcher. `PushDispatcher::dispatch` returns the outcome; each caller decides what to log and at what level. Phase 1: the listener replaces lines 119-135 with a single call to `dispatcher.dispatch(...)` plus its own `info!` / `error!` lines that include the event id (preserving today's log shape). Phase 2: the future `/api/notify` handler will add `request_id` context the same way.
- **D-07:** **No new log lines added inside the dispatcher.** Keeps the dispatcher predictable and unit-testable.
- **D-08:** **The pubkey-hashing helper (PRIV-01) is NOT introduced in Phase 1.** The lines that get touched by the lift (`listener.rs:108, 112-116, 137` currently log `&trade_pubkey[..16]`) keep their existing prefix-truncation log shape. Phase 2 introduces `log_pubkey()` and migrates these lines together with the new endpoint and the `RUST_LOG=info` deploy flip (PRIV-02). This preserves the "Phase 1 = no observable change" property — a production operator should see the same log lines after Phase 1 ships.

### Trait Surface Hygiene

- **D-09:** **Tighten `PushService::send_to_token` signature** to `Result<(), Box<dyn std::error::Error + Send + Sync>>`. Bundles the MIN-5 fix recorded in PITFALLS into Phase 1 because we are already editing `src/push/mod.rs` and the cascade is mechanical:
  - `src/push/fcm.rs` — `FcmPush::send_to_token` impl
  - `src/push/unifiedpush.rs` — `UnifiedPushService::send_to_token` impl
  - The two blanket `impl PushService for Arc<...>` re-exports in `src/push/mod.rs`
  Drops the existing `.map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })` workarounds (`fcm.rs:222, 274`) where they exist; Phase 2's `tokio::spawn` plans (if OPEN-1 lands on always-202) won't have to reintroduce them.
- **D-10:** **Delete the dead `send_silent_push` method** from the trait, both concrete impls, and both blanket `Arc<>` impls. The method is never called from production code (per CONCERNS.md / PITFALLS reference). Removing it keeps the trait surface focused on what callers actually use.

### Anti-Pattern Guard at the Filter

- **D-11:** **Add an explicit anti-CRIT-1 block comment above `Filter::new()`** in `src/nostr/listener.rs:73-79`. Required content (paraphrase, in English):
  > `// DO NOT add .authors(...) here. Two reasons:`
  > `//  1. Gift Wrap (NIP-59, kind 1059) wraps each event with an EPHEMERAL outer key.`
  > `//     The outer pubkey is never the Mostro daemon — filtering by author would drop everything.`
  > `//  2. Admin DMs in disputes are sent directly user-to-user, NOT through the Mostro daemon.`
  > `//     A mostro_pubkey author filter would silently drop every dispute notification.`
  > `// See PROJECT.md anti-requirement OOS-19 / CRIT-1.`
  This is the highest-leverage place to prevent a future reviewer from "fixing" the dormant `MOSTRO_PUBKEY` validation by applying it as a filter.

### MOSTRO_PUBKEY Config Disposition (OPEN-6 resolution)

- **D-12:** **Leave the dormant config field and listener-startup validation as-is.** The user explicitly chose to keep them out of Phase 1's scope. The `MOSTRO_PUBKEY` field on `NostrConfig` (`src/config.rs:60-72`), the validation in `NostrListener::new` (`src/nostr/listener.rs:25-39`), and the `.env.example` entry remain untouched. The anti-CRIT-1 block comment from D-11 is sufficient protection on its own. A future cleanup milestone may revisit deletion vs `#[allow(dead_code)]`.

### Wiring Changes in main.rs

- **D-13:** `main.rs:46` builds `Vec<Arc<dyn PushService>>` (not `Vec<Box<dyn PushService>>`). Existing `Arc::clone(&fcm_service)` / `Arc::clone(&unifiedpush_service)` calls collapse from `Box::new(Arc::clone(...))` to just `Arc::clone(...) as Arc<dyn PushService>`.
- **D-14:** `main.rs:79` constructs `Arc::new(PushDispatcher::new(push_services))` (not `Arc::new(Mutex::new(push_services))`). The `tokio::sync::Mutex` import (`main.rs:4`) is dropped if no other Mutex remains.
- **D-15:** `NostrListener::new` (`src/nostr/listener.rs:20-40`) accepts `Arc<PushDispatcher>` instead of `Arc<Mutex<Vec<Box<dyn PushService>>>>`. The struct's `push_services` field becomes `dispatcher: Arc<PushDispatcher>`. Same change in the `tokio::sync::Mutex` import (`listener.rs:5`).

### Phase 2 Seam (NOT implemented in Phase 1)

- **D-16:** Phase 1 deliberately does NOT add `dispatcher` to `AppState`. That wiring belongs in Phase 2 alongside the new endpoint. The dispatcher exists, is owned by `main.rs`, and is shared with the listener via `Arc::clone(...)` at startup; that is enough to satisfy DISPATCH-01 / DISPATCH-02 without prejudging Phase 2 design.

### Claude's Discretion

- Naming of the new module file (`src/push/dispatcher.rs`) and the public types (`PushDispatcher`, `DispatchOutcome`, `DispatchError`) is fixed by the decisions above. Internal helper functions are at Claude's discretion.
- Test scaffolding: Phase 1 introduces no new tests. The success criteria are observable via manual smoke-test against the existing relay path; integration tests live in Phase 3 (VERIFY-01/02).
- Commit shape: single commit `refactor(push): extract PushDispatcher and replace Mutex with Arc<[Arc<dyn>]>` is the recommended grain. If the trait-surface hygiene change (D-09 + D-10) is large enough to warrant its own commit on review, splitting into two commits is acceptable.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project / milestone scope (mandatory)

- `.planning/PROJECT.md` — project context, Active requirements for v1.1, Constraints, Anti-requirements (esp. line 51 / line 89 / line 103 about no Mostro author filter)
- `.planning/REQUIREMENTS.md` — DISPATCH-01, DISPATCH-02 are the two requirements assigned to this phase; OPEN-6 listed in Open Decisions
- `.planning/ROADMAP.md` — Phase 1 success criteria (4 items) the planner must satisfy

### Research outputs (mandatory)

- `.planning/research/SUMMARY.md` — § "Suggested Phase Shape" → "Phase 1 — Refactor PushDispatcher"; § "Critical Convergence" rows on `Mutex` removal
- `.planning/research/ARCHITECTURE.md` — § Q1 "Refactor the dispatch ownership" (full reasoning for Option A + B combined); § Q6 "Build order" Phase 1; § "NEW / MODIFIED / UNTOUCHED" tables with file:line references
- `.planning/research/PITFALLS.md` — CRIT-1 (anti-author-filter, drives D-11), CRIT-5 (Mutex contention, drives D-02 + D-14), MIN-5 (Send + Sync trait bound, drives D-09)
- `.planning/research/FEATURES.md` — TS-1 anti-coupling note (single dispatch path used by both producers)

### Codebase analysis (read for current state)

- `.planning/codebase/ARCHITECTURE.md` — § "Push Service Layer" (lines 47-52) and § "Key Abstractions / `PushService` trait" (lines 113-117)
- `.planning/codebase/CONCERNS.md` — § "Mutex<Vec<Box<dyn PushService>>> serializes all delivery" (lines 139-142); § "send_silent_push trait method never invoked"; § "Box<dyn Error> everywhere" (lines 62-66)
- `.planning/codebase/CONVENTIONS.md` — module naming (mod.rs entry, snake_case files), import organization, error-handling patterns (Box<dyn Error[+ Send + Sync]>)

### External / cross-repo (informational, not load-bearing for Phase 1)

- `mobile/docs/plans/CHAT_NOTIFICATIONS_PLAN.md` — Phase 4 of the mobile plan is what this milestone unblocks. Phase 1 itself is server-internal; the mobile plan is informational only.

### Anti-requirements to keep present in mind

- PROJECT.md OOS-19 / PITFALLS CRIT-1 — no `.authors(mostro_pubkey)` filter; D-11 enforces structurally with a comment block.
- PROJECT.md OOS-20 / PITFALLS COMPAT-1 — no incidental refactor of `RegisterResponse` / `RegisterTokenRequest` / `UnregisterTokenRequest` shapes. Phase 1 does not touch `src/api/routes.rs`.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets

- **`Arc<dyn PushService>` blanket impls** at `src/push/mod.rs:25-63` — the existing two `impl PushService for Arc<UnifiedPushService>` / `Arc<FcmPush>` blocks already let `Arc<...>` be used wherever the trait is expected. The Phase 1 wiring change in `main.rs:46-77` collapses from `Box::new(Arc::clone(&svc))` to `Arc::clone(&svc) as Arc<dyn PushService>`. After D-10 (delete `send_silent_push`), each blanket impl loses one method but is otherwise unchanged.
- **`RegisteredToken`** at `src/store/mod.rs:23-28` — value object with `device_token: String`, `platform: Platform`, `registered_at`. The dispatcher consumes this by reference; no new types needed.
- **`Platform` enum** at `src/store/mod.rs:8-21` — passed by reference into `supports_platform` and `send_to_token`. Unchanged.

### Established Patterns

- **`async-trait`** is already in use for `PushService` (`src/push/mod.rs:1`). The dispatcher can be a plain `impl` (no async-trait macro) since it is a concrete type, not a trait.
- **Error type:** Boxed trait objects are the dominant return type. Existing code already uses `Box<dyn std::error::Error + Send + Sync>` in some hot paths (e.g., `src/nostr/listener.rs:57` `connect_and_listen`). D-09 brings the trait in line.
- **Arc-shared state:** `Arc<TokenStore>`, `Arc<RwLock<...>>` patterns are used throughout `main.rs`. `Arc<PushDispatcher>` fits the convention.
- **Logging style:** plain English at `info!`/`warn!`/`error!`/`debug!` with truncated identifiers. Phase 1 inherits this style at the listener boundary; the dispatcher itself emits no log lines (D-07).

### Integration Points

- **`main.rs:46-79`** — the construction site for the services list. After Phase 1: builds `Vec<Arc<dyn PushService>>`, wraps in `Arc::new(PushDispatcher::new(...))`, clones into the listener.
- **`main.rs:82-86`** — `NostrListener::new` call site. New signature accepts `Arc<PushDispatcher>` instead of the `Mutex<Vec<...>>`.
- **`src/nostr/listener.rs:14, 22, 36, 87, 119-135`** — the field, two constructor mentions, the closure capture, and the inline iteration loop. Phase 1 changes the field type, drops the lock, and replaces the loop with a single `dispatcher.dispatch(&registered_token).await` call followed by a `match` that emits the same `info!` "Push sent successfully" / `error!` "Failed to send push" log lines as today.
- **`src/nostr/listener.rs:73-79`** — `Filter::new()` site. D-11 adds a block comment here.
- **`src/push/mod.rs:1-23`** — trait surface. D-09 tightens the bound; D-10 deletes `send_silent_push`.
- **`src/push/fcm.rs:218-305`** and **`src/push/unifiedpush.rs:125-199`** — concrete impls. D-09 cascades; D-10 deletes one method per impl.

### Untouched in Phase 1

- `src/store/`, `src/api/`, `src/config.rs` (except no MOSTRO_PUBKEY change per D-12), `src/crypto/`, `src/utils/`, `Cargo.toml`, `deploy-fly.sh`, `fly.toml`. Any change to these files in Phase 1 is a scope violation.

</code_context>

<specifics>
## Specific Ideas

- The user prefers Phase 1 to remain a structurally-revertible commit ("Phase 1 = no observable behaviour change"). Reflected in D-08 (no log shape change) and D-12 (no MOSTRO_PUBKEY churn).
- The user explicitly wanted the anti-CRIT-1 comment block at the highest-leverage location (the filter), not buried in a config file. Reflected in D-11.
- The user opted to bundle two trait-surface hygiene items (D-09 + D-10) because we're already editing `push/mod.rs`; this rejects "minimum lines changed" for "minimum trips through this file".

</specifics>

<deferred>
## Deferred Ideas

- **Delete or `#[allow(dead_code)]` the `MOSTRO_PUBKEY` config field + listener validation** (D-12). User chose to leave for a future cleanup milestone, not bundle into Phase 1. Recorded in PROJECT.md / REQUIREMENTS.md OPEN-6 already.
- **Hash-based pubkey logging helper** (D-08). PRIV-01 in Phase 2; introduced together with PRIV-02 (`RUST_LOG=info` deploy flip) so the privacy posture changes are bundled with the new endpoint, not split across two phases.
- **Single shared `reqwest::Client` with timeouts** (CONCERNS.md / SUMMARY OPEN bundle). Phase 2 carries this — the listener's existing per-service `reqwest::Client` calls are out of scope here.
- **Spawn-and-bound dispatch with semaphore** (PITFALLS CONC-1, REQUIREMENTS F-01). Phase 2 if OPEN-1 lands on always-202; Phase 1 keeps inline `await` to preserve "no behaviour change".

</deferred>

---

*Phase: 01-pushdispatcher-refactor-no-behaviour-change*
*Context gathered: 2026-04-24*
