---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: milestone
status: executing
last_updated: "2026-04-25T01:16:49.547Z"
progress:
  total_phases: 3
  completed_phases: 1
  total_plans: 1
  completed_plans: 1
  percent: 100
---

# State — Mostro Push Server v1.1 (Chat Notifications)

**Project:** mostro-push-server
**Milestone:** v1.1 — Chat notifications support
**Initialised:** 2026-04-24

---

## Project Reference

**Core value:** The Mostro Mobile client receives a silent push the moment a relevant Nostr event lands on the configured relays — without the push server, Google/Apple, or any operator learning who is trading with whom or what is being said.

**Current focus:** Phase 1 — PushDispatcher refactor (no behaviour change)

**Brownfield context:** Phases 1-3 of `docs/IMPLEMENTATION_PHASES.md` (HTTP API, FCM/UnifiedPush dispatch, deploy) are complete. Phase 4 (token encryption) is deferred to a separate milestone. The current milestone is the **first GSD-tracked milestone** in the project; phase numbering starts at 1.

---

## Current Position

**Phase:** 1 — PushDispatcher refactor (no behaviour change) — COMPLETE
**Plan:** 1 of 1 (complete)
**Status:** Phase 1 complete; awaiting Phase 2 planning
**Progress:** [██████████] 100% Phase 1 (1/1 plans)

```
[████████████████████] 100%  Phase 1: PushDispatcher refactor
[░░░░░░░░░░░░░░░░░░░░]   0%  Phase 2: /api/notify endpoint with privacy hardening
[░░░░░░░░░░░░░░░░░░░░]   0%  Phase 3: Dual-keyed rate limiting and verification harness
```

---

## Performance Metrics

| Metric | Value |
|--------|-------|
| Phases planned | 3 |
| Phases complete | 1 |
| Requirements (v1.1, active) | 17 |
| Requirements mapped to phases | 17 / 17 (100%) |
| Open Design Decisions deferred to plan-phase | 6 (OPEN-1..6) |
| Anti-requirements recorded | 12 (OOS-10..21) |
| Plans complete | 1 |
| Verifications passed | 0 (Phase 1 manual smoke pending operator) |

| Phase / Plan | Duration (s) | Tasks | Files |
|--------------|--------------|-------|-------|
| Phase 01 P01 | 416 | 6 tasks | 6 files |

---

## Accumulated Context

### Decisions

(See `PROJECT.md` "Key Decisions" for the milestone-level decisions. Phase-level decisions are added here as they are taken.)

| When | Phase | Decision | Rationale |
|------|-------|----------|-----------|
| 2026-04-24 | Roadmap | Adopt the research-converged 3-phase shape (refactor → endpoint → rate-limit) instead of splitting PRIV/VERIFY into their own phases. | All three independent research dimensions converged on this ordering; PRIV bundle-alongs (especially the `RUST_LOG=info` flip) cannot be deferred without shipping intermediate states with regressed privacy posture; VERIFY-01/02 cannot exist without Phase 3 wiring. |
| 2026-04-24 | Roadmap | Place VERIFY-03 (dispute-chat runbook) in Phase 2, not Phase 3. | The runbook is the Phase 2-end checkpoint that the Phase 1 refactor and Phase 2 addition did not regress the unchanged listener path. Putting it in Phase 3 would let a regression hide behind the rate-limiting layer's complexity. |

- [Phase 01]: Extracted PushDispatcher with Arc<[Arc<dyn PushService>]> immutable slice; removed Mutex from dispatch path; bundled D-09 (Send + Sync error tightening) and D-10 (delete unused send_silent_push) trait-surface hygiene; added anti-CRIT-1 comment block above Filter::new().

### Open Decisions (resolved during `/gsd-plan-phase`)

These are deliberately NOT pre-decided in the roadmap. The plan for the named phase must resolve them.

| ID | Phase | Decision | Notes |
|----|-------|----------|-------|
| OPEN-1 | 2 | `/api/notify` response contract: differentiated `200/404/429` (per PROJECT.md & mobile plan) vs always-`202` (per PITFALLS CRIT-2/CRIT-6). | Coordinate with Mostro Mobile team owning `CHAT_NOTIFICATIONS_PLAN.md` Phase 4 before implementation. |
| OPEN-2 | 2 | Backend-failure response: silent (`200`/`202`, mobile fetches via Nostr fallback) vs explicit (`502`). | Auto-resolves if OPEN-1 picks always-`202`; otherwise default to silent on Pitfalls grounds. |
| OPEN-3 | 3 | Rate-limit burst sizing — PROJECT.md `~5/min` per-pubkey + `~60/min` per-IP vs PITFALLS RL-3 `30/min burst 10` + `120/min burst 30`. | Needs mobile-team chat traffic-pattern input; default to more permissive if no data. |
| OPEN-4 | 3 | `actix-governor` version pin and exact `KeyExtractor` API surface (0.5 vs 0.6). | Verify against current crate docs. Adding `actix-governor` to `Cargo.toml` requires explicit user approval per global CLAUDE.md. |
| OPEN-5 | 2 | Whether to ship a separate FCM payload builder for `/api/notify` (FCM-1: `apns-priority: 5` + `apns-push-type: background`) or reuse the existing `build_payload_for_token`. | Recommend separate builder; verify against current Apple/Google docs. |
| OPEN-6 | 1 | Whether to delete the dormant `MOSTRO_PUBKEY` config field + listener validation as part of this milestone, or leave for a separate cleanup. | Recommend deletion in Phase 1 with a comment explaining why no `.authors(...)` filter can ever be added (CRIT-1). |

### Todos / Pending Items

- Run `/gsd-plan-phase 1` to decompose Phase 1 (PushDispatcher refactor) into executable plans.
- Mobile-team coordination ticket for OPEN-1 + OPEN-2 (response contract negotiation) needed before Phase 2 starts.
- Mobile-team request for chat traffic profile data (OPEN-3 burst tuning) needed before Phase 3 starts.
- Pre-flight crate-docs verification of `actix-governor` 0.5 vs 0.6 (OPEN-4) before Phase 3 implementation.

### Blockers

None at roadmap stage.

---

## Session Continuity

**Last action:** Phase 1 Plan 1 (`01-01-PLAN.md`) executed and committed (commit `a43aa49` on `feat/fcm-for-p2p-chat`). PushDispatcher extracted, Mutex removed from dispatch path, anti-CRIT-1 comment added above `Filter::new()`, `send_silent_push` deleted, `send_to_token` return type tightened to `Send + Sync`. SUMMARY.md created at `.planning/phases/01-pushdispatcher-refactor-no-behaviour-change/01-01-SUMMARY.md`. Manual smoke test on Fly.io staging is pending operator action.

**Next action:** Operator runs the manual smoke test (procedure in 01-01-SUMMARY.md "Manual smoke test" section); then `/gsd-plan-phase 2` to decompose Phase 2 (`POST /api/notify` endpoint with privacy hardening). Mobile-team coordination on OPEN-1 + OPEN-2 (response contract) needed before Phase 2 implementation begins.

**Files in play:**

- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/PROJECT.md`
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/REQUIREMENTS.md` (Traceability section now populated)
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/ROADMAP.md` (created this session)
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/STATE.md` (this file, created this session)
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/research/SUMMARY.md`
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/research/{ARCHITECTURE,FEATURES,PITFALLS}.md`
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/codebase/{ARCHITECTURE,CONCERNS,CONVENTIONS,INTEGRATIONS,STACK,STRUCTURE,TESTING}.md`

---

*Last updated: 2026-04-24 by `/gsd-roadmapper`*
