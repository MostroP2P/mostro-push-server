---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: milestone
status: completed
last_updated: "2026-04-26T00:59:55.131Z"
progress:
  total_phases: 3
  completed_phases: 3
  total_plans: 6
  completed_plans: 6
  percent: 100
---

# State — Mostro Push Server v1.1 (Chat Notifications)

**Project:** mostro-push-server
**Milestone:** v1.1 — Chat notifications support
**Initialised:** 2026-04-24

---

## Project Reference

**Core value:** The Mostro Mobile client receives a silent push the moment a relevant Nostr event lands on the configured relays — without the push server, Google/Apple, or any operator learning who is trading with whom or what is being said.

**Current focus:** Milestone v1.1 SHIPPED 2026-04-26 — no active phase

**Brownfield context:** Phases 1-3 of `docs/IMPLEMENTATION_PHASES.md` (HTTP API, FCM/UnifiedPush dispatch, deploy) are complete. Phase 4 (token encryption) is deferred to a separate milestone. The current milestone is the **first GSD-tracked milestone** in the project; phase numbering starts at 1.

---

## Current Position

Phase: — (milestone shipped 2026-04-26)
Plan: —
**Phase 1:** PushDispatcher refactor (no behaviour change) — COMPLETE (1/1 plans)
**Phase 2:** /api/notify endpoint with privacy hardening — COMPLETE (3/3 plans) — commits `56a1a6d`, `d01dc97`, `ce619fa`
**Phase 3:** Dual-keyed rate limiting and verification harness — COMPLETE (2/2 plans) — commits `c9070a9`, `227a8b5`
**Status:** v1.1 milestone complete (SHIPPED 2026-04-26)
**Progress:** [██████████] 100%

```text
[████████████████████] 100%  Phase 1: PushDispatcher refactor (1/1 plans)
[████████████████████] 100%  Phase 2: /api/notify endpoint with privacy hardening (3/3 plans)
[████████████████████] 100%  Phase 3: Dual-keyed rate limiting and verification harness (2/2 plans)
```

---

## Performance Metrics

| Metric | Value |
|--------|-------|
| Phases planned | 3 |
| Phases complete | 3 |
| Requirements (v1.1, active) | 17 |
| Requirements mapped to phases | 17 / 17 (100%) |
| Open Design Decisions deferred to plan-phase | 6 (OPEN-1..6, all resolved) |
| Anti-requirements recorded | 12 (OOS-10..21) |
| Plans complete | 6 |
| Requirements closed | 17 / 17 (DISPATCH-01..02, NOTIFY-01..04, PRIV-01..03, LIMIT-01..06, VERIFY-01..03) |
| Verifications passed | 3 source-level (Phase 1, 2, 3); device-delivery smoke is `human_needed` per design (Apple/Google edge behaviour cannot be asserted in-process). |

| Phase / Plan | Duration (s) | Tasks | Files |
|--------------|--------------|-------|-------|
| Phase 01 P01 | 416 | 6 tasks | 6 files |
| Phase 02 P01 | 234 | 3 tasks | 3 files |
| Phase 02 P02 | 359 | 8 tasks | 12 files |
| Phase 02 P03 | 131 | 1 task  | 1 file  |
| Phase 03 P01 | 421 | 3 tasks | 6 files |
| Phase 03 P02 | 739 | 4 tasks | 5 files |

## Accumulated Context

### Decisions

(See `PROJECT.md` "Key Decisions" for the milestone-level decisions. Phase-level decisions are added here as they are taken.)

| When | Phase | Decision | Rationale |
|------|-------|----------|-----------|
| 2026-04-24 | Roadmap | Adopt the research-converged 3-phase shape (refactor → endpoint → rate-limit) instead of splitting PRIV/VERIFY into their own phases. | All three independent research dimensions converged on this ordering; PRIV bundle-alongs (especially the `RUST_LOG=info` flip) cannot be deferred without shipping intermediate states with regressed privacy posture; VERIFY-01/02 cannot exist without Phase 3 wiring. |
| 2026-04-24 | Roadmap | Place VERIFY-03 (dispute-chat runbook) in Phase 2, not Phase 3. | The runbook is the Phase 2-end checkpoint that the Phase 1 refactor and Phase 2 addition did not regress the unchanged listener path. Putting it in Phase 3 would let a regression hide behind the rate-limiting layer's complexity. |

- [Phase 01]: Extracted PushDispatcher with Arc<[Arc<dyn PushService>]> immutable slice; removed Mutex from dispatch path; bundled D-09 (Send + Sync error tightening) and D-10 (delete unused send_silent_push) trait-surface hygiene; added anti-CRIT-1 comment block above Filter::new().
- Phase 02 Plan 01: Constructed shared Arc<reqwest::Client> with timeouts (connect=2s, total=5s, pool_idle=90s) per D-07/D-08; FcmPush::new and UnifiedPushService::new now take Arc<reqwest::Client> as a second argument. No behavioural change to either dispatch path.
- Phase 02 Plan 02: Shipped POST /api/notify endpoint with privacy hardening bundle (D-05/D-09/D-10/D-11/D-12/D-13/D-14/D-15/D-16/D-20/D-21/D-22) in atomic commit d01dc97. always-202 contract, salted-BLAKE3 log_pubkey, UUIDv4 X-Request-Id middleware scoped to /notify resource, separate FCM silent payload (apns-priority 5, apns-push-type background), bounded tokio::spawn via Arc<Semaphore>(50), RUST_LOG=info flip. Phase 1 listener path byte-identical.
- Phase 02 Plan 03: shipped docs/verification/dispute-chat.md operator runbook for VERIFY-03 (D-17, D-18) — Spanish prose, four sections, anti-CRIT-1 grep one-liner. Plan 02-03 is doc-only; src/nostr/listener.rs byte-identical.
- Phase 03 Plan 01: hand-rolled per_ip_rate_limit_mw over governor::DefaultKeyedRateLimiter<IpAddr> (actix-governor rejected, GPL-3.0 incompatible with project MIT)
- Phase 03 Plan 01: per-pubkey check wired in notify_token between log_pk emission and semaphore acquire (D-12); byte-identical 429 via shared rate_limited_response (D-13)
- actix_web::test aliased as atest in test modules to avoid shadowing #[test] stdlib attribute
- RateLimiter<FakeRelativeClock> requires explicit 4th generic NoOpMiddleware<<FakeRelativeClock as Clock>::Instant> due to QuantaInstant/Nanos mismatch under quanta feature
- make_test_app() redesigned as TestAppComponents factory pair to avoid annotating actix_http::Request without direct dep

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

All milestone-level pending items closed at ship time (2026-04-26). Remaining `human_needed` items live in the per-phase VERIFICATION reports and the `Deferred Items` table below.

### Blockers

None — milestone shipped.

---

## Session Continuity

**Last action:** Milestone v1.1 SHIPPED on 2026-04-26 with all three phases executed. Phase 03 Plan 02 closed VERIFY-01 + VERIFY-02 (commit `227a8b5`). Final wiring includes the dual-keyed rate limiter (per-pubkey 30/min burst 10, per-IP 120/min burst 30, byte-identical 429 with `Retry-After`), the in-process integration suite (33 tests covering all 6 mandatory TEST-1 scenarios plus regressions for `/api/health` 1000-burst, `X-Request-Id`, 429 byte-equality, and `retain_recent` plumbing), and the hand-rolled `from_fn` middleware over `governor::DefaultKeyedRateLimiter<IpAddr>` (actix-governor rejected as GPL-3.0).

**Next action:** Open the next milestone via `/gsd-new-milestone` when scope is defined. Operator-side device-delivery smoke for Phase 1 + 2 + 3 remains `human_needed` per design (Apple/Google edge behaviour cannot be asserted in-process); see the `Deferred Items` table below.

All milestone commits: Phase 01 (`56a1a6d` superseded by structural refactor commits), Phase 02 (`56a1a6d`, `d01dc97`, `ce619fa`), Phase 03 (`c9070a9`, `227a8b5`).

**Files in play:**

- `.planning/PROJECT.md`
- `.planning/REQUIREMENTS.md` (Traceability section now populated)
- `.planning/ROADMAP.md` (created this session)
- `.planning/STATE.md` (this file, created this session)
- `.planning/research/SUMMARY.md`
- `.planning/research/{ARCHITECTURE,FEATURES,PITFALLS}.md`
- `.planning/codebase/{ARCHITECTURE,CONCERNS,CONVENTIONS,INTEGRATIONS,STACK,STRUCTURE,TESTING}.md`

---

## Deferred Items

Items acknowledged and deferred at milestone close on 2026-04-26:

| Category | Item | Status |
|----------|------|--------|
| uat_gap | Phase 02 — 02-HUMAN-UAT.md (7 pending operator scenarios: iOS/Android device wake on FCM silent push, dispute-chat runbook walkthrough, PRIV audit on staging logs) | partial |
| verification_gap | Phase 01 — 01-VERIFICATION.md (DISPATCH-02 operator smoke on Fly.io staging) | human_needed |
| verification_gap | Phase 02 — 02-VERIFICATION.md (device-delivery scenarios require real APNs/FCM credentials) | human_needed |

These items are `human_needed` by design — Apple/Google edge behaviour and physical-device wake-up cannot be asserted from in-process tests. Operator UAT happens post-tag during staging rollout.

---

*Last updated: 2026-04-26 by /gsd-execute-phase 03-02 — Phase 03 Plan 02 complete (commit `227a8b5`).*

**Planned Phase:** 03 (dual-keyed-rate-limiting-and-verification-harness) — 2 plans — 2026-04-25T23:38:11.647Z
**Executed Plans:** 02-01 (`56a1a6d`), 02-02 (`d01dc97`), 02-03 (`ce619fa`), 03-01 (`c9070a9`), 03-02 (`227a8b5`, 2026-04-26T00:08:58Z)
**Phase 03 Complete:** VERIFY-01 + VERIFY-02 closed. 30 tests passing. Milestone v1.1 all plans executed.
