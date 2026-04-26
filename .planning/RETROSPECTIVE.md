# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v1.1 — Chat Notifications

**Shipped:** 2026-04-26
**Phases:** 3 | **Plans:** 6 | **Commits:** 44 | **Code delta:** +17,307 / -153 LOC (Rust: +1,617 / -134)

### What Was Built

- `PushDispatcher` extracted with `Arc<[Arc<dyn PushService>]>` lock-free, `Mutex` removed from the dispatch path; Nostr listener flow byte-identical (DISPATCH-01/02).
- `POST /api/notify` endpoint with always-202 contract, UUIDv4 server-side X-Request-Id middleware, bounded `tokio::spawn` via `Arc<Semaphore>(50)`, separate FCM silent payload (apns-priority 5, push-type background), and shared `Arc<reqwest::Client>` with 2s/5s timeouts (NOTIFY-01..04).
- Privacy hardening: salted-BLAKE3 `log_pubkey()` correlator, legacy pubkey-prefix logs migrated, `RUST_LOG=info` flip in `deploy-fly.sh` (PRIV-01..03).
- Dual-keyed rate limiting on `/api/notify` only via hand-rolled `from_fn` middleware over `governor 0.6` (per-IP: Fly-Client-IP > rightmost-XFF > peer_addr; per-pubkey in-handler); 429 byte-identical between paths with `Retry-After` and `x-request-id` (LIMIT-01..06).
- 31 in-process integration tests via `actix_web::test` with `StubPushService` and `governor::FakeRelativeClock` covering 6 TEST-1 scenarios + byte-identical regression of legacy endpoints + anti-DEPLOY-3 (VERIFY-01/02).
- Spanish operator runbook `docs/verification/dispute-chat.md` with anti-CRIT-1 grep one-liner reinforcing that `.authors(mostro_pubkey)` must never be added to the listener filter (VERIFY-03).

### What Worked

- **Research-converged 3-phase shape adopted verbatim.** Three independent research dimensions (Architecture, Features, Pitfalls) agreed on `refactor → endpoint → rate-limit` ordering. Resisting the urge to split PRIV/VERIFY into their own phases avoided shipping intermediate states with regressed privacy posture and saved at least one cycle.
- **Atomic-commit policy on the privacy bundle.** Phase 02 Plan 02 landed all 12 co-dependent decisions (D-05/D-09..D-16, D-20..D-22) in a single commit because intermediate states would have leaked pubkey prefixes, hit FCM unbounded, or run with no salt. Made review easier and the production rollback trivial.
- **Validated anti-RL-2 oracle invariant by construction.** A single `rate_limited_response` helper feeds both 429 paths and `request_id_mw` is outermost so both 429s carry `x-request-id`. Two regression tests (`rate_limited_429_body_byte_identical_per_ip_vs_per_pubkey`, `x_request_id_present_on_both_429_paths`) lock the invariant.
- **License-first dependency review.** Discovered actix-governor was GPL-3.0 across all 21 published versions during context gathering, before plan-phase. Pivoted to a hand-rolled `from_fn` middleware over bare `governor 0.6` (already declared, MIT). Saved a wasted plan cycle.
- **Operator runbook reinforcing code-level anti-requirements.** `docs/verification/dispute-chat.md` ships with a bash grep one-liner an operator runs after every deploy. Catches regressions even if a future PR removes the in-code anti-CRIT-1 comment.

### What Was Inefficient

- **WR-01 surfaced in Phase 03 code review, not in plan-phase.** The middleware ordering bug (request_id_mw must be outermost) was caught by the code review agent rather than during planning. Cost: one extra commit (`6573733`) and a regression test (`x_request_id_present_on_both_429_paths`). Lesson: when a milestone has byte-identical-output invariants, plan-phase should explicitly model the actix-web middleware stack ordering as a sequence diagram, not just list the middlewares.
- **Per-plan commit grain inconsistency between Phase 02 (atomic mega-commit) and Phase 03 (split commits).** Both choices were correct for their context (P2 was bundle-or-leak; P3 was incremental-test-driven), but the rationale should have been documented earlier in the plan-phase artefact, not derived during execution.
- **3 pre-existing source warnings (WR-02/WR-03/IN-02) surfaced during Phase 03 code review** but not in pre-flight `/gsd-scan`. They predate v1.1 (commits 1f848fb 2025-11-12 and 42140c4 2026-01-20). Not a regression, but a hint that `/gsd-scan` should run against the full src/ tree before milestone start, not just newly touched files.

### Patterns Established

- **Operator runbook + code anti-requirement pair** for hard invariants (anti-CRIT-1). Two layers — code comment block + deploy-time grep one-liner — so a single layer regression is caught by the other.
- **`actix_web::test` aliased as `atest`** in test modules to avoid shadowing the `#[test]` built-in attribute. Adopted across all `#[cfg(test)] mod tests` modules in the API layer.
- **`TestAppComponents` factory pair** (`make_app_state` + `build_test_actix_app`) instead of returning `impl Service<actix_http::Request, ...>` — avoids annotating the opaque `actix_http::Request` type without a direct dep on `actix_http`.
- **Constructor-cascade injection of shared `reqwest::Client`** via `Arc<reqwest::Client>` — construct once in `main.rs`, clone via `Arc::clone` to each push-service constructor. Pattern reusable for any future outbound HTTP service.
- **Salted-BLAKE3 truncated keyed-hash correlator** (`log_pubkey()`) — process-local 32-byte salt + BLAKE3 keyed hash + 8-hex truncation. Reusable for any future privacy-safe operator log of high-entropy identifiers.
- **`from_fn` middleware that short-circuits with `BoxBody`** — pattern for inserting per-resource enforcement (rate limit, auth gate) without a custom middleware factory.

### Key Lessons

1. **License audits at context-gathering, not plan-phase.** Catching actix-governor's GPL-3.0 license during `/gsd-discuss-phase` (vs during plan-phase or worse, execution) saved a full plan cycle. For any future milestone that adds a dependency, license verification belongs in the discuss-phase pre-flight.
2. **Byte-identical invariants need explicit ordering models.** Phase 03's middleware-order bug (WR-01) would have been caught at plan-phase if the artefact included a stack-ordering diagram of all middlewares applied to `/api/notify`. Lesson for future phases that touch actix-web middleware composition: model the stack explicitly, name each layer, and assert ordering invariants in the success criteria.
3. **Atomic-commit-or-leak is a real category for privacy bundles.** Phase 02 Plan 02 landed 12 co-dependent decisions in one commit because any intermediate state would leak pubkey prefixes, hit FCM unbounded, or run with no salt. Privacy-bundle rationale should be a first-class commit-grain choice in plan-phase, alongside "atomic per logical change" and "incremental TDD".
4. **`human_needed` UAT items are by design, not tech debt.** Apple/Google edge behaviour and physical-device wake-up cannot be asserted in-process. The audit correctly flagged 3 such items for v1.1 — these belong in milestone close as `acknowledged deferred`, not as planning gaps to fix.

### Cost Observations

- Sessions: not tracked at this granularity yet; instrument in v1.2.
- Phases 1-3 wall-clock execution time (sum of plan durations): 416s + 234s + 359s + 131s + 421s + 739s ≈ 2,300s ≈ 38 minutes of pure execution time across 6 plans.
- Notable: Phase 03 Plan 02 (test suite) took the longest single plan execution (739s / ~12min) — proportional to the 21-test surface and the `RateLimiter<FakeRelativeClock>` 4th-generic-annotation friction.

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Phases | Plans | Key Change |
|-----------|--------|-------|------------|
| v1.1 | 3 | 6 | First GSD-tracked milestone; baseline established for research-converged phase shape and atomic-bundle commit policy on privacy work. |

### Cumulative Quality

| Milestone | Tests | Coverage | Zero-Dep Additions |
|-----------|-------|----------|-------------------|
| v1.1 | 31 (in-process integration) | 17/17 requirements satisfied; 0 audit gaps | 1 (actix-governor avoided in favour of bare `governor`) |

### Top Lessons (Verified Across Milestones)

*Awaits v1.2 and beyond to cross-validate. Tracked candidates from v1.1:*
1. License audits belong in `/gsd-discuss-phase`, not in `/gsd-plan-phase`.
2. Byte-identical-output invariants require explicit middleware-stack ordering models.
3. `human_needed` items are an audit category, not a planning failure.
