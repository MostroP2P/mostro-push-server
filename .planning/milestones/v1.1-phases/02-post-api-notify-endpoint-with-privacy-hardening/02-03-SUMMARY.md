---
phase: 02-post-api-notify-endpoint-with-privacy-hardening
plan: 03
subsystem: docs
tags: [docs, runbook, verification, dispute-chat, anti-crit-1, spanish]

requires:
  - phase: 01-pushdispatcher-refactor-no-behaviour-change
    provides: anti-CRIT-1 comment block above Filter::new() in src/nostr/listener.rs (D-11)
  - phase: 02-post-api-notify-endpoint-with-privacy-hardening
    plan: 01
    provides: byte-identical listener path under shared reqwest client
provides:
  - docs/verification/dispute-chat.md — Spanish operator runbook reinforcing anti-CRIT-1 at the operator-procedure level
  - Bash grep one-liner an operator runs after every deploy to confirm no .authors(mostro_pubkey) filter has crept into src/nostr/listener.rs
affects:
  - VERIFY-03 — sole deliverable for this requirement (manual runbook per D-18)
  - Phase 3 VERIFY-01 — the runbook is the manual gold standard the in-process integration test harness must agree with for the dispute-chat code path

tech-stack:
  added: []
  patterns:
    - "Operator runbook in Spanish (per global CLAUDE.md) reinforcing repository-level anti-requirements at the deploy-checklist layer"

key-files:
  created:
    - docs/verification/dispute-chat.md
  modified: []

key-decisions:
  - "D-17: docs/verification/dispute-chat.md is the single deliverable for VERIFY-03; four sections — registrar pubkey via /api/register, publicar kind 1059 desde un cliente Nostr secundario (NO el daemon), verificar info!(\"Push sent successfully for event ...\") + device push, anti-CRIT-1 grep check"
  - "D-18: No test code in Phase 2 for the dispute-chat path; manual runbook only — Apple/FCM delivery decisions cannot be unit-tested"
  - "D-19 (commit grain): standalone third commit in Phase 2, message literal 'docs: add dispute chat verification runbook' per plan <verification>"

patterns-established:
  - "Doc-only plans commit through the same `gsd-execute-phase` pipeline as code plans, with substance gates (line/word count, keyword anchors, anti-pattern absence) replacing build/test gates"
  - "Anti-requirement reinforcement at multiple layers — code (Phase 1 D-11 comment block), planning artifacts (PROJECT.md OOS-19, RESEARCH.md PITFALLS CRIT-1), operator runbook (this plan) — so a single layer regression is caught by the others"

requirements-completed:
  - VERIFY-03

duration: 2m11s
completed: 2026-04-25
---

# Phase 2 Plan 3: Dispute Chat Verification Runbook Summary

**Shipped `docs/verification/dispute-chat.md` — a 203-line, 1076-word Spanish operator runbook documenting the four-step manual procedure that an operator runs after every Phase 2-onward deploy to confirm admin DMs (sent directly user-to-user, NOT through the Mostro daemon) still reach registered devices as silent pushes via the unmodified Nostr-listener path; reinforces anti-CRIT-1 with both the prose explanation and the bash grep one-liner that fails fast if `.authors(mostro_pubkey)` ever creeps into `src/nostr/listener.rs::Filter::new()`.**

## Performance

- **Duration:** ~2m11s (131s wall-clock)
- **Started:** 2026-04-25T18:38:30Z
- **Completed:** 2026-04-25T18:40:41Z
- **Tasks:** 1 of 1 completed
- **Files created:** 1 (`docs/verification/dispute-chat.md`)
- **Files modified:** 0

## Accomplishments

- Created `docs/verification/` directory and added `dispute-chat.md` (203 lines, 1076 words, Spanish prose, no emojis).
- Documented the four mandatory sections from D-17:
  1. **Registrar la pubkey de prueba** via `POST /api/register` (curl example with expected `200 OK` body).
  2. **Publicar un evento `kind 1059`** from a second Nostr client (NIP-59 Gift Wrap addressed to the registered `trade_pubkey`); explicitly stipulates the publisher is NOT the Mostro daemon.
  3. **Verificar la entrega del push silencioso** by tailing `flyctl logs` and grepping for `Push sent successfully for event` (the literal log line emitted by `src/nostr/listener.rs:123`); cross-checked by device-side handler observation (FCM `didReceiveRemoteNotification` / `FirebaseMessagingService.onMessageReceived`, UnifiedPush distributor receiver).
  4. **Verificación anti-CRIT-1** via `grep -n '\.authors(' src/nostr/listener.rs` (expected output: exactly one match — the Phase 1 D-11 comment block) plus the exit-status variant `if grep -nE '^\s*[^/].*\.authors\(' src/nostr/listener.rs; then echo "FAIL ..."; exit 1; fi`.
- Added a "Por qué este runbook existe" prose section explaining the anti-requirement to future contributors: admin DMs are direct user-to-user, NIP-59 Gift Wrap uses an ephemeral outer key (so an `authors` filter is structurally impossible even if desired), and the restriction is documented at three layers (PROJECT.md OOS-19, the listener code comment, this runbook).
- Added Prerrequisitos, Limpieza (`POST /api/unregister`), Frecuencia recomendada, and Referencias sections beyond the four mandatory steps to make the procedure executable end-to-end without reading other documents.
- Followed all global + project CLAUDE.md rules: Spanish prose for the runbook (per global rule on operator runbooks), no emojis anywhere in the file or commit message, no Co-Authored-By trailer (per project memory).

## Task Commits

1. **Task 1: Create `docs/verification/dispute-chat.md` runbook** — committed as `ce619fa`.

**Plan commit:** `ce619fa docs: add dispute chat verification runbook`

## Files Created/Modified

- **`docs/verification/dispute-chat.md`** (new, 203 lines, 1076 words): Spanish operator runbook with four-step procedure, prose explanation of the anti-requirement, prerequisites, cleanup, frequency guidance, references.

## Decisions Made

None — plan executed essentially as written. The plan provided the verbatim runbook content as a fenced block.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking issue] `POST /api/unregister` literal missing from prose**

- **Found during:** Plan-level acceptance-criteria verification (line 374 of `02-03-PLAN.md`: `grep -nE 'POST /api/unregister' docs/verification/dispute-chat.md` must return ≥ 1 match).
- **Issue:** As initially written from the plan's verbatim block, the Limpieza section mentioned only the URL `https://...fly.dev/api/unregister` inside the curl command, not the literal phrase `POST /api/unregister` in the prose. The grep returned 0 matches, failing acceptance criterion.
- **Fix:** Added a 5-word prose insertion in the Limpieza section header sentence: "elimina el token de prueba mediante el endpoint `POST /api/unregister` para evitar...". Symmetric to how Paso 1 already mentions "POST /api/register" in its header sentence (line 59).
- **Files modified:** `docs/verification/dispute-chat.md` (1 line of prose, +1 line net).
- **Commit:** `ce619fa` (the single plan commit; the fix landed before staging).

The plan's verbatim Spanish block at lines 143-346 was otherwise reproduced as-is; this 5-word prose insertion was the only deviation.

## Verification Results

### Plan-Level Gates (all passed)

| Gate | Required | Actual | Result |
|------|----------|--------|--------|
| `test -f docs/verification/dispute-chat.md` | exists | exists | PASS |
| `git diff --name-only HEAD~1 HEAD` | exactly `docs/verification/dispute-chat.md` | exactly `docs/verification/dispute-chat.md` | PASS |
| `wc -l docs/verification/dispute-chat.md` | ≥ 50 | 203 | PASS |
| `wc -w docs/verification/dispute-chat.md` | ≥ 500 | 1076 | PASS |
| Spanish keywords (extended set) `(verificación\|disputa\|administrador\|silencioso\|escucha\|daemon\|relay\|prerrequisitos)` | ≥ 4 | 27 | PASS |
| `grep -cE 'CRIT-1' docs/verification/dispute-chat.md` | ≥ 2 | 6 | PASS |
| `grep -cE '\.authors\(' docs/verification/dispute-chat.md` | ≥ 2 | 6 | PASS |
| Bash grep one-liner with `^\s*[^/]` present verbatim | yes | yes (line 160) | PASS |
| `! grep -E '^\s*//' docs/verification/dispute-chat.md` (no Rust-style code comments) | 0 | 0 | PASS |
| `! grep -E 'curl.*POST.*api/notify' docs/verification/dispute-chat.md` (no /api/notify smoke step) | 0 | 0 | PASS |
| Approximate emoji UTF-8 sequences | 0 | 0 | PASS |

### Task-Level Acceptance Criteria

All passed:

- `test -f docs/verification/dispute-chat.md` — file exists.
- `wc -l docs/verification/dispute-chat.md` returns 203 (plan requires ≥ 50).
- `grep -cE 'kind 1059' docs/verification/dispute-chat.md` returns 5 (plan requires ≥ 2).
- `grep -cE '\.authors\(' docs/verification/dispute-chat.md` returns 6 (plan requires ≥ 2).
- `grep -cE 'CRIT-1' docs/verification/dispute-chat.md` returns 6 (plan requires ≥ 2).
- `grep -cE 'OOS-19' docs/verification/dispute-chat.md` returns 2 (plan requires ≥ 1).
- `grep -nE 'POST /api/register' docs/verification/dispute-chat.md` returns 1 match (plan requires ≥ 1).
- `grep -nE 'POST /api/unregister' docs/verification/dispute-chat.md` returns 1 match (plan requires ≥ 1) — secured by the deviation fix above.
- `grep -nE 'flyctl logs' docs/verification/dispute-chat.md` returns 1 match (plan requires ≥ 1).
- `grep -nE 'Push sent successfully for event' docs/verification/dispute-chat.md` returns 3 matches (plan requires ≥ 1).
- `grep -nE 'NIP-59' docs/verification/dispute-chat.md` returns 4 matches (plan requires ≥ 1).
- `grep -nE 'usuario-a-usuario|usuario a usuario' docs/verification/dispute-chat.md` returns 2 matches (plan requires ≥ 1).
- Approximate emoji 4-byte UTF-8 / pictographic block check returns 0 (plan requires 0).
- Spanish keyword anchor `grep -cE '(verificación|disputa|administrador|silenciosos)'` returns 10 (plan requires ≥ 4).
- `! grep -nE '^\s*//' docs/verification/dispute-chat.md` returns 0 (no Rust-style code comments leaked into prose).
- `! grep -nE 'curl.*POST.*api/notify' docs/verification/dispute-chat.md` returns 0 (no /api/notify smoke step — runbook covers listener path only, per plan-level boundary with Plan 02).

### Manual Walkthrough Status

**PENDING** — a Spanish-reading operator should skim the four-section structure (Por qué / Prerrequisitos / Procedimiento / Limpieza) and confirm each step is executable as written. Recommended for the operator running the Phase 2 staging deploy that consumes Plans 02-01, 02-02, and 02-03 together.

## Threat Mitigations Applied

Per the plan's `<threat_model>`:

- **T-02-10 (T — anti-CRIT-1 regression on src/nostr/listener.rs Filter::new()):** mitigated. Step 4 of the runbook gives the operator both an inspection grep (`grep -n '\.authors(' src/nostr/listener.rs` — expected 1 match, the Phase 1 D-11 comment block) and an exit-status grep (`if grep -nE '^\s*[^/].*\.authors\( ...; then ... exit 1`) that fails the deploy check if a non-comment `.authors(` call has been added. Reinforced by a paragraph of Spanish prose in "Por qué este runbook existe" explaining the structural reason the filter cannot exist (NIP-59 Gift Wrap ephemeral outer key + admin DMs being direct user-to-user).
- **T-02-RUNBOOK-MISLEADING (R — Spanish-only runbook in an otherwise-English doc set):** accepted per plan threat register. Project audience reads Spanish (per global CLAUDE.md). All anti-requirement keywords (`OOS-19`, `CRIT-1`, `VERIFY-03`, `NIP-59`, `kind 1059`, `.authors(`, `mostro_pubkey`) are language-neutral identifiers and remain greppable.
- **T-02-RUNBOOK-RELAY-SHARED (I — publishing the test kind 1059 to a public relay):** accepted. The test event is structurally identical to a real Mostro Gift Wrap (NIP-59 ephemeral outer key, `p` tag = test pubkey). No incremental information leakage.

## Hand-off to Phase 3 (VERIFY-01 in-process harness)

Phase 3 introduces the in-process integration test harness for `POST /api/notify` (VERIFY-01). The dispute-chat path (Nostr-listener → `PushDispatcher::dispatch`) stays manual per D-18: Apple/FCM delivery decisions cannot be unit-tested. This runbook is the manual gold standard the integration test must agree with for any code path that intersects the dispute-chat flow:

- The runbook's Step 3 expected log line `Push sent successfully for event <event-id>` is emitted at `src/nostr/listener.rs:123`. Phase 3's harness exercises the equivalent code path (`PushDispatcher::dispatch` returning `Ok(DispatchOutcome::Delivered)`) but with a stub `PushService` instead of a real FCM backend.
- The runbook's Step 4 anti-CRIT-1 grep is a deploy-time check, NOT a test-suite check. Phase 3 may supplement it with a `cargo` build-time `compile_error!` or a CI-side grep, but the runbook remains the authoritative operator artifact.

`docs/verification/dispute-chat.md` is referenced by `02-CONTEXT.md` D-17 and by Phase 3 planning artifacts as the canonical anchor for the dispute-chat code path's manual verification.

## Self-Check: PASSED

- `docs/verification/dispute-chat.md` — FOUND (created, 203 lines / 1076 words)
- Commit `ce619fa` — FOUND in `git log --oneline --all`
- 1 file changed in commit, matching the plan's scope-discipline gate exactly
- All 11 plan-level gates and 16 task-level acceptance criteria pass
