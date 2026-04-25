---
phase: 02
slug: post-api-notify-endpoint-with-privacy-hardening
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-25
---

# Phase 02 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Built-in `cargo test` (Rust 2021 edition + tokio runtime via `#[tokio::test]`) |
| **Config file** | None — Cargo defaults |
| **Quick run command** | `cargo build --release` |
| **Full suite command** | `cargo test --release` (currently no-op — repo has no `#[cfg(test)]` modules with assertions; Phase 3 establishes the integration harness) |
| **Estimated runtime** | ~30 seconds incremental release build; full clean build ~3-5 minutes |

---

## Sampling Rate

- **After every task commit:** Run `cargo build --release`
- **After every plan wave:** Run `cargo build --release` + the manual grep checks tabulated below
- **Before `/gsd-verify-work`:** Compile-clean + manual grep checks PASS + Fly.io staging deploy + D-06 iOS smoke + D-17 runbook walkthrough
- **Max feedback latency:** ~30 seconds (incremental compile)

---

## Per-Task Verification Map

| Req ID | Behavior | Test Type | Automated Command | File Exists |
|--------|----------|-----------|-------------------|-------------|
| NOTIFY-01 | `POST /api/notify` accepts valid body, dispatches via `PushDispatcher` | manual-only (Phase 2) → integration in Phase 3 | `cargo build --release` (compile check); manual curl on Fly.io staging | n/a — manual only |
| NOTIFY-02 | Wire contract matches mobile-team plan modulo D-01 always-202 | manual coordination | (out-of-band — user/orchestrator confirms with mobile team) | n/a |
| NOTIFY-03 | Existing endpoints byte-identical (no Register* DTO refactor) | manual diff against pre-Phase-2 fixture | `git diff main -- src/api/routes.rs` shows only `AppState` extension + 1 new `.route()` line + import additions | n/a |
| NOTIFY-04 | UUIDv4 in `X-Request-Id` response header on `/api/notify` only; inbound header ignored | manual smoke + curl | `curl -i -X POST $STAGING/api/notify -d '{"trade_pubkey":"<64-hex>"}'` shows `X-Request-Id:` header; inbound `X-Request-Id: foo` does NOT echo back as `foo` | n/a |
| PRIV-01 | `log_pubkey()` is the only sanctioned form in new endpoint logs | manual grep on resulting code | `! grep -nE "(info\|warn\|error\|debug)!.*trade_pubkey\[" src/api/notify.rs` returns no matches | n/a |
| PRIV-02 | `RUST_LOG="info"` in deploy script | manual diff | `grep 'RUST_LOG=' deploy-fly.sh` returns `RUST_LOG="info"` | n/a |
| PRIV-03 | No source IP / token / body in handler logs | manual grep + code review | `! grep -nE "(req\.peer_addr\|connection_info\|forwarded)" src/api/notify.rs` returns no matches | n/a |
| VERIFY-03 | Runbook at `docs/verification/dispute-chat.md` exists, contains anti-CRIT-1 grep | manual presence check | `test -f docs/verification/dispute-chat.md` AND `grep -q '\.authors(' docs/verification/dispute-chat.md` | n/a |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] No Wave 0 test infrastructure setup is performed in Phase 2 — automated coverage is explicitly deferred to Phase 3 (VERIFY-01, VERIFY-02). The repo has no `tests/` directory and no `#[cfg(test)]` modules with assertions; this is a known gap.
- [ ] No mock `PushService` impl exists. Phase 3 introduces `NoopPush` (PITFALLS TEST-1).
- [ ] No frozen pre-Phase-2 fixture for byte-identity check. The COMPAT-1 protection is enforced by code-level discipline + diff review (Phase 1 SUMMARY's anti-requirement check methodology).

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| End-to-end silent push reaches a real iOS device | NOTIFY-01 | Apple's delivery decision cannot be unit-tested; requires real APNs path through FCM | D-06 manual smoke: register a test pubkey with an iOS FCM token, call `POST /api/notify`, confirm `didReceiveRemoteNotification` fires on device and background handler runs |
| Mobile-team contract coordination | NOTIFY-02 | Server-only repo cannot validate mobile client behavior | Out-of-band Slack/PR exchange with mobile team confirming acceptance of always-202 (D-04) before mobile Phase 4 ships |
| Byte-identity of existing endpoints | NOTIFY-03 | No frozen fixture stored in repo | `git diff main -- src/api/routes.rs` review by author + reviewer; ensure only `AppState` field additions + 1 `.route("/notify", ...)` line + imports — no DTO touch |
| Dispute-chat path still works after Phase 2 deploy | VERIFY-03 | Path is in `src/nostr/listener.rs` (untouched) but Phase 2 changes downstream `PushDispatcher` callers; runbook validates no regression | Operator follows `docs/verification/dispute-chat.md` end-to-end against staging: register test pubkey, publish kind 1059 from a second Nostr client to a configured relay, observe device receives silent push, observe `info!("Push sent successfully...")` log line, run runbook's `grep -q '\.authors(' src/nostr/listener.rs` anti-CRIT-1 check (must return 0 matches) |
| iOS silent push not throttled by APNs | (D-05 / FCM-1) | Apple's throttling decision is observable only on real device over time | Optional: Phase 2 operator monitors a registered iOS device for 24h post-deploy; observes silent pushes still wake background handler. If Apple-flagged, escalate. |

*Why Phase 2 is manual-heavy:*

1. The handler logic is genuinely small (~50 lines). Reviewer + compile-pass catch the bulk of regressions.
2. The privacy-relevant invariants (anti-oracle, anti-pubkey-leak, anti-IP-leak) are **structural**: they're either present or absent in the code, not behavioral. `grep` catches them more reliably than a test that has to provoke the negative case.
3. The end-to-end path requires a real FCM service account and a real iOS device — both operator-side resources, not unit-testable. D-06 + D-17 capture this.
4. **Phase 3 closes the gap** with VERIFY-01 (in-process integration suite via `actix_web::test::init_service`) — explicitly traced in REQUIREMENTS.md and ROADMAP.md.

---

## Nyquist Gap (for Phase 3)

Phase 2 ships **8 requirements with 0 automated tests**. Phase 3's VERIFY-01 must cover at minimum:

- **NOTIFY-01** — registered pubkey path returns 202 and dispatches via stub `PushService`
- **NOTIFY-04** — `X-Request-Id` header present; inbound `X-Request-Id` from client does NOT round-trip
- **PRIV-01** — log lines from handler do NOT contain `trade_pubkey[..16]`-shaped substrings (assert against captured stderr in test)
- **PRIV-03** — no peer-IP / `Forwarded` / `X-Forwarded-For` / `connection_info` in handler logs
- **NOTIFY-03 (regression guard)** — golden-file fixture: snapshot of `RegisterResponse`, `RegisterTokenRequest`, `UnregisterTokenRequest` JSON shapes; CI fails on drift

Without these in Phase 3, the manual-only check vector remains the only safety net for Phase 2's privacy invariants. Mark **`nyquist_compliant: false`** in this phase's frontmatter and only flip to true after Phase 3's VERIFY-01 passes.

---

## Validation Sign-Off

- [ ] Every PLAN.md task has either `<automated>` verify or a Wave 0 manual-only entry above
- [ ] Sampling continuity: every wave includes at least one `cargo build --release` command
- [ ] Wave 0 gaps explicitly accepted (handler is small enough; structural privacy invariants grep-checkable)
- [ ] No watch-mode flags in any task command
- [ ] Feedback latency < 60s (cargo incremental build target)
- [ ] `nyquist_compliant: true` set in frontmatter ONLY after Phase 3 VERIFY-01 closes the gap

**Approval:** pending
