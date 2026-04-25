---
phase: 02-post-api-notify-endpoint-with-privacy-hardening
verified: 2026-04-25T19:08:05Z
status: human_needed
score: 5/6 must-haves verified (1 partial, with documented intentional deviation)
overrides_applied: 0
gaps:
  - truth: "After the Phase 2 change is deployed (RUST_LOG=info), no log line — emitted from any module — contains a recognisable hex pubkey prefix or a registered FCM/UnifiedPush token; pubkey identifiers in logs originate exclusively from the salted truncated BLAKE3 helper."
    status: partial
    reason: |
      ROADMAP Success Criterion #5 is written as "any module". CONTEXT.md D-14
      and the Phase 2 plans deliberately narrowed the scope to /api/notify only,
      explicitly preserving the existing 16-hex-char prefix-truncation logs in
      src/nostr/listener.rs, src/api/routes.rs, and src/store/mod.rs (operator
      grep continuity). Under RUST_LOG=info these legacy logs DO emit hex
      pubkey prefixes in production. The narrower D-14 scope is fully
      satisfied (notify.rs uses log_pubkey() exclusively); the broader
      ROADMAP wording is not. This is an intentional, documented scope
      reduction and a candidate for an override.
    artifacts:
      - path: src/api/routes.rs
        issue: "Lines 94-95, 138-141, 155-156 emit info! lines with `&req.trade_pubkey[..16]` prefixes (register_token + unregister_token handlers)"
      - path: src/store/mod.rs
        issue: "Lines 58-62 and 70-74 emit info! with `&trade_pubkey[..16]` prefixes (register + unregister)"
      - path: src/nostr/listener.rs
        issue: "Lines 110 and 114-117 emit info! with `&trade_pubkey[..16]` prefixes (Event recipient + MATCH log lines) — these are reached on every Mostro daemon event in production"
    missing:
      - "Either: migrate the 7 existing `&trade_pubkey[..16]` info! call sites to log_pubkey() so SC #5 is literally satisfied"
      - "Or: amend ROADMAP SC #5 to reflect the D-14 scope (notify.rs only) and add an explicit override entry to this VERIFICATION.md"
      - "Note: FCM/UnifiedPush token prefix logs (fcm.rs:270, fcm.rs:303, unifiedpush.rs:139) are debug! and DO NOT emit at RUST_LOG=info — those are not part of this gap"
human_verification:
  - test: "Manual smoke against staging: register a test pubkey + iOS FCM token via POST /api/register, then POST /api/notify { trade_pubkey } and confirm the iOS device receives a silent push within ~5s (didReceiveRemoteNotification fires)"
    expected: "HTTP 202 {\"accepted\":true}, X-Request-Id header is a server-generated UUIDv4, device wakes via background handler"
    why_human: "Apple's APNs delivery decision (apns-priority 5 + apns-push-type background) cannot be verified without a real iOS device under FCM project credentials; D-06 explicitly defers this to operator smoke"
  - test: "Manual smoke against staging: register a test pubkey + Android FCM token, then POST /api/notify and confirm Android FirebaseMessagingService.onMessageReceived runs"
    expected: "HTTP 202 {\"accepted\":true}, device receives data-only push"
    why_human: "Android FCM delivery is a runtime behaviour against Google's edge that requires a real device or emulator with the FCM project SDK"
  - test: "Inbound X-Request-Id strip: curl -i -X POST $STAGING/api/notify -H 'X-Request-Id: client-supplied-foo' -H 'content-type: application/json' -d '{\"trade_pubkey\":\"<64-hex>\"}'"
    expected: "Response X-Request-Id header is NOT 'client-supplied-foo' — must be a server-generated UUIDv4 (36 chars, canonical UUID form)"
    why_human: "Verifying the actual response header value at runtime requires a deployed instance; static grep confirms the code is in place but cannot prove the header is replaced on the wire"
  - test: "Always-202 oracle check: curl with an UNREGISTERED 64-hex pubkey vs a REGISTERED one"
    expected: "Both calls return byte-identical 202 {\"accepted\":true} with no latency-distinguishable timing"
    why_human: "Anti-enumeration property requires runtime A/B comparison against the deployed endpoint; static analysis confirms a single HttpResponse::Accepted() site but cannot prove no observable timing oracle exists end-to-end"
  - test: "Run the full dispute-chat runbook (docs/verification/dispute-chat.md) end-to-end against staging"
    expected: "Steps 1-4 complete as written; flyctl logs shows 'Push sent successfully for event <id>'; step 4 anti-CRIT-1 grep returns only the comment-block match"
    why_human: "Runbook is operator-facing; its executable correctness is a manual gold-standard check"
  - test: "PRIV-01/PRIV-03 production log audit: flyctl logs -a mostro-push-server | grep -E 'notify:'"
    expected: "Pubkey identifiers ONLY appear as 8-char hex tokens (e.g. pk=a1b2c3d4); never full 16-char hex prefixes; never source IPs; never FCM token strings"
    why_human: "Confirms the privacy-safe log shape under live traffic; static grep cannot rule out runtime panic/log lines that emit raw values"
  - test: "Manual smoke against staging: deploy with deploy-fly.sh and tail flyctl logs to confirm RUST_LOG=info silences fcm.rs:270/303 + unifiedpush.rs:139 debug! lines that log token prefixes"
    expected: "After deploy, no log line contains 20+ char FCM token prefixes; no log line contains 30+ char UnifiedPush endpoint prefixes"
    why_human: "Confirms the deploy-fly.sh RUST_LOG flip is in effect on the running machine and the secret is actually exported to the binary"
---

# Phase 2: POST /api/notify Endpoint with Privacy Hardening — Verification Report

**Phase Goal:** A registered Mostro Mobile client sending POST /api/notify { trade_pubkey } causes a silent push to reach the device registered for that pubkey, and shipping this endpoint does not introduce a trade_pubkey ↔ source IP correlation in production logs.

**Verified:** 2026-04-25T19:08:05Z
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

The endpoint exists, is wired through the existing `/api` scope, dispatches via the new `dispatch_silent` path, returns 202 unconditionally on parse-valid input, and ships with the privacy hardening bundle (X-Request-Id middleware, log_pubkey helper, semaphore-bounded spawn, silent FCM payload, RUST_LOG=info flip, dispute-chat runbook). All structural and source-level invariants required by the Phase goal are present and compile clean (`cargo build --release` exits 0). The two missing pieces are (1) operator-side iOS/Android delivery smoke that no static check can substitute for, and (2) one literal-vs-intent gap on SC #5 covered below.

### Observable Truths (against ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | POST /api/notify with a registered trade_pubkey produces a silent push reaching the registered device via the same backend the listener path would have used | ? UNCERTAIN | Code path is structurally complete: handler at `src/api/notify.rs:49-109` calls `dispatcher.dispatch_silent(&token)` inside a spawned task; `PushDispatcher::dispatch_silent` (`src/push/dispatcher.rs:56-61`) routes through `send_silent_to_token`; `FcmPush::send_silent_to_token` (`src/push/fcm.rs:289-320`) uses the new `build_silent_payload_for_notify` (apns-priority 5 + apns-push-type background). Manual device smoke (D-06) is required to confirm Apple/Google actually deliver — see human_verification items 1 and 2. |
| 2 | POST /api/notify with malformed pubkey returns 400; response is byte-identical regardless of registration | ✓ VERIFIED | Validation at `src/api/notify.rs:54-61` mirrors `register_token` validation. Single `HttpResponse::Accepted()` site at line 108 (`grep -cE 'HttpResponse::Accepted\(\)' = 1`). 202 path returns `json!({"accepted": true})` — compile-time-constant body, no echo of trade_pubkey. Anti-enumeration oracle structurally satisfied per D-01. End-to-end timing equivalence remains a runtime concern (human_verification item 4). |
| 3 | Existing /api/register, /api/unregister, /api/health, /api/info, /api/status request and response bodies remain byte-identical to the pre-milestone fixture | ✓ VERIFIED | Per-DTO and per-handler diff vs `56a1a6d^` (pre-Phase-2 tip): all 4 protected DTOs (`RegisterTokenRequest`, `UnregisterTokenRequest`, `RegisterResponse`, `StatusResponse`) byte-identical; all 5 protected handlers (`health_check`, `status`, `server_info`, `register_token`, `unregister_token`) byte-identical. Only AppState struct grew (3 new fields) — that is not part of NOTIFY-03's contract. |
| 4 | Every /api/notify response carries a server-generated UUIDv4 X-Request-Id header; any inbound X-Request-Id is ignored | ✓ VERIFIED | `request_id_mw` at `src/api/notify.rs:117-132` strips inbound (`req.headers_mut().remove("x-request-id")` line 121) BEFORE generating UUIDv4 (line 123) and inserting into response (line 126). Wrapped via `web::resource("/notify").wrap(from_fn(request_id_mw))` (`src/api/routes.rs:56-60`). Per orchestrator note: SC #4 scope is /api/notify only (sibling endpoints intentionally exempt to preserve COMPAT-1). Confirmed: `grep web::scope("/api").wrap(` returns 0 (middleware NOT on scope). |
| 5 | After deploy with RUST_LOG=info, no log line — emitted from any module — contains a recognisable hex pubkey prefix or a registered FCM/UnifiedPush token; pubkey identifiers come exclusively from log_pubkey() | ⚠️ PARTIAL | `notify.rs` uses `log_pubkey()` exclusively (2 calls at lines 64 and 81; no `trade_pubkey[..16]` slicing — `grep returns 0`). FCM/UnifiedPush token-prefix logs at `fcm.rs:270`, `fcm.rs:303`, `unifiedpush.rs:139` are `debug!` and silenced by RUST_LOG=info. **However**, info!-level logs at `src/store/mod.rs:60,72,78`, `src/api/routes.rs:95,141,156`, and `src/nostr/listener.rs:110,116` still emit `&trade_pubkey[..16]` prefixes and DO emit at RUST_LOG=info. CONTEXT.md D-14 explicitly chose to PRESERVE these for operator grep continuity, deliberately scoping log_pubkey() to /api/notify paths only. ROADMAP SC #5 is literally not satisfied; the narrower D-14 scope IS. See gaps section. |
| 6 | docs/verification/dispute-chat.md walks an operator through verifying admin DM (user-to-user, NOT through Mostro daemon) reaches device via Nostr-listener path; includes anti-CRIT-1 reminder | ✓ VERIFIED | File exists at `docs/verification/dispute-chat.md` (203 lines, 1076 words). All 4 mandatory sections present: register pubkey (Step 1, line 56), publish kind 1059 from secondary Nostr client NOT Mostro daemon (Step 2, line 77), verify dispatch via flyctl logs (Step 3, line 103), anti-CRIT-1 grep with comment-excluding regex `^\s*[^/]` (Step 4, line 141). References OOS-19, CRIT-1, VERIFY-03, NIP-59, kind 1059. Spanish per global CLAUDE.md. |

**Score:** 5/6 truths verified (1 partial)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/api/notify.rs` | NotifyRequest DTO + notify_token handler + request_id_mw middleware | ✓ VERIFIED | Exists, 132 lines, compiles. Contains: `pub struct NotifyRequest`, `pub async fn notify_token`, `pub async fn request_id_mw`. Single `HttpResponse::Accepted()` site. Wired via `src/api/routes.rs:8` import + `:56-60` route. |
| `src/utils/log_pubkey.rs` | salted truncated BLAKE3 keyed-hash helper | ✓ VERIFIED | Exists, 21 lines. `pub fn log_pubkey(salt: &[u8; 32], pk: &str) -> String` returning `blake3::keyed_hash(salt, pk.as_bytes()).to_hex()[..8].to_string()`. Wired via `src/utils/mod.rs:2` declaration + `src/api/notify.rs:14` import. |
| `src/api/routes.rs` | AppState 4 fields + /notify route wrapped with X-Request-Id middleware | ✓ VERIFIED | AppState has `token_store`, `dispatcher`, `semaphore`, `notify_log_salt` (lines 41-46). `/notify` registered at line 56-60 with `web::resource(...).wrap(from_fn(request_id_mw))`. Existing 5 routes byte-identical. |
| `src/push/dispatcher.rs` | dispatch_silent method routing FCM through silent payload builder | ✓ VERIFIED | `pub async fn dispatch_silent` at line 56-61 delegates to private `dispatch_with(token, true)` (line 63). `silent=true` branch calls `send_silent_to_token` (line 78). |
| `src/push/fcm.rs` | build_silent_payload_for_notify (apns-priority 5, apns-push-type background) + send_silent_to_token override | ✓ VERIFIED | `fn build_silent_payload_for_notify` at line 226. Payload contains `"apns-priority": "5"` (line 240), `"apns-push-type": "background"` (line 241), `"content-available": 1` (line 245). `async fn send_silent_to_token` impl at line 289. Existing `build_payload_for_token` (apns-priority 10, line 198) byte-identical. |
| `src/push/mod.rs` | PushService trait with default send_silent_to_token method | ✓ VERIFIED | Trait `send_silent_to_token` default at lines 28-34 delegates to `send_to_token`. Both `Arc<UnifiedPushService>` and `Arc<FcmPush>` blanket impls forward (lines 50-56 and 74-80). |
| `src/main.rs` | salt + semaphore construction; AppState wired with 4 fields; /api/notify endpoint banner | ✓ VERIFIED | `rand::thread_rng().fill_bytes(&mut salt_bytes)` at line 99; `Arc::new(Semaphore::new(50))` at line 104; 4-field AppState literal at lines 118-123; banner `info!("  POST /api/notify     - Trigger silent push (best-effort)")` at line 134. |
| `Cargo.toml` | blake3 = "1" + uuid v1/v4 + actix-web 4.9 | ✓ VERIFIED | `actix-web = "4.9"` at line 8; `blake3 = "1"` at line 44; `uuid = { version = "1", features = ["v4"] }` at line 57. |
| `deploy-fly.sh` | RUST_LOG="info" (down from debug) | ✓ VERIFIED | `RUST_LOG="info"` at line 42; legacy `"debug"` value 0 matches. |
| `docs/verification/dispute-chat.md` | Operator runbook reinforcing anti-CRIT-1 | ✓ VERIFIED | 203 lines, 1076 words, Spanish, 4 sections, anti-CRIT-1 grep one-liner present. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|----|--------|---------|
| `src/api/routes.rs` | `src/api/notify.rs` | `use crate::api::notify::{notify_token, request_id_mw}` | ✓ WIRED | Line 8 import; line 59 route binding |
| `src/api/notify.rs` | `src/utils/log_pubkey.rs` | `use crate::utils::log_pubkey::log_pubkey` | ✓ WIRED | Line 14 import; 2 invocations (lines 64, 81) |
| `src/api/notify.rs` | `src/push/dispatcher.rs` | `dispatcher.dispatch_silent(&token).await` | ✓ WIRED | Line 85 inside spawned task closure |
| `src/push/dispatcher.rs` | `src/push/fcm.rs` | `send_silent_to_token` polymorphic dispatch | ✓ WIRED | dispatcher line 78 calls trait method; FcmPush impl at fcm.rs:289 overrides default |
| `src/main.rs` | `src/api/routes.rs` | `AppState { token_store, dispatcher, semaphore, notify_log_salt }` literal | ✓ WIRED | Lines 118-123 populate all 4 fields |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `src/api/notify.rs::notify_token` | `state.token_store` | populated at startup in `main.rs:38` (`Arc::new(TokenStore::new(...))`); registered/unregistered through `/api/register` and `/api/unregister` handlers | YES — real `Arc<TokenStore>` with `RwLock<HashMap>` populated by live registrations | ✓ FLOWING |
| `src/api/notify.rs::notify_token` | `state.dispatcher` | populated at `main.rs:93` from `Arc::new(PushDispatcher::new(push_services))` containing `FcmPush` and/or `UnifiedPushService` | YES — real `PushDispatcher` with concrete backends pushed in main.rs:79-91 | ✓ FLOWING |
| `src/api/notify.rs::notify_token` | `state.notify_log_salt` | populated at `main.rs:99-100` from `rand::thread_rng().fill_bytes(...)` (32 bytes random per process) | YES — real random salt | ✓ FLOWING |
| `src/api/notify.rs::notify_token` | `state.semaphore` | populated at `main.rs:104` (`Arc::new(Semaphore::new(50))`) | YES — real bounded semaphore | ✓ FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Project compiles clean (release profile) | `cargo build --release` | `Finished release profile [optimized] target(s) in 0.18s` (cached); 21 warnings, 0 errors | ✓ PASS |
| Anti-CRIT-1 — no active `.authors(...)` filter in listener | `grep -n '\\.authors\\s*(' src/nostr/listener.rs \| grep -v '//'` | exit code 1 (no non-comment match); only comment at line 72 | ✓ PASS |
| Single `HttpResponse::Accepted()` site (anti-enumeration oracle) | `grep -cE 'HttpResponse::Accepted\\(\\)' src/api/notify.rs` | 1 | ✓ PASS |
| No `HttpRequest`/peer_addr/connection_info/forwarded reads in handler (PRIV-03) | `grep -nE 'HttpRequest\|peer_addr\|connection_info\|forwarded' src/api/notify.rs` | exit 1 (0 matches) | ✓ PASS |
| No `&trade_pubkey[..16]` slicing in notify.rs | `grep -nE 'trade_pubkey\\[' src/api/notify.rs` | exit 1 (0 matches) | ✓ PASS |
| log_pubkey() called twice in notify.rs (handler + spawn) | `grep -cE 'log_pubkey\\(' src/api/notify.rs` | 2 | ✓ PASS |
| try_acquire_owned bounded spawn | `grep -nE 'try_acquire_owned' src/api/notify.rs` | line 68 | ✓ PASS |
| Inbound X-Request-Id header stripped | `grep -nE 'remove\\(\"x-request-id\"\\)' src/api/notify.rs` | line 121 | ✓ PASS |
| RUST_LOG flipped from debug to info | `grep -nE 'RUST_LOG' deploy-fly.sh` | line 42: `RUST_LOG="info"` | ✓ PASS |
| Middleware NOT on /api scope (COMPAT-1 guardrail) | `grep -nE 'web::scope\\(\"/api\"\\)\\.wrap\\(' src/api/routes.rs` | exit 1 (0 matches) | ✓ PASS |
| Silent payload uses apns-priority 5 + background | `grep -nE 'apns-priority\|apns-push-type' src/push/fcm.rs` | line 240 priority 5 silent, line 241 background, line 198 priority 10 (existing) | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| NOTIFY-01 | 02-02 | POST /api/notify endpoint accepting `{trade_pubkey}`, validates shape, dispatches silent push via PushDispatcher | ✓ SATISFIED | `src/api/notify.rs:49-109` notify_token handler; `src/api/routes.rs:56-60` route registration; `src/push/dispatcher.rs:56-61` dispatch_silent |
| NOTIFY-02 | 02-02 | Endpoint matches mobile contract (`POST /api/notify { trade_pubkey }`); always-202 locked under D-04 | ✓ SATISFIED (with mobile coordination caveat) | Wire shape matches; coordination per D-04 is operator-side and out of band — flagged informational |
| NOTIFY-03 | 02-02 | Existing /api/register, /api/unregister, /api/health, /api/info, /api/status request/response shapes byte-identical | ✓ SATISFIED | Per-DTO and per-handler diff vs 56a1a6d^ shows 0-byte diff for all 4 DTOs and 5 handlers (RegisterTokenRequest, UnregisterTokenRequest, RegisterResponse, StatusResponse, health_check, status, server_info, register_token, unregister_token) |
| NOTIFY-04 | 02-02 | X-Request-Id middleware generates UUIDv4 server-side, ignores inbound | ✓ SATISFIED | `request_id_mw` at notify.rs:117-132. Strips inbound (line 121) before generating UUIDv4 (line 123). Note: per orchestrator clarification, scoped to /api/notify only (D-11/D-13/COMPAT-1) |
| PRIV-01 | 02-02 | log_pubkey helper using salted truncated BLAKE3 keyed-hash | ✓ SATISFIED | `src/utils/log_pubkey.rs:18-21` returns `blake3::keyed_hash(salt, pk.as_bytes()).to_hex()[..8]`. Used in notify.rs handler (line 64) and spawn (line 81). |
| PRIV-02 | 02-02 | deploy-fly.sh sets RUST_LOG="info" | ✓ SATISFIED | `deploy-fly.sh:42` `RUST_LOG="info"` |
| PRIV-03 | 02-02 | notify_token handler never logs source IP, body, response, FCM token, or correlation data | ✓ SATISFIED | No HttpRequest parameter in handler signature (line 49-52); no peer_addr/connection_info/forwarded reads (grep returns 0); no trade_pubkey echo in 202 body (line 108) |
| VERIFY-03 | 02-03 | Manual runbook docs/verification/dispute-chat.md with anti-CRIT-1 reminder | ✓ SATISFIED | File present, 4 mandatory sections per D-17, anti-CRIT-1 grep one-liner included |

All 8 phase-declared requirement IDs (NOTIFY-01..04, PRIV-01..03, VERIFY-03) are SATISFIED at the source-code level. Per ROADMAP traceability table, no other requirement IDs are mapped to Phase 2 (LIMIT-* and VERIFY-01/02 belong to Phase 3). No orphans.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `src/api/routes.rs` | 95, 141, 156 | `info!("... {}...", &req.trade_pubkey[..16.min(req.trade_pubkey.len())])` — register/unregister handlers emit hex pubkey prefix at info level | ⚠️ Warning | Tension with ROADMAP SC #5 "any module"; explicitly preserved by D-14. See gaps. |
| `src/store/mod.rs` | 60, 72, 78 | `info!/debug!("... {}...", &trade_pubkey[..16.min(trade_pubkey.len())])` — TokenStore register/unregister logs | ⚠️ Warning | Same as above. The line at 78 is `debug!` (silenced by RUST_LOG=info); 60 and 72 are `info!`. |
| `src/nostr/listener.rs` | 110, 116 | `info!("... {}...", &trade_pubkey[..16])` — Event recipient and MATCH log lines | ⚠️ Warning | Same as above; reached on every Mostro daemon event in production. |
| `src/push/fcm.rs` | 270, 303 | `debug!("Sending FCM ... {}...", &device_token[..20.min(...)])` — FCM token prefix logs | ℹ️ Info | Silenced by RUST_LOG=info per D-15; not a runtime gap. |
| `src/push/unifiedpush.rs` | 139 | `debug!("Sending UnifiedPush ... {}...", &device_token[..30.min(...)])` | ℹ️ Info | Silenced by RUST_LOG=info per D-15; not a runtime gap. |
| `src/api/notify.rs` | 19-20 | Doc comment text contains the strings `sender_pubkey`, `signature`, `Idempotency-Key`, `auth header` | ℹ️ Info | False-positive on plan acceptance grep; the doccomment documents the prohibition (anti-OOS-11). Auto-fixed/documented in 02-02-SUMMARY.md. No code change needed. |

No blocker (🛑) anti-patterns found. The 3 ⚠️ Warning entries cluster around a single root cause (D-14's deliberate scope reduction vs ROADMAP SC #5).

### Human Verification Required

See the `human_verification:` block in the YAML frontmatter for the 7 items requiring operator action. Summary:

1. iOS device smoke (apns-priority 5 + background) — Apple delivery decision
2. Android device smoke (FCM data-only payload) — Google FCM delivery
3. Inbound X-Request-Id strip on the wire
4. Always-202 oracle equivalence (registered vs unregistered timing)
5. Full dispute-chat runbook walkthrough end-to-end
6. PRIV-01/PRIV-03 production log audit
7. RUST_LOG=info effective on the deployed Fly machine

### Gaps Summary

There is one structural gap and one set of items requiring human verification.

**Structural gap (SC #5 partial):** ROADMAP SC #5 says "no log line — emitted from any module — contains a recognisable hex pubkey prefix". Phase 2 CONTEXT.md D-14 deliberately narrowed log_pubkey() scope to /api/notify only, explicitly preserving 7 existing `&trade_pubkey[..16]` info!-level call sites in `src/api/routes.rs`, `src/store/mod.rs`, and `src/nostr/listener.rs` for operator grep continuity. Under RUST_LOG=info these legacy logs DO emit hex pubkey prefixes in production. The narrower D-14 scope is fully satisfied (notify.rs uses log_pubkey() exclusively); the broader ROADMAP wording is not.

**This looks intentional.** D-14 in `02-CONTEXT.md` is explicit: "Existing logs in src/nostr/listener.rs (lines ~108, 115-116, 137), src/api/routes.rs (register/unregister handlers), and src/store/mod.rs (TokenStore log lines) KEEP their current `&trade_pubkey[..16]` prefix-truncation shape — NOT migrated. Rationale: operators that grep production logs by hex prefix today do not break; retroactive migration is deferred to a future observability milestone."

To accept this deviation, add to VERIFICATION.md frontmatter (after operator confirms intent):

```yaml
overrides:
  - must_have: "After the Phase 2 change is deployed (RUST_LOG=info), no log line — emitted from any module — contains a recognisable hex pubkey prefix or a registered FCM/UnifiedPush token; pubkey identifiers in logs originate exclusively from the salted truncated BLAKE3 helper."
    reason: "Phase 2 CONTEXT.md D-14 deliberately narrowed log_pubkey() scope to /api/notify paths only. Existing 7 hex-prefix info! call sites in routes.rs, store/mod.rs, and nostr/listener.rs are preserved for operator grep continuity. Retroactive migration is deferred to a future observability milestone. The narrower D-14 scope (/api/notify only) is fully satisfied."
    accepted_by: "<operator name>"
    accepted_at: "<ISO timestamp>"
```

If the deviation is NOT accepted, the closure plan must migrate the 7 call sites:
- `src/store/mod.rs` lines 58-62, 70-74 (`register`, `unregister`)
- `src/api/routes.rs` lines 94-95, 138-141, 155-156 (`register_token`, `unregister_token`)
- `src/nostr/listener.rs` lines 110, 114-117 (`Event recipient`, `MATCH! Found registered token`)

That migration would also need to plumb the salt through `TokenStore` and the Nostr listener (currently only `AppState` holds it), enlarging the surface area beyond Phase 2's locked D-19 commit grain. This is the reason D-14 chose the narrower scope to begin with.

**Manual smoke gap:** D-06 explicitly defers iOS/Android device delivery confirmation to operator action post-deploy. The structural code path is complete and compiles; only Apple/Google's runtime delivery decision can validate end-to-end behaviour. See `human_verification` items 1-2.

---

_Verified: 2026-04-25T19:08:05Z_
_Verifier: Claude (gsd-verifier)_
