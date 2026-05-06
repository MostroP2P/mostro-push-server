---
status: partial
phase: 02-post-api-notify-endpoint-with-privacy-hardening
source: [02-VERIFICATION.md]
started: 2026-04-25T19:30:00Z
updated: 2026-04-25T19:30:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. iOS silent push delivery
expected: HTTP 202 {"accepted":true}, X-Request-Id header is a server-generated UUIDv4, iOS device wakes via background handler (didReceiveRemoteNotification fires) within ~5s.
result: [pending]
why_human: Apple's APNs delivery decision (apns-priority 5 + apns-push-type background) cannot be verified without a real iOS device under FCM project credentials.

### 2. Android silent push delivery
expected: HTTP 202 {"accepted":true}, Android FirebaseMessagingService.onMessageReceived runs (data-only push received).
result: [pending]
why_human: Android FCM delivery is a runtime behaviour against Google's edge that requires a real device or emulator with the FCM project SDK.

### 3. Inbound X-Request-Id strip
expected: `curl -i -X POST $STAGING/api/notify -H 'X-Request-Id: client-supplied-foo' -H 'content-type: application/json' -d '{"trade_pubkey":"<64-hex>"}'` — response X-Request-Id header is NOT 'client-supplied-foo'; it is a server-generated canonical UUIDv4 (36 chars).
result: [pending]
why_human: Verifying the response header value at runtime requires a deployed instance.

### 4. Always-202 oracle (timing equivalence)
expected: curl with an UNREGISTERED 64-hex pubkey vs a REGISTERED one returns byte-identical 202 {"accepted":true} bodies with no latency-distinguishable timing.
result: [pending]
why_human: Anti-enumeration property requires runtime A/B comparison against the deployed endpoint.

### 5. Dispute-chat runbook end-to-end
expected: Steps 1-4 of `docs/verification/dispute-chat.md` complete as written; `flyctl logs` shows `Push sent successfully for event <id>`; step 4 anti-CRIT-1 grep returns only the comment-block match.
result: [pending]
why_human: Runbook is operator-facing; its executable correctness is a manual gold-standard check.

### 6. PRIV-01/PRIV-03 production log audit
expected: `flyctl logs -a mostro-push-server | grep -E 'pk='` — pubkey identifiers ONLY appear as 8-char hex tokens (e.g. `pk=a1b2c3d4`); never full 16-char hex prefixes anywhere in any module's logs; never source IPs; never FCM token strings.
result: [pending]
why_human: Confirms the privacy-safe log shape under live traffic after the SC #5 migration commit (118222b). Static grep verifies the source; only live traffic confirms no panic/log path emits raw values.

### 7. RUST_LOG=info active on Fly.io
expected: After deploy with `deploy-fly.sh`, no log line contains 20+ char FCM token prefixes; no log line contains 30+ char UnifiedPush endpoint prefixes (fcm.rs:270/303 + unifiedpush.rs:139 debug! lines silenced).
result: [pending]
why_human: Confirms the deploy-fly.sh RUST_LOG flip is in effect on the running machine and the secret is exported to the binary.

## Summary

total: 7
passed: 0
issues: 0
pending: 7
skipped: 0
blocked: 0

## Gaps
