---
phase: 02-post-api-notify-endpoint-with-privacy-hardening
reviewed: 2026-04-25T00:00:00Z
depth: standard
files_reviewed: 13
files_reviewed_list:
  - Cargo.toml
  - deploy-fly.sh
  - docs/verification/dispute-chat.md
  - src/api/mod.rs
  - src/api/notify.rs
  - src/api/routes.rs
  - src/main.rs
  - src/push/dispatcher.rs
  - src/push/fcm.rs
  - src/push/mod.rs
  - src/push/unifiedpush.rs
  - src/utils/log_pubkey.rs
  - src/utils/mod.rs
findings:
  critical: 0
  warning: 2
  info: 6
  total: 8
status: issues_found
---

# Phase 2: Code Review Report

**Reviewed:** 2026-04-25
**Depth:** standard
**Files Reviewed:** 13
**Status:** issues_found

## Summary

Phase 2 introduces the `POST /api/notify` endpoint together with a coherent set of privacy measures: validation before any logging, a BLAKE3 correlator with a per-process random salt (never persisted), an `X-Request-Id` middleware scoped strictly to `/notify`, a separate FCM silent payload (`apns-priority: 5`, `apns-push-type: background`), decoupled dispatch via `tokio::spawn` bounded by `Arc<Semaphore>(50)`, and a silent drop on saturation.

The review found no critical security vulnerabilities. The always-202 contract, the middleware scoping, the in-memory salt, the `try_acquire_owned()` error handling, and log redaction are all implemented correctly and respect the anti-requirements (CRIT-2/3/6, OOS-11). The findings are two minor warnings (unused imports flagged by `cargo check`) and six info items: a leftover `Cargo.toml` field, non-essential but recommended APNs headers, a redundant re-derivation, missing validation against mixed-case pubkeys, a hardcoded secret in `deploy-fly.sh` (already documented as inert because encryption is disabled — flagged for visibility), and pre-existing dead-code in `Cargo.toml` (deps not used in this phase).

The endpoint's privacy contract is solid: `trade_pubkey` validation happens before any log line that references it (line 54 before line 64 in `notify.rs`), the handler emits `info!` only with the opaque correlator, and the spawn-saturated path emits a `warn!` with no pubkey at all (`notify.rs` line 103). Middleware scoping is implemented via `web::resource("/notify").wrap(...)` (`routes.rs` lines 56-60), preventing leakage to `/register`/`/unregister`/`/info`/`/health`/`/status`, which retain their previous behaviour.

## Warnings

### WR-01: Unused imports in `src/push/fcm.rs` and `src/push/unifiedpush.rs`

**File:** `src/push/fcm.rs:3` and `src/push/unifiedpush.rs:3`
**Issue:** The line `use reqwest::Client;` was left over after the field migration from `client: Client` to `client: Arc<reqwest::Client>` in Phase 2 (the commit uses the fully-qualified `reqwest::Client` path instead). This produces an active warning under `cargo check`:

```text
warning: unused import: `reqwest::Client`
 --> src/push/fcm.rs:3:5
warning: unused import: `reqwest::Client`
 --> src/push/unifiedpush.rs:3:5
```

If the project later adopts `#![deny(warnings)]` or `cargo clippy -- -D warnings` in CI, this would break the build. As of today it is just noise in the `cargo check`/`cargo build` output.

**Fix:** Remove the line in both files:

```rust
// src/push/fcm.rs:3 — DELETE
- use reqwest::Client;

// src/push/unifiedpush.rs:3 — DELETE
- use reqwest::Client;
```

`reqwest::Client` continues to be used as `Arc<reqwest::Client>` via the fully-qualified path in the struct and the constructor; no import is required.

---

### WR-02: `x-request-id` header is not added to error responses propagated via `?`

**File:** `src/api/notify.rs:117-132`
**Issue:** The `request_id_mw` middleware propagates errors from `next.call(req).await?` with the `?` operator. On that path, the subsequent branch that inserts the `x-request-id` header into the response is NOT executed. If any future chained middleware or extractor returns an `Err(actix_web::Error)` (instead of an `Ok(ServiceResponse)` carrying a 4xx status — which is what the current `web::Json` malformed-body handler does), the client will not see the correlator on that error response.

In current actix-web 4.x practice, the `web::Json` extractor returns `Ok(ServiceResponse)` with 400 (not `Err`) when the JSON fails to parse, so the `?` path is rarely exercised. The issue is defensive / forward-looking, not a bug in production today.

**Fix:** If a guarantee on every response (including propagated errors) is desired, capture the `Result` and add the header on both branches. Example:

```rust
let id = uuid::Uuid::new_v4().to_string();
let header_value = HeaderValue::from_str(&id)
    .expect("uuid string is always valid header value");
let header_name = HeaderName::from_static("x-request-id");

let result = next.call(req).await;
match result {
    Ok(mut res) => {
        res.headers_mut().insert(header_name, header_value);
        Ok(res)
    }
    Err(e) => {
        // Actix errors are converted to a 500 response later;
        // the header would be lost anyway under the current `?`.
        // The 400-from-extractor case (which already arrives as Ok) is covered.
        Err(e)
    }
}
```

Simpler alternative: leave it as is and add a comment explaining that propagated errors do not include the header — also acceptable, since in those cases the client no longer has control over the response. Mark as a "deliberate decision" if that is the chosen path.

## Info

### IN-01: Dependency `tokio-tungstenite` declared but unused by the phase

**File:** `Cargo.toml:12`
**Issue:** `tokio-tungstenite = "0.21"` is declared in the manifest. A scope review (`grep -r "tokio_tungstenite\|tungstenite" src/`) finds no uses in Phase 2 nor in the rest of the crate (Nostr traffic flows via `nostr-sdk`). This is documented in `CLAUDE.md` as "declared but not used", but it still contributes to compile time and binary footprint.

**Fix:** Out of scope for this phase (no dep changes without explicit approval per the global CLAUDE.md). Tracked as a future improvement: if it really is unused anywhere in the crate, it can be removed in a dedicated cleanup phase.

---

### IN-02: APNs `apns-expiration` header missing from FCM silent payload

**File:** `src/push/fcm.rs:226-251` (`build_silent_payload_for_notify`)
**Issue:** The silent payload uses `apns-priority: 5` and `apns-push-type: background`, which is correct for silent wakes. However, it does not include `apns-expiration`. Apple explicitly recommends that silent pushes specify a TTL (with value 0 — deliver immediately or discard). Without `apns-expiration`, the default behaviour can vary by APNs operator configuration.

This is NOT a bug — the push is delivered — but an explicit `apns-expiration` increases delivery predictability and reduces the risk of "stale" pushes arriving on the device after the trade context has changed.

**Fix:** Add the header in `build_silent_payload_for_notify`:

```rust
"apns": {
    "headers": {
        "apns-priority": "5",
        "apns-push-type": "background",
        "apns-expiration": "0"
    },
    ...
}
```

Treat as an optional, non-blocking improvement.

---

### IN-03: Redundant re-derivation of `log_pubkey` inside the spawn

**File:** `src/api/notify.rs:64, 81`
**Issue:** `log_pk` is already derived on line 64 (outer handler) and is available as a `String` capturable by value. Line 81 recomputes it inside the `tokio::spawn` (`task_log_pk = log_pubkey(&salt, &pubkey)`). The computation is deterministic (salt and pubkey do not change), so the result is identical to the one already derived.

The comment on lines 79-80 justifies the re-derivation: "to keep task-side log lines independent of outer-scope state". This is defensible stylistically, but since the salt and pubkey are ALREADY moved into the spawn via `Arc::clone` and `clone()`, the outer `log_pk` could equally have been `clone()`-ed into the spawn.

Cost: one extra `blake3::keyed_hash` call per request. With 50 permits and sustained throughput that is ~50/sec of redundant hashes — negligible, but free.

**Fix:** Keep the current implementation if the "state independence" justification is valued — it is defensible. If economy is preferred:

```rust
let log_pk_for_task = log_pk.clone(); // or reuse the same binding
tokio::spawn(async move {
    let _permit = permit;
    if let Some(token) = token_store.get(&pubkey).await {
        match dispatcher.dispatch_silent(&token).await {
            Ok(_) => info!("notify: dispatched pk={}", log_pk_for_task),
            Err(e) => warn!("notify: dispatch failed pk={} err={}", log_pk_for_task, e),
        }
    }
});
```

Not a bug; optional.

---

### IN-04: Pubkey validation accepts mixed case

**File:** `src/api/notify.rs:54` and `src/api/routes.rs:98, 159`
**Issue:** Validation is `len() == 64 && hex::decode(...).is_ok()`. `hex::decode` accepts both lowercase and uppercase (`0xab` and `0xAB` decode to the same value). This means `"ABCDEF...123"` and `"abcdef...123"` represent the same pubkey but yield distinct `log_pubkey` correlators (BLAKE3 hashes the UTF-8 bytes, not the decoded value).

This can cause "ghost pubkeys" in logs: the same device with the same pubkey under different capitalisations will appear as two distinct correlators. The runbook `docs/verification/dispute-chat.md:137` already lists "no mixed upper/lower case" as an operational precondition, which confirms awareness of the issue.

Likewise, no `.to_lowercase()` is applied before `token_store.get(&pubkey)`, so a client that registers with `"abc..."` and notifies with `"ABC..."` is treated as an unregistered pubkey (no match), and the handler returns 202 normally — privacy preserved, but the push does not arrive.

**Fix:** If the strict byte-for-byte behaviour is desired, document it. If normalisation is desired, normalise to lowercase after validation:

```rust
if req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err() {
    return HttpResponse::BadRequest().json(NotifyError { ... });
}
let trade_pubkey = req.trade_pubkey.to_lowercase();
let log_pk = log_pubkey(&state.notify_log_salt, &trade_pubkey);
// pass `trade_pubkey` into the spawn instead of `req.trade_pubkey.clone()`.
```

This is a behaviour change in `register_token` (`routes.rs:98`) too — coordination is required to keep both endpoints consistent (if one normalises, the other must as well, or the lookup fails).

Treat as an operational consistency issue, not a security one.

---

### IN-05: `SERVER_PRIVATE_KEY` hardcoded in `deploy-fly.sh`

**File:** `deploy-fly.sh:30`
**Issue:** The script ships a 64-character hex private key in plaintext. Per project memory, this is treated as "inert" because the crypto module is gated behind `#[allow(dead_code)]` and encryption is disabled.

The latent risk: if a future phase (Phase 4 / encryption enabled) reactivates the crypto path without regenerating and rotating the key in production, the service would ship with a private key that is publicly readable in the repo. The script also lives on operators' disks and can leak into backups or screenshots.

**Fix:** Tracked as a known risk. Before enabling Phase 4:
1. Generate a new private key in production.
2. Rotate via `flyctl secrets set SERVER_PRIVATE_KEY=...` from a secure channel (never via commit).
3. Remove the hardcoded line from `deploy-fly.sh` and replace it with a placeholder or an operator-provided env read.

No action required in this phase. Reported for stakeholder visibility.

---

### IN-06: Pre-existing dead-code warnings accumulating

**File:** multiple — `src/push/fcm.rs:51` (`config` unused), `src/push/unifiedpush.rs:23` (`config` unused field), `src/push/dispatcher.rs:12` (`backend` unused field), `src/utils/batching.rs:3` (`BatchingManager` unused), `src/store/mod.rs:108` (`count` unused), etc.
**Issue:** `cargo check` produces 21 warnings. Most are pre-existing (not introduced by this phase) and reflect code gated for future phases (`crypto/`, `batching.rs`) or fields unused under deserialization (`ServiceAccount.project_id`).

The specific issue introduced by Phase 2: `FcmPush::new(config: Config, ...)` and `UnifiedPushService::new(config: Config, ...)` receive a `Config` that is no longer stored in `FcmPush` (it reads from env directly on lines 52-54). The `config` parameter on `FcmPush::new` is completely unused — `cargo check` reports it as `warning: unused variable: config`.

**Fix:** For `FcmPush::new` specifically (introduced with the new signature in this phase):

```rust
// src/push/fcm.rs:51
pub fn new(_config: Config, client: Arc<reqwest::Client>) -> Self {
    // ... (rest unchanged)
}
```

Or remove the parameter from the signature if it is not planned for use (breaks the call site at `main.rs:73` — but that is the only invocation). Treat as optional cleanup.

For pre-existing warnings (`config` in `UnifiedPushService`, `BatchingManager`, etc.), they are out of scope for this review (artifacts of earlier phases).

---

_Reviewed: 2026-04-25_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
