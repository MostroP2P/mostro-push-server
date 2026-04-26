---
phase: 03-dual-keyed-rate-limiting-and-verification-harness
reviewed: 2026-04-25T00:00:00Z
depth: standard
files_reviewed: 7
files_reviewed_list:
  - src/api/rate_limit.rs
  - src/api/mod.rs
  - src/api/notify.rs
  - src/api/routes.rs
  - src/api/test_support.rs
  - src/config.rs
  - src/main.rs
findings:
  critical: 0
  warning: 3
  info: 2
  total: 5
status: issues_found
---

# Phase 03: Code Review Report

**Reviewed:** 2026-04-25
**Depth:** standard
**Files Reviewed:** 7
**Status:** issues_found

## Summary

Phase 03 introduces dual-keyed rate limiting via governor and an in-process integration test harness. The implementation is solid overall: the IP extraction precedence chain is correct (Fly-Client-IP > rightmost-XFF > peer_addr), the fail-closed behaviour on IP extraction failure is implemented, the 429 body is byte-identical between both paths by routing through a single `rate_limited_response` helper, the per-pubkey GCRA cleanup task mirrors the token-store pattern, and privacy-safe logging via `log_pubkey` is applied consistently throughout the new handler.

Three findings require attention before closing the phase. Two are warnings: a middleware ordering issue that causes per-IP 429 responses to lack `x-request-id` while per-pubkey 429 responses carry it (header drift between the two 429 paths, which the review context calls a finding), and a dead variable in `config.rs` that silently uses a different default pubkey from the one assigned to `NostrConfig`. The third warning is a log injection risk from user-supplied platform strings being logged verbatim. Two informational items cover a misleading comment and unsanitised platform content in the error response body.

---

## Warnings

### WR-01: Per-IP 429 lacks `x-request-id`; per-pubkey 429 carries it — header drift between paths

**File:** `src/api/routes.rs:61-63`

**Issue:** In actix-web 4, `web::resource().wrap()` applies middleware in reverse-registration order: the **last** `.wrap()` call is outermost (executes first). With the current registration:

```rust
.wrap(from_fn(request_id_mw))        // registered first → innermost
.wrap(from_fn(per_ip_rate_limit_mw)) // registered second → outermost
```

`per_ip_rate_limit_mw` executes before `request_id_mw`. When it short-circuits with a 429, `request_id_mw` never runs, so the response carries no `x-request-id` header. A per-pubkey 429 is returned from inside `notify_token`, which `request_id_mw` does process, so that response carries the header. An attacker can distinguish which limiter fired by checking for the header's presence — this is precisely the oracle the review context marks as a finding ("any drift in body/headers between the two paths is a finding").

**Fix:** Swap the `.wrap()` call order so `request_id_mw` is outermost and always runs regardless of which layer produces the 429:

```rust
.wrap(from_fn(per_ip_rate_limit_mw)) // registered first → innermost
.wrap(from_fn(request_id_mw))        // registered second → outermost
```

After this change, both 429 paths will carry a server-generated `x-request-id`. Add a test asserting the header is present on a per-IP 429 response (the existing `per_ip_burst_exhaustion_returns_429` test can be extended).

---

### WR-02: Dead variable `let mostro_pubkey` in `config.rs` with divergent default

**File:** `src/config.rs:70-82`

**Issue:** `Config::from_env` reads `MOSTRO_PUBKEY` twice with two different hard-coded fallbacks:

- Line 70 (dead variable, never referenced again): default `"82fa8cb978b43c79b2156585bac2c011176a21d2aead6d9f7c575c005be88390"`
- Line 81 (`NostrConfig::mostro_pubkey`, the value actually used): default `"dbe0b1be7aafd3cfba92d7463571bf438f09d24f4e021d9fe208ed0ab5823711"`

When `MOSTRO_PUBKEY` is not set, `NostrConfig` receives the second default — a completely different key than what the comment at line 69 claims. The dead variable will cause a compiler warning (`unused variable`) and the divergent defaults could confuse operators reading the code or the config template.

**Fix:** Remove the dead variable and use the local binding in `NostrConfig`:

```rust
let mostro_pubkey = env::var("MOSTRO_PUBKEY")
    .unwrap_or_else(|_| "dbe0b1be7aafd3cfba92d7463571bf438f09d24f4e021d9fe208ed0ab5823711".to_string());

Ok(Config {
    nostr: NostrConfig {
        relays,
        subscription_id: "mostro-push-listener".to_string(),
        event_kinds: vec![1059],
        mostro_pubkey,
    },
    // ...
})
```

Agree on a single canonical default and document it in `.env.example`.

---

### WR-03: User-supplied `platform` string logged verbatim — log injection

**File:** `src/api/routes.rs:128`

**Issue:**

```rust
warn!("Invalid platform: {}", req.platform);
```

`req.platform` is an arbitrary user-supplied string. If it contains newline characters (`\n`), ANSI escape codes, or other control characters, a crafted request can inject fake log lines or corrupt the log output, potentially causing operators to misread the server state.

**Fix:** Either (a) truncate and sanitise before logging, or (b) log only a fixed-length representation that strips control characters:

```rust
let safe_platform = req.platform
    .chars()
    .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
    .take(32)
    .collect::<String>();
warn!("Invalid platform: {}", safe_platform);
```

The error response body at line 131 has the same issue but is lower risk (the value only travels back to the requester, not into logs).

---

## Info

### IN-01: Misleading comment claims `request_id_mw` is outermost

**File:** `src/api/notify.rs:298`

**Issue:** The comment `"request_id_mw is outermost"` is incorrect given the actual middleware registration order in `routes.rs`. As described in WR-01, `per_ip_rate_limit_mw` is currently outermost. The comment should be updated in tandem with the WR-01 fix to reflect the corrected order.

**Fix:** After applying the WR-01 fix (swapping wrap order), update the comment to:

```
"request_id_mw is outermost — always runs, even when per_ip_rate_limit_mw fires 429"
```

---

### IN-02: User-supplied `platform` string reflected verbatim in error response body

**File:** `src/api/routes.rs:131`

**Issue:**

```rust
message: format!("Invalid platform '{}' (expected 'android' or 'ios')", req.platform),
```

This reflects the raw user input back to the caller. While the risk is low (the value only returns to the sender), it is inconsistent with the project's approach of not echoing unvalidated input. A crafted platform value containing HTML or JSON metacharacters could confuse clients that render the message string.

**Fix:** Return a fixed message that does not include the user-supplied value:

```rust
message: "Invalid platform (expected 'android' or 'ios')".to_string(),
```

---

_Reviewed: 2026-04-25_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
