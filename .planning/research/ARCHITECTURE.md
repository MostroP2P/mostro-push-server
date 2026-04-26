# Architecture Research — `POST /api/notify` integration

**Project:** mostro-push-server (milestone v1.1 — Chat notifications)
**Researched:** 2026-04-24
**Confidence:** HIGH on layering / build-order / data flow (grounded in repo); MEDIUM on `actix-governor` 0.5/0.6 API specifics (web verification blocked; based on training data up to Jan 2026 — flag for validation in `/gsd-plan-phase`).

> Note: This document was written by the orchestrator from findings returned inline by the `gsd-project-researcher` agent (the agent's environment denied writing `.md` artifacts and external WebSearch/WebFetch). Content is verbatim from the agent's report.

---

## Executive recommendation

Land the milestone in **three small commits**, in this order:

1. **Refactor**: introduce `PushDispatcher` (new module `src/push/dispatcher.rs`) and replace `Arc<Mutex<Vec<Box<dyn PushService>>>>` with `Arc<[Arc<dyn PushService>]>`. Both `NostrListener` and (next commit) the new HTTP handler become callers of the same dispatcher. This is **Option A + Option B combined** — they reinforce each other and the "fix" for the existing `Mutex` concern is essentially free once you're already touching the wiring.
2. **Endpoint**: add `POST /api/notify` handler that calls `PushDispatcher::dispatch`. Wire `Arc<PushDispatcher>` into `AppState`.
3. **Rate limit**: add per-IP `actix-governor` middleware on the `/api/notify` route (using a `Fly-Client-IP`-aware `KeyExtractor`), and add a per-pubkey limiter inside the handler reading from a shared `Arc<PerPubkeyLimiter>` in `AppState`. Per-pubkey cannot be middleware because the key is in the JSON body.

Per-IP gets rejected first (cheap, before body parsing); per-pubkey gets checked after body parse (necessarily, by the body-in-key constraint).

---

## Components — new vs modified vs untouched

### NEW

| Component | Location | Responsibility |
|-----------|----------|----------------|
| `PushDispatcher` | `src/push/dispatcher.rs` (new file, re-exported via `src/push/mod.rs`) | Owns `Arc<[Arc<dyn PushService>]>`. Single method: `async fn dispatch(&self, token: &RegisteredToken) -> Result<DispatchOutcome, DispatchError>`. Encapsulates the "find first matching `supports_platform`, call `send_to_token`, break on first success" loop currently inlined in the listener. |
| `DispatchOutcome` / `DispatchError` enum | same file | `Delivered { backend: &'static str }`, `NoBackendForPlatform`, `AllBackendsFailed { errors: Vec<String> }`. Lets the new HTTP handler return distinct status codes (`200` vs `502`) without leaking backend specifics. |
| `notify_token` handler | `src/api/routes.rs` (added) | Validates `trade_pubkey` (reuse the 64-hex-char check pattern), per-pubkey rate-limit check, `TokenStore::get`, `PushDispatcher::dispatch`, return `200` / `404` / `429` / `502`. |
| `NotifyRequest` / `NotifyResponse` DTOs | `src/api/routes.rs` | `{ "trade_pubkey": "<64-hex>" }` request, minimal `{ "success": bool, "message": "..." }` response (no per-backend leakage). |
| `PerPubkeyLimiter` | `src/api/rate_limit.rs` (new module under `api/`) | Wraps `governor::RateLimiter<String, DefaultKeyedStateStore<String>, ..>`. One method: `fn check(&self, pubkey: &str) -> Result<(), NotUntil<...>>`. Held in `AppState` as `Arc<PerPubkeyLimiter>`. |
| `FlyClientIpKeyExtractor` | `src/api/rate_limit.rs` | Custom `actix_governor::KeyExtractor` that reads `Fly-Client-IP` header (Fly-Proxy-injected; see fly.io docs), falls back to `PeerIpKeyExtractor`. Used by the per-IP middleware on `/api/notify` only. |

### MODIFIED

| File | Change | Lines |
|------|--------|-------|
| `src/main.rs` | Replace `let push_services = Arc::new(Mutex::new(push_services));` (line 79) with `let dispatcher = Arc::new(PushDispatcher::new(push_services_vec));`. Pass `dispatcher.clone()` into both `NostrListener::new` and `AppState`. Drop `use tokio::sync::Mutex` (line 4) if no other Mutex remains. | 4, 46, 79, 82-86, 93-95 |
| `src/api/routes.rs` | Extend `AppState` (line 36-39) with `dispatcher: Arc<PushDispatcher>` and `per_pubkey_limiter: Arc<PerPubkeyLimiter>`. Add the new route in `configure` (line 41-49) wrapped with `Governor::new(...)` for per-IP. Add `notify_token` handler. | 36-49, +new handler |
| `src/nostr/listener.rs` | Replace the field type `push_services: Arc<Mutex<Vec<Box<dyn PushService>>>>` (line 14) with `dispatcher: Arc<PushDispatcher>`. Replace the inline loop at lines 119-135 with a single `self.dispatcher.dispatch(&registered_token).await` call and log the outcome. | 14, 22, 36, 87, 119-135 |
| `src/push/mod.rs` | Add `pub mod dispatcher;` and `pub use dispatcher::{PushDispatcher, DispatchOutcome, DispatchError};` | 4-8 |
| `src/api/mod.rs` | Add `pub mod rate_limit;` | new line |
| `Cargo.toml` | Add `actix-governor = "0.5"` (or `"0.6"` if a release with `KeyExtractor` API present in 0.5 ships before phase work — confirm during `/gsd-plan-phase`). `governor = "0.6"` is already declared (line 41). MEDIUM confidence on the version pin — verify the API matches before committing. | line 41 area |

### UNTOUCHED

- `src/push/fcm.rs`, `src/push/unifiedpush.rs` — concrete backends keep the same `PushService` trait surface.
- `src/store/mod.rs`, `src/config.rs` (new env vars optional; can reuse existing `RATE_LIMIT_PER_MINUTE` for one of the limits and add `NOTIFY_RATE_LIMIT_PER_PUBKEY_PER_MINUTE` later if needed).
- `src/crypto/`, `src/utils/batching.rs` — out of scope (per PROJECT.md "Out of Scope").
- All existing routes (`/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister`).

---

## Data flow — `POST /api/notify`

```
Mobile client (User A — sender)
        |  HTTP POST /api/notify  { "trade_pubkey": "<peer B's tradeKey.public>" }
        v
Fly Proxy (terminates TLS, injects Fly-Client-IP header)
        |
        v
HttpServer (src/main.rs:107-114)
        |
        v
[per-IP middleware: actix-governor wrap on /api/notify scope]
        |   FlyClientIpKeyExtractor reads Fly-Client-IP, falls back to peer addr
        |   429 + Retry-After here if IP exceeds quota (BEFORE body parse — cheap)
        v
notify_token handler (src/api/routes.rs)
        |   1. web::Json<NotifyRequest> body parse + serde validation
        |   2. validate trade_pubkey: 64 hex chars (reuse pattern from register_token:86)
        |       -> 400 if invalid
        |   3. per-pubkey limiter check: state.per_pubkey_limiter.check(&req.trade_pubkey)
        |       -> 429 + Retry-After if exceeded
        |   4. token lookup: state.token_store.get(&req.trade_pubkey).await
        |       -> 404 if None  (do NOT differentiate "not registered" vs "rate limited";
        |          reveals registration status. Consider returning 202 for both — design
        |          decision for /gsd-plan-phase.)
        |   5. dispatch: state.dispatcher.dispatch(&registered_token).await
        v
PushDispatcher::dispatch (src/push/dispatcher.rs)
        |   - iterate self.services (Arc<[Arc<dyn PushService>]> — no lock)
        |   - first service.supports_platform(&token.platform) wins
        |   - service.send_to_token(&token.device_token, &token.platform).await
        |   - return Delivered { backend: "fcm" } | NoBackendForPlatform | AllBackendsFailed
        v
Concrete backend (FcmPush or UnifiedPushService) — UNCHANGED
        |  outbound HTTPS to FCM v1 / UnifiedPush distributor
        v
notify_token returns:
        200 { "success": true }     on Delivered
        404 { "success": false }    on token_store miss   (or 202 to hide existence)
        429 + Retry-After           on rate-limit (IP or pubkey)
        502 { "success": false }    on AllBackendsFailed
```

The Nostr-driven path (current behaviour) flows through the same `PushDispatcher::dispatch`:

```
NostrListener::handle_notifications closure (src/nostr/listener.rs:90-146)
        |  extracts p tag -> trade_pubkey
        |  token_store.get(&trade_pubkey)
        |  dispatcher.dispatch(&registered_token).await   <-- shared with HTTP path
        v  (logs outcome; no caller waiting for a response)
```

---

## Open architectural questions — recommendations

### Q1. Refactor the dispatch ownership

**Recommendation: Option A + Option B combined.** Introduce `PushDispatcher` AND change the underlying storage to `Arc<[Arc<dyn PushService>]>`.

Rationale:
- **Option A alone** (just lift the loop into a helper) leaves the `Mutex<Vec<Box<...>>>` in place. CONCERNS.md explicitly flags this as a performance bottleneck ("`Mutex<Vec<Box<dyn PushService>>>` serializes all delivery", lines 139-142). Two callers contending the same Mutex makes it worse, not better.
- **Option B alone** (just swap the container) doesn't deduplicate the loop; both callers still need to know the iteration protocol.
- **Combined**, the Mutex disappears (the vector is read-only after `main.rs` startup — no one mutates it at runtime), reads become lock-free (`Arc<[T]>` is `Clone` + `Sync`), AND the iteration protocol lives in one place.
- **Option C (mpsc worker)** is overkill for this milestone. It's the right design once you also want backpressure, retries, batching, and per-event spawning (CONCERNS.md "Single-task event loop blocks on each push", lines 130-133). Defer it; recommend mentioning explicitly in PITFALLS for a future scaling milestone.

Idiomatic Rust shape:

```rust
// src/push/dispatcher.rs
pub struct PushDispatcher {
    services: Arc<[Arc<dyn PushService>]>,
}

impl PushDispatcher {
    pub fn new(services: Vec<Arc<dyn PushService>>) -> Self {
        Self { services: services.into() }  // Vec<T> -> Arc<[T]>
    }

    pub async fn dispatch(&self, token: &RegisteredToken) -> Result<DispatchOutcome, DispatchError> {
        let mut errors = Vec::new();
        for svc in self.services.iter() {
            if !svc.supports_platform(&token.platform) { continue; }
            match svc.send_to_token(&token.device_token, &token.platform).await {
                Ok(()) => return Ok(DispatchOutcome::Delivered),
                Err(e) => errors.push(e.to_string()),
            }
        }
        if errors.is_empty() {
            Err(DispatchError::NoBackendForPlatform)
        } else {
            Err(DispatchError::AllBackendsFailed(errors))
        }
    }
}
```

The `Vec<Box<dyn PushService>>` in `main.rs:46` becomes `Vec<Arc<dyn PushService>>` — trivial change since the existing blanket `impl PushService for Arc<FcmPush>` / `impl PushService for Arc<UnifiedPushService>` (`src/push/mod.rs:27-63`) means the existing `Box::new(Arc::clone(&fcm_service))` calls collapse to just `Arc::clone(&fcm_service) as Arc<dyn PushService>`.

### Q2. Where does the rate limiter live?

**Recommendation: split — middleware for per-IP, handler-level shared state for per-pubkey.**

- **Per-IP**: per-route `wrap()` middleware (`actix_governor::Governor`) on the `/api/notify` route only. Idiomatic Actix-web 4.x. Fires before the handler, before body parsing — cheap rejection of floods.
- **Per-pubkey**: cannot be middleware because the key is in the JSON body. Reading the body inside middleware works (you'd extract via `Payload`/`Bytes`, then put it back) but it's awkward, fragile, and pays the body-parsing cost twice. Handler-level is cleaner.

Don't make per-pubkey a middleware:

> A custom middleware that pre-reads the body would have to (a) consume `actix_web::dev::Payload`, (b) buffer it into `Bytes`, (c) `serde_json::from_slice` to pull `trade_pubkey`, (d) reconstruct a `Payload` from the buffered bytes for the downstream handler to re-parse. That doubles parse cost, blocks on a fully-buffered body inside middleware, and entangles error handling (what if the body isn't JSON? Middleware would 400 before the handler even runs, changing failure surface). Handler-level pays for itself in clarity.

### Q3. Per-pubkey limiter shape

**Recommendation:** wrap `governor::RateLimiter<String, DefaultKeyedStateStore<String>, MonotonicClock>` (or whichever clock `governor` defaults to in 0.6) in a small `PerPubkeyLimiter` struct held as `Arc<PerPubkeyLimiter>` in `AppState`. Handler does:

```rust
match state.per_pubkey_limiter.check(&req.trade_pubkey) {
    Ok(()) => { /* proceed */ }
    Err(not_until) => {
        let retry_after = not_until.wait_time_from(/* now */);
        return HttpResponse::TooManyRequests()
            .insert_header(("Retry-After", retry_after.as_secs().to_string()))
            .json(serde_json::json!({"success": false, "message": "rate limited"}));
    }
}
```

Confidence: MEDIUM on the `governor` 0.6 keyed-rate-limiter API surface; verify exact method names (`check_key` vs `check`) and `Quota` builder during `/gsd-plan-phase`. The conceptual shape (keyed rate limiter, GCRA) is HIGH confidence.

Memory budget: keyed `governor` stores ~128 bytes per active key (rough; depends on `DefaultKeyedStateStore` impl). At Fly's 25-connection cap and 512MB RAM, this is non-issue even with thousands of distinct pubkeys. Add a periodic cleanup or rely on `governor`'s internal `shrink_to_fit` if the API exposes one — verify in plan-phase.

### Q4. Per-IP `KeyExtractor` for Fly.io

**Recommendation:** custom `KeyExtractor` that reads `Fly-Client-IP` first, falls back to `actix_governor::PeerIpKeyExtractor`.

Fly's edge proxy injects `Fly-Client-IP` (it's the documented header for the originating client IP; `X-Forwarded-For` is also populated but `Fly-Client-IP` is the canonical single-value form on Fly). Without this, every request appears to come from the Fly proxy's internal address — effectively one bucket for all traffic, breaking per-IP limiting entirely.

Sketch:

```rust
pub struct FlyClientIpKeyExtractor;

impl KeyExtractor for FlyClientIpKeyExtractor {
    type Key = IpAddr;
    type KeyExtractionError = SimpleKeyExtractionError<&'static str>;

    fn extract(&self, req: &ServiceRequest) -> Result<Self::Key, Self::KeyExtractionError> {
        if let Some(hv) = req.headers().get("Fly-Client-IP") {
            if let Ok(s) = hv.to_str() {
                if let Ok(ip) = s.parse::<IpAddr>() { return Ok(ip); }
            }
        }
        // Fallback for local/non-Fly deployments
        req.peer_addr()
            .map(|a| a.ip())
            .ok_or_else(|| SimpleKeyExtractionError::new("missing peer addr"))
    }
}
```

**Trust note:** `Fly-Client-IP` is only trustworthy because all ingress traffic to a Fly machine routes through the Fly edge proxy (Fly's network architecture; verify in fly.toml that no direct port is exposed bypassing the proxy — `fly.toml` already has `force_https = true` per CONCERNS.md context). For non-Fly deployments (Docker Compose, local dev), `peer_addr()` is the correct fallback. Document this in CONCERNS for the deploy-section.

Confidence: MEDIUM on the exact `actix-governor` `KeyExtractor` API names (`extract` signature, `SimpleKeyExtractionError`); HIGH on the architectural pattern (read trusted header, fall back to peer addr).

### Q5. Fix existing CONCERNS-flagged issues during this refactor, or defer?

| Concern (from CONCERNS.md) | Recommendation | Why |
|----------------------------|----------------|-----|
| `Mutex<Vec<Box<dyn PushService>>>` serializes all delivery (lines 139-142) | **Fix** in commit 1 (refactor) | Unavoidably touched. Going from `Mutex<Vec<Box<...>>>` to `Arc<[Arc<dyn PushService>]>` is the same lines you're already editing. Negative cost. |
| `reqwest::Client::new()` per service (lines 134-137) | **Defer** | Touches `FcmPush::new` and `UnifiedPushService::new` constructors and their `reqwest` initialization paths. Out of scope for chat notifications. Document in PITFALLS as a future "outbound HTTP hardening" milestone. |
| Single-task event loop blocks on each push (lines 130-133) | **Defer** | Fixing requires `tokio::spawn` per event in the listener and proper backpressure. The new HTTP path doesn't suffer (Actix runs handlers concurrently across worker threads natively). The Nostr-side serialization remains a known issue. Document. |
| FCM access-token cache double-check race (lines 144-147) | **Defer** | Independent of this milestone. Minor (extra OAuth call under contention). |
| `send_silent_push` trait method never invoked | **Defer** | Don't touch the trait surface in this milestone. The new endpoint uses `send_to_token`, same as the listener. |
| `RATE_LIMIT_PER_MINUTE` config unused (lines 44-48) | **Resolve** by wiring it into the per-IP and/or per-pubkey limiter quotas in commit 3 | The whole milestone is about rate limiting; this concern dissolves naturally. Add a second env var like `NOTIFY_RATE_LIMIT_PER_PUBKEY_PER_MINUTE` if quotas should differ. |

The general principle: only fix concerns that would otherwise be re-introduced or made worse by the milestone. Everything else stays as-is and is documented in PITFALLS so future milestones can pick them up cleanly.

### Q6. Build order — sequenced for safe phase transitions

**Phase 1 — Refactor `PushDispatcher` (no behaviour change).**
- New file `src/push/dispatcher.rs` with `PushDispatcher`, `DispatchOutcome`, `DispatchError`.
- Modify `src/main.rs:46-79` to build `Vec<Arc<dyn PushService>>` and wrap in `Arc<PushDispatcher>`.
- Modify `src/nostr/listener.rs:14, 22, 119-135` to call `dispatcher.dispatch(...)` instead of inline loop.
- Verify: existing Gift Wrap → push flow still works end-to-end. Same logs, same outcomes.
- Commit message hint: `refactor(push): extract PushDispatcher and replace Mutex with Arc<[Arc<dyn>]>`.
- This phase resolves the existing CONCERNS Mutex issue and prepares the seam for the next phase.

**Phase 2 — Add `POST /api/notify` (no rate limit yet).**
- Add `Arc<PushDispatcher>` field to `AppState` (`src/api/routes.rs:36-39`).
- Pass `dispatcher.clone()` from `main.rs:93-95`.
- Add `NotifyRequest` DTO and `notify_token` handler.
- Add route in `configure` (`src/api/routes.rs:41-49`).
- Verify with curl: `POST /api/notify { trade_pubkey: ... }` → registered pubkey returns 200 and a push reaches the device; unregistered returns 404.
- Commit hint: `feat(api): add POST /api/notify endpoint`.

**Phase 3 — Layer rate limits on `/api/notify`.**
- Add `actix-governor` to `Cargo.toml` (after explicit user approval per global CLAUDE.md).
- Add `src/api/rate_limit.rs` with `FlyClientIpKeyExtractor` and `PerPubkeyLimiter`.
- Wire `Arc<PerPubkeyLimiter>` into `AppState` and construct in `main.rs`.
- Wrap `/api/notify` route with `Governor::new(...)` per-IP middleware.
- Add per-pubkey check at the start of `notify_token` handler.
- Verify: flood from one IP → 429 at middleware; many IPs flooding one pubkey → 429 from handler; legitimate single request → 200.
- Commit hint: `feat(api): rate limit /api/notify per-IP and per-trade_pubkey`.

**Why this order:**
- Phase 1 first: refactor with no API change is the safest revertible commit. If something breaks, you revert one commit and you're back to known-good.
- Phase 2 before Phase 3: get the endpoint working end-to-end so you know the contract matches mobile's expectation, *then* add the protective layer. Adding rate limiting to a non-functional endpoint hides which layer broke when something fails.
- Phase 3 last: rate limiting is the most likely place for "works in dev, mysteriously rejects in prod" surprises (Fly-Client-IP, clock skew, quota tuning). Land it independently so any rollback is surgical.

---

## Risks / pitfalls flagged for downstream

1. **`actix-governor` API verification needed.** Versions 0.5 and 0.6 had `KeyExtractor` API differences. Confirm the exact trait signatures during `/gsd-plan-phase` against the crate docs. (LOW confidence on API specifics; HIGH on the pattern.)
2. **Information disclosure via 404 vs 200.** Returning 404 for "no token registered" tells an attacker which `trade_pubkey`s have notifications enabled. Consider returning 202 for both registered-and-dispatched and not-registered. Decision belongs in `/gsd-plan-phase` (PROJECT.md hints at 200/404/429 as the contract — confirm with mobile team).
3. **Per-pubkey limiter memory growth.** Unbounded set of `trade_pubkey`s could accumulate state. Fly cap is 512MB, so this is unlikely to bite in practice, but a `governor` keyed-store cleanup or periodic `shrink` should be evaluated.
4. **Nostr listener still blocks per push.** This refactor does NOT spawn per-event tasks. The Nostr side keeps its serial behaviour (already a known issue in CONCERNS). The new HTTP side benefits from Actix's worker concurrency natively.
5. **Trust boundary on `Fly-Client-IP`.** Only valid when traffic always traverses Fly's edge proxy. Document for non-Fly deployments. Consider a config flag `TRUST_FLY_CLIENT_IP=true|false` if you want to be defensive.
6. **`Box<dyn Error>` mismatch.** Existing `PushService::send_to_token` returns `Box<dyn std::error::Error>` (not `Send + Sync`). The dispatcher will need to convert these to strings (`e.to_string()`) for `AllBackendsFailed.errors`, same workaround currently used elsewhere. Don't try to fix the trait error type in this milestone (it cascades into FCM and UnifiedPush). Defer to a future "error-types hygiene" milestone.

---

## Files referenced (absolute paths)

- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/src/main.rs` — lines 4, 46, 79, 82-86, 93-95 (modified)
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/src/api/routes.rs` — lines 36-49 (modified), new `notify_token` handler appended
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/src/nostr/listener.rs` — lines 14, 22, 36, 87, 119-135 (modified)
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/src/push/mod.rs` — lines 4-8 (modified, add `pub mod dispatcher`)
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/src/push/dispatcher.rs` — new
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/src/api/rate_limit.rs` — new
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/src/api/mod.rs` — add `pub mod rate_limit;`
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/Cargo.toml` — add `actix-governor` (requires explicit user approval per global CLAUDE.md)
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/src/store/mod.rs` — UNTOUCHED
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/src/push/fcm.rs`, `src/push/unifiedpush.rs` — UNTOUCHED
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/src/config.rs` — UNTOUCHED in this milestone

---

## Notes on what was NOT verified

- `actix-governor` 0.5/0.6 documentation could not be fetched from the web (sandbox denied `WebSearch`/`WebFetch`/Bash). All `actix-governor` API specifics (`KeyExtractor` trait signature, `Governor::new` builder shape, `SimpleKeyExtractionError`) are from training data and should be re-verified against current crate docs in `/gsd-plan-phase` before writing the implementation.
- The agent's environment denied reading the official template at `$HOME/.claude/get-shit-done/templates/research-project/ARCHITECTURE.md`. Structure follows the prompt's `<downstream_consumer>` checklist (component boundaries, data flow, integration points, build order, per-question recommendations).
