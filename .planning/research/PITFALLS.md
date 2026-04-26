# PITFALLS — Sender-Triggered Notify Endpoint (Mostro Push Server v1.1)

**Domain:** Sender-triggered, unauthenticated `POST /api/notify` with dual-keyed (per-pubkey + per-IP) rate limiting added to a privacy-preserving Rust/Actix-web push notification server.
**Researched:** 2026-04-24
**Confidence:** HIGH for items grounded in the codebase (file/line citations); MEDIUM for FCM/iOS delivery semantics and Fly proxy header behavior (based on stable published guidance but should be re-verified at implementation phase — web search was unavailable in this run).

> Note: This document was written by the orchestrator from findings returned inline by the `gsd-project-researcher` agent (the agent's environment denied writing `.md` artifacts and external WebSearch/WebFetch). Content is verbatim from the agent's report.

---

## Critical Pitfalls

### CRIT-1: Adding a `mostro_pubkey` author filter to the Nostr listener as a "fix" for spurious events

**What goes wrong:** A reviewer reads `.planning/codebase/CONCERNS.md` lines 20-24 ("Mostro author filter not actually applied") and proposes filtering kind 1059 events by `author = mostro_pubkey` to close the spam vector. This silently breaks dispute chat: admin DMs are sent **directly user-to-user**, not via the Mostro daemon. After the change, dispute notifications stop arriving and nobody notices because there are no integration tests and disputes are rare. P2P chat (the entire purpose of v1.1) also breaks because peers send their own events.

**Why it happens:** The naming `mostro_pubkey` and commit `1f848fb` ("filter Nostr events by Mostro instance public key") suggest the filter was *meant* to be applied. The codebase even validates `MOSTRO_PUBKEY` at startup (`src/nostr/listener.rs:25-39`) but never uses it — looks like a forgotten TODO. Furthermore, Gift Wrap (kind 1059) uses **ephemeral one-time keys for the outer wrap** (NIP-59), so even if you wanted to filter by Mostro identity, the outer `event.pubkey` is never the Mostro daemon — the filter would drop *everything*. The check is structurally impossible without decrypting the rumor.

**Prevention (concrete):**
- Add a comment block above the filter in `src/nostr/listener.rs:73-83` that explains *why* author filtering is impossible (Gift Wrap ephemeral keys + admin DMs not routed through Mostro), with a `// DO NOT add .authors(...) here, see PROJECT.md anti-requirement` directive.
- Either delete the now-dead `mostro_pubkey` config field and validation (`src/config.rs:60-72`, `src/nostr/listener.rs:25-39`) or repurpose the name (the codebase analysis already recommends deletion).
- Add a roadmap audit step that greps the diff for `.authors(` in the listener file and fails review if introduced.

**Detection (warning signs):**
- Diff in `src/nostr/listener.rs` adds `.authors(...)` to the `Filter::new()` chain.
- A new env var like `MOSTRO_AUTHOR_FILTER_ENABLED` appears in `src/config.rs`.
- Manual smoke test: after deploy, send a Mostro-daemon-originated event AND an admin-originated DM to a registered `tradeKey` — both must produce a push.

**Phase mapping:** Add this anti-requirement to the **Phase 1 plan** (the listener-side phase) as an explicit "DO NOT" check, and to the **final Phase audit** as a `git diff` grep.

---

### CRIT-2: Distinguishing 200 vs 404 on `/api/notify` enables pubkey enumeration

**What goes wrong:** Naive implementation looks up `trade_pubkey` in `TokenStore`, returns `200` if found and `404` if missing. An attacker who knows or guesses a `trade_pubkey` can enumerate **which Mostro users have registered for push** by polling and observing the status code. This leaks the entire `tradeKey → registered` set even though tokens themselves remain unreachable.

**Why it happens:** REST convention says "404 = resource not found", and the existing `register_token` handler (`src/api/routes.rs:78-137`) returns differentiated status codes for validation failures. A developer following local convention will produce a differentiated 200/404 by reflex.

**Consequences:** Adversary builds a registered-user oracle. Combined with on-chain trade history (Mostro is a P2P trading network — pubkeys appear in trade events), this links trade activity to "user has the mobile app + push enabled". Timing differential between hit and miss remains exploitable: `TokenStore::get` (`src/store/mod.rs:85-88`) under `RwLock<HashMap>` is not constant-time, and a hit triggers an FCM dispatch that shows up as cross-correlatable network egress.

**Prevention (concrete):**
- Always return `202 Accepted { "accepted": true }`, regardless of hit/miss. Never reveal whether a token exists. The mobile client cannot register on the recipient's behalf, so it has no actionable response to "no token registered".
- Push dispatch must happen **after** the response is sent (or in a `tokio::spawn` decoupled from the response future) so response latency does not encode hit/miss.
- Apply the rate limiter (RL-* below) *before* the lookup, so a 429 is returned without consuming a lookup. 429 must also not depend on registration status (see RL-2).
- Document in handler doccomment that 200/404 differentiation is **forbidden**.

**Detection (warning signs):**
- Code review: any `match token_store.get(...)` that branches into different `HttpResponse::*().json(...)` calls.
- Integration test: two requests, one with a known-registered pubkey and one with a known-unregistered pubkey, must produce byte-identical responses (modulo a per-request timestamp/UUID if any) and similar latency distributions.

**Phase mapping:** **Endpoint design phase** (handler signature + response contract). Add a verification step in the **integration test phase** that asserts byte-equality of hit vs miss responses.

---

### CRIT-3: Logging `trade_pubkey` (or its 16-char prefix) at INFO/DEBUG correlates user identity with IP in production

**What goes wrong:** The current handlers log `trade_pubkey[..16]` at INFO (`src/api/routes.rs:82-83, 126-130, 143-144` and `src/store/mod.rs:58-62, 70-73, 76-79`). The listener also logs the prefix at INFO (`src/nostr/listener.rs:108, 112-116, 137`). A 16-char hex prefix is **64 bits of entropy** — sufficient to uniquely identify a `trade_pubkey` in any practical user set. Combined with `RUST_LOG="debug"` set by `deploy-fly.sh:42`, Fly's request log adds source IP + timestamp. The operator (and anyone with log access) can build `trade_pubkey ↔ IP` mappings, breaking the privacy model.

For `/api/notify`, this is **strictly worse**: the sender's IP gets logged alongside the recipient's `trade_pubkey`, leaking `sender_IP ↔ recipient_tradeKey` — exactly the linkability the unauthenticated design exists to prevent.

**Why it happens:** The 16-char prefix "feels safe" (only a quarter of the full key). It's not. The new endpoint will inherit the same pattern by copy-paste from `register_token`.

**Prevention (concrete):**
- For the new endpoint, log **only a salted truncated hash**, never the pubkey or its prefix. Concrete: `BLAKE3::hash(format!("notify-log-v1:{pubkey}").as_bytes()).to_hex()[..8]`. The salt prefix prevents cross-endpoint correlation.
- Do **not** log the source IP at all in application code; rely on Fly's HTTP access log.
- Demote all existing `info!("...trade_pubkey: {}...")` lines that the new endpoint touches to `debug!`, and use the hash form.
- Bundle the deploy-script change `RUST_LOG="debug"` → `RUST_LOG="info"` (`deploy-fly.sh:42`) into this milestone — otherwise the new endpoint's clean logging is meaningless because the existing FCM/UnifiedPush `debug!` lines (`src/push/fcm.rs:283`, `src/push/unifiedpush.rs:176`) leak token prefixes.
- Reviewer checklist: any `debug!`/`info!` referencing `trade_pubkey`, `pubkey`, `token`, `device_token`, or `endpoint` must use the hash helper.

**Detection (warning signs):**
- `rg 'trade_pubkey\[' src/` after the change should return zero hits in `info!`/`debug!`/`warn!` macros.
- Staging deploy with a known test `trade_pubkey` + `flyctl logs | grep <prefix>` reveals leakage.

**Phase mapping:** **Endpoint implementation phase** (introduce `log_pubkey(pk: &str) -> String` helper). Bundle the `RUST_LOG="info"` deploy-script change into the same phase.

---

### CRIT-4: Trusting `X-Forwarded-For` without restricting to Fly's proxy makes per-IP rate limiting trivially bypassable

**What goes wrong:** `actix-governor` needs an IP key. The naive choice is `X-Forwarded-For` or `Fly-Client-IP` from request headers. If the handler trusts whatever the *client* sends (because `req.peer_addr()` returns the immediate TCP peer = Fly's edge proxy, the same for all requests), an attacker can inject `X-Forwarded-For: 1.2.3.4` and rotate per request, bypassing the per-IP limiter entirely.

**Why it happens:** Actix's default `PeerIpKeyExtractor` collapses all traffic behind Fly to one IP (global limit instead of per-IP). The reflexive fix is `X-Forwarded-For` directly — that header is **client-controllable**.

**Consequences:** Per-IP limiter becomes a no-op; only the per-pubkey limit defends. An attacker can hammer many pubkeys (DoS the pubkey-limiter map, see RL-1). Per-pubkey-per-IP composite keys collapse to a single bucket per pubkey.

**Prevention (concrete):**
- Use `Fly-Client-IP` (Fly's proxy strips and rewrites this header on every request — it is *not* client-passthrough). Confidence: MEDIUM (verify against Fly's current docs at plan time).
- If using `X-Forwarded-For`, take **only the rightmost entry** (Fly's edge appends the real client IP last). Never the leftmost — that's attacker-controlled.
- Implement a custom `KeyExtractor` for `actix-governor`:
  1. Read `Fly-Client-IP` first.
  2. Fall back to rightmost `X-Forwarded-For` segment.
  3. Fall back to `req.peer_addr()` for local dev.
  4. Return an explicit error (request rejected, not unrate-limited) if none parses.
- Integration test: send `X-Forwarded-For: 1.1.1.1, 2.2.2.2` and `X-Forwarded-For: 3.3.3.3` from the same source and verify they share a rate-limit bucket.

**Detection (warning signs):**
- Code uses `req.headers().get("X-Forwarded-For")` and naively parses leftmost.
- Code uses `req.connection_info().realip_remote_addr()` without auditing what Actix returns under Fly's proxy.
- Production logs show suspiciously few unique source IPs.

**Phase mapping:** **Rate-limiter wiring phase**, before any other limiter logic. Keep as a separate commit for reviewability.

---

### CRIT-5: Holding `Mutex<Vec<Box<dyn PushService>>>` across the FCM `await` blocks the listener and the new endpoint simultaneously

**What goes wrong:** The existing listener (`src/nostr/listener.rs:119-135`) acquires `push_services.lock().await`, then iterates services calling `service.send_to_token(...).await` **while holding the mutex**. A slow FCM call (median ~200ms, p99 multi-second under throttling) blocks every other event AND every `/api/notify` call needing the same mutex. Already documented in `CONCERNS.md:129-142`. Adding a second producer (the HTTP handler) makes contention multiplicative.

**Why it happens:** The existing structure invites copy-paste. `Arc<Mutex<Vec<Box<dyn PushService>>>>` looks correct but the `Mutex` is unnecessary — the vector is read-only after `main.rs:79`. A naive notify handler will follow the listener's pattern.

**Consequences:** One slow FCM dispatch stalls notify endpoint and event ingestion. With Fly's 25-connection cap (`fly.toml:31-33`), a 5s FCM stall + 30 incoming requests = client timeouts. Cancellation: dropped handler future drops the FCM request mid-flight, possibly leaving HTTP/2 stream half-open against Google.

**Prevention (concrete):**
- Replace `Arc<Mutex<Vec<Box<dyn PushService>>>>` with `Arc<[Arc<dyn PushService + Send + Sync>]>` (immutable after init, no mutex needed). Already recommended in `CONCERNS.md:139-142`. **Bundle into milestone** — the new endpoint will otherwise inherit contention at a worse multiplier.
- The notify handler should `tokio::spawn` the FCM call and return immediately (also helps CRIT-2). Use a bounded `tokio::sync::Semaphore` (e.g., 50 permits) to bound in-flight tasks and shed load. Without a bound, an attacker spawns unbounded background tasks via valid `/api/notify` calls.
- Set explicit `reqwest::Client` timeouts in `main.rs`: `timeout(Duration::from_secs(5))`, `connect_timeout(Duration::from_secs(2))`. Currently `reqwest::Client::new()` has no timeout (`CONCERNS.md:134-137`).

**Detection (warning signs):**
- The notify handler signature contains `push_services: web::Data<Arc<Mutex<...>>>` — `Mutex` should not survive into v1.1.
- Handler awaits `service.send_to_token(...)` directly inside the request lifecycle.
- Load test: 50 concurrent `/api/notify` against a stub FCM with 2s latency — observe whether listener still processes incoming Nostr events.

**Phase mapping:** **Refactor phase before endpoint implementation** — flip `push_services` to `Arc<[Arc<dyn ...>]>`, add the spawn+semaphore pattern.

---

### CRIT-6: Sender-triggered notify reveals "the recipient is online" / "the recipient unregistered" via FCM error propagation

**What goes wrong:** FCM v1's response has codes like `UNREGISTERED`, `INVALID_ARGUMENT` (stale token), `QUOTA_EXCEEDED` that leak metadata about the recipient's token validity. If the notify handler propagates these into its response (or worse, logs them with the pubkey), the *sender* learns recipient-side state.

The privacy model says the *server* must not learn sender↔recipient mappings. Corollary easy to miss: the server must also not be an oracle that lets the *sender* probe recipient state.

**Why it happens:** Natural pattern is to map FCM errors to HTTP status. `UNREGISTERED` → 410 Gone is the "RESTful" thing to do. Wrong here.

**Consequences:** Sender can probe `/api/notify` with a peer's `trade_pubkey` and learn whether the peer's token is still valid (and by extension whether the device is still installed). Allows targeted enumeration ("give me 100 random pubkeys, tell me which have valid devices").

**Prevention (concrete):**
- Always return `202 Accepted { "accepted": true }`, regardless of:
  - whether `trade_pubkey` was found,
  - whether FCM dispatch was attempted,
  - whether FCM accepted,
  - whether FCM returned `UNREGISTERED`/`INVALID_ARGUMENT`.
- FCM error handling (including token cleanup on `UNREGISTERED`) must happen in the spawned background task, **not** in the response path.
- 202 body is a constant — no request id, no timestamp.

**Detection (warning signs):**
- Handler signature returns `Result<HttpResponse, ApiError>` where `ApiError` maps FCM errors to non-202 statuses.
- The notify handler has a `match` against `service.send_to_token().await` that returns different HTTP responses.

**Phase mapping:** **Endpoint contract phase**. Document the 202 invariant in OpenAPI / handler doccomment.

---

## Moderate Pitfalls

### RL-1: `governor` per-key state grows unbounded with attacker-controlled keys

**What goes wrong:** `governor`'s `KeyedRateLimiter` maintains per-key state in a `DashMap`. If keyed by `trade_pubkey` (64-char hex) or by source IP, an attacker rotating values per request grows the map indefinitely. On a 512MB machine, ~1M unique keys ≈ 100MB+, and the map never shrinks until you call `retain_recent()`.

**Why it happens:** `governor`'s cleanup is opt-in. Most tutorials show `RateLimiter::keyed(quota)` without cleanup. The Fly 25-conn cap caps concurrency but **not key cardinality**.

**Prevention (concrete):**
- Configure the limiter and call `limiter.retain_recent()` from a periodic task (every minute). Verify governor 0.6 API at plan time.
- For per-pubkey, validate the pubkey is 64-char hex *before* the limiter sees it (reuse validation from `src/api/routes.rs:86`). A 400 returned before the limiter consults its map keeps random garbage out.
- For per-IP, source via the trusted-proxy method from CRIT-4 — random spoofed `X-Forwarded-For` values are a key-cardinality amplifier.
- Soft cap: if `limiter.len()` exceeds N (e.g., 100k), log warning and trigger immediate `retain_recent`. Smoke alarm for active key-bombing.

**Detection (warning signs):**
- Memory grows steadily without rise in registered tokens.
- `flyctl status` shows memory > 60% with no traffic spike.
- Log line: `governor map size > 100000`.

**Phase mapping:** **Rate-limiter wiring phase**. Plan must include periodic `retain_recent` task and cardinality alarm.

---

### RL-2: Rate-limit decision must not depend on whether `trade_pubkey` is registered

**What goes wrong:** Naive: rate-limit only after lookup ("if not registered, return 202 without consuming a slot; if registered, consume a slot then dispatch"). Wrong because:
1. Differential consumption is itself an oracle: hammering a pubkey and observing whether you eventually get a 429 reveals registration status.
2. An attacker enumerating to find registered pubkeys gets unlimited probes per pubkey because misses don't consume slots.

**Prevention (concrete):**
- Order: (1) parse + validate pubkey → 400 if bad; (2) consume per-IP slot → 429 if exhausted; (3) consume per-pubkey slot → 429 if exhausted; (4) lookup + dispatch in background; (5) always return 202.
- Both limiter checks happen **before** `TokenStore::get`. The 429 response shape must be byte-identical regardless of registration status.

**Detection (warning signs):**
- Code review: any `if let Some(token) = store.get(...)` *before* the rate-limit check.
- Differential test: registered pubkey becomes 429 after N reqs, unregistered after the same N.

**Phase mapping:** **Endpoint design phase**. Order of operations specified in plan.

---

### RL-3: Wrong burst sizing creates UX cliff or no protection

**What goes wrong:**
- **Too tight per-pubkey:** legitimate user sending 10 chat messages in 30s gets 429s after the 5th, recipient's app silent, user thinks app is broken. Worst kind of failure — invisible from sender side (relay publish succeeded).
- **Too loose per-IP:** coffee-shop NAT carries 50 users; one chatty pair exhausts limit, silences others.
- **Burst = capacity:** `governor`'s leaky bucket allows full burst then drains. Without explicit `burst_size` smaller than full quota, attacker gets one full burst worth of free traffic per cycle.

**Why it happens:** Codebase has `RATE_LIMIT_PER_MINUTE="60"` (`deploy-fly.sh:39`) — sized for register/unregister, not chat notify (different traffic shape).

**Prevention (concrete):**
- Per-pubkey: ~30 req/min, burst 10. Bounds chat to ~one notify every 2s sustained, allows 10-message back-and-forth burst.
- Per-IP: ~120 req/min, burst 30. Higher than per-pubkey for NAT.
- **Separate** `Quota` instances; do not share `RATE_LIMIT_PER_MINUTE` (reserved for register endpoint to avoid backcompat surprises).
- Per-pubkey is the privacy/abuse-relevant limit (caps how often any recipient can be woken). Per-IP is coarse anti-flood. Both apply.
- Document chosen numbers; revisit after a week of production data.

**Detection (warning signs):**
- Mobile users report "messages don't notify when chatting fast."
- 429 rate > 1% (too tight) or ~0% under sustained load (too loose, or IP bypass per CRIT-4).

**Phase mapping:** **Rate-limiter configuration phase**. Plan includes chosen numbers + rationale + post-rollout audit step.

---

### FCM-1: iOS silent push (`content-available: 1`) is throttled aggressively; high-priority data messages risk delivery suppression

**What goes wrong:** Apple throttles silent pushes — documented "no more than two or three per hour" sustainable rate. The current FCM payload (`src/push/fcm.rs:196-211`) sets `apns-priority: "10"` (high) AND `content-available: 1`, which Apple's docs explicitly warn against: high-priority silent pushes can flag the app as misbehaving and have its push privileges throttled.

For chat, user expectation is real-time. Sender-triggered notify fires on every message, easily exceeding "a few per hour" for an active conversation. After throttling, the silent pushes that actually deliver are unpredictable.

**Why it happens:** Existing `build_payload_for_token` (`src/push/fcm.rs:165-215`) was sized for the rare Mostro-daemon event (low frequency). Chat notify has a totally different frequency profile. `apns-priority: 10` for `content-available: 1` is a documented Apple anti-pattern that often goes undetected because it works in dev (low volume) and degrades under real use.

**Prevention (concrete):**
- For `/api/notify`-triggered iOS pushes, set `apns-priority: "5"` (background priority, what Apple specifies for `content-available: 1`). Confidence: MEDIUM-HIGH per Apple's APNs docs. Verify at implementation time.
- Add `apns-push-type: background` header (FCM v1 requires it for silent pushes; without it APNs may silently drop). Currently absent from `src/push/fcm.rs:196-211` — verify and add.
- Do NOT include `alert` payload key in silent-push branch — presence of `alert` upgrades to user-visible and bypasses background throttling but defeats the silent design.
- For Android (`src/push/fcm.rs:184-194`), `priority: "high"` is appropriate — Doze/App Standby will defer normal-priority data indefinitely, `high` is the documented escape hatch. No change.
- Build a separate `build_silent_payload_for_notify(device_token, platform)` rather than reusing existing `build_payload_for_token`. The existing function carries `alert` content (`src/push/fcm.rs:204-206`) and `apns-priority: "10"` which are wrong for the new use case. Reusing will be the path of least resistance and will be wrong.

**Detection (warning signs):**
- iOS users report "notifications don't always arrive" during active chat sessions but work for the first few messages.
- FCM dashboard shows high success but mobile-side analytics show low `didReceiveRemoteNotification` rate on iOS.

**Phase mapping:** **Endpoint implementation phase** — design iOS payload separately. Add manual iOS smoke test as verification.

---

### FCM-2: Battery-saver / Doze / App Standby silently drop messages with no error to the server

**What goes wrong:** Android Doze and App Standby buckets (rare/restricted) drop or defer FCM data messages even at `priority: "high"`. Recipient device shows nothing; FCM returns success; server has no signal. Sender thinks recipient was woken and conversation continues; recipient's app is silent until manual open.

**Why it happens:** By Android design, not a bug. Pitfall is treating FCM 200 OK as "delivered" — it is "accepted by Google for delivery", nothing more.

**Prevention (concrete):**
- Document explicitly in PROJECT.md and endpoint contract that `/api/notify` is **best-effort**; no delivery guarantee. Mobile-side must have a fallback (relay polling on app open) to recover missed events. Flag in plan for mobile team confirmation.
- Server side: nothing to fix. Do not add a delivery-confirmation channel — would require recipient to call back, leaking linkability.
- Do NOT bump priority further or add `alert` payload to "force" delivery — breaks silent-push UX (lock-screen visible) and on iOS triggers throttling per FCM-1.

**Detection (warning signs):** Field reports of "I sent a message and the other person didn't get it for an hour." Cannot be detected server-side.

**Phase mapping:** **Endpoint contract documentation phase**. No implementation work — explicit non-guarantee in contract.

---

### CONC-1: `tokio::spawn` from the HTTP handler without bounding spawns an unbounded futures pile

**What goes wrong:** The CRIT-5 fix (spawn FCM dispatch, return 202 immediately) is correct, but the naive form `tokio::spawn(async move { ... })` with no bound lets attackers (or below-rate-limit traffic) accumulate in-flight FCM dispatches. With FCM at p99 multi-second latency, sustained 60 req/min from one source plus per-IP limit at 120/min (RL-3) means up to ~600 in-flight tokio tasks each holding a `reqwest` connection. Saturates the 512MB machine and 25-connection cap well before reaching the per-IP limit.

**Why it happens:** `tokio::spawn` is fire-and-forget; futures aren't accounted unless you do it yourself.

**Prevention (concrete):**
- `tokio::sync::Semaphore` with permits = 50 (tunable). Acquire before spawning. If `try_acquire` fails: return 503 (operationally clearer) OR return 202 and silently drop dispatch (privacy-safer). Pick one and document.
- Wrap shared `reqwest::Client` with `connect_timeout(2s)` and `timeout(5s)` at construction (in `main.rs`, per `CONCERNS.md:134-137`).
- Do not use `spawn_blocking` — FCM is HTTP I/O, fully async.

**Detection (warning signs):**
- `flyctl logs` shows "task panicked" or "tokio runtime shutdown" under load.
- Memory climbing during load test, falling sharply when load stops (futures backlog draining).
- p99 endpoint latency growing over time during sustained traffic (queueing delay).

**Phase mapping:** **Concurrency design phase** — bundled with CRIT-5 refactor. Plan specifies semaphore size and overflow behavior.

---

### CONC-2: Holding `RwLock` across `await` in the new endpoint causes deadlocks under contention

**What goes wrong:** `TokenStore` uses `tokio::sync::RwLock<HashMap<...>>` (`src/store/mod.rs:31`). Current `get` (`src/store/mod.rs:85-88`) acquires read, clones, drops — correct. But a developer copy-pasting from the listener might write:

```rust
let tokens = store.tokens.read().await;
if let Some(token) = tokens.get(pubkey) {
    service.send_to_token(&token.device_token, ...).await?;  // BAD: holds read lock across await
}
```

This holds a read lock across the FCM dispatch (multi-second). New `register` calls block waiting for write access. Tokio writer-preferring semantics then queue subsequent readers behind the writer.

**Why it happens:** Textbook async lock anti-pattern. Compiler does not warn. Clippy's `await_holding_lock` lint catches `std::sync::Mutex` but not `tokio::sync::RwLock` reliably.

**Prevention (concrete):**
- Notify handler must call `let token = state.token_store.get(pubkey).await;` (existing API correctly drops the lock) and use `token.device_token` outside any lock scope. Do NOT reach into `store.tokens` directly.
- Enable `clippy::await_holding_lock` in `Cargo.toml` `[lints.clippy]`.
- Code review checklist: any `.read().await` or `.write().await` in the new handler must be followed by `drop(...)` or scope-end before the next `.await`.

**Detection (warning signs):** Load test shows latency cliff after N concurrent requests. `tokio-console` shows tasks blocked on `RwLock::read()` for long durations.

**Phase mapping:** **Code review phase**. Add to reviewer checklist.

---

### CONC-3: Cancellation of HTTP request mid-handler can leave registered-token state inconsistent

**What goes wrong:** Handler does `(1) consume rate-limit slot → (2) lookup token → (3) await FCM`. Client disconnects between (1) and (2): future dropped, slot consumed (no rollback), dispatch never happened. Fine for `/api/notify` (rate limit is soft, dispatch is best-effort). The bug bites if the handler does **anything stateful** between awaits — e.g., updates "last-notified-at" then awaits FCM. Cancellation between leaves the store thinking a notification was sent that never went out.

**Why it happens:** Async cancellation in Rust is implicit (drop the future); developers from Go/Java backgrounds expect either guaranteed completion or explicit cancellation tokens.

**Prevention (concrete):**
- Keep notify handler **stateless on the store**: no `TokenStore` mutation as part of dispatch. Store mutates only via explicit `register`/`unregister`.
- If "last-notified-at" or per-pubkey notify counter needed for analytics, update inside the spawned background task (detached from request cancellation), and accept overcounting on retry storms.

**Detection (warning signs):** `TokenStore` gains a new field that mutates inside `/api/notify`.

**Phase mapping:** **Endpoint implementation phase** — make stateless dispatch an explicit design constraint.

---

### COMPAT-1: Introducing a shared error type for `/api/notify` accidentally changes `/api/register` response shape

**What goes wrong:** Current handlers use ad-hoc JSON (`RegisterResponse` struct in `src/api/routes.rs:29-34`, raw `serde_json::json!` in `src/api/routes.rs:149-167`). A reasonable refactor for the new endpoint introduces `enum ApiError { ValidationFailed, RateLimited, Internal }` with `ResponseError` impl producing a unified body. If the refactor touches `register_token` to use the new error type, the response body shape changes for existing mobile clients. Mobile uses strict-typed deserialization — silent failure, retry storm.

**Why it happens:** "Tidy up while we're here" is a common reviewer suggestion. Current shape is `{"success": true, "message": "..."}` with optional `platform`; a unified shape would be `{"error": null, "data": {...}}` or similar.

**Prevention (concrete):**
- New endpoint's response structures live in a new file (e.g., `src/api/notify.rs`) with their own types. Do **not** refactor `RegisterTokenRequest`/`RegisterResponse`/`UnregisterTokenRequest` in this milestone.
- Integration test (or curl in `test_server.sh`) verifies existing register/unregister responses byte-identical to pre-milestone version.
- Capture current responses (run against current main) and commit as frozen fixture. Diff in PR review.

**Detection (warning signs):**
- Diff modifies `src/api/routes.rs` definitions of `RegisterResponse`/`RegisterTokenRequest`.
- Diff introduces `From<ApiError> for HttpResponse` and applies to `register_token`.

**Phase mapping:** **Endpoint design phase** + **PR review checklist**. Design explicitly calls out "no changes to existing response shapes".

---

### TEST-1: Mocking too much hides the rate-limiter integration mistake; mocking too little blocks dev velocity

**What goes wrong:** Without integration tests, the new rate limiter ships untested. Failure modes:
- **Too much mocking:** unit test instantiates handler with stub limiter that always allows; actix-governor middleware integration never exercised. Production discovers middleware was registered on wrong scope, or key extractor returns constant for test IP.
- **Too little mocking:** test spins up FCM and Nostr clients, hits real services, becomes flaky, gets disabled, leaves zero coverage.

**Why it happens:** Zero integration tests exist (`CONCERNS.md:231-233`). No precedent for "the right level". Milestone explicitly NOT adopting CI (`PROJECT.md:46`).

**Prevention (concrete):**
- Mandatory in-process integration tests using `actix_web::test::init_service` exercising:
  1. `/api/notify` with valid registered pubkey → 202.
  2. `/api/notify` with valid unregistered pubkey → 202 (same shape, CRIT-2).
  3. `/api/notify` with malformed pubkey → 400.
  4. `/api/notify` 31 times for same pubkey within a minute → at least one 429 (per-pubkey limiter exercised).
  5. `/api/notify` 121 times from same `Fly-Client-IP` header within a minute → at least one 429 (per-IP limiter exercised).
  6. `/api/register` smoke: response shape unchanged from pre-milestone (COMPAT-1).
- Use stub `PushService` impl (`struct NoopPush; impl PushService for NoopPush { ... }`) so FCM not hit.
- Do NOT mock the rate limiter. Use real `governor` middleware, real `KeyExtractor`, real `Quota`. The point is to catch the wiring.
- Run with `cargo test` locally; one-line README note "before pushing, run `cargo test --all`". CI out of scope per `PROJECT.md:46`.

**Detection (warning signs):**
- Test file mocks `governor::RateLimiter` (red flag — wiring is exactly what needs testing).
- Test file makes real HTTP calls to FCM (red flag — flake bait).

**Phase mapping:** **Integration test phase** — must precede production rollout.

---

### DEPLOY-1: `RUST_LOG="debug"` in `deploy-fly.sh` plus new debug logs in notify endpoint = pubkeys leaked at scale

**What goes wrong:** Already covered in CRIT-3 from app-code angle. Deploy-script angle: `deploy-fly.sh:42` sets `RUST_LOG="debug"`. Any `debug!()` added to the new endpoint emits to stdout, captured by Fly. Adding *correct* hash-based logs (per CRIT-3) at `info!` is fine; adding *any* `debug!()` touching pubkey, token, or IP is a leak.

**Why it happens:** Developers add `debug!()` liberally during implementation and forget to remove. Deploy script's `RUST_LOG` is far from app code and easy to overlook.

**Prevention (concrete):**
- Bundle the change `RUST_LOG="debug"` → `RUST_LOG="info"` in `deploy-fly.sh:42` into this milestone. Even if the new endpoint's logging is clean, leaving debug on means *any other* `debug!()` in the codebase (e.g., `src/push/fcm.rs:283` logs token prefix) leaks.
- If debug visibility needed in production, set per-module: `RUST_LOG="info,mostro_push_server::api::notify=debug"` with explicit understanding of what that module logs.
- Audit grep before merge: `rg 'debug!|trace!' src/api/ src/store/` should produce only entries reviewed using the hash helper.

**Detection (warning signs):**
- Test grep against diff shows new `debug!`/`trace!` macros without hashing.
- `flyctl logs` contains hex strings 16+ chars matching hex pubkey pattern.

**Phase mapping:** **Deployment phase** — single-line commit alongside endpoint rollout. Cannot be deferred without leaving milestone in a regressed privacy posture.

---

### DEPLOY-2: Hard 25-connection Fly cap interacts with synchronous push dispatch to cause cascading 503s

**What goes wrong:** `fly.toml:31-33` enforces hard cap of 25 concurrent connections. With existing inline `await service.send_to_token(...)` (CRIT-5), each in-flight notify holds an HTTP connection from Fly's perspective until the handler returns. 5s FCM stall + 30 incoming `/api/notify` = 5 succeed, 25 queued at Fly edge, queue overflow returns 503 to clients. Mobile retries → cascade.

**Why it happens:** 25-conn cap was set when server only had `/api/register` (millisecond response) and `/api/health`. New notify has fundamentally different latency if implemented synchronously.

**Prevention (concrete):**
- The CRIT-5 + CONC-1 fix (return 202 immediately, dispatch in spawned task with semaphore) makes handler latency ~1ms regardless of FCM latency. With ~1ms handler latency, 25 concurrent connections accommodate ~25k req/s — cap no longer binding.
- Do not raise 25-conn cap as a "fix" — treats symptom. Fix is fast handlers.
- Explicit p99 handler-latency target in plan: `/api/notify` p99 < 50ms regardless of FCM state.

**Detection (warning signs):**
- `flyctl logs` shows `connection limit exceeded`.
- p99 `/api/notify` latency > 100ms.
- Mobile reports `503` from `/api/notify`.

**Phase mapping:** **Concurrency design phase** + **load-test verification phase**.

---

### DEPLOY-3: Adding `actix-governor` middleware globally breaks `/api/health` for Fly's health checks

**What goes wrong:** `actix-governor`'s default scope is the whole app. Apply as `App::new().wrap(Governor::new(&config))` and it rate-limits `/api/health` too. Fly's health check hits `/api/health` from a small set of internal IPs at high frequency. Once per-IP limit exceeded, Fly thinks machine is unhealthy and kills it. Restart loop.

**Why it happens:** `wrap` at App level is the pattern in every actix-governor README example. Per-route scoping requires deliberate `web::scope("/api/notify").wrap(...)`, less obvious.

**Prevention (concrete):**
- Apply governor middleware **only** to `/api/notify`, never globally. Concrete: `web::resource("/notify").wrap(Governor::new(&notify_config)).route(web::post().to(notify))`.
- Even better: define `web::scope("/api/notify")` and wrap that scope.
- `/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister` must remain unrate-limited by this milestone's middleware.
- Integration test that hammers `/api/health` 1000 times, all 200s.

**Detection (warning signs):**
- Middleware wrap appears outside `/api/notify` scope.
- Post-deploy: Fly machine restart loop, `flyctl status` shows `health check failing`.

**Phase mapping:** **Middleware wiring phase**. Plan calls out scoping explicitly.

---

## Minor Pitfalls

### MIN-1: `since` filter loses notify-relevant events on reconnect (existing fragility)

`since = Timestamp::now() - 60s` (`src/nostr/listener.rs:76-79`) — fragility flagged in `CONCERNS.md:168-171`. Not new for v1.1, but worth noting: if listener disconnects >60s, events arriving during downtime are missed. Sender-triggered notify works around this — sender calls `/api/notify` even if listener missed. **One of the value-adds of the new endpoint** — call out positively in milestone summary.

### MIN-2: Reusing `RATE_LIMIT_PER_MINUTE` env var creates ambiguity

`deploy-fly.sh:39` and `Config::rate_limit.max_per_minute` already exist (currently unused). Repurposing them for notify means future readers can't tell whether "60/min" applies to register, notify, or both. **Prevention:** Introduce `NOTIFY_RATE_PER_PUBKEY_PER_MIN` and `NOTIFY_RATE_PER_IP_PER_MIN` as fresh env vars; leave existing alone (it remains unused, in line with the milestone's defer-to-anti-abuse-work scope).

### MIN-3: `Fly-Client-IP` not present in local dev — handler crashes if not optional

If the `KeyExtractor` returns `Err` when both `Fly-Client-IP` and `X-Forwarded-For` are absent, local `cargo run` fails 500. **Prevention:** Fall back to `peer_addr().ip()` for local dev. Document in README.

### MIN-4: `apns-collapse-id` already set to `"mostro-trade"` (`src/push/fcm.rs:199`) coalesces multiple chat notifications into one

Apple coalesces APNs by `apns-collapse-id`. Reusing `"mostro-trade"` for chat means rapid-fire chat notifications get coalesced into a single delivery — fine for "you have an update" semantics, possibly wrong for chat where "5 new messages" matters. **Prevention:** Leave existing event-driven payload alone; use a different `apns-collapse-id` (e.g., `"mostro-chat"`) or omit it for chat-notify pushes. The chat-app on the mobile side does its own state recovery from relays, so coalescing a wake-up is acceptable; flag for mobile team confirmation.

### MIN-5: `PushService` trait returns `Box<dyn Error>` (not `Send + Sync`)

`CONCERNS.md:62-66`. Spawning the FCM call (CONC-1) into `tokio::spawn` requires the future `Send`. Current trait return type may force `e.to_string().into()` conversions that lose source error chain — making background-task failures harder to diagnose. **Prevention:** Tighten trait to `Result<(), Box<dyn Error + Send + Sync>>` (low-risk localized change).

### MIN-6: `test_server.sh` is broken (per `CONCERNS.md:57-60`) — do not extend it for notify smoke tests

`test_server.sh` already references endpoints that no longer exist. Adding `/api/notify` curl perpetuates broken file. **Prevention:** Either repair `test_server.sh` to match current API as part of milestone OR write a new minimal `notify_smoke.sh` and document `test_server.sh` deprecated. The minimal new script avoids scope creep.

---

## Phase-Specific Warnings

| Phase Topic | Likely Pitfall | Mitigation |
|---|---|---|
| **Concurrency refactor** (`Mutex<Vec<>>` → `Arc<[Arc<dyn ...>]>`) | Touching listener regresses Gift Wrap handling | Keep refactor purely structural; manually verify a Mostro event still produces a push after refactor. (CRIT-5) |
| **`KeyExtractor` implementation** | Trusts `X-Forwarded-For` first segment | Use `Fly-Client-IP`; rightmost-only XFF fallback; document. (CRIT-4) |
| **Rate-limiter wiring** | Applied at `App` level, breaks `/api/health` | Wrap only the notify scope. Test `/api/health` under flood. (DEPLOY-3) |
| **Endpoint contract** | Differential 200/404 / FCM error propagation | Always 202 + opaque body. (CRIT-2, CRIT-6) |
| **Logging** | `trade_pubkey[..16]` at info/debug | Hash helper; demote prefix logs; flip `RUST_LOG` to info. (CRIT-3, DEPLOY-1) |
| **Listener filter "fix"** | Reviewer adds `.authors(mostro_pubkey)` | Comment block + diff grep + anti-requirement in PROJECT.md (already there). (CRIT-1) |
| **iOS payload** | Reuses event payload (`apns-priority: 10` + `content-available: 1`) | Build separate silent-payload for notify; `apns-priority: 5`; `apns-push-type: background`. (FCM-1) |
| **Background dispatch** | Unbounded `tokio::spawn` | Semaphore-bounded spawns; reqwest timeouts on shared client. (CONC-1, CRIT-5) |
| **Existing endpoint compat** | Refactor breaks `/api/register` shape | New types in new file; frozen fixture diff in review. (COMPAT-1) |
| **Integration tests** | Mocking the rate limiter | Real governor + stub PushService. (TEST-1) |
| **Deploy** | `RUST_LOG="debug"` left in script | Bundle the `RUST_LOG="info"` change with this milestone. (DEPLOY-1) |

---

## Cross-References to Existing CONCERNS.md

This milestone interacts with the following existing concerns. **[BUNDLE]** = must be addressed in v1.1 or milestone ships in regressed state. **[DEFER]** = stays in its own milestone per `PROJECT.md` Out of Scope.

| CONCERNS.md item | Lines | Status for v1.1 | Reason |
|---|---|---|---|
| Mostro author filter not actually applied | 20-24 | **[ANTI-FIX]** | Removing the validation/config field is fine; *applying* the filter is forbidden (CRIT-1). |
| Trade pubkey logged at INFO | 114-117 | **[BUNDLE]** | New endpoint amplifies the leak; must hash-and-demote (CRIT-3). |
| `RUST_LOG=debug` in deploy script | 119-122 | **[BUNDLE]** | Hard blocker for safe rollout (DEPLOY-1). |
| `Mutex<Vec<dyn PushService>>` serializes delivery | 139-142 | **[BUNDLE]** | New endpoint multiplies contention (CRIT-5). |
| Single-task event loop blocks on each push | 129-132 | **[BUNDLE]** | New endpoint must spawn-and-bound (CONC-1). |
| `reqwest::Client` per service, no timeouts | 134-137 | **[BUNDLE]** | Shared client with timeouts in `main.rs` (CONC-1). |
| Unused rate-limit configuration | 44-48 | **[BUNDLE]** | This is the milestone. Use new env vars (MIN-2). |
| `Box<dyn Error>` everywhere | 62-66 | **[BUNDLE-LITE]** | Tighten to `+ Send + Sync` for the spawn path (MIN-5). |
| No request signing on `/api/register` | 108-112, 221-223 | **[DEFER]** | Anti-abuse milestone. |
| `SERVER_PRIVATE_KEY` in git | 89-96 | **[DEFER]** | Bundled with Phase 4 encryption. |
| `nostr-sdk = 0.27` outdated | 194-197 | **[DEFER]** | Substantial migration; not on critical path. |
| In-memory `TokenStore` | 175-179, 209-211 | **[DEFER]** | Persistent storage milestone. |
| Zero integration tests | 231-233 | **[BUNDLE-LITE]** | Add minimum tests covering new endpoint (TEST-1); do not adopt CI. |
| `BatchingManager` unused | 38-42 | **[DEFER]** | Per `PROJECT.md:49`. |
| iOS/APNs delivery untested | 225-227 | **[BUNDLE-LITE]** | Manual iOS smoke test as part of milestone verification (FCM-1). |

---

## Sources

- Codebase (HIGH): `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/src/nostr/listener.rs`, `src/api/routes.rs`, `src/store/mod.rs`, `src/push/fcm.rs`, `src/main.rs`, `deploy-fly.sh`, `fly.toml`.
- Project constraints (HIGH): `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/PROJECT.md`.
- Pre-existing analysis (HIGH): `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/codebase/CONCERNS.md`.
- Apple APNs background-priority semantics (`apns-priority: 5`, `apns-push-type: background`, silent-push throttling): Apple Developer Documentation — *Pushing background updates to your app* (MEDIUM — based on stable published guidance; web search blocked this run, recommend re-verification at endpoint implementation).
- FCM v1 payload structure (`android.priority`, `apns.headers`, `apns.payload.aps.content-available`): Firebase Cloud Messaging HTTP v1 API reference (MEDIUM — verify against current Google docs).
- `governor` 0.6 keyed-rate-limiter retention (`retain_recent`, in-memory cardinality): governor documentation (MEDIUM — verify exact API at implementation time).
- Fly.io `Fly-Client-IP` header / proxy behavior: Fly.io networking documentation (MEDIUM — verify at implementation time).
- `actix-governor` middleware scoping behavior: actix-governor README (MEDIUM).
