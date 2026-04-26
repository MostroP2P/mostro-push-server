# Feature Landscape

**Domain:** Privacy-preserving push notification backend (Mostro Push Server, milestone v1.1 — Chat notifications)
**Researched:** 2026-04-24
**Mode:** Ecosystem
**Overall confidence:** MEDIUM (project-specific evidence is HIGH from `.planning/PROJECT.md` and `.planning/codebase/ARCHITECTURE.md`; ecosystem comparison from training data only — `WebSearch` / `WebFetch` were unavailable in this session, see "Research Limitations" at the bottom)

> Note: This document was written by the orchestrator from findings returned inline by the `gsd-project-researcher` agent (the agent's environment denied writing `.md` artifacts and external WebSearch/WebFetch). Content is verbatim from the agent's report.

---

## Scope of This Document

This is a **subsequent-milestone** features study. The existing feature surface (Nostr `kind 1059` listener, `/api/register`, `/api/unregister`, `/api/health`, `/api/info`, `/api/status`, in-memory `TokenStore`, FCM v1 dispatch, UnifiedPush dispatch, Fly.io deploy) is treated as fixed and is NOT re-researched. The document categorizes features for the **new** surface area only:

1. `POST /api/notify { trade_pubkey }` — sender-triggered silent push.
2. Rate limiting on `/api/notify` (per `trade_pubkey` and per source IP).
3. End-to-end verification of dispute chat push delivery (no dispatch change; observability only).

Each feature is annotated with:

- **Origin:** whether the mobile `CHAT_NOTIFICATIONS_PLAN.md` already specifies it (per `.planning/PROJECT.md` lines 32-37, 71-73, 87-88, which quote/summarize that plan).
- **Complexity:** S / M / L (subjective, based on the existing codebase abstractions surveyed in `.planning/codebase/ARCHITECTURE.md`).
- **Dependencies:** other features in this milestone or existing components.
- **Privacy implication:** explicit note for every feature, since this is the project's hard invariant (`PROJECT.md` lines 68-71, 84-89).

---

## Table Stakes (must ship in v1.1)

### TS-1. `POST /api/notify { trade_pubkey }` — sender-triggered silent push

| Field | Value |
|-------|-------|
| Origin | Specified in mobile plan Phase 4 (per `PROJECT.md` line 73). |
| Complexity | S (one new handler reusing `AppState.token_store` and the existing `Vec<Box<dyn PushService>>` dispatch path lifted out of the Nostr listener). |
| Dependencies | Existing `TokenStore::get`, existing `PushService::send_to_token`. No data-model change. |
| Privacy implication | NEUTRAL. Reveals to the server only `(source IP, trade_pubkey, timestamp)` — same projection the server already has when dispatching from a relay event. No new sender↔recipient linkage because the request is unauthenticated by design. |

**Behaviour:**
- Validate body is `{ "trade_pubkey": "<64-char hex>" }`. Same validation as `/api/register`. Reject with `400` otherwise.
- Lookup token in `TokenStore`. If absent, return `404` (no body leakage about which other pubkeys exist).
- If present, dispatch a silent push exactly as the Nostr listener path does today (first matching `PushService::supports_platform`, `send_to_token`, break on first success).
- Return `200` with `{ "success": true }`.
- Return `429` if rate limit triggered (TS-2).

**Anti-coupling note:** The dispatch path used by `/api/notify` MUST be the same code used by `nostr::listener` so future changes (batching, retries) apply uniformly. Recommend factoring `dispatch_silent_push(trade_pubkey)` into `src/push/mod.rs` and calling from both sites. (`ARCHITECTURE.md` lines 86-93 show the dispatch logic is currently inline in the listener closure.)

### TS-2. Rate limiting on `/api/notify`

| Field | Value |
|-------|-------|
| Origin | `PROJECT.md` lines 35-36. Targets `~5 req/min` per `trade_pubkey` and `~60 req/min` per source IP. |
| Complexity | M (two `governor` keyed limiters wired as middleware or per-handler guards; `governor` already in `Cargo.toml` per `PROJECT.md` line 80). |
| Dependencies | TS-1, existing `governor` dep. |
| Privacy implication | POSITIVE. Without it the endpoint is a free notification-storm vector. Bucketing by `trade_pubkey` adds no server-side knowledge that wasn't already present. |

**Behaviour:**
- Two `governor` instances ANDed: a request is allowed only if BOTH the IP bucket AND the `trade_pubkey` bucket admit it.
- On rejection, return `429` with `{ "success": false, "error": "rate_limited" }`. No `Retry-After` (would leak bucket internals).
- In-memory only (consistent with `ARCHITECTURE.md` line 109). Lost on restart, acceptable for an anti-burst limit.

**Open for `/gsd-plan-phase`:** exact `Quota` expression, keyed extractor, middleware vs per-handler.

### TS-3. Structured error responses on `/api/notify`

| Field | Value |
|-------|-------|
| Origin | Implied by the `200/404/429` contract (`PROJECT.md` line 87). |
| Complexity | S. |
| Dependencies | TS-1, TS-2. |
| Privacy implication | NEUTRAL/POSITIVE. Responses must not differentiate "pubkey unknown" from "pubkey known but no token" — `404` is the single bucket. Must not echo the `trade_pubkey` back in the body. |

**Behaviour:**
- All responses JSON, content-type `application/json`.
- Bodies terse: `{ "success": true }`, `{ "success": false, "error": "not_registered" }`, `{ "success": false, "error": "rate_limited" }`, `{ "success": false, "error": "invalid_pubkey" }`.
- No internal error details (stack traces, backend names, FCM error codes) exposed. Backend failures still return `200` to the client (silent push has been *attempted*); failure modes visible to the operator via logs (TS-4). **Alternative under discussion:** return `502` on backend failure. Recommendation: stay with `200` to avoid encouraging retry-storms on transient FCM/UP failures (mobile will eventually fetch via Nostr).

### TS-4. Operator-facing observability for `/api/notify` and dispute-chat path

| Field | Value |
|-------|-------|
| Origin | Not in mobile plan. Required to satisfy the dispute-chat verification objective (`PROJECT.md` line 33). |
| Complexity | S (extend existing `log` macros; add a small `Metrics` struct with `AtomicU64` counters). |
| Dependencies | TS-1; touches `nostr::listener` for the dispute-chat path. |
| Privacy implication | HIGH-SCRUTINY. Any new log line is a new persistent record. MUST log only `trade_pubkey` (truncated), platform, dispatch backend, success/failure, opaque per-request id. MUST NOT log: source IP for `/api/notify` requests, request body, response body, FCM/UP token strings, or anything that could link sender to recipient. |

**Recommended additions (log-level only — no Prometheus endpoint in this milestone, deferred per `PROJECT.md` line 47):**

1. `info!` on `/api/notify` admit: `notify dispatched: pubkey={short_hex} backend={fcm|unifiedpush} elapsed_ms={n}` (truncate pubkey to 8 chars).
2. `warn!` on `/api/notify` 404: `notify miss: pubkey={short_hex}` (no IP).
3. `warn!` on `/api/notify` 429: `notify rate_limited: bucket={ip|pubkey}` (do not log which pubkey or which IP).
4. `info!` on listener dispatch (already exists per `ARCHITECTURE.md` line 90; verify it includes enough to correlate).
5. **Source-of-event tag:** add a single string field `source=relay|notify` so the operator can verify "dispute admin DM did go through the relay listener path" without re-instrumenting code.

**Counters (in-memory `AtomicU64`, exposed via existing `GET /api/status`):**
- `notify_total`
- `notify_404_total`
- `notify_429_ip_total`, `notify_429_pubkey_total`
- `relay_dispatch_total`
- `dispatch_fcm_success_total`, `dispatch_fcm_error_total`
- `dispatch_unifiedpush_success_total`, `dispatch_unifiedpush_error_total`

These extend the existing `TokenStoreStats` returned by `GET /api/status` (`ARCHITECTURE.md` lines 152-155). Adding fields is backwards-compatible.

### TS-5. Dispute-chat E2E verification path (test-only, no dispatch change)

| Field | Value |
|-------|-------|
| Origin | `PROJECT.md` line 33 (requirement) and lines 60-66 (data flow). |
| Complexity | M (no production code change beyond TS-4 logging; the work is a documented manual or integration test exercising the existing relay path). |
| Dependencies | TS-4 (need the `source=relay` log/counter to confirm the path). |
| Privacy implication | NEUTRAL. Reuses existing flow. |

**Behaviour:**
- Document a runbook (`docs/verification/dispute-chat.md` or in milestone notes) that:
  1. Registers a test `trade_pubkey` via `/api/register` with a dummy FCM token.
  2. Has the admin client publish a `kind 1059` Gift Wrap (`p` tag = that `trade_pubkey`) on a configured relay.
  3. Asserts the server logs a `relay_dispatch_total` increment within N seconds, with `source=relay`.
  4. Optionally, with a real device registered, asserts FCM/UP delivery client-side.
- Explicitly does NOT introduce a Mostro-daemon author filter (anti-requirement on `PROJECT.md` line 51).

---

## Differentiators

### D-1. Request-ID propagation (`X-Request-Id` header)

| Field | Value |
|-------|-------|
| Origin | Not in mobile plan. Standard production HTTP hygiene (LOW confidence on whether sygnal/ntfy expose it). |
| Complexity | S (Actix middleware, ~30 LOC). |
| Dependencies | None. |
| Privacy implication | NEUTRAL if generated server-side; LOW-RISK if accepted from the client. **Recommendation:** ALWAYS generate server-side with UUIDv4, ignore inbound `X-Request-Id`. |

**Why differentiator:** the milestone has only one new endpoint. Reasonable to scaffold if it costs <30 minutes; otherwise defer.

### D-2. Idempotency-Key header on `/api/notify`

| Field | Value |
|-------|-------|
| Origin | Not in mobile plan. Common in payments/webhook APIs (most push services don't expose it — FCM v1 expects caller dedupe). |
| Complexity | M. |
| Dependencies | TS-1. |
| Privacy implication | NEGATIVE if persisted. The dedupe cache becomes correlatable record. |

**Recommendation: DO NOT implement in v1.1.** "Wake the recipient" is already idempotent in effect; mobile dedupes at the Nostr-event level. Server-side idempotency stores correlatable state for marginal benefit.

### D-3. Request-level timeout on outbound FCM/UnifiedPush call

| Field | Value |
|-------|-------|
| Origin | Not in mobile plan. Standard hygiene. |
| Complexity | S. |
| Dependencies | None. |
| Privacy implication | NEUTRAL. |

**Recommendation: include.** A `/api/notify` handler blocking 30+ seconds on an unreachable FCM exhausts the 25-connection cap (`PROJECT.md` line 88) — self-DoS. A 5-10s outbound timeout is cheap. Verify if existing `reqwest::Client` already has one.

### D-4. CORS configuration for `/api/notify`

| Field | Value |
|-------|-------|
| Origin | Not in mobile plan. |
| Complexity | S. |
| Dependencies | None. |
| Privacy implication | NEUTRAL. |

**Recommendation: NO CORS.** Endpoint consumed by native mobile apps (no CORS enforcement). Allowing cross-origin browser calls invites a different abuse vector (malicious websites issuing notify storms via victims' browsers). Default-deny by simply not adding `actix-cors`.

### D-5. Health-check enrichment

| Field | Value |
|-------|-------|
| Origin | Not in mobile plan. |
| Complexity | S. |
| Dependencies | None. |
| Privacy implication | NEUTRAL. |

**Recommendation: defer.** `/api/status` already exposes `TokenStoreStats`. Readiness sub-checks belong to an observability milestone (out of scope per `PROJECT.md` line 47).

### D-6. Dispatch source distinction in `/api/status`

Folded into TS-4. Listed for visibility.

---

## Anti-Features

### AF-1. Authenticated `/api/notify`
- **Why tempting:** standard "abuse mitigation".
- **Why forbidden:** Documented Key Decision in `PROJECT.md` line 100. Auth forces sender identification, building a sender→recipient graph. Breaks unlinkability invariant on `PROJECT.md` line 70.
- **Use instead:** rate limiting (TS-2).

### AF-2. Message content forwarding / payload customization
- **Why tempting:** "Show preview in notification."
- **Why forbidden:** Server would learn content. Breaks invariant on `PROJECT.md` line 70. Whole point of silent pushes is empty payload — mobile fetches and decrypts the Nostr event locally.
- **Use instead:** Silent push with empty payload.

### AF-3. Sender identification in request body or headers
- **Why tempting:** "Audit who triggered which notify."
- **Why forbidden:** Same as AF-1. Even an *optional* `sender_pubkey` field is mineable by operators or attackers.
- **Use instead:** Don't collect. Contract is intentionally `{ trade_pubkey }` only (`PROJECT.md` line 87).

### AF-4. Storing `sharedKey` mappings on the server
- **Why tempting:** "Server could look up by sharedKey directly."
- **Why forbidden:** Documented Key Decision in `PROJECT.md` line 99. Server would learn `sharedKey ↔ tradeKey` correlations and could infer trading partners.
- **Use instead:** Sender-triggered `/api/notify` (TS-1).

### AF-5. Persistent log of who-pushed-whom
- **Why tempting:** "Forensics for abuse investigations."
- **Why forbidden:** Long-lived `(timestamp, source IP, target trade_pubkey)` is an attractive subpoena/breach target. A single record confirms "user X tried to reach trade_pubkey Y at 14:32." Exactly what the project prevents.
- **Use instead:** Aggregate counters (TS-4); short-lived per-IP counters for rate limiting only. The truncated-pubkey lines in TS-4 are a calculated tradeoff.

### AF-6. Mostro-daemon author filter on the Nostr listener
- **Why tempting:** Suggested in `.planning/codebase/CONCERNS.md` (per `PROJECT.md` line 78).
- **Why forbidden:** Hard anti-requirement, `PROJECT.md` lines 51, 89, 103. Admin DMs in disputes are sent directly user-to-user, not by the daemon — author filter would silently drop them and break TS-5.
- **Use instead:** Listener processes all `kind 1059` on configured relays. Spam mitigation belongs at the relay layer.

### AF-7. Token registration via `/api/notify` side-effects
- **Why tempting:** "Return 404 with registration hint."
- **Why forbidden:** Mixes registration and dispatch concerns; would leak which pubkeys are NOT registered, enabling enumeration.
- **Use instead:** Plain `404` with `{ "success": false, "error": "not_registered" }`. No hints.

### AF-8. Recipient-controlled push customization (sound, badge, group, channel)
- **Why tempting:** Standard mobile UX.
- **Why forbidden:** (1) These require a `notification` payload (iOS displays it before app processes it). Server cannot generate user-facing strings without knowing content (AF-2). (2) FCM v1 silent pushes are `data`-only.
- **Use instead:** True silent push (`data` only on FCM, empty body on UnifiedPush). Mobile constructs local notification with full UX after decrypting.

### AF-9. Push payload keyed by recipient identity beyond `trade_pubkey`
- **Why tempting:** "Routing hint so client knows which conversation woke it up."
- **Why forbidden:** Anything beyond a generic wake-up is a server-side claim about the recipient's conversation graph — server does not have, must not have, that information.
- **Use instead:** Pure wake-up. Mobile polls Nostr after waking.

### AF-10. Webhook callback / delivery receipt to the sender
- **Why tempting:** "Tell the sender whether the recipient was online."
- **Why forbidden:** Builds a server-mediated presence channel between sender and recipient — exactly the linkability the project rejects.
- **Use instead:** None. Sender does not get delivery info from the push server. (Mobile chat protocol may have its own receipts over Nostr; out of scope.)

---

## Feature Dependencies

```
TS-1 (POST /api/notify)
  ├── enables TS-2 (rate limiting)
  ├── enables TS-3 (error contract)
  └── feeds   TS-4 (observability counters)

TS-4 (observability)
  └── enables TS-5 (dispute-chat verification runbook)

D-3 (outbound timeout)
  └── protects TS-1 from self-DoS under 25-connection cap

D-1 (request-id) — independent, scaffolding-grade
D-2 (idempotency) — REJECTED for v1.1
D-4 (CORS)        — REJECTED-by-default
D-5 (health++)    — DEFERRED to observability milestone
D-6 (status++)    — folded into TS-4
```

**Critical-path bundle (table stakes only):**
TS-1 → TS-2 → TS-3 → TS-4 → TS-5
(Linear; TS-2 and TS-3 can be implemented in parallel after TS-1 lands.)

---

## MVP Recommendation

**Ship in this milestone:**
1. TS-1: `POST /api/notify`
2. TS-2: rate limiting (per-pubkey + per-IP)
3. TS-3: structured error contract (`200 / 400 / 404 / 429`)
4. TS-4: observability counters and structured log lines (with `source=relay|notify` tag)
5. TS-5: dispute-chat verification runbook
6. D-3: outbound `reqwest` timeout (verify if already present; add if not)

**Optionally include if cheap:** D-1 (server-generated UUIDv4 request-id middleware).

**Defer:** D-2 (idempotency: rejected), D-5 (health enrichment: out of scope), D-6 (folded).

**Reject permanently:** AF-1 through AF-10. Add to `docs/PRIVACY_INVARIANTS.md` or a code-review checklist so they cannot drift back in.

---

## Privacy-Implication Summary Table

| Feature | Privacy Class | Net Effect |
|---------|---------------|------------|
| TS-1 `/api/notify`         | Neutral  | Same projection server already has. |
| TS-2 Rate limiting         | Positive | Mitigates abuse vector the endpoint creates. |
| TS-3 Error contract        | Neutral  | If responses don't echo input or differentiate "unknown" vs "no token". |
| TS-4 Observability         | Tradeoff | Aggregate counters: positive. Per-request logs: must truncate pubkey, omit IP. |
| TS-5 Dispute verification  | Neutral  | No new code path. |
| D-1 Request-id             | Neutral  | Server-generated only. |
| D-2 Idempotency keys       | NEGATIVE | Creates correlatable state. **Reject.** |
| D-3 Outbound timeout       | Neutral  | Operational hygiene. |
| D-4 CORS                   | Negative | Opens browser-mediated abuse. **Reject (default-deny).** |
| D-5 Health++               | Neutral  | Deferred. |
| D-6 Status counters        | Neutral  | Folded into TS-4. |
| AF-1 Auth on /api/notify   | NEGATIVE | Sender-recipient linkability. **Forbidden.** |
| AF-2 Content forwarding    | NEGATIVE | Server learns content. **Forbidden.** |
| AF-3 Sender identification | NEGATIVE | Same as AF-1. **Forbidden.** |
| AF-4 SharedKey storage     | NEGATIVE | Recipient graph leakage. **Forbidden.** |
| AF-5 Persistent audit log  | NEGATIVE | Subpoena/breach target. **Forbidden.** |
| AF-6 Daemon author filter  | NEGATIVE | Drops dispute DMs. **Forbidden** (functional). |
| AF-7 Registration via notify | NEGATIVE | Enables pubkey enumeration. **Forbidden.** |
| AF-8 Push customization    | NEGATIVE | Requires content. **Forbidden.** |
| AF-9 Routing hints         | NEGATIVE | Conversation-graph leak. **Forbidden.** |
| AF-10 Delivery receipts    | NEGATIVE | Builds presence channel. **Forbidden.** |

---

## Mobile Plan Alignment Matrix

Direct read of the mobile plan was unavailable in this session — alignment is inferred from `PROJECT.md` references.

| Server feature | Mobile plan says | This doc says | Aligned? |
|----------------|------------------|---------------|----------|
| `POST /api/notify { trade_pubkey }` | Required (Phase 4) | TS-1 | YES |
| Response codes `200/404/429` | Required | TS-3 | YES |
| Unauthenticated | Required (privacy threat model) | TS-1 + AF-1 | YES |
| Rate limiting per-pubkey ~5/min, per-IP ~60/min | Required | TS-2 | YES |
| Silent push (no payload customization) | Implied | TS-1 + AF-2/AF-8/AF-9 | YES |
| Sender identification | Explicitly NOT required | AF-3 | YES (rejected) |
| Idempotency / receipts | Not mentioned | D-2 / AF-10 rejected | YES (consistent) |

**No conflicts identified.**

---

## Sources

- **HIGH confidence (project files, read directly):**
  - `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/PROJECT.md`
  - `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/codebase/ARCHITECTURE.md`
  - `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/docs/IMPLEMENTATION_PHASES.md`

- **MEDIUM confidence (training-data ecosystem patterns, not verified live in this session):**
  - Matrix sygnal — accepts notification with no message content for E2EE-encrypted rooms (supports AF-2 reasoning).
  - APNs / FCM v1 silent-push semantics (`content-available` / `data`-only) — supports TS-1 / AF-8.
  - `governor` rate-limiting crate (keyed `RateLimiter`, `Quota::per_minute`) — supports TS-2 mechanics.
  - Stripe-style `Idempotency-Key` header — referenced for D-2 context, rejected on privacy grounds.

- **LOW confidence:**
  - Specific feature surfaces of ntfy.sh, Element notification gateway, Pushbullet, web-push libraries: not verified live. Not load-bearing for any decision; every recommendation is grounded in the project's own privacy invariants.

## Research Limitations

In this session `WebSearch`, `WebFetch`, `Bash`, and `Write` were all permission-denied, as were direct `Read` calls on `/home/andrea/Documents/oss/mostrop2p/mobile/docs/plans/CHAT_NOTIFICATIONS_PLAN.md` and `$HOME/.claude/get-shit-done/templates/research-project/FEATURES.md`. This document was therefore produced from:

1. The two project files that loaded (`PROJECT.md`, `ARCHITECTURE.md`).
2. `IMPLEMENTATION_PHASES.md`.
3. Training-data knowledge of FCM, APNs, sygnal, `governor`, and standard HTTP API patterns, used cautiously and labelled with confidence levels.

Sufficient for FEATURES.md because the project's own files specify the contract, anti-requirements, and privacy invariants in detail. Where a recommendation depends on training-data only (D-1/D-2/D-3 specifics, ntfy/sygnal API surface), it is flagged. If the design phase wants stronger ecosystem corroboration, recommend a follow-up pass with web tools enabled, focused on:
- Sygnal `/_matrix/push/v1/notify` request/response shape (compare to TS-1).
- ntfy.sh anonymous publish quotas and per-IP / per-topic split (compare to TS-2 thresholds).
- Whether any privacy-focused push gateway exposes per-event-type counters in `/status` (compare to TS-4).
