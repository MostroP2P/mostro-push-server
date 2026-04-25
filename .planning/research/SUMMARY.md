# Project Research Summary — Mostro Push Server v1.1 (Chat Notifications)

**Project:** mostro-push-server
**Domain:** Privacy-preserving push notification backend (Rust / Actix-web), brownfield extension
**Milestone:** v1.1 — Chat notifications support (unblocks mobile `CHAT_NOTIFICATIONS_PLAN.md` Phase 4)
**Researched:** 2026-04-24
**Overall confidence:** MEDIUM-HIGH (HIGH on codebase-grounded items; MEDIUM on specific crate APIs and external delivery semantics that could not be web-verified this run)

> Note: This document was written by the orchestrator from findings returned inline by the `gsd-research-synthesizer` agent (the agent's environment denied writing `.md` artifacts). Content is verbatim from the agent's report.

---

## Executive Summary

The milestone is small in surface area (one new endpoint) but load-bearing for the project's privacy posture. All three completed research dimensions — Architecture, Features, Pitfalls — converge on the same shape: a sender-triggered `POST /api/notify { trade_pubkey }` handler that reuses the existing `PushService` dispatch path, fronted by a dual-keyed (per-pubkey + per-IP) rate limiter, with the per-IP key sourced from Fly's `Fly-Client-IP` header. The recommended sequencing is also unanimous: a pure refactor commit (extract `PushDispatcher`, drop the `Mutex`) lands first, the new endpoint lands second, and the rate-limiting layer lands third. This ordering makes each step independently revertible and lets manual smoke-testing isolate failures to one layer.

The **central open design decision** that this synthesis surfaces — and explicitly does not resolve — is the response contract. PROJECT.md and the mobile plan currently specify `200 / 404 / 429`. Both Features (TS-3, AF-7) and Pitfalls (CRIT-2, CRIT-6, RL-2) argue for **always-`202`** on dispatch attempts because differentiated 200/404 enables registered-pubkey enumeration and is itself a privacy oracle. This decision must be coordinated with the mobile team during `/gsd-plan-phase`; the roadmapper should not pre-commit either way.

The biggest risks are CRIT-1 (a future reviewer "fixing" the dormant `mostro_pubkey` validation by applying it as a Nostr author filter — which would silently break dispute chat, defeating one of the milestone's two stated goals) and CRIT-3/DEPLOY-1 (the existing 16-char `trade_pubkey` prefix logging at INFO combined with `RUST_LOG=debug` in `deploy-fly.sh` already correlates pubkeys to IPs in production, and the new sender-triggered endpoint amplifies the leak unless bundled with a hash-based logging helper and a `RUST_LOG=info` deploy change). Those two items are non-negotiable bundle-alongs.

---

## Stack Additions

> **Coverage gap acknowledgement:** The dedicated STACK.md research file does not exist for this milestone. The Stack researcher's environment denied the `WebSearch`/`WebFetch` access required to verify crate versions live, so version-pinning decisions are deferred to `/gsd-plan-phase` (which can re-attempt verification with web tools enabled). The notes below are extracted from ARCHITECTURE.md and PROJECT.md and reflect what the architecture work assumed; treat all version numbers as MEDIUM confidence.

**New dependency (requires explicit user approval per global CLAUDE.md):**
- `actix-governor` — Actix-web middleware adapter on top of the already-declared `governor` crate. Provides the `KeyExtractor` trait used to source the per-IP rate-limit key from `Fly-Client-IP`. Version pin (`0.5` vs `0.6`) is **NOT** decided here — there were `KeyExtractor` API differences across those minors and the exact signature of `extract`, `SimpleKeyExtractionError`, and `Governor::new` must be verified against current crate docs in `/gsd-plan-phase` before writing implementation code.

**Already declared, finally wired in this milestone:**
- `governor` 0.6 — keyed leaky-bucket rate limiter. Used directly inside the handler for the per-pubkey limit (because the key lives in the JSON body and cannot be middleware-extracted). API surface to verify: `RateLimiter::keyed`, `Quota::per_minute().allow_burst(...)`, `check_key`, and the `retain_recent` cleanup hook used to bound key cardinality (RL-1).

**Reused, untouched:**
- `actix-web` 4.x, `tokio` 1.35, `reqwest` 0.11, `serde`/`serde_json`, `log`/`env_logger`, the existing `PushService` trait abstraction.

**Not changed:** `nostr-sdk` 0.27 stays at its current pinned version. Upgrading is explicitly Out of Scope per PROJECT.md line 48.

---

## Critical Convergence (all three dimensions agreed)

These are load-bearing for both REQUIREMENTS.md and ROADMAP.md. Where all three independent research passes reached the same conclusion, treat it as settled.

| Topic | Architecture | Features | Pitfalls | Synthesis |
|---|---|---|---|---|
| Three-commit build order: refactor → endpoint → rate-limit | Q6 (explicit phases 1/2/3) | "Critical-path bundle TS-1 → TS-2" | Phase mapping table rows align with this order | Adopt as the roadmap phase shape. |
| Drop `Mutex<Vec<Box<dyn PushService>>>` in favour of `Arc<[Arc<dyn PushService>]>` | Q1 (Option A + B combined) | TS-1 anti-coupling note | CRIT-5 | Bundle into commit 1; the refactor is "free" given the wiring already changes. |
| Per-IP via middleware, per-pubkey via in-handler check | Q2 (with explicit reasoning against body-parse-in-middleware) | TS-2 | RL-2 (order: validate → per-IP → per-pubkey → lookup → dispatch) | Per-IP must reject before body parse; per-pubkey cannot. Both apply (ANDed). |
| `Fly-Client-IP` is the trusted IP source on Fly; fall back to `peer_addr()` for local dev | Q4 + custom `KeyExtractor` sketch | (not addressed) | CRIT-4 + MIN-3 | Custom `KeyExtractor` reading `Fly-Client-IP`, with documented trust assumption that all ingress traverses the Fly edge proxy. |
| Per-pubkey `governor` map needs cardinality bounding | Q3 (memory-budget note) | (not addressed) | RL-1 | Periodic `retain_recent` task; pre-validate 64-hex pubkey before the limiter sees the key (so garbage doesn't enter the map). |
| Endpoint scoping for the rate-limit middleware | Q2/Q6 (per-route `wrap`) | TS-2 | DEPLOY-3 | Wrap **only** the `/api/notify` scope. Never apply globally — would rate-limit Fly's `/api/health` probes and trigger restart loop. |
| Single shared `reqwest::Client` with explicit `timeout`/`connect_timeout` | Q5 ("defer" but acknowledges concern) | D-3 (include) | CONC-1, CRIT-5 | Two of three say bundle it; combined with the spawn-and-bound pattern this is effectively unavoidable. Treat as bundle-along. |
| `RUST_LOG="debug"` → `RUST_LOG="info"` in `deploy-fly.sh:42` | (not addressed) | TS-4 implication | CRIT-3 + DEPLOY-1 | Hard bundle. Without it the new endpoint's clean logging is meaningless because existing `debug!` calls leak token prefixes. |
| Logs must use a salted truncated hash, never `trade_pubkey[..N]` | (not addressed) | TS-4 (truncate to 8 chars) | CRIT-3 (`BLAKE3::hash("notify-log-v1:..").to_hex()[..8]`) | Pitfalls' stricter form wins (16-char hex prefix is 64 bits — uniquely identifying). New helper `log_pubkey(pk: &str) -> String`. |

---

## Critical Disagreements / Open Design Decisions

### OPEN-1 — Response contract for `/api/notify`: `200/404/429` vs always-`202`

**Disagreement:**
- **PROJECT.md** (line 87) and the mobile plan specify `200 / 404 / 429`.
- **ARCHITECTURE.md Q-tree** lists the same `200/404/429/502` shape as a working assumption but flags it as a design decision for plan-phase ("Consider returning 202 for both — design decision for `/gsd-plan-phase`").
- **FEATURES.md TS-3 + AF-7** argues that 404 must not echo or differentiate, but stops short of recommending 202.
- **PITFALLS.md CRIT-2 + CRIT-6 + RL-2** argues unambiguously for **always-`202` `{ "accepted": true }`** with constant body and similar latency, and dispatch happening in a `tokio::spawn` after the response is sent. Differential 200/404 is called out as a registered-pubkey enumeration oracle; FCM error propagation as a recipient-state oracle.

**Why this matters:** This is a wire-contract decision shared with the mobile codebase. Picking either silently breaks one side: choosing 202 changes what mobile expects to see; sticking with 200/404 keeps a privacy oracle live in production.

**Synthesis recommendation for `/gsd-plan-phase`:** Surface this to the mobile team as a contract change request, framing it as the privacy correction the project's invariants demand. If mobile cannot accept 202 for the registered-but-dispatched case, the fallback is "always 202 for hit-or-miss, 429 for rate-limit, 400 for malformed body" — i.e., never differentiate hit from miss, never propagate FCM error state. The roadmapper **must not pre-pick** in ROADMAP.md; it should appear as an explicit design-spike item in the endpoint phase.

**Tied secondary decisions** that ride on the resolution of OPEN-1:
- Whether to `tokio::spawn` the FCM dispatch after responding (CRIT-2 timing-channel mitigation, CRIT-6 error-oracle mitigation, CONC-1 unbounded-spawn risk).
- Whether to bound spawned tasks via a `tokio::sync::Semaphore` (Pitfalls says yes; Architecture treats as deferred to a future scaling milestone).
- Per-IP vs per-pubkey burst sizing (RL-3 proposes 30/min burst 10 per-pubkey, 120/min burst 30 per-IP; PROJECT.md says ~5/min and ~60/min — there is a 6x and 2x discrepancy that mobile-side traffic-pattern data should resolve in plan-phase).

### OPEN-2 — Backend-failure response: `200/202` (silent) vs `502` (explicit)

**Disagreement:**
- ARCHITECTURE.md Q-tree returns `502` on `AllBackendsFailed`.
- FEATURES.md TS-3 keeps `200` "to avoid encouraging retry-storms on transient FCM/UP failures" (mobile will eventually fetch via Nostr).
- PITFALLS.md CRIT-6 is the strongest: never propagate any FCM failure state, always `202`.

**Synthesis:** Resolution flows from OPEN-1. If always-202 wins, this auto-resolves. If 200/404/429 wins, the question becomes whether to differentiate dispatch failure (502) at all — recommend NOT, on Pitfalls grounds.

### OPEN-3 — Rate-limit burst tuning

PROJECT.md line 35 says `~5/min per trade_pubkey, ~60/min per source IP`. Pitfalls RL-3 argues these are too tight for chat back-and-forth and proposes `30/min burst 10` and `120/min burst 30`. Mobile-side traffic data (typical messages-per-minute during active chat) is needed to resolve. Defer to `/gsd-plan-phase` with input from mobile team.

---

## Anti-Features and Anti-Fixes (REQUIREMENTS must explicitly exclude)

These are hard exclusions. They are listed here so the roadmapper can flag them as anti-requirements in REQUIREMENTS.md and as review-checklist items in the relevant phase.

| ID | Anti-item | Why forbidden | Source |
|---|---|---|---|
| **CRIT-1** | **Adding a `mostro_pubkey` Nostr author filter "to fix" the dormant validation** | Silently breaks dispute chat (admin DMs are user-to-user, not from Mostro daemon) AND breaks P2P chat (peers are senders). Also structurally impossible because Gift Wrap kind 1059 uses ephemeral outer keys (NIP-59). | PITFALLS CRIT-1, PROJECT.md lines 51, 89, 103 |
| AF-1 | Authentication on `/api/notify` (signature, JWT, anything that identifies sender) | Forces sender identification → server can build sender→recipient graph → breaks unlinkability invariant. | FEATURES AF-1, PROJECT.md line 100 |
| AF-2 / AF-8 / AF-9 | Forwarding message content, push UX customization, recipient-routing hints in payload | Server cannot generate any per-conversation user-facing content without seeing content. iOS silent push must be `data`-only. Routing hints leak conversation graph. | FEATURES AF-2, AF-8, AF-9 |
| AF-3 | Including `sender_pubkey` (even optional) in request body or headers | Mineable by operator or via breach. Same outcome as AF-1. | FEATURES AF-3 |
| AF-4 | Storing or accepting `sharedKey` mappings on the server | Server would learn `sharedKey ↔ tradeKey` correlation → can infer trading partners. | FEATURES AF-4, PROJECT.md line 99 |
| AF-5 | Persistent log of `(timestamp, source IP, trade_pubkey)` tuples | Subpoena/breach-attractive. Aggregate counters only. | FEATURES AF-5 |
| AF-7 | Differentiating "registered + dispatched" vs "not registered" in response | Enables registered-pubkey enumeration. (Same root as OPEN-1.) | FEATURES AF-7, PITFALLS CRIT-2 |
| AF-10 | Webhook callback / delivery receipt back to the sender | Builds server-mediated presence channel between sender and recipient. | FEATURES AF-10 |
| **COMPAT-1** | Refactoring `RegisterResponse` / `RegisterTokenRequest` shapes "while we're here" | Breaks existing mobile clients that strict-deserialize current responses. New endpoint's types must live in a new file. | PITFALLS COMPAT-1 |
| **CONC-3** | Storing `last-notified-at` or any per-pubkey state mutation inside the `/api/notify` request lifecycle | Async cancellation can leave the store inconsistent (slot consumed, dispatch never happened). Notify dispatch must be stateless on the store. | PITFALLS CONC-3 |
| **D-2** | `Idempotency-Key` header on `/api/notify` | Persisted dedupe cache becomes correlatable record. Marginal benefit — mobile already dedupes at Nostr-event level. | FEATURES D-2 |
| **D-4** | CORS configuration / `actix-cors` on `/api/notify` | Endpoint is for native mobile apps; allowing browser cross-origin invites a separate browser-mediated abuse vector. Default-deny by not adding. | FEATURES D-4 |

---

## Suggested Phase Shape

The three independent dimensions all converge on the same three-commit ordering. The roadmapper should adopt this as the spine of ROADMAP.md, with bundle-along items distributed across the three phases.

### Phase 1 — Refactor `PushDispatcher` (no behaviour change)

**Rationale:** Pure refactor, easiest commit to revert if anything goes wrong. Resolves CONCERNS Mutex serialization for free since the wiring is already being touched. Establishes the `PushDispatcher` seam that both the existing Nostr listener and the new HTTP handler will call into.

**Delivers:**
- New `src/push/dispatcher.rs` with `PushDispatcher`, `DispatchOutcome`, `DispatchError`.
- `main.rs` wiring change: `Vec<Box<dyn PushService>>` → `Vec<Arc<dyn PushService>>` → `Arc<PushDispatcher>`. Drop `tokio::sync::Mutex` wrapper.
- `nostr/listener.rs` calls `dispatcher.dispatch(...)` instead of inlining the iteration loop.

**Verification:** Existing Gift Wrap → push flow still works end-to-end (Mostro daemon event still produces a push). Same logs, same outcomes.

**Avoids:** CRIT-5 (Mutex contention multiplier when the second producer arrives in Phase 2).

### Phase 2 — `POST /api/notify` endpoint (no rate limit yet)

**Rationale:** Land the contract end-to-end so the mobile team can integrate against staging while Phase 3's rate-limiting is being built. Adding rate limiting to a non-functional endpoint hides which layer broke when something fails.

**Delivers:**
- New types in a new file `src/api/notify.rs` (NOT in `routes.rs`, per COMPAT-1) for `NotifyRequest` and the response type.
- `notify_token` handler: validate 64-hex pubkey, lookup via `TokenStore`, dispatch via `PushDispatcher`, respond per the OPEN-1 resolution.
- New `log_pubkey()` helper using salted BLAKE3 hash (CRIT-3) — used by the new handler from day one.
- Wire `Arc<PushDispatcher>` into `AppState`.

**Bundle-alongs (load-bearing):**
- Single shared `reqwest::Client` with `timeout(5s)` + `connect_timeout(2s)` constructed in `main.rs` (CONCERNS, D-3, CRIT-5).
- `RUST_LOG="debug"` → `RUST_LOG="info"` in `deploy-fly.sh:42` (CRIT-3, DEPLOY-1). One-line change, hard-bundle: shipping Phase 2 without it leaves the existing `debug!` calls leaking token prefixes.
- Resolve OPEN-1 (response contract) and OPEN-2 (backend-failure response). Document the choice in the handler doccomment.
- Decision and implementation of "dispatch in `tokio::spawn`" (Pitfalls CRIT-2/CRIT-6/CONC-1) tied to OPEN-1 resolution.

**Verification:** curl POST `/api/notify` → registered pubkey produces a push; manual smoke against the existing iOS/Android FCM path. (FCM-1: new payload builder for silent notify, `apns-priority: 5` + `apns-push-type: background`, no `alert` key.)

**Addresses:** TS-1, TS-3, partially TS-4. Avoids CRIT-3, CRIT-6, COMPAT-1, FCM-1.

### Phase 3 — Rate limiting on `/api/notify` (per-IP middleware + per-pubkey handler check)

**Rationale:** Most likely place for "works in dev, mysteriously rejects in prod" surprises (Fly-Client-IP, clock skew, quota tuning). Land it last so any rollback is surgical.

**Delivers:**
- New `src/api/rate_limit.rs` with `FlyClientIpKeyExtractor` and `PerPubkeyLimiter`.
- Per-IP `actix-governor` middleware wrapping ONLY the `/api/notify` scope (DEPLOY-3).
- Per-pubkey `governor` keyed limiter checked at the start of `notify_token` (after pubkey validation, before token lookup, per RL-2 ordering).
- New env vars `NOTIFY_RATE_PER_PUBKEY_PER_MIN` and `NOTIFY_RATE_PER_IP_PER_MIN` (MIN-2 — leave existing `RATE_LIMIT_PER_MINUTE` alone).
- Periodic `retain_recent` task to bound `governor` map cardinality (RL-1).
- `actix-governor` added to `Cargo.toml` after explicit user approval.
- Cardinality alarm: log warning if `limiter.len()` exceeds soft cap.

**Bundle-alongs:**
- Minimum integration tests using `actix_web::test::init_service` exercising the six TEST-1 scenarios (registered hit, unregistered "miss", malformed body, per-pubkey 429, per-IP 429, register-shape compat). Real `governor` middleware, stub `PushService`.
- TS-4 observability counters extending `GET /api/status` (`notify_total`, `notify_429_ip_total`, `notify_429_pubkey_total`, `relay_dispatch_total`, dispatch success/error per backend). In-memory `AtomicU64`.
- Documented dispute-chat verification runbook (TS-5) — manual test, not code.

**Avoids:** CRIT-4, RL-1, RL-2, RL-3 (with the burst-tuning resolution from OPEN-3), DEPLOY-3.

### Phase Ordering Rationale

- **Refactor first:** structurally revertible; resolves the existing Mutex concern as a side effect of work that has to happen anyway.
- **Endpoint before rate-limit:** mobile can integrate against staging while Phase 3 builds; avoids debugging "endpoint broken or rate-limit broken?" ambiguity.
- **Rate-limit last:** highest production-environment risk surface (Fly proxy headers, quota tuning) isolated to a small, surgical commit.

### Research Flags

- **Phase 1:** Standard refactor patterns. No deeper research needed beyond reading the current `nostr/listener.rs` carefully. Skip `/gsd-research-phase`.
- **Phase 2:** Needs `/gsd-plan-phase` design spike on the OPEN-1 contract decision (mobile-team coordination), the OPEN-2 backend-failure question, and FCM-1 iOS payload verification (`apns-push-type: background` + `apns-priority: 5`). Recommend running `/gsd-research-phase` if web tools are available, focused narrowly on FCM v1 + APNs silent-push semantics.
- **Phase 3:** Needs `/gsd-plan-phase` to verify `actix-governor` and `governor` 0.6 API surface (`KeyExtractor::extract` signature, `Quota` builder, `retain_recent` cleanup hook) against current crate docs, and to verify Fly's `Fly-Client-IP` header semantics against current Fly docs. Recommend `/gsd-research-phase` here too if web tools are available.

---

## Items Needing Verification in `/gsd-plan-phase`

| Item | Confidence | What to verify | Why it matters |
|---|---|---|---|
| `actix-governor` `KeyExtractor` trait surface (`extract` signature, associated types, `SimpleKeyExtractionError`) | MEDIUM | Crate docs for the chosen version (0.5 vs 0.6) | Whole per-IP limiter sketch in ARCHITECTURE depends on it. |
| `actix-governor` version pin | MEDIUM | Whether 0.5 or 0.6 has the API the implementation expects | Affects `Cargo.toml` and triggers explicit user approval before adding the dep. |
| `governor` 0.6 keyed-limiter API (`check_key` vs `check`, `Quota::per_minute(...).allow_burst(...)`) | MEDIUM | Crate docs | RL-3 burst tuning pattern + RL-1 cardinality cleanup `retain_recent` depend on the exact method names. |
| `Fly-Client-IP` header behaviour (always-set, always-stripped-on-ingress, single-value semantics) | MEDIUM | Fly.io networking docs | CRIT-4 trust assumption. If the header is client-passthrough on any path, per-IP limiting is bypassable. |
| FCM v1 silent-push payload requirements: `apns-push-type: background` (required for silent) and `apns-priority: 5` (instead of current code's `10`) | MEDIUM-HIGH | Apple APNs `Pushing background updates to your app` doc + FCM v1 reference | FCM-1: high-priority silent pushes are an Apple-documented anti-pattern that throttles the app over time. Currently `src/push/fcm.rs:196-211` uses `apns-priority: "10"` for silent — wrong shape for chat frequency. |
| Mobile-side traffic pattern for rate-limit burst sizing (`~5/min` per PROJECT.md vs `30/min burst 10` per RL-3) | LOW | Mobile team input + observed chat back-and-forth profile | RL-3 UX cliff vs effective abuse mitigation. |
| Resolution of OPEN-1 (response contract) and OPEN-2 (backend-failure response) | n/a (decision) | Coordinate with mobile team owning `CHAT_NOTIFICATIONS_PLAN.md` | Whole privacy posture of the endpoint depends on it. |
| Verify the existing `reqwest::Client::new()` calls in `src/push/fcm.rs` and `src/push/unifiedpush.rs` actually have no timeout | HIGH (per CONCERNS) but bears re-checking | Read constructors | Confirms whether shared-client + timeouts is a refactor or a fix. |

---

## Coverage Gap from the Missing STACK.md

The Stack research dimension did not produce a file because the assigned researcher's environment lacked WebSearch / WebFetch needed for live version verification. The downstream impact is bounded — most of the milestone's stack is already declared in the existing `Cargo.toml` and is not changing — but it does mean:

- **No independent recommendation on `actix-governor` 0.5 vs 0.6.** The architecture work flagged this and pushed the decision to plan-phase. Roadmapper should treat the version pin as an explicit task, not a foregone conclusion.
- **No independent verification of `governor` 0.6's keyed-API stability.** ARCHITECTURE assumes `RateLimiter::keyed`, `check_key`, `retain_recent`. Plan-phase must confirm.
- **No survey of alternatives.** Whether `tower-governor`, a hand-rolled DashMap-based limiter, or another middleware would be a better fit was not researched. Architecture's "stick with `governor` because it's already declared" reasoning is sound but is not the result of a comparative study.
- **No independent stack-level take on the iOS silent-push payload (FCM-1) or on `reqwest` timeout configuration.** Both came in via Pitfalls/Architecture, not Stack. Confidence on those is correspondingly MEDIUM.

The roadmapper should mark "verify and pin `actix-governor` version + verify `governor` 0.6 keyed-API surface" as an explicit Phase 3 prep task, and should consider re-running just the Stack dimension during `/gsd-plan-phase` if web tools become available — focused narrowly on those two crates and on FCM v1 / APNs silent-push doc verification.

---

## Confidence Assessment

| Area | Confidence | Notes |
|---|---|---|
| Stack | LOW (no file) — see coverage gap above | Version pins inferred from ARCHITECTURE; not independently verified. |
| Features | MEDIUM-HIGH | HIGH on project-specific items (grounded in PROJECT.md and codebase analysis); MEDIUM on ecosystem comparison (FEATURES researcher couldn't access ntfy/sygnal docs). Privacy reasoning is HIGH because it's grounded in PROJECT.md's invariants. |
| Architecture | HIGH on layering / build-order / data flow (codebase-grounded with file/line citations); MEDIUM on `actix-governor` API specifics (web verification was unavailable). |
| Pitfalls | HIGH on items grounded in the codebase (file/line citations); MEDIUM on FCM/iOS delivery semantics and Fly proxy header behavior (based on stable published guidance, web search was unavailable). |

**Overall confidence:** MEDIUM-HIGH for proceeding to REQUIREMENTS.md and ROADMAP.md, with the explicit understanding that `/gsd-plan-phase` must verify the items listed above before implementation begins.

### Gaps to Address

- **OPEN-1 / OPEN-2** must be resolved with mobile-team input before Phase 2 implementation. Roadmapper should mark these as design-decision tasks at the start of Phase 2.
- **Crate API surfaces** for `actix-governor` and `governor` 0.6 need live verification. Mark as a Phase 3 prep task.
- **Rate-limit burst values** need mobile-team input on traffic profile.
- **FCM v1 + APNs silent-push payload** for the new endpoint needs verification against current Apple/Google docs (FCM-1).

---

## Sources

### Primary (HIGH confidence — read directly from the codebase)

- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/PROJECT.md`
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/codebase/ARCHITECTURE.md`
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/codebase/CONCERNS.md`
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/docs/IMPLEMENTATION_PHASES.md`
- `src/main.rs`, `src/api/routes.rs`, `src/nostr/listener.rs`, `src/store/mod.rs`, `src/push/fcm.rs`, `src/push/mod.rs`, `src/config.rs`, `deploy-fly.sh`, `fly.toml`

### Research dimension files

- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/research/ARCHITECTURE.md` (HIGH on codebase grounding, MEDIUM on `actix-governor` specifics)
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/research/FEATURES.md` (HIGH on project-specific items, MEDIUM on ecosystem comparison)
- `/home/andrea/Documents/oss/mostrop2p/mostro-push-server/.planning/research/PITFALLS.md` (HIGH on codebase-grounded items, MEDIUM on FCM/APNs/Fly semantics)
- **STACK.md — NOT PRODUCED** (researcher environment lacked WebSearch/WebFetch)

### Secondary (MEDIUM confidence — training-data ecosystem patterns)

- Apple Developer Documentation — `Pushing background updates to your app` (`apns-priority: 5`, `apns-push-type: background`, silent-push throttling)
- Firebase Cloud Messaging HTTP v1 API reference (`android.priority`, `apns.headers`, `apns.payload.aps.content-available`)
- `governor` 0.6 keyed-rate-limiter docs (`retain_recent`, in-memory cardinality)
- `actix-governor` README (middleware scoping, `KeyExtractor` trait shape)
- Fly.io networking documentation (`Fly-Client-IP` header semantics, edge-proxy trust boundary)

### Tertiary (LOW confidence — single-source / inference)

- Matrix sygnal `/_matrix/push/v1/notify` shape comparison (referenced in FEATURES, not verified live)
- ntfy.sh anonymous publish quotas (referenced in FEATURES, not verified live)

---

*Research synthesis completed: 2026-04-24*
*Ready for requirements / roadmap: yes, with the OPEN-1 / OPEN-2 / OPEN-3 design decisions explicitly marked for `/gsd-plan-phase`*
