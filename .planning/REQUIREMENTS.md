# Requirements — Mostro Push Server v1.1 (Chat Notifications)

**Project:** mostro-push-server
**Milestone:** v1.1 — Chat notifications support
**Defined:** 2026-04-24
**Source documents:** `.planning/PROJECT.md`, `.planning/research/SUMMARY.md`, `.planning/research/{ARCHITECTURE,FEATURES,PITFALLS}.md`, `mobile/docs/plans/CHAT_NOTIFICATIONS_PLAN.md`

This milestone unblocks Phase 4 of the mobile chat-notifications plan by giving the push server a sender-triggered notify endpoint, dual-keyed rate limiting, and the dispatch-layer refactor needed to share push delivery between the existing Nostr listener and the new HTTP handler — without compromising the project's unlinkability invariants.

---

## v1.1 Requirements

### DISPATCH — Push dispatch refactor (foundation)

- [x] **DISPATCH-01**: Push dispatch logic is extracted into a single `PushDispatcher` component that owns an immutable `Arc<[Arc<dyn PushService>]>` (no `Mutex`), exposes one async `dispatch(token)` method, and is callable by both the existing Nostr listener and the new HTTP notify handler.
- [x] **DISPATCH-02**: After the refactor, the existing Nostr-listener → silent-push flow for Mostro daemon events continues to work end-to-end with no observable behaviour change.

### NOTIFY — Sender-triggered notify endpoint

- [x] **NOTIFY-01
**: Server exposes a new `POST /api/notify` endpoint that accepts a `{ "trade_pubkey": "<64-hex>" }` body, validates the pubkey shape, and dispatches a silent push to the device registered for that pubkey via `PushDispatcher`. The response contract (status codes / body shape) is finalized in `/gsd-plan-phase` against open decision OPEN-1 — see "Open Design Decisions" below.
- [x] **NOTIFY-02
**: The endpoint matches the wire contract that Mostro Mobile will call from `mobile/docs/plans/CHAT_NOTIFICATIONS_PLAN.md` Phase 4. Any contract change negotiated under OPEN-1 is coordinated with the mobile team before implementation.
- [x] **NOTIFY-03
**: The existing `POST /api/register`, `POST /api/unregister`, `GET /api/health`, `GET /api/info`, and `GET /api/status` endpoints' request and response shapes remain byte-identical to the pre-milestone version (no incidental refactor of `RegisterResponse` / `RegisterTokenRequest` / `UnregisterTokenRequest`).
- [x] **NOTIFY-04
**: An `X-Request-Id` middleware generates a server-side UUIDv4 per request and exposes it on the response. The middleware ignores any inbound `X-Request-Id` from the client (privacy-safe correlation only).

### LIMIT — Abuse mitigation on `/api/notify`

- [ ] **LIMIT-01**: A per-source-IP rate limit is enforced on `/api/notify` via an `actix-governor` middleware whose `KeyExtractor` reads `Fly-Client-IP` first (Fly's edge-injected canonical client-IP header), falls back to the rightmost segment of `X-Forwarded-For`, and finally to `req.peer_addr()` for local development. Exact governor crate version and `KeyExtractor` API are pinned in `/gsd-plan-phase` (OPEN-4).
- [ ] **LIMIT-02**: A per-`trade_pubkey` rate limit is enforced inside the `notify_token` handler (after pubkey validation, before token lookup) using the existing `governor` crate's keyed limiter.
- [ ] **LIMIT-03**: The rate-limiting middleware is applied **only** to the `/api/notify` route scope. `GET /api/health`, `GET /api/info`, `GET /api/status`, `POST /api/register`, and `POST /api/unregister` are not rate-limited by this milestone's middleware.
- [ ] **LIMIT-04**: Rate-limit quotas (per-pubkey and per-IP) are configurable at runtime via two new environment variables — names tentatively `NOTIFY_RATE_PER_PUBKEY_PER_MIN` and `NOTIFY_RATE_PER_IP_PER_MIN`. The existing `RATE_LIMIT_PER_MINUTE` env var is left untouched. Burst sizes are decided in `/gsd-plan-phase` (OPEN-3).
- [ ] **LIMIT-05**: A periodic background task calls `governor`'s `retain_recent` (or equivalent) on the per-pubkey keyed limiter to bound in-memory key cardinality on the 512MB Fly machine.
- [ ] **LIMIT-06**: When the per-pubkey limiter's internal map size exceeds a configurable soft cap (default ~100k entries), a `warn!` line is logged so an operator can detect active key-bombing.

### PRIV — Privacy hardening bundled across phases

- [x] **PRIV-01
**: A new `log_pubkey(pk: &str) -> String` helper in the source tree produces a salted truncated BLAKE3 hash (e.g. `BLAKE3::hash("notify-log-v1:" + pk).to_hex()[..8]`) and is the only sanctioned form of pubkey identifier in any `info!`/`warn!` log line emitted by the new endpoint or by the dispatch refactor.
- [x] **PRIV-02
**: `deploy-fly.sh` sets `RUST_LOG="info"` (down from the current `"debug"`). Bundled into this milestone because shipping `/api/notify` while production logs at `debug` would amplify the existing token-prefix leakage in `src/push/fcm.rs` and `src/push/unifiedpush.rs`.
- [x] **PRIV-03
**: The `notify_token` handler never logs source IP, request body, response body, FCM/UnifiedPush token strings, or anything that could correlate sender to recipient. (Source IP for rate-limiting is held in memory only by the governor middleware; not emitted to logs.)

### VERIFY — Verification and tests

- [ ] **VERIFY-01**: An in-process integration test suite (using `actix_web::test::init_service` against a real `governor` middleware and a stub `PushService`) covers `/api/notify` with: a valid registered pubkey, a valid unregistered pubkey, a malformed pubkey body, sustained calls hitting the per-pubkey 429 boundary, and sustained calls from a single `Fly-Client-IP` header value hitting the per-IP 429 boundary. The exact assertion shape adapts to the OPEN-1 resolution (e.g. `200/404` differentiated bodies vs always-`202`).
- [ ] **VERIFY-02**: A regression test verifies the existing `/api/register` and `/api/unregister` responses are byte-identical to a frozen pre-milestone fixture, catching any incidental refactor that would break current mobile clients.
- [x] **VERIFY-03
**: A manual runbook lives at `docs/verification/dispute-chat.md` documenting how to verify end-to-end that an admin DM (sent directly user-to-user, NOT routed through the Mostro daemon, addressed at `p` tag = a registered `trade_pubkey`) reaches the registered device as a silent push via the existing relay-monitoring path. Includes a reminder that no `.authors(mostro_pubkey)` filter must be added to the listener (anti-requirement on the milestone).

---

## Future Requirements (deferred — candidates for follow-up milestones)

- **F-01**: Bound `tokio::spawn`-based notify dispatch with a `tokio::sync::Semaphore` so the new endpoint cannot accumulate unbounded in-flight FCM calls. Surfaces in this milestone only if OPEN-1 resolves to "always-202 with deferred dispatch"; otherwise belongs to a scaling/concurrency milestone.
- **F-02**: TS-4 observability counters (`notify_total`, `notify_429_ip_total`, `notify_429_pubkey_total`, `relay_dispatch_total`, `dispatch_fcm_success_total`, `dispatch_fcm_error_total`, etc.) exposed via `GET /api/status` as `AtomicU64` extensions to `TokenStoreStats`.
- **F-03**: A separate FCM payload builder for `/api/notify` with `apns-priority: "5"` and `apns-push-type: "background"`, distinct from the existing `build_payload_for_token` (which is sized for low-frequency Mostro events at `apns-priority: "10"`). FCM-1 in PITFALLS — required to avoid Apple's documented silent-push throttling, but deferrable if `/api/notify` only sees Android traffic in early rollout.
- **F-04**: Server-side integration test for the dispute-chat path (publishes a simulated kind 1059 admin DM at the registered `trade_pubkey` against an embedded relay or the configured staging relay, asserts the listener fires).
- **F-05**: Tighten `PushService::send_to_token` to return `Result<(), Box<dyn Error + Send + Sync>>` so future `tokio::spawn` users don't lose error chains via `e.to_string()` workarounds.
- **F-06**: Replace `reqwest::Client::new()` per-service with a single shared `reqwest::Client` constructed in `main.rs` with explicit `connect_timeout(2s)` and `timeout(5s)`. CONCERNS already flags this; folds in here if we need it for `/api/notify`'s self-DoS resilience, otherwise its own outbound-hardening milestone.
- **F-07**: Unify the duplicate `Platform` enum across `src/store/` and `src/crypto/` into a single source of truth.

---

## Out of Scope (anti-requirements — explicit exclusions)

These are deliberately not built, with reasons recorded so future contributors do not re-propose them.

### Deferred to other milestones (could be valuable, just not this one)

- **OOS-01**: Activating the encryption path in `src/crypto/` (`#[allow(dead_code)]` Phase 4) — separate milestone with mobile coordination and key rotation.
- **OOS-02**: Rotating the `SERVER_PRIVATE_KEY` literal committed in `deploy-fly.sh:30` and removing it from git history — bundled with OOS-01 because the key is dormant until then.
- **OOS-03**: Persistent `TokenStore` (Redis / SQLite migration) — separate scaling milestone.
- **OOS-04**: Authentication on `/api/register` (NIP-98 / Schnorr signature on registration body) — separate anti-abuse milestone.
- **OOS-05**: Migration off `nostr-sdk = "0.27"` — substantial dependency-upgrade milestone.
- **OOS-06**: CI / GitHub Actions pipeline, formal integration test harness beyond VERIFY-01/02 — observability/CI milestone.
- **OOS-07**: Metrics endpoint, graceful SIGTERM shutdown, structured/JSON logging — observability milestone.
- **OOS-08**: APNs-direct backend (without FCM) — iOS continues delivering via FCM as it does today.
- **OOS-09**: Wiring the existing `BatchingManager` and consuming `BATCH_DELAY_MS` / `COOLDOWN_MS` — batching is irrelevant to the chat-notification flow.

### Forbidden by privacy invariants (must NEVER be added)

- **OOS-10**: Authentication on `/api/notify` (signature, JWT, or any header that identifies the sender) — would let the server build a sender→recipient graph and break the unlinkability invariant. Documented Key Decision in PROJECT.md.
- **OOS-11**: Any field that identifies the sender (e.g. an optional `sender_pubkey` in the request body) — same outcome as OOS-10. The contract is intentionally `{ trade_pubkey }` only.
- **OOS-12**: Server-side storage or registration of `sharedKey` mappings — server would learn `sharedKey ↔ tradeKey` correlations and could infer trading partners. Mobile chose the sender-triggered design specifically to avoid this.
- **OOS-13**: Persistent log of `(timestamp, source IP, target trade_pubkey)` tuples — subpoena/breach-attractive record. Aggregate counters only; rate-limiter state is in-memory.
- **OOS-14**: Forwarding message content, push payload customization (sound, badge, group, channel), or any conversation-routing hint in the silent push payload — server cannot generate user-facing content without seeing content; routing hints leak conversation graph.
- **OOS-15**: Webhook callback / delivery receipt to the sender — would build a server-mediated presence channel between sender and recipient.
- **OOS-16**: `Idempotency-Key` header on `/api/notify` — persisted dedupe cache becomes a correlatable record. Mobile already dedupes at the Nostr-event level.
- **OOS-17**: CORS configuration / `actix-cors` on `/api/notify` — endpoint is consumed by native mobile apps; allowing browser cross-origin invites a separate browser-mediated abuse vector.
- **OOS-18**: Differentiating "registered + dispatched" vs "not registered" in the response shape (status code, body, latency, headers) — enables registered-pubkey enumeration. Tied to OPEN-1 resolution: even if OPEN-1 keeps `200/404`, the bodies must not echo or differentiate.

### Anti-fixes (changes that look like improvements but would regress this milestone)

- **OOS-19**: Adding `.authors(mostro_pubkey)` to the Nostr listener's `Filter::new()` chain — would silently drop admin DMs (admin contacts the user directly, NOT through the Mostro daemon) and P2P chat (peers are senders). Also structurally impossible because Gift Wrap kind 1059 uses ephemeral outer keys (NIP-59). The dormant `MOSTRO_PUBKEY` validation may be deleted but the filter must NOT be applied. Hard anti-requirement, recorded in PROJECT.md and PITFALLS CRIT-1.
- **OOS-20**: Refactoring `RegisterResponse` / `RegisterTokenRequest` / `UnregisterTokenRequest` shapes "while we're here" — would break existing strict-deserialized mobile clients. New endpoint's types live in a new file.
- **OOS-21**: Mutating `TokenStore` from the `notify_token` handler (e.g. `last-notified-at` field) — async cancellation would leave the store inconsistent. Notify dispatch is stateless on the store; only `register`/`unregister` mutate it.

---

## Open Design Decisions (resolved during `/gsd-plan-phase`)

These are surfaced from the research and **deliberately not pre-decided here**. The roadmapper should mark each as a design-spike task in the relevant phase.

| ID | Decision | Default if no other input | Resolved in |
|----|----------|---------------------------|-------------|
| **OPEN-1** | Response contract for `/api/notify`: `200/404/429` (per PROJECT.md & mobile plan) vs always-`202` (per PITFALLS CRIT-2/CRIT-6). Affects whether dispatch happens in-request or via `tokio::spawn` after response. | Coordinate with mobile team; if they cannot accept always-`202`, fall back to `200` for hit-or-miss + `429` for rate-limit + `400` for malformed (i.e. never differentiate hit vs miss). | Phase 2 plan |
| **OPEN-2** | Backend-failure response: `200`/`202` silent (mobile fetches via Nostr fallback) vs `502` explicit. | Auto-resolves if OPEN-1 picks always-`202`. Otherwise default to `200` (silent) on Pitfalls grounds. | Phase 2 plan |
| **OPEN-3** | Rate-limit burst sizing — PROJECT.md says ~`5`/min per-pubkey + ~`60`/min per-IP; PITFALLS RL-3 argues for `30`/min burst `10` per-pubkey + `120`/min burst `30` per-IP based on chat back-and-forth profile. | Need mobile-team traffic-pattern input; default to the more permissive numbers if no data. | Phase 3 plan |
| **OPEN-4** | `actix-governor` version pin and exact `KeyExtractor` trait surface. | Verify against current crate docs at plan time; pick the version whose API matches the implementation sketch in `.planning/research/ARCHITECTURE.md`. | Phase 3 plan |
| **OPEN-5** | Whether to ship a separate FCM payload builder for `/api/notify` (FCM-1: `apns-priority: 5` + `apns-push-type: background`) or reuse `build_payload_for_token`. | Recommend separate builder to avoid Apple silent-push throttling, but verify against current Apple/Google docs. | Phase 2 plan or F-03 follow-up |
| **OPEN-6** | Whether to delete the dormant `MOSTRO_PUBKEY` config field + listener validation (CONCERNS dead-code item) as part of this milestone, or leave for a separate cleanup. | Recommend deletion in Phase 1 with a comment explaining WHY no author filter can ever be added (CRIT-1). | Phase 1 plan |

---

## Traceability

Every v1.1 requirement is mapped to exactly one phase. Coverage: 17 / 17.

| REQ-ID | Phase | Status |
|--------|-------|--------|
| DISPATCH-01 | Phase 1 | Complete |
| DISPATCH-02 | Phase 1 | Complete |
| NOTIFY-01   | Phase 2 | Pending |
| NOTIFY-02   | Phase 2 | Pending |
| NOTIFY-03   | Phase 2 | Pending |
| NOTIFY-04   | Phase 2 | Pending |
| PRIV-01     | Phase 2 | Pending |
| PRIV-02     | Phase 2 | Pending |
| PRIV-03     | Phase 2 | Pending |
| VERIFY-03   | Phase 2 | Pending |
| LIMIT-01    | Phase 3 | Pending |
| LIMIT-02    | Phase 3 | Pending |
| LIMIT-03    | Phase 3 | Pending |
| LIMIT-04    | Phase 3 | Pending |
| LIMIT-05    | Phase 3 | Pending |
| LIMIT-06    | Phase 3 | Pending |
| VERIFY-01   | Phase 3 | Pending |
| VERIFY-02   | Phase 3 | Pending |

### Phase composition

| Phase | Requirements | Count |
|-------|--------------|-------|
| Phase 1 — PushDispatcher refactor | DISPATCH-01, DISPATCH-02 | 2 |
| Phase 2 — `/api/notify` endpoint with privacy hardening | NOTIFY-01, NOTIFY-02, NOTIFY-03, NOTIFY-04, PRIV-01, PRIV-02, PRIV-03, VERIFY-03 | 8 |
| Phase 3 — Dual-keyed rate limiting and verification harness | LIMIT-01, LIMIT-02, LIMIT-03, LIMIT-04, LIMIT-05, LIMIT-06, VERIFY-01, VERIFY-02 | 8 |
| **Total** | | **17 / 17** |

---

*Last updated: 2026-04-24 by `/gsd-roadmapper` (Traceability section populated from ROADMAP.md)*
