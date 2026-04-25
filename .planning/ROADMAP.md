# Roadmap — Mostro Push Server v1.1 (Chat Notifications)

**Project:** mostro-push-server
**Milestone:** v1.1 — Chat notifications support
**Granularity:** standard (3 phases — converged from research)
**Defined:** 2026-04-24
**Source documents:** `.planning/PROJECT.md`, `.planning/REQUIREMENTS.md`, `.planning/research/SUMMARY.md`, `.planning/research/{ARCHITECTURE,FEATURES,PITFALLS}.md`

This roadmap unblocks Phase 4 of the Mostro Mobile `CHAT_NOTIFICATIONS_PLAN.md` by adding a sender-triggered `POST /api/notify` endpoint and dual-keyed rate limiting on top of a small dispatch-layer refactor — without weakening the project's unlinkability invariants.

The three independent research dimensions (Architecture, Features, Pitfalls) all converged on the same 3-commit ordering: **refactor first, endpoint second, rate-limit third**. PRIV (privacy hardening) and VERIFY (tests/runbook) requirements are bundle-alongs distributed across the phases that need them, not standalone phases — putting them in their own phase would either ship insecure intermediate states (PRIV) or test against incomplete code (VERIFY).

---

## Phases

- [ ] **Phase 1: PushDispatcher refactor (no behaviour change)** — Extract the inline dispatch loop from the Nostr listener into a reusable `PushDispatcher` and drop the `Mutex<Vec<Box<dyn PushService>>>` in favour of `Arc<[Arc<dyn PushService>]>`.
- [ ] **Phase 2: `POST /api/notify` endpoint with privacy hardening** — Ship the sender-triggered notify handler, request-id middleware, hash-based pubkey logging, and the deploy-side `RUST_LOG=info` change required to keep the endpoint privacy-safe in production.
- [ ] **Phase 3: Dual-keyed rate limiting and verification harness** — Add per-IP `actix-governor` middleware (Fly-Client-IP keyed) scoped strictly to `/api/notify`, plus an in-handler per-`trade_pubkey` keyed limiter, with the integration-test suite that exercises the wiring end-to-end.

---

## Phase Details

### Phase 1: PushDispatcher refactor (no behaviour change)
**Goal**: The push-dispatch path is owned by a single reusable component callable by both the existing Nostr listener and the upcoming HTTP notify handler, with the Mutex-serialised delivery bottleneck removed and the existing Mostro daemon push flow unchanged.
**Depends on**: Nothing (first phase of the milestone)
**Requirements**: DISPATCH-01, DISPATCH-02
**Open Decisions resolved here**: OPEN-6 (delete dormant `MOSTRO_PUBKEY` config + listener validation, with a comment block explaining why no `.authors(...)` filter can ever be added — anti-CRIT-1).
**Success Criteria** (what must be TRUE):
  1. A Mostro daemon `kind 1059` Gift Wrap event addressed at a registered `trade_pubkey` still produces a silent push to the registered device, with the same observable behaviour as before the refactor (no missed events, no doubled events, same backend chosen).
  2. There is no `tokio::sync::Mutex` left wrapping the push-services list anywhere in the runtime; the services are held as `Arc<[Arc<dyn PushService>]>` and shared lock-free between the listener and any future caller.
  3. The Nostr listener no longer inlines the "find first matching backend, send, break on success" loop; it makes a single call into the new `PushDispatcher` whose dispatch outcome is logged.
  4. The dormant `MOSTRO_PUBKEY` config field and its startup validation are either removed or annotated with a hard-anti-fix comment that names the CRIT-1 anti-requirement and forbids ever adding `.authors(mostro_pubkey)` to the listener filter chain.
**Plans:** 1 plan
Plans:
- [x] 01-01-PLAN.md — Refactor push-dispatch ownership: extract PushDispatcher, drop Mutex, add anti-CRIT-1 comment, tighten PushService trait

### Phase 2: `POST /api/notify` endpoint with privacy hardening
**Goal**: A registered Mostro Mobile client sending `POST /api/notify { trade_pubkey }` causes a silent push to reach the device registered for that pubkey, and shipping this endpoint does not introduce a `trade_pubkey ↔ source IP` correlation in production logs.
**Depends on**: Phase 1 (consumes `PushDispatcher` from `AppState`)
**Requirements**: NOTIFY-01, NOTIFY-02, NOTIFY-03, NOTIFY-04, PRIV-01, PRIV-02, PRIV-03, VERIFY-03
**Open Decisions resolved here**:
  - OPEN-1 (response contract for `/api/notify`: `200/404/429` per PROJECT.md vs always-`202` per PITFALLS CRIT-2/CRIT-6) — coordinate with the Mostro Mobile team that owns `CHAT_NOTIFICATIONS_PLAN.md` Phase 4 before implementation.
  - OPEN-2 (backend-failure response: `200`/`202` silent vs `502` explicit) — auto-resolves with OPEN-1; default to silent on Pitfalls grounds.
  - OPEN-5 (separate FCM payload builder for `/api/notify` with `apns-priority: 5` + `apns-push-type: background` vs reuse of `build_payload_for_token`) — recommend separate builder per FCM-1; verify against current Apple/Google docs.
**Success Criteria** (what must be TRUE):
  1. `POST /api/notify` with a registered `trade_pubkey` produces a silent push that reaches the registered device via the same backend the Nostr-listener path would have used (manual smoke test against a real iOS or Android device with FCM, plus a log line indicating dispatch succeeded).
  2. `POST /api/notify` with a malformed pubkey body returns the documented `400`-class error; the response contract negotiated under OPEN-1 (whether `200/404` or always-`202` for hit-or-miss) is honoured byte-identically regardless of whether the pubkey was registered.
  3. Existing `/api/register`, `/api/unregister`, `/api/health`, `/api/info`, and `/api/status` endpoints' request and response bodies remain byte-identical to a frozen pre-milestone fixture (no incidental refactor of `RegisterResponse`, `RegisterTokenRequest`, or `UnregisterTokenRequest`).
  4. Every response carries an `X-Request-Id` header generated server-side as a UUIDv4; any inbound `X-Request-Id` from the client is ignored.
  5. After the Phase 2 change is deployed (including `deploy-fly.sh` flipping `RUST_LOG="debug"` to `"info"`), no log line — emitted from any module — contains a recognisable hex pubkey prefix or a registered FCM/UnifiedPush token; pubkey identifiers in logs originate exclusively from the salted truncated BLAKE3 helper introduced in this phase.
  6. A documented manual runbook at `docs/verification/dispute-chat.md` walks an operator through verifying that an admin DM (sent directly user-to-user, NOT routed through the Mostro daemon) reaches a registered device as a silent push via the existing Nostr-listener path — including the explicit reminder that no `.authors(mostro_pubkey)` filter must ever be added (anti-CRIT-1).
**Plans:** 3 plans
Plans:
- [x] 02-01-PLAN.md — Add shared reqwest::Client with timeouts (D-07/D-08 foundation; constructor cascade through FcmPush + UnifiedPushService)
- [x] 02-02-PLAN.md — Add POST /api/notify endpoint + privacy hardening bundle (handler, X-Request-Id middleware, log_pubkey, semaphore, silent FCM payload, RUST_LOG flip, deps)
- [x] 02-03-PLAN.md — Add dispute-chat verification runbook in Spanish (VERIFY-03)
**UI hint**: no

### Phase 3: Dual-keyed rate limiting and verification harness
**Goal**: Sustained `POST /api/notify` traffic from a single client cannot exhaust the server or flood any one recipient, the new endpoint's wiring is exercised by an in-process integration suite that catches regressions before deploy, and the rate-limiting layer never affects any endpoint other than `/api/notify`.
**Depends on**: Phase 2 (rate-limits a functional endpoint; debugging "endpoint broken or rate-limit broken?" ambiguity is avoided)
**Requirements**: LIMIT-01, LIMIT-02, LIMIT-03, LIMIT-04, LIMIT-05, LIMIT-06, VERIFY-01, VERIFY-02
**Open Decisions resolved here**:
  - OPEN-3 (rate-limit burst tuning: PROJECT.md `~5/min` per-pubkey + `~60/min` per-IP vs PITFALLS RL-3 `30/min burst 10` per-pubkey + `120/min burst 30` per-IP) — request mobile-team traffic-pattern data; default to the more permissive numbers if no data is available before implementation.
  - OPEN-4 (`actix-governor` version pin and exact `KeyExtractor` API surface) — verify against current crate docs; obtain explicit user approval to add `actix-governor` to `Cargo.toml` (per global CLAUDE.md no-new-deps policy; the bare `governor` crate is already declared and counts as approved).
**Success Criteria** (what must be TRUE):
  1. Sustained `POST /api/notify` from a single source whose `Fly-Client-IP` header is fixed eventually returns `429` after the configured per-IP quota is exhausted; the same flood with rotating `X-Forwarded-For` values from the same TCP peer cannot bypass the limit (rightmost-XFF or trusted-`Fly-Client-IP`-only resolution).
  2. Sustained `POST /api/notify` for the same `trade_pubkey` from many distinct source IPs eventually returns `429` from the per-pubkey limiter, and the `429` response shape is byte-identical regardless of whether the pubkey was registered (anti-RL-2 oracle).
  3. `GET /api/health`, `GET /api/info`, `GET /api/status`, `POST /api/register`, and `POST /api/unregister` are not subject to this milestone's rate-limiting middleware; a 1000-request burst against `/api/health` from a single source returns 1000 successes (anti-DEPLOY-3 Fly-health-check-restart-loop).
  4. Rate-limit quotas for both per-pubkey and per-IP are configurable at runtime via `NOTIFY_RATE_PER_PUBKEY_PER_MIN` and `NOTIFY_RATE_PER_IP_PER_MIN` environment variables; the existing unused `RATE_LIMIT_PER_MINUTE` env var is left untouched.
  5. The per-`trade_pubkey` keyed limiter's in-memory map is bounded over time by a periodic background `retain_recent` (or equivalent) call, and a `warn!` line is logged when the map size crosses a configurable soft cap (default ~100k entries) so an operator can detect active key-bombing.
  6. An in-process integration suite (`actix_web::test::init_service` against a real `governor` middleware and a stub `PushService`) covers the six TEST-1 scenarios — registered hit, unregistered "miss", malformed body, per-pubkey 429 boundary, per-IP 429 boundary, and `/api/register` byte-identical-shape regression — and runs green on `cargo test` against the merged milestone.
**Plans:** 2 plans
Plans:
- [ ] 03-01-PLAN.md — Add per-IP middleware + per-pubkey limiter to /api/notify (rate_limit module, AppState extension, NotifyRateLimitConfig env vars, cleanup task)
- [ ] 03-02-PLAN.md — Add in-process integration test suite (StubPushService + 19 tests across notify/rate_limit/routes covering VERIFY-01 + VERIFY-02 + 4 regressions)
**UI hint**: no

---

## Coverage

All 17 v1.1 requirements are mapped. No orphans, no duplicates.

| Category | Requirements | Mapped to | Count |
|----------|--------------|-----------|-------|
| DISPATCH | DISPATCH-01, DISPATCH-02 | Phase 1 | 2 |
| NOTIFY   | NOTIFY-01, NOTIFY-02, NOTIFY-03, NOTIFY-04 | Phase 2 | 4 |
| LIMIT    | LIMIT-01, LIMIT-02, LIMIT-03, LIMIT-04, LIMIT-05, LIMIT-06 | Phase 3 | 6 |
| PRIV     | PRIV-01, PRIV-02, PRIV-03 | Phase 2 | 3 |
| VERIFY   | VERIFY-01 (Phase 3), VERIFY-02 (Phase 3), VERIFY-03 (Phase 2) | Phase 2 + Phase 3 | 3 (1 in P2, 2 in P3) |
| **Total** | | | **17 / 17** |

VERIFY-03 (dispute-chat manual runbook) is in Phase 2 because it documents the unchanged Nostr-listener path that must keep working after the Phase 1 refactor and the Phase 2 endpoint addition — a Phase 2-end checkpoint is the right moment, before Phase 3's rate-limiting layer can mask any regression. VERIFY-01 and VERIFY-02 (in-process integration suite) are in Phase 3 because the suite exercises the full stack including the `governor` middleware wiring, which doesn't exist until Phase 3.

---

## Anti-Requirements (must NOT appear in any phase)

These are recorded as a roadmap-level guardrail. Reviewers checking phase plans against the roadmap should fail any plan that re-introduces them.

- **OOS-19 / CRIT-1**: No `.authors(mostro_pubkey)` filter on the Nostr listener — would silently break dispute chat (admin DMs are user-to-user, not from the Mostro daemon) and is structurally impossible against Gift Wrap kind 1059 ephemeral outer keys.
- **OOS-10 / AF-1**: No authentication on `/api/notify` (no signature, no JWT, no header that identifies the sender).
- **OOS-11 / AF-3**: No `sender_pubkey` field anywhere in the request body or headers, even optional.
- **OOS-12 / AF-4**: No server-side storage or registration of `sharedKey` mappings.
- **OOS-13 / AF-5**: No persistent log of `(timestamp, source IP, target trade_pubkey)` tuples; aggregate counters only.
- **OOS-14 / AF-2 / AF-8 / AF-9**: No message content forwarding, no push payload customisation (sound, badge, group, channel), no recipient-routing hint in the silent push payload.
- **OOS-15 / AF-10**: No webhook callback or delivery receipt back to the sender.
- **OOS-16 / D-2**: No `Idempotency-Key` header on `/api/notify`.
- **OOS-17 / D-4**: No CORS configuration / `actix-cors` on `/api/notify`.
- **OOS-18 / AF-7**: No differentiation between "registered + dispatched" and "not registered" beyond what the OPEN-1 resolution explicitly permits — never echo the pubkey in the response, never differentiate response body or latency oracle-style.
- **OOS-20 / COMPAT-1**: No incidental refactor of `RegisterResponse`, `RegisterTokenRequest`, or `UnregisterTokenRequest` shapes — would break existing strict-deserialised mobile clients.
- **OOS-21 / CONC-3**: No `TokenStore` mutation from the `notify_token` handler (no `last-notified-at` field, no per-pubkey notify counter mutation inside the request lifecycle).

---

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. PushDispatcher refactor | 1/1 | Complete | 2026-04-25 |
| 2. `POST /api/notify` endpoint with privacy hardening | 3/3 | Complete | 2026-04-25 |
| 3. Dual-keyed rate limiting and verification harness | 0/2 | Planned | - |

---

*Last updated: 2026-04-25 — Phase 03 planned (2 plans, 7 tasks total). Plan 01 implements LIMIT-01..06; Plan 02 implements VERIFY-01 + VERIFY-02. Phase 02 complete (3/3 plans).*
