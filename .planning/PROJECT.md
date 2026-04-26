# Mostro Push Server

## What This Is

Privacy-preserving push notification backend for the Mostro P2P trading ecosystem. A Rust service that observes Nostr Gift Wrap events (kind 1059) on configured relays, looks up registered device tokens by `trade_pubkey`, and dispatches silent push notifications via Firebase Cloud Messaging (FCM) and UnifiedPush so Mostro Mobile clients can wake up and process trade events without exposing user identity, message content, or peer relationships to the server operator or to Google/Apple. Inspired by [MIP-05](https://github.com/MostroP2P/MIPs).

## Core Value

The mobile client receives a silent push the moment a relevant Nostr event lands on the configured relays — without the push server, Google/Apple, or any operator learning who is trading with whom or what is being said.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. Inferred from existing codebase (Phase 1-3 in docs/IMPLEMENTATION_PHASES.md). -->

- ✓ Actix-web HTTP API with `/api/health`, `/api/info`, `/api/status` — existing
- ✓ `POST /api/register` — register `{ trade_pubkey, token, platform }` (plaintext, validated 64-char hex pubkey, non-empty token, `android`|`ios` platform) — existing
- ✓ `POST /api/unregister` — remove a registered token — existing
- ✓ In-memory `TokenStore` with TTL-based cleanup background task — existing
- ✓ Persistent Nostr relay subscription to `kind 1059` (Gift Wrap) events with reconnect/backoff loop — existing
- ✓ Push dispatch on incoming event: extract `p` tag, look up token, send silent push via first matching backend — existing
- ✓ FCM v1 backend with OAuth2 service-account JWT-bearer flow and access-token caching — existing
- ✓ UnifiedPush backend (degoogled Android: GrapheneOS, LineageOS) with endpoint persistence to JSON — existing
- ✓ Configuration via environment variables / `.env` (`Config::from_env()`) — existing
- ✓ Multi-stage Dockerfile (rust:1.83 → debian:bookworm-slim) and Fly.io deployment (`fly.toml`, `deploy-fly.sh`) — existing

### Active

<!-- Current scope: Milestone v1.1 — Chat notifications support. -->

- [ ] **Server enables push notifications for P2P chat between buyer and seller** — currently the server only delivers Mostro daemon events; chat messages addressed to a session's `sharedKey.public` (ECDH-derived per peer) never trigger a push because the server doesn't and won't know about `sharedKey`s. Validated end-to-end in Phase 2: `POST /api/notify` allows the sender to wake the recipient on demand.
- [x] **Server enables push notifications for dispute chat between admin and user** — Validated in Phase 2 (operator runbook `docs/verification/dispute-chat.md` ships with anti-CRIT-1 guard). Pending: operator smoke on staging (tracked in `02-HUMAN-UAT.md`).
- [x] **Sender-triggered notification endpoint** — Validated in Phase 2: `POST /api/notify { trade_pubkey }` ships with always-202, X-Request-Id middleware (UUIDv4 server-side), salted-BLAKE3 `log_pubkey()` correlators across all modules, bounded `tokio::spawn` (50-permit semaphore), separate FCM silent payload (apns-priority 5, apns-push-type background), and `RUST_LOG=info` in production. Source-level checks all green; device delivery pending operator smoke (`02-HUMAN-UAT.md`).
- [x] **Abuse mitigation on the new endpoint** — Validated in Phase 3: dual-keyed rate limiting on `POST /api/notify` only — per-`trade_pubkey` (burst 10, 30/min) in-handler check + per-IP (`Fly-Client-IP` > rightmost-XFF > peer_addr, burst 30, 120/min) `from_fn` middleware over `governor::DefaultKeyedRateLimiter`. Both 429 paths produce a byte-identical body (`{"success":false,"message":"rate limited"}`) and both carry `x-request-id` (anti-RL-2 oracle). Other endpoints unaffected (anti-DEPLOY-3). Quotas configurable via `NOTIFY_RATE_PER_PUBKEY_PER_MIN` / `NOTIFY_RATE_PER_IP_PER_MIN`; legacy `RATE_LIMIT_PER_MINUTE` untouched. Periodic `retain_recent` cleanup + soft-cap `warn!` (default 100k). 31 in-process integration tests cover the 6 TEST-1 scenarios and run green. Unauthenticated by design.
- [ ] **Compatible with the Mostro Mobile client implementing Phase 4 of `mobile/docs/plans/CHAT_NOTIFICATIONS_PLAN.md`** — the contract must match what the mobile client will call. Wire shape locked in Phase 2; mobile coordination pending.

### Out of Scope

<!-- Explicit boundaries for milestone v1.1 to prevent scope creep. -->

- **Encrypted token registration (Phase 4 of `docs/IMPLEMENTATION_PHASES.md`)** — the `src/crypto/` module is scaffolded but gated `#[allow(dead_code)]`; activating it is a separate milestone with its own coordination cost on the mobile side. Memory note: the `SERVER_PRIVATE_KEY` hardcoded in `deploy-fly.sh` is currently inert.
- **Authentication on `/api/register` and `/api/notify`** — both endpoints stay unauthenticated. Adding signature-based auth on `/api/notify` would require the sender to identify themselves, which would let the server learn `sender tradeKey ↔ recipient tradeKey` mappings and break the unlinkability guarantee. Adding auth on `/api/register` is a separate decision tied to anti-abuse work.
- **Persistent `TokenStore` (Redis/SQLite migration)** — restarts continue to lose FCM/APNs token state and require re-registration. Migrating storage is a scaling milestone, not a chat-notification milestone.
- **Rotating the compromised `SERVER_PRIVATE_KEY` in `deploy-fly.sh` and removing the secret from git history** — the key is dormant until Phase 4 lands; rotation is bundled with the encryption milestone, not this one.
- **CI / GitHub Actions / formal integration test harness** — there are zero integration tests today and no CI workflow. Adding a baseline is valuable but is its own milestone.
- **Metrics endpoint, graceful shutdown (SIGTERM), structured/JSON logging** — observability and lifecycle hardening are deferred.
- **Upgrading `nostr-sdk = "0.27"`** — several major versions behind upstream. Migration requires a focused rewrite of `src/nostr/listener.rs`; not on the path for chat notifications.
- **Wiring `BatchingManager` and consuming `BATCH_DELAY_MS` / `COOLDOWN_MS`** — the batching scaffold in `src/utils/batching.rs` stays dormant. Not required for the chat notification flow.
- **APNs-direct backend (without FCM)** — iOS continues to deliver via FCM as it does today.
- **Adding a Mostro-daemon author filter to the Nostr listener** — would break dispute chat delivery (admin DMs are sent directly user-to-user, not by the Mostro daemon). Recorded as an explicit anti-requirement.

## Context

**Codebase state:** Brownfield Rust service; phases 1-3 of `docs/IMPLEMENTATION_PHASES.md` are complete. A full codebase analysis exists at `.planning/codebase/` (STACK, ARCHITECTURE, CONCERNS, CONVENTIONS, INTEGRATIONS, STRUCTURE, TESTING) generated 2026-04-24.

**Mobile coordination:** The companion Flutter app at `/home/andrea/Documents/oss/mostrop2p/mobile` already specifies the desired behaviour in `mobile/docs/plans/CHAT_NOTIFICATIONS_PLAN.md`. Mobile Phase 1 (admin DM background notifications) has merged; Phase 2 (P2P chat background notifications) is in PR review; Phases 3 and 4 are pending. **This server milestone unblocks mobile Phase 4.**

**Three Nostr message classes the mobile must surface — only the first is covered today:**

| Class | `p` tag (recipient) | Sender | Server coverage today |
|-------|---------------------|--------|-----------------------|
| Mostro daemon → user | `tradeKey.public` | Mostro daemon | Covered via relay subscription |
| User ↔ user (P2P chat) | `sharedKey.public` = ECDH(my tradeKey.private, peer tradeKey.public) | The other user | **Not covered** — server has no `sharedKey` registered |
| Admin ↔ user (dispute chat) | `tradeKey.public` (DM payload format inside) | Admin (sends directly, not via Mostro daemon) | Theoretically covered (relay subscription matches `tradeKey`) — never verified end-to-end |

**Privacy invariants the server must preserve:**
- Server only learns `tradeKey → device token` mappings (already the case today).
- Server never learns `sharedKey`s, peer relationships, or sender identities.
- Server never sees plaintext message content (silent pushes carry no payload).
- The new `/api/notify` endpoint must not require authentication — adding it would force the sender to identify themselves and let the server correlate sender↔recipient.

**Sender-triggered design (chosen by the mobile team in `CHAT_NOTIFICATIONS_PLAN.md` Phase 4):** When User A sends a chat message to User B, after publishing the encrypted Nostr event, User A also calls `POST /api/notify { trade_pubkey: <peer's tradeKey.public> }`. The server simply looks up B's registered token and pushes a silent FCM/UnifiedPush. No `sharedKey` registration, no peer mapping stored, no content transmitted. Same model is intended for admin DMs in case relay-monitoring proves unreliable.

**Critical concerns deferred to other milestones (from `.planning/codebase/CONCERNS.md`):**
- `SERVER_PRIVATE_KEY` literal committed in `deploy-fly.sh:30` — bundled with the Phase 4 encryption milestone (key is dormant until then).
- Zero integration tests; no CI workflow — bundled with a hardening milestone.
- No request signing on `/api/register` — bundled with anti-abuse work.

**Stack at a glance:** Rust 1.75+ (edition 2021), Tokio 1.35 + actix-web 4.4, `nostr-sdk` 0.27, `reqwest` 0.11 (FCM v1 + UnifiedPush), `jsonwebtoken` 9 (Firebase OAuth2), `governor` 0.6 (declared, unused — to be wired in this milestone). Single Fly.io machine, 512MB, region `gru`.

## Constraints

- **Tech stack:** Rust + Actix-web + Tokio. The new endpoint is additive — must not introduce a different framework, async runtime, or HTTP client. Reuse `reqwest::Client` and the `PushService` trait wherever possible.
- **Privacy:** Hard requirement that the server never learns `sharedKey`s, peer-to-peer relationships, or sender identity. Designs that would weaken this (e.g. signature auth on `/api/notify`, registering `sharedKey`s, forwarding plaintext) are rejected.
- **Backwards compatibility:** Existing `/api/register`, `/api/unregister`, `/api/health`, `/api/info`, `/api/status` contracts must not change in this milestone. Mobile clients on the current API must keep working.
- **Mobile contract:** The new endpoint must match what `mobile/docs/plans/CHAT_NOTIFICATIONS_PLAN.md` Phase 4 specifies (`POST /api/notify { "trade_pubkey": "<64-char hex>" }`, returns `200`/`404`/`429`). Detailed wire format (response body, error shape) is finalized in `/gsd-plan-phase`.
- **Deployment:** Single Fly.io machine, 512MB RAM, hard connection cap of 25 (`fly.toml`). Rate limits and any new state structures must respect this.
- **Anti-requirement:** No Mostro-daemon author filter on the Nostr listener. Dispute admin DMs are sent directly user-to-user; filtering by `mostro_pubkey` author would silently drop them.
- **No new dependencies without explicit approval** (per global CLAUDE.md). The `governor` crate is already declared and counts as already-approved.
- **Language:** Code, comments, commit messages, branch names, and documentation in English. Conversation in Spanish (per global CLAUDE.md).

## Key Decisions

<!-- Decisions that constrain future work. Add throughout project lifecycle. -->

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Adopt sender-triggered `/api/notify` over registering `sharedKey`s | Registering `sharedKey`s would let the server correlate `sharedKey ↔ tradeKey` and infer who trades with whom — breaks unlinkability. The sender already knows the peer's `tradeKey`, so a one-shot notify call reveals nothing the server doesn't already know. | — Pending (validated when chat push works E2E with the mobile Phase 4 client) |
| `/api/notify` stays unauthenticated | Signature-based auth would force the sender to identify themselves, letting the server learn sender↔recipient mappings — breaks the privacy model. Threat model documented in `CHAT_NOTIFICATIONS_PLAN.md` Phase 4 (data-harvest = none, DoS = mitigated by rate limiting, unsolicited wake-ups = silent FCM is low-impact). | — Pending |
| Rate-limit using the already-declared `governor` crate | `governor` is in `Cargo.toml` but unused; wiring it in costs no new dependency approval and resolves an outstanding concern from the codebase analysis. | Validated in Phase 3 — `actix-governor` was rejected (D-05, GPL-3.0 incompatible with project MIT); a hand-rolled `from_fn` middleware over bare `governor::DefaultKeyedRateLimiter` is what shipped. |
| Both 429 paths must be byte-identical (anti-RL-2 oracle) | If the per-IP and per-pubkey 429 differed in body or headers, an attacker could distinguish which limiter fired and learn whether a given `trade_pubkey` is actively rate-limited (a privacy leak). | Validated in Phase 3 — single `rate_limited_response` helper feeds both paths; `request_id_mw` is outermost so both 429s carry `x-request-id`; regression tests `rate_limited_429_body_byte_identical_per_ip_vs_per_pubkey` and `x_request_id_present_on_both_429_paths` enforce the invariant. |
| Defer Phase 4 encryption rollout, key rotation, persistent storage, CI, and `nostr-sdk` upgrade to separate milestones | Each is a substantial milestone with its own coordination cost (mobile encryption client, secrets rewrite, infra change, test harness, breaking API migration). Bundling them into the chat-notification milestone would slip the mobile Phase 4 unblocker. | — Pending |
| Do **not** add a Mostro-daemon author filter on the Nostr listener | Recorded as an anti-requirement: admin DMs in disputes are sent directly user-to-user, not by the Mostro daemon. A `mostro_pubkey` author filter (suggested as a "fix" in `.planning/codebase/CONCERNS.md`) would silently drop dispute notifications. | — Pending (must remain enforced through reviews) |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-26 — Phase 03 complete (dual-keyed rate limiting + in-process verification harness; 6/6 success criteria PASS, 31/31 tests green). Milestone v1.1 has no remaining phases — ready for `/gsd-complete-milestone` once mobile Phase 4 coordinates.*
