# Mostro Push Server

## What This Is

Privacy-preserving push notification backend for the Mostro P2P trading ecosystem. A Rust service that observes Nostr Gift Wrap events (kind 1059) on configured relays, looks up registered device tokens by `trade_pubkey`, and dispatches silent push notifications via Firebase Cloud Messaging (FCM) and UnifiedPush, plus a sender-triggered `POST /api/notify` endpoint that lets Mostro Mobile clients wake their peers (P2P chat, dispute chat) without the server learning `sharedKey`s or sender identity. Inspired by [MIP-05](https://github.com/MostroP2P/MIPs).

## Core Value

The mobile client receives a silent push the moment a relevant Nostr event lands on the configured relays — without the push server, Google/Apple, or any operator learning who is trading with whom or what is being said.

## Current State

**Shipped:** v1.1 — Chat Notifications (2026-04-26)
**Source:** `.planning/milestones/v1.1-ROADMAP.md`, `.planning/milestones/v1.1-REQUIREMENTS.md`, `.planning/milestones/v1.1-MILESTONE-AUDIT.md`

v1.1 unblocks Phase 4 of the Mostro Mobile `CHAT_NOTIFICATIONS_PLAN.md`. Highlights:
- `POST /api/notify` (always-202) reaches the registered device for any registered `trade_pubkey` via the same `PushDispatcher` the Nostr-listener path uses.
- Dual-keyed rate limiting (per-IP + per-`trade_pubkey`) on `/api/notify` only; 429 byte-identical on both paths (anti-RL-2 oracle).
- Privacy hardening: salted-BLAKE3 `log_pubkey()` correlator, server-side UUIDv4 X-Request-Id, `RUST_LOG=info` in production.
- 31 in-process integration tests green covering 6 TEST-1 scenarios, byte-identical regression for legacy endpoints, anti-DEPLOY-3.

## Requirements

### Validated

- ✓ Actix-web HTTP API with `/api/health`, `/api/info`, `/api/status` — pre-v1.1
- ✓ `POST /api/register` — register `{ trade_pubkey, token, platform }` (plaintext, validated 64-char hex pubkey, non-empty token, `android`|`ios`) — pre-v1.1
- ✓ `POST /api/unregister` — remove a registered token — pre-v1.1
- ✓ In-memory `TokenStore` with TTL-based cleanup background task — pre-v1.1
- ✓ Persistent Nostr relay subscription to `kind 1059` (Gift Wrap) events with reconnect/backoff loop — pre-v1.1
- ✓ Push dispatch on incoming event: extract `p` tag, look up token, send silent push via first matching backend — pre-v1.1
- ✓ FCM v1 backend with OAuth2 service-account JWT-bearer flow and access-token caching — pre-v1.1
- ✓ UnifiedPush backend (degoogled Android: GrapheneOS, LineageOS) with endpoint persistence to JSON — pre-v1.1
- ✓ Configuration via environment variables / `.env` (`Config::from_env()`) — pre-v1.1
- ✓ Multi-stage Dockerfile (rust:1.83 → debian:bookworm-slim) and Fly.io deployment (`fly.toml`, `deploy-fly.sh`) — pre-v1.1
- ✓ **PushDispatcher refactor (DISPATCH-01/02)** — single owner of immutable `Arc<[Arc<dyn PushService>]>`; Mutex removed from dispatch path — v1.1
- ✓ **Sender-triggered `POST /api/notify` endpoint (NOTIFY-01..04)** — always-202 contract, X-Request-Id (UUIDv4 server-side), bounded `tokio::spawn` via `Arc<Semaphore>(50)`, separate FCM silent payload (apns-priority 5, push-type background), shared `Arc<reqwest::Client>` with 2s/5s timeouts — v1.1
- ✓ **Privacy hardening across modules (PRIV-01..03)** — salted-BLAKE3 `log_pubkey()` correlator, legacy pubkey-prefix logs migrated, `RUST_LOG=info` in `deploy-fly.sh` — v1.1
- ✓ **Dual-keyed rate limiting on `/api/notify` only (LIMIT-01..06)** — per-IP `from_fn` middleware (Fly-Client-IP > rightmost-XFF > peer_addr) + in-handler per-pubkey check on `governor 0.6`; 429 byte-identical between paths; quotas configurable via `NOTIFY_RATE_PER_PUBKEY_PER_MIN`/`NOTIFY_RATE_PER_IP_PER_MIN`; periodic `retain_recent` + soft-cap `warn!` (default 100k) — v1.1
- ✓ **In-process verification harness (VERIFY-01/02)** — 31 tests covering 6 TEST-1 scenarios, byte-identical regression for `/api/register|unregister`, anti-DEPLOY-3 (1000-burst on `/api/health`), x-request-id parity on both 429 paths — v1.1
- ✓ **Dispute-chat operator runbook (VERIFY-03)** — `docs/verification/dispute-chat.md` (Spanish, 203 lines) with anti-CRIT-1 grep one-liner — v1.1

### Active

<!-- Next milestone candidates — to be locked in /gsd-new-milestone. -->

- [ ] **Operator UAT on real devices for v1.1** — 1 Phase 01 staging smoke (DISPATCH-02) + 7 Phase 02 device-delivery scenarios (iOS/Android FCM silent push, dispute-chat runbook walkthrough, PRIV audit on staging logs). Tracked in `.planning/milestones/v1.1-phases/02-…/02-HUMAN-UAT.md`. Cannot be asserted in-process; needs APNs/FCM credentials and physical devices.
- [ ] **Compatible with Mostro Mobile Phase 4** — wire shape locked in v1.1 (always-202 + `{ trade_pubkey }`); awaiting mobile coordination ticket and end-to-end smoke once mobile lands its Phase 4.
- [ ] **Pre-existing source warnings cleanup** — WR-02 (`config.rs:70-82` dead `let mostro_pubkey` with divergent default), WR-03 (`routes.rs:128` log injection on user-supplied platform), IN-02 (`routes.rs:131` echo of unsanitized platform in 400 body). All predate v1.1 (commits `1f848fb` 2025-11-12 and `42140c4` 2026-01-20). Small focused cleanup phase.
- [ ] **Nyquist validation backfill for v1.1 phases** — Phase 01/03 lack VALIDATION.md; Phase 02 has draft `nyquist_compliant: false`. Structural-completeness debt only — explicit verifications + 31 in-process tests already cover function. Run `/gsd-validate-phase` retroactively on each.

### Out of Scope

<!-- Explicit boundaries — reasons still valid post-v1.1. -->

- **Encrypted token registration (Phase 4 of `docs/IMPLEMENTATION_PHASES.md`)** — the `src/crypto/` module is scaffolded but gated `#[allow(dead_code)]`; activating it is a separate milestone with mobile-side coordination cost. Memory note: the `SERVER_PRIVATE_KEY` hardcoded in `deploy-fly.sh` is currently inert.
- **Authentication on `/api/register` and `/api/notify`** — both endpoints stay unauthenticated. Adding signature-based auth on `/api/notify` would let the server correlate sender↔recipient and break unlinkability. Auth on `/api/register` is a separate decision tied to anti-abuse work.
- **Persistent `TokenStore` (Redis/SQLite migration)** — restarts continue to lose FCM/APNs token state and require re-registration. Migrating storage is a scaling milestone.
- **Rotating the compromised `SERVER_PRIVATE_KEY` in `deploy-fly.sh` and removing the secret from git history** — bundled with the encryption milestone (the key is dormant until then).
- **CI / GitHub Actions / formal integration test harness beyond VERIFY-01/02** — no CI workflow today. Adding one is its own milestone.
- **Metrics endpoint, graceful shutdown (SIGTERM), structured/JSON logging** — observability and lifecycle hardening are deferred.
- **Upgrading `nostr-sdk = "0.27"`** — several major versions behind upstream; migration requires a focused rewrite of `src/nostr/listener.rs`.
- **Wiring `BatchingManager` and consuming `BATCH_DELAY_MS` / `COOLDOWN_MS`** — the batching scaffold in `src/utils/batching.rs` stays dormant. Not relevant to chat notifications.
- **APNs-direct backend (without FCM)** — iOS continues to deliver via FCM as it does today.
- **Adding a Mostro-daemon author filter to the Nostr listener** — would break dispute chat delivery (admin DMs are sent directly user-to-user, not by the Mostro daemon). Hard anti-requirement enforced by code comment + operator runbook grep one-liner.

## Context

**Codebase state (post-v1.1):** Brownfield Rust service. v1.1 shipped 6 plans across 3 phases on `feat/fcm-for-p2p-chat` (44 commits, +17,307/-153 LOC across 60 files; +1,617/-134 LOC across 13 Rust files). Codebase analysis under `.planning/codebase/` was generated 2026-04-24 and is still load-bearing for next-milestone planning.

**Mobile coordination:** The companion Flutter app at `/home/andrea/Documents/oss/mostrop2p/mobile` specifies the desired behaviour in `mobile/docs/plans/CHAT_NOTIFICATIONS_PLAN.md`. Mobile Phase 1 (admin DM background notifications) merged; Phase 2 (P2P chat background notifications) was in PR review; Phases 3 and 4 are pending — **mobile Phase 4 is the consumer of `/api/notify` shipped in v1.1.**

**Three Nostr message classes the mobile must surface — all three covered post-v1.1:**

| Class | `p` tag (recipient) | Sender | Server coverage |
|-------|---------------------|--------|-----------------|
| Mostro daemon → user | `tradeKey.public` | Mostro daemon | Pre-v1.1 — relay subscription |
| User ↔ user (P2P chat) | `sharedKey.public` = ECDH(my tradeKey.private, peer tradeKey.public) | The other user | v1.1 — sender calls `POST /api/notify { trade_pubkey: peer_tradeKey }` after publishing the encrypted Nostr event |
| Admin ↔ user (dispute chat) | `tradeKey.public` (DM payload format inside) | Admin (sends directly, not via Mostro daemon) | Pre-v1.1 relay subscription path; v1.1 ships operator runbook validating it survives the refactor (anti-CRIT-1) |

**Privacy invariants (preserved through v1.1):**
- Server only learns `tradeKey → device token` mappings.
- Server never learns `sharedKey`s, peer relationships, or sender identities.
- Server never sees plaintext message content (silent pushes carry no payload).
- `/api/notify` is unauthenticated — adding auth would force the sender to identify themselves and let the server correlate sender↔recipient.

**Critical concerns deferred to other milestones:**
- `SERVER_PRIVATE_KEY` literal committed in `deploy-fly.sh:30` — bundled with the Phase 4 encryption milestone (key is dormant until then).
- Zero CI workflow — bundled with a hardening milestone.
- No request signing on `/api/register` — bundled with anti-abuse work.

**Stack at a glance (post-v1.1):** Rust 1.75+ (edition 2021), Tokio 1.35 + actix-web 4.4, `nostr-sdk` 0.27, `reqwest` 0.11 (FCM v1 + UnifiedPush, shared Arc client with 2s/5s timeouts), `jsonwebtoken` 9 (Firebase OAuth2), `governor` 0.6 (wired in v1.1 over hand-rolled `from_fn` middleware — `actix-governor` rejected for GPL-3.0). New v1.1 deps: `blake3` 1, `uuid` 1 (v4). Single Fly.io machine, 512MB, region `gru`.

## Constraints

- **Tech stack:** Rust + Actix-web + Tokio. Additive only — no different framework, async runtime, or HTTP client. Reuse `reqwest::Client` and the `PushService` trait wherever possible.
- **Privacy:** Hard requirement that the server never learns `sharedKey`s, peer-to-peer relationships, or sender identity. Designs that would weaken this (e.g. signature auth on `/api/notify`, registering `sharedKey`s, forwarding plaintext) are rejected.
- **Backwards compatibility:** `/api/register`, `/api/unregister`, `/api/health`, `/api/info`, `/api/status` contracts must remain byte-identical for existing mobile clients.
- **Mobile contract for `/api/notify`:** `POST /api/notify { "trade_pubkey": "<64-char hex>" }`, always returns `202` (silent on hit/miss), `400` on malformed body, `429` on rate limit. Locked in v1.1.
- **Deployment:** Single Fly.io machine, 512MB RAM, hard connection cap of 25 (`fly.toml`). Rate limits and any new state structures must respect this.
- **Anti-requirement:** No Mostro-daemon author filter on the Nostr listener. Dispute admin DMs are sent directly user-to-user; filtering by `mostro_pubkey` author would silently drop them. Enforced by code comment in `src/nostr/listener.rs` and operator runbook grep check.
- **No new dependencies without explicit approval** (per global CLAUDE.md). Approved in v1.1: `blake3`, `uuid`. Already declared (counted as approved): `governor`.
- **Language:** Code, comments, commit messages, branch names, and documentation in English. Conversation in Spanish (per global CLAUDE.md).

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Adopt sender-triggered `/api/notify` over registering `sharedKey`s | Registering `sharedKey`s would let the server correlate `sharedKey ↔ tradeKey` and infer who trades with whom — breaks unlinkability. The sender already knows the peer's `tradeKey`, so a one-shot notify call reveals nothing the server doesn't already know. | ✓ Validated v1.1 — endpoint shipped; mobile Phase 4 will wire the producer side. |
| `/api/notify` stays unauthenticated | Signature-based auth would force the sender to identify themselves, letting the server learn sender↔recipient mappings — breaks the privacy model. | ✓ Validated v1.1 — endpoint shipped without auth; threat model documented in `CHAT_NOTIFICATIONS_PLAN.md` Phase 4. |
| Rate-limit using already-declared `governor` (reject `actix-governor`) | `actix-governor` is GPL-3.0; project is MIT — incompatible. Bare `governor 0.6` was already declared and is MIT-compatible; hand-rolling a `from_fn` middleware over `DefaultKeyedRateLimiter` costs no new approval. | ✓ Validated v1.1 (Phase 3, D-05/D-06) — shipped with `from_fn` middleware over keyed limiter. |
| Both 429 paths must be byte-identical (anti-RL-2 oracle) | Differing response shape between per-IP and per-pubkey 429 would let an attacker distinguish which limiter fired and learn whether a given `trade_pubkey` is rate-limited. | ✓ Validated v1.1 — single `rate_limited_response` helper feeds both paths; `request_id_mw` outermost so both 429s carry `x-request-id`; regression tests `rate_limited_429_body_byte_identical_per_ip_vs_per_pubkey` and `x_request_id_present_on_both_429_paths` enforce it. |
| Always-202 contract for `/api/notify` (over differentiated 200/404) | Differentiating registered hit vs unregistered miss creates a registered-pubkey enumeration oracle. always-202 keeps the server side opaque; mobile already has the Nostr-event-level dedupe to handle hits + the relay fallback to handle misses. | ✓ Validated v1.1 (Phase 2, OPEN-1 resolution) — all responses on the happy path are 202 regardless of registration status. |
| Defer Phase 4 encryption rollout, key rotation, persistent storage, CI, and `nostr-sdk` upgrade to separate milestones | Each is a substantial milestone with its own coordination cost. Bundling them into v1.1 would slip the mobile Phase 4 unblocker. | — Pending (next-milestone planning). |
| Do **not** add a Mostro-daemon author filter on the Nostr listener | Admin DMs in disputes are sent directly user-to-user, not by the Mostro daemon. A `mostro_pubkey` author filter (suggested as a "fix" in `.planning/codebase/CONCERNS.md`) would silently drop dispute notifications. Also structurally impossible against Gift Wrap kind 1059 ephemeral outer keys. | ✓ Validated v1.1 — anti-CRIT-1 comment block above `Filter::new()` in `src/nostr/listener.rs`; operator runbook grep one-liner reinforces at deploy time. Must remain enforced in reviews. |

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
*Last updated: 2026-04-26 after v1.1 milestone (Chat Notifications) shipped.*
