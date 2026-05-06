# Milestones

## v1.1 Chat Notifications (Shipped: 2026-04-26)

**Phases completed:** 3 phases, 6 plans
**Timeline:** 2026-04-24 → 2026-04-25 (~2 days)
**Git range:** 41d01e1 -> 5122d1d (44 commits)
**Code delta:** 60 files changed, +17,307 / -153 LOC (Rust: +1,617 / -134 across 13 files)
**Audit status:** tech_debt — 17/17 requirements satisfied, 0 gaps; 11 deferred items (3 acknowledged at close)

**Key accomplishments:**

1. **PushDispatcher extracted** with `Arc<[Arc<dyn PushService>]>` lock-free; eliminated `Mutex<Vec<...>>` from the dispatch path while keeping the Nostr listener flow byte-identical (DISPATCH-01 / DISPATCH-02).
2. **POST /api/notify shipped** with always-202 contract, UUIDv4 X-Request-Id middleware scoped to the /notify resource, bounded `tokio::spawn` via `Arc<Semaphore>(50)`, separate FCM silent payload (apns-priority 5, apns-push-type background), and shared `Arc<reqwest::Client>` with 2s/5s timeouts (NOTIFY-01..04).
3. **Privacy hardening** via salted-BLAKE3 `log_pubkey()` correlator, migration of legacy pubkey-prefix logs to the new helper, and `RUST_LOG=info` flip in `deploy-fly.sh` (PRIV-01..03).
4. **Dual-keyed rate limiting** on `governor 0.6` (actix-governor rejected — GPL-3.0 vs project MIT): per-IP `from_fn` middleware (Fly-Client-IP > rightmost-XFF > peer_addr) + per-pubkey check in-handler, 429 byte-identical between paths with `Retry-After` and `x-request-id` (LIMIT-01..06, anti-RL-2 oracle).
5. **31 in-process integration tests green** via `actix_web::test` with `StubPushService` and `governor::FakeRelativeClock`, covering the 6 TEST-1 scenarios plus byte-identical regression for `/api/register` and `/api/unregister`, anti-DEPLOY-3 (1000-burst on `/api/health` returns 1000/1000), and `x-request-id` parity on both 429 paths (VERIFY-01 / VERIFY-02).
6. **Operator runbook** `docs/verification/dispute-chat.md` (Spanish, 203 lines) with anti-CRIT-1 grep one-liner that fails fast if `.authors(mostro_pubkey)` ever creeps into `src/nostr/listener.rs::Filter::new()` (VERIFY-03).

**Known deferred items at close:** 3 (see STATE.md Deferred Items)

- 1 UAT gap: Phase 02 — 7 operator scenarios pending real device + APNs/FCM credentials.
- 2 verification gaps: Phase 01 (DISPATCH-02 staging smoke) and Phase 02 (device-delivery scenarios). Both `human_needed` by design.

Additionally documented in the audit: 3 pre-existing source warnings (config.rs WR-02, routes.rs WR-03, routes.rs IN-02) that predate this milestone, and 3 phases pending Nyquist validation (structural completeness debt only — explicit verifications + 31 in-process tests provide functional coverage).

---
