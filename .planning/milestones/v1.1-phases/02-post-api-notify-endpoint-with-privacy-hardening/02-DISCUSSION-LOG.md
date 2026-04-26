# Phase 2: `POST /api/notify` endpoint with privacy hardening - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-24
**Phase:** 02-post-api-notify-endpoint-with-privacy-hardening
**Areas discussed:** Response contract + dispatch strategy (OPEN-1 + OPEN-2), iOS silent push payload (OPEN-5), Outbound hygiene bundle, Privacy hardening scope

---

## Response contract + dispatch strategy (OPEN-1 + OPEN-2)

### Q1: Response contract for `/api/notify`

| Option | Description | Selected |
|--------|-------------|----------|
| Always-202 (Recommended) | `202 { "accepted": true }` always, body byte-identical hit vs miss. Exceptions: 429 rate-limit (Phase 3), 400 malformed. Closes enumeration + FCM-state oracles (CRIT-2/CRIT-6). Requires tokio::spawn dispatch. | ✓ |
| 200/404/429 (plan mobile literal) | 200 on success + dispatch, 404 not registered, 429 rate-limit. Preserves "RESTful" convention. Cost: registered-pubkey enumeration oracle. | |
| Hybrid 202/429/400 (same shape hit-or-miss) | 202 for both hit and miss with byte-identical body, 429, 400. Same privacy posture as always-202, slight semantic difference. | |

**User's choice:** Always-202.
**Notes:** Privacy-safer; deviates from mobile plan's literal text (200/404/429). Mobile team adaptation required (see Q3).

### Q2: Dispatch strategy

| Option | Description | Selected |
|--------|-------------|----------|
| tokio::spawn + Semaphore (Recommended) | Handler returns 202 immediately; dispatch in spawned task bounded by `tokio::sync::Semaphore` (50 permits). Silently drop on overflow. Handler p99 ~1ms. | ✓ |
| Inline await | Handler awaits dispatcher before returning. Latency channel leaks hit/miss (even with 202). p99 >100ms under 25-conn Fly cap → cascade 503. | |

**User's choice:** tokio::spawn + Semaphore.
**Notes:** Closes timing-channel oracle + protects 25-conn cap. 50 permits tunable.

### Q3: Mobile team coordination

| Option | Description | Selected |
|--------|-------------|----------|
| Decidimos ahora, mobile se adapta | Lock contract now (always-202), document in CONTEXT.md, communicate deviation to mobile team before their Phase 4 implementation. | ✓ |
| Abrir issue/PR en el repo mobile primero | Block discuss until mobile confirms. | |
| Asumir always-202, marcar TODO | Proceed and add TODO; adjust if mobile pushes back. | |

**User's choice:** Decidimos ahora.
**Notes:** Mobile's Phase 4 client is not yet merged — deviation is still cheap. If mobile can't accept always-202, the handler adjustment is localized.

---

## iOS silent push payload (OPEN-5)

### Q1: FCM payload builder for `/api/notify`

| Option | Description | Selected |
|--------|-------------|----------|
| Separate silent builder (Recommended) | New `build_silent_payload_for_notify()` with `apns-priority: 5` + `apns-push-type: background` + data-only, no `alert`, no `apns-collapse-id`. Existing `build_payload_for_token` stays untouched for listener path. | ✓ |
| Reusar build_payload_for_token para todo | One builder serves both paths. Simpler, but chat volume with `apns-priority: 10` triggers Apple's silent-push throttling. | |
| Reusar pero fixar el existente | One builder, downgraded to priority 5. Retroactively changes listener path behaviour (violates Phase 1 "no behaviour change" post-hoc). | |

**User's choice:** Separate silent builder.
**Notes:** Chat frequency profile is fundamentally different from Mostro event frequency; Apple's silent-push throttling is documented.

### Q2: iOS payload verification approach

| Option | Description | Selected |
|--------|-------------|----------|
| Manual smoke en Phase 2 (Recommended) | Deploy to staging; register a real iOS FCM token; verify `didReceiveRemoteNotification` fires. Documented in SUMMARY.md. | ✓ |
| Defer a F-03 | Ship Phase 2 Android-only verified; iOS hardening in a later milestone. | |
| Checklist verify sin deploy | Document expected payload values; trust spec; no smoke. | |

**User's choice:** Manual smoke en Phase 2.
**Notes:** No automated iOS test because the server-side integration suite uses stub PushService and can't validate Apple's delivery decision.

---

## Outbound hygiene bundle

### Q1: Shared `reqwest::Client` with timeouts

| Option | Description | Selected |
|--------|-------------|----------|
| Bundle en Phase 2 (Recommended) | Single `reqwest::Client` constructed in `main.rs` with `connect_timeout(2s)` + `timeout(5s)` + `pool_idle_timeout(90s)`, passed as `Arc<reqwest::Client>` to `FcmPush::new(config, client)` and `UnifiedPushService::new(config, client)` (constructor breaking change). | ✓ |
| Timeout sólo, sin sharing | Each service keeps own client but gains timeouts. Lower blast radius; no shared pool. | |
| Diferir a milestone de outbound hardening | Leave as-is; accept self-DoS risk. Semaphore (D-03) partially mitigates. | |

**User's choice:** Bundle en Phase 2.
**Notes:** Self-DoS protection is load-bearing for `/api/notify` under sustained traffic.

---

## Privacy hardening scope

### Q1: `log_pubkey()` helper application scope (PRIV-01)

| Option | Description | Selected |
|--------|-------------|----------|
| Solo al handler nuevo /api/notify (Recommended) | Helper used only by new notify handler + its spawned dispatch task. Existing `&trade_pubkey[..16]` log sites in listener/register/store stay UNTOUCHED — operators that grep logs today don't break. | ✓ |
| Retroactive: migrar TODOS los logs existentes también | Full coherence — no prefix-truncated logs leak 64 bits anywhere. Cost: breaks existing operator grep patterns. Post-hoc change to Phase 1's "no behaviour change" property. | |

**User's choice:** Solo al handler nuevo.
**Notes:** Operator grep-ability preserved; retroactive migration deferred to a future observability milestone.

### Q2: X-Request-Id middleware scope (NOTIFY-04)

| Option | Description | Selected |
|--------|-------------|----------|
| Solo /api/notify (Recommended) | Middleware wraps only the `/api/notify` resource via `web::resource().wrap(...)`. UUIDv4 server-side, exposed in response header. Other endpoints unchanged — COMPAT-1 preserved absolutely. | ✓ |
| Global (todas las responses) | Middleware at `App::new().wrap(...)`. Uniform correlation header on every endpoint. Cost: adds header to register/unregister/health/info/status responses. | |
| Diferir X-Request-Id a futuro | Skip NOTIFY-04 in Phase 2. Would require moving it formally in REQUIREMENTS.md. | |

**User's choice:** Solo /api/notify.
**Notes:** Coherent with Phase 3's scoped rate-limit middleware (LIMIT-03).

### Q3: PRIV-02 (`RUST_LOG=info`) commit grain

| Option | Description | Selected |
|--------|-------------|----------|
| Bundle con Phase 2 (Recommended) | Same commit as endpoint. Obligatory per SUMMARY.md bundle — shipping `/api/notify` with debug active amplifies existing token-prefix leakage. | ✓ |
| Commit separado en mismo PR | One-line change separated for surgical revert. Same PR, different history grain. | |

**User's choice:** Bundle con Phase 2.
**Notes:** Hard bundle — the two privacy changes must land together or neither ships.

---

## Claude's Discretion

- Exact file paths for new modules (`src/api/notify.rs`, `src/utils/log_pubkey.rs` — names may shift for convention).
- Semaphore overflow log level (`warn!` vs `debug!`) — plan-phase decides.
- Exact 400 response body shape — match existing `RegisterResponse { success, message }` for consistency, or a lean new body in `notify.rs`.
- `tokio::sync::Semaphore::try_acquire` vs `try_acquire_owned` — owned typically needed for spawn.
- 32-byte salt initialization details — random-in-memory per process, never persisted.
- `blake3` `Cargo.toml` position + feature flags (defaults are fine).

## Deferred Ideas

- Rate limiting — entire Phase 3 (LIMIT-01..06).
- Integration test suite — Phase 3 (VERIFY-01, VERIFY-02).
- Retroactive migration of existing pubkey-prefix logs — future observability milestone.
- iOS APNs-direct backend — permanently out of scope (OOS-08).
- X-Request-Id → handler logs propagation — deferred to a future unification phase if operator feedback requires.
- Semaphore permits number tuning — review after production data with Phase 3 rate limits active.
