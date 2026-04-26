# Phase 1: PushDispatcher refactor (no behaviour change) - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-24
**Phase:** 01-pushdispatcher-refactor-no-behaviour-change
**Areas discussed:** MOSTRO_PUBKEY disposition (OPEN-6), Trait hygiene bundle (MIN-5 + send_silent_push), DispatchError shape + logging position

---

## MOSTRO_PUBKEY disposition (OPEN-6)

### Q1: What to do with the dormant MOSTRO_PUBKEY config field and validation

| Option | Description | Selected |
|--------|-------------|----------|
| Borrar entero (Recommended) | Eliminate field from `NostrConfig`, validation in `NostrListener::new`, and `.env.example` entry. Add comment in `Filter::new()` explaining why no author filter is possible. | |
| Anotar con dead-code | Keep field as `#[allow(dead_code)]` with comment explaining it must NEVER be applied as a filter. Preserves env var for hypothetical future use. | |
| Dejarlo igual | Don't touch in this phase. Out of scope (minimal refactor). Cleanup in a separate hardening milestone. | ✓ |

**User's choice:** Dejarlo igual.
**Notes:** Phase 1 stays minimal. Anti-CRIT-1 protection moves to Q2 (filter-level comment).

### Q2: Add explicit anti-CRIT-1 comment above `Filter::new()` (listener.rs:77-79)?

| Option | Description | Selected |
|--------|-------------|----------|
| Sí, comentario explícito (Recommended) | 6-8 line block comment: (a) Gift Wrap NIP-59 ephemeral keys, (b) admin DMs are direct user-to-user, (c) hard ban on `.authors(...)` with reference to PROJECT.md OOS-19 / CRIT-1. | ✓ |
| No, ya basta con el comentario actual | The current comment at lines 74-75 already mentions ephemeral keys. Leave as-is. | |

**User's choice:** Sí, comentario explícito.
**Notes:** This is the highest-leverage place to prevent a future reviewer from "fixing" the dormant validation.

---

## Trait hygiene bundle (MIN-5 + send_silent_push)

### Q1: Tighten `PushService::send_to_token` to `Result<(), Box<dyn Error + Send + Sync>>`?

| Option | Description | Selected |
|--------|-------------|----------|
| Bundle en Phase 1 (Recommended) | Cascade through trait + `FcmPush` + `UnifiedPushService` + 2 blanket `Arc<...>` impls. Already editing `push/mod.rs`. Removes existing `e.to_string().into()` workarounds. | ✓ |
| Diferir a Phase 2 | Keep Phase 1 minimal; if Phase 2 needs Send + Sync for `tokio::spawn`, adjust there. | |

**User's choice:** Bundle en Phase 1.
**Notes:** User accepts that the cascade is mechanical and prefers one trip through the file.

### Q2: Delete the dead `send_silent_push` method from the trait?

| Option | Description | Selected |
|--------|-------------|----------|
| Borrar (Recommended) | Remove from trait + 2 concrete impls + 2 blanket `Arc<>` impls. ~80 LOC less. | ✓ |
| Mantener | Out of scope; preserve in case it's needed later. | |

**User's choice:** Borrar.
**Notes:** Method has zero production callers per CONCERNS.md.

---

## DispatchError shape + logging position

### Q1: What error/outcome shape does the dispatcher return?

| Option | Description | Selected |
|--------|-------------|----------|
| Enum estructurado (Recommended) | `DispatchOutcome::Delivered { backend }` + `DispatchError { NoBackendForPlatform, AllBackendsFailed { errors } }`. Lets Phase 2's `/api/notify` distinguish 404 vs 502 if the contract calls for it. | ✓ |
| Result simple | `Result<(), Box<dyn Error + Send + Sync>>`. Minimal change; richer errors deferred to Phase 2. | |
| Result + Outcome simple | `Result<DispatchOutcome, Box<dyn Error + Send + Sync>>` with `DispatchOutcome { Delivered, NoBackendForPlatform }`. Compromise. | |

**User's choice:** Enum estructurado.
**Notes:** Pays a small cost now to make Phase 2's contract decision (OPEN-1) easier.

### Q2: Where do dispatch details get logged?

| Option | Description | Selected |
|--------|-------------|----------|
| Caller logs (Recommended) | Dispatcher returns outcome; each caller (listener Phase 1, `/api/notify` Phase 2) decides what to log and at what level. | ✓ |
| Dispatcher logs | Dispatcher emits its own `info!`/`error!`. More DRY but loses caller context (event_id, request_id). | |
| Mixed | Dispatcher logs backend choice + errors; caller adds its own context line. | |

**User's choice:** Caller logs.
**Notes:** Caller context (event_id today, request_id in Phase 2) is what makes logs grep-able.

### Q3: Apply hash-based pubkey logging (PRIV-01) at the touched lines?

| Option | Description | Selected |
|--------|-------------|----------|
| Esperar a Phase 2 (Recommended) | PRIV-01 helper `log_pubkey()` is introduced in Phase 2 alongside the new endpoint and the `RUST_LOG=info` deploy bundle (PRIV-02). Phase 1 stays as a no-observable-change refactor. | ✓ |
| Aprovechar Phase 1 | Introduce helper now and migrate the touched lines. Coherent "you touched it, you fixed it" but breaks "no behaviour change" property. | |

**User's choice:** Esperar a Phase 2.
**Notes:** Preserves the structural-only property of Phase 1.

---

## Claude's Discretion

- Internal helper function names inside `src/push/dispatcher.rs`.
- Whether to commit Phase 1 as one commit (recommended grain) or split D-09/D-10 into a separate trait-hygiene commit.
- No new tests added in Phase 1 (success criteria are observable via manual smoke test against the existing relay path).

## Deferred Ideas

- Delete or `#[allow(dead_code)]` the `MOSTRO_PUBKEY` config field + listener validation — out of scope per the user; future cleanup milestone candidate.
- Hash-based pubkey logging helper — Phase 2 (PRIV-01).
- Single shared `reqwest::Client` with timeouts — Phase 2.
- Spawn-and-bound dispatch with semaphore — Phase 2 if OPEN-1 lands on always-202.
