# Phase 3: Dual-keyed rate limiting and verification harness - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-25
**Phase:** 03-dual-keyed-rate-limiting-and-verification-harness
**Areas discussed:** Tuning per-pubkey + per-IP (OPEN-3), actix-governor approval + version (OPEN-4), Wiring per-pubkey limiter + cleanup (LIMIT-02/05/06), Test suite design (VERIFY-01/02)

---

## Tuning per-pubkey + per-IP (OPEN-3)

### Per-pubkey rate sustained + burst

| Option | Description | Selected |
|--------|-------------|----------|
| 30/min, burst 10 (PITFALLS RL-3) | Permite ráfaga de 10 mensajes seguidos (chat real), luego sostenido ~1 cada 2s. Ajusta al perfil de chat back-and-forth. | ✓ |
| 5/min, burst 5 (PROJECT.md) | Más restrictivo. Bueno contra abuso pero rompe chat: una conversación normal toca el límite en 1 minuto. | |
| 60/min, burst 20 (más permisivo) | Más margen al chat heavy y a iOS donde Apple ya throttleó (FCM-1) el silent push. Casi no-op si la mayoría de pares tiene <20 mensajes/min. | |

**User's choice:** 30/min, burst 10 (PITFALLS RL-3) — recommended.
**Notes:** Locked as D-01 in CONTEXT.md.

### Per-IP rate sustained + burst

| Option | Description | Selected |
|--------|-------------|----------|
| 120/min, burst 30 (PITFALLS RL-3) | Acomoda NAT (cybercafé, móvil-roaming, hogar con varios usuarios). Per-pubkey ya protege a cada destino; per-IP es solo anti-flood grueso. | ✓ |
| 60/min, burst 10 (alineado con RATE_LIMIT_PER_MINUTE actual) | Más estricto. Riesgo de falsos positivos en NAT compartido. | |
| 300/min, burst 60 (muy permisivo) | Per-IP solo como backstop catastrófico. La mayor parte del trabajo lo hace per-pubkey. | |

**User's choice:** 120/min, burst 30 (PITFALLS RL-3) — recommended.
**Notes:** Locked as D-02 in CONTEXT.md.

### Behavior when env vars NOTIFY_RATE_PER_*_PER_MIN are absent or malformed at startup

| Option | Description | Selected |
|--------|-------------|----------|
| Defaults compile-time + log info | Si el env está ausente, usar el default decidido y log info!('NOTIFY_RATE_PER_PUBKEY_PER_MIN unset, using default 30'). Si es malformada, panic. | ✓ |
| Fail-fast: requerir las env vars explícitas | main.rs panic si no están declaradas. Fuerza decisión consciente. Rompe `cargo run` local sin .env. | |
| Defaults silenciosos sin log | Igual que la primera pero sin la línea info. Pierde la señal en logs. | |

**User's choice:** Defaults compile-time + log info — recommended.
**Notes:** Locked as D-03 in CONTEXT.md.

### Behavior when env value is 0 or negative

| Option | Description | Selected |
|--------|-------------|----------|
| Panic en startup con mensaje claro | Config::from_env() devuelve Err. Nunca arranca con un limiter inservible. Patrón consistente con el existente. | ✓ |
| Fallback al default + warn! | Loguea warn y arranca. Resilencia operativa pero el operador no nota que el limiter quedó en otro valor. | |
| Tratar 0 como 'desactivado' | Permite kill switch del rate limiter por env. Conveniente para emergencias pero un typo desactiva el limiter. | |

**User's choice:** Panic en startup con mensaje claro — recommended.
**Notes:** Locked as D-04 in CONTEXT.md.

---

## actix-governor approval + version (OPEN-4)

### Crate strategy after the GPL-3.0 finding

**Pre-question research finding:** All published versions of `actix-governor` (0.2.0 through 0.10.0, last release 2025-10-12) are licensed GPL-3.0-or-later. The project is MIT. Adding it would force the distributed binary to GPL-3.0-or-later — an unintended re-licensing. `governor` itself is MIT-licensed in all versions.

| Option | Description | Selected |
|--------|-------------|----------|
| Hand-rolled middleware on governor (MIT) | Implementar la middleware Actix per-IP a mano usando `actix_web::middleware::from_fn` (mismo patrón que `request_id_mw`). Por dentro consulta governor::RateLimiter. Sin GPL, sin nueva dep. | ✓ |
| Adoptar actix-governor (GPL-3.0) | Aceptar el cambio de licencia: el binario distribuido pasa a GPL-3.0-or-later. Ahorra ~50 LoC. | |
| Otra librería MIT/Apache (e.g. tower_governor + adaptador) | tower_governor (MIT) existe pero es para Tower/Axum. Adaptar implica más código que la opción hand-rolled. | |

**User's choice:** Hand-rolled middleware on governor (MIT) — recommended.
**Notes:** Locked as D-05 + D-06 in CONTEXT.md. License finding documented as a project-level invariant in canonical_refs.

### Bump governor 0.6 → 0.10?

| Option | Description | Selected |
|--------|-------------|----------|
| Mantener governor 0.6 | Ya está declarado y aprobado. API de keyed RateLimiter es funcionalmente idéntica a 0.10. Cero churn. | ✓ |
| Bump a governor 0.10 | Más reciente. Cuenta como version-bump. Trae hashbrown 0.16 + web-time 1.1 vs 0.6 sin esas. | |
| Bump a governor 0.7 o 0.8 (intermedio) | Compromiso. Sin razones claras para preferir vs 0.6 o 0.10. | |

**User's choice:** Mantener governor 0.6 — recommended.
**Notes:** Locked as D-07 in CONTEXT.md.

### Module location

| Option | Description | Selected |
|--------|-------------|----------|
| Nuevo módulo src/api/rate_limit.rs | Modulo dedicado: FlyClientIpKeyExtractor, per_ip_rate_limit_mw, PerPubkeyLimiter struct. Re-exportado vía src/api/mod.rs. Patrón consistente con notify.rs. | ✓ |
| Inline en src/api/notify.rs | Middleware + helpers viven al lado del handler. Pro: cohesión. Con: notify.rs crece a 250+ líneas, mezcla concerns. | |
| Distribuido (middleware en notify.rs, helper en utils/) | Más split. Probablemente no para este alcance. | |

**User's choice:** Nuevo módulo src/api/rate_limit.rs — recommended.
**Notes:** Locked as D-08 in CONTEXT.md.

### Behavior when IP extraction fails

| Option | Description | Selected |
|--------|-------------|----------|
| Reject con 500 (fallar cerrado) | En producción Fly siempre inyecta Fly-Client-IP; la ausencia indica configuración rota. 500 hace visible el problema. En tests/local-dev peer_addr() siempre está. | ✓ |
| Compartir un bucket global (fallar abierto pero limitado) | Si no hay IP, todos los requests sin IP comparten un solo bucket. Mantiene el endpoint vivo pero cross-contamination. | |
| Skip rate limit (fallar abierto sin límite) | Sin IP → deja pasar sin contar. Permite bypass simplemente no enviando header válido. Inaceptable. | |

**User's choice:** Reject con 500 (fallar cerrado) — recommended.
**Notes:** Locked as D-10 + D-11 in CONTEXT.md.

---

## Wiring per-pubkey limiter + cleanup (LIMIT-02/05/06)

### Per-pubkey limiter shape in AppState

| Option | Description | Selected |
|--------|-------------|----------|
| Arc<DefaultKeyedRateLimiter<String>> directo | Type alias `pub type PerPubkeyLimiter = governor::DefaultKeyedRateLimiter<String>;`. Handler hace `state.per_pubkey_limiter.check_key(&pubkey)`. No wrapper struct. | ✓ |
| Wrapper struct PerPubkeyLimiter { inner, cap } | Struct con métodos check, cleanup, len, cap. Encapsula la lógica. Capa extra para algo que governor ya hace. | |
| Static OnceCell<PerPubkeyLimiter> | Limiter como global estático. Dificulta tests. | |

**User's choice:** Arc<DefaultKeyedRateLimiter<String>> directo — recommended.
**Notes:** Locked as D-09 in CONTEXT.md.

### Cleanup task lifecycle

| Option | Description | Selected |
|--------|-------------|----------|
| Función start_rate_limit_cleanup_task() en src/api/rate_limit.rs | Patrón simétrico al store::start_cleanup_task. main.rs llama la función después de construir el limiter. | ✓ |
| Inline tokio::spawn en main.rs | Igual semántica pero el código vive en main.rs. main.rs ya tiene 150+ líneas. | |
| Lazy: trigger retain_recent en el handler cada N requests | Counter atómico, cada N requests llama retain_recent inline. Atacante DOS-sea el limiter map saltando el threshold. | |

**User's choice:** start_rate_limit_cleanup_task() en src/api/rate_limit.rs — recommended.
**Notes:** Locked as D-15 in CONTEXT.md.

### Cleanup interval and soft-cap warn configuration

| Option | Description | Selected |
|--------|-------------|----------|
| Constantes hardcoded + env override | Compile-time defaults: 60s cleanup, 100k soft-cap. Env vars opcionales NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS y NOTIFY_PUBKEY_LIMITER_SOFT_CAP para override. | ✓ |
| Solo env vars (sin defaults) | Operador debe declarar todas las env vars o panic. Rompe `cargo run` local. | |
| Solo hardcoded (sin override) | 100% determinístico. Cambiar el cap requiere recompile. | |

**User's choice:** Constantes hardcoded + env override — recommended.
**Notes:** Locked as D-16 + D-17 + D-18 + D-28 in CONTEXT.md.

### 429 response shape and Retry-After

| Option | Description | Selected |
|--------|-------------|----------|
| Body byte-idéntico + Retry-After header | Body fijo `{"success": false, "message": "rate limited"}`. Retry-After computed con not_until.wait_time_from. | ✓ |
| Body byte-idéntico, SIN Retry-After | RFC permite omitir. Privacy-leve mejor pero los móviles ya implementan backoff exponencial. | |
| Body 'rate_limited_ip' vs 'rate_limited_pubkey' | Diferenciar fuente del 429. Anti-RL-2 oracle leak. NO recomendado. | |

**User's choice:** Body byte-idéntico + Retry-After header — recommended.
**Notes:** Locked as D-13 + D-14 in CONTEXT.md.

---

## Test suite design (VERIFY-01/02)

### Test location

| Option | Description | Selected |
|--------|-------------|----------|
| Co-located en src/api/*.rs como #[cfg(test)] mod tests | Patrón actual del repo. Tests viven junto al módulo bajo prueba. No requiere agregar lib.rs. | ✓ |
| Nuevo directorio tests/ a nivel crate | Idiomático Rust integración. Pero requiere exponer un lib.rs (el crate actual es binary-only). Cambio estructural fuera del alcance. | |
| Módulo dedicado src/api/tests.rs compartido | Helpers + tests en un solo archivo. 200+ líneas todas en un sitio; less locality. | |

**User's choice:** Co-located en src/api/*.rs — recommended.
**Notes:** Locked as D-22 in CONTEXT.md.

### Stub PushService design

| Option | Description | Selected |
|--------|-------------|----------|
| Stub con Arc<Mutex<Vec<(token, platform)>>> | Graba cada llamada. Tests asertan stub.calls.lock().len() y contenido. Soporta toggle fail. | ✓ |
| Stub con tokio::sync::mpsc channel | Cada call manda al channel; test recibe con timeout. Detecta ausencia. Race conditions si el test asume orden estricto. | |
| Stub no-op sin observabilidad | Solo retorna Ok(()) sin registrar. Insuficiente para 'registered hit' meaning. | |

**User's choice:** Stub con Arc<Mutex<Vec<(token, platform)>>> — recommended.
**Notes:** Locked as D-23 in CONTEXT.md.

### Additional regression coverage beyond the mandatory 6 (multiSelect)

| Option | Description | Selected |
|--------|-------------|----------|
| /api/health 1000-burst no rate-limited (anti-DEPLOY-3) | Llama 1000 veces a /api/health desde la misma 'IP' simulada; aserta 1000× 200. SC #3 del roadmap. | ✓ |
| X-Request-Id header presente y válido (NOTIFY-04 regression) | Aserta header X-Request-Id 36 chars (UUIDv4) en toda response a /api/notify. Aserta que un X-Request-Id enviado por el cliente es ignorado. | ✓ |
| 429 body byte-idéntico per-IP vs per-pubkey (anti-RL-2) | Dispara per-IP 429 y per-pubkey 429, captura ambos response bodies, assert_eq!(body_ip, body_pubkey). | ✓ |
| Cleanup task: retain_recent reduce limiter.len() (LIMIT-05) | Construye limiter, llena con keys, espera el TTL, llama retain_recent, aserta len() bajo. Cubre RL-1. | ✓ |

**User's choice:** ALL 4 selected.
**Notes:** Locked as D-25 in CONTEXT.md.

### VERIFY-02 byte-identical fixture for /api/register

| Option | Description | Selected |
|--------|-------------|----------|
| Literal JSON inline en el test | Test envia POST /api/register con fixture conocido, lee body, compara con string literal. ~5 líneas. Cero deps, cero archivos. | ✓ |
| Golden file en tests/fixtures/ | JSON fixture en archivo. include_str! en el test. Archivo extra para mantener sincronizado. | |
| Snapshot library (insta o similar) | Crate insta (MIT). Tests escriben snapshots automáticamente. NUEVA DEP requiere aprobación; overkill para 5-line JSON. | |

**User's choice:** Literal JSON inline en el test — recommended.
**Notes:** Locked as D-26 in CONTEXT.md.

---

## Claude's Discretion

Areas explicitly delegated to the planner / executor in CONTEXT.md:

- Exact internal helper function signatures inside `src/api/rate_limit.rs` (e.g. `extract_client_ip(req: &ServiceRequest) -> Result<IpAddr, ()>` vs `Option<IpAddr>` vs custom error type).
- Whether to use a custom error type or `actix_web::error::ErrorInternalServerError` for the IP extraction failure path.
- The exact UUIDv4 assertion approach in the X-Request-Id test (`uuid::Uuid::parse_str(&header).is_ok()` vs regex match).
- Logging level for the per-IP 429 path: `debug!` (high cardinality, recommended default) vs `warn!` (noisy under attack) vs no log at all.
- Whether the cleanup task uses `tokio::time::interval` (default) or `tokio::time::interval_at` for jittered start.
- Exact arrangement of test helper functions (e.g. `make_test_app()` factory, `register_test_pubkey()` helper) — DRY vs locality balance.
- Whether `deploy-fly.sh` gets explicit `NOTIFY_RATE_PER_PUBKEY_PER_MIN` / `NOTIFY_RATE_PER_IP_PER_MIN` env vars set or relies on compile-time defaults.

---

## Deferred Ideas

Captured in CONTEXT.md `<deferred>` section. Not lost, not acted on:

- Per-IP-per-pubkey composite key limiter
- Burst-size env override (`NOTIFY_RATE_PER_PUBKEY_BURST` etc.)
- Throttled soft-cap warning (warn once per 5min)
- Metrics endpoint (F-02)
- CI / GitHub Actions for the integration suite
- Trust toggle for `Fly-Client-IP` (`TRUST_FLY_CLIENT_IP`)
- `tower_governor` adapter for Actix
- Switch to `actix-governor` if it ever re-licenses to MIT/Apache
- Future cleanup of unused `RATE_LIMIT_PER_MINUTE` / `RateLimitConfig.max_per_minute`
- Bump `governor` 0.6 → 0.10
