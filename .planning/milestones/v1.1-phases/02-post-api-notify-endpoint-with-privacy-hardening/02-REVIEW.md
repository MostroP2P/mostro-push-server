---
phase: 02-post-api-notify-endpoint-with-privacy-hardening
reviewed: 2026-04-25T00:00:00Z
depth: standard
files_reviewed: 13
files_reviewed_list:
  - Cargo.toml
  - deploy-fly.sh
  - docs/verification/dispute-chat.md
  - src/api/mod.rs
  - src/api/notify.rs
  - src/api/routes.rs
  - src/main.rs
  - src/push/dispatcher.rs
  - src/push/fcm.rs
  - src/push/mod.rs
  - src/push/unifiedpush.rs
  - src/utils/log_pubkey.rs
  - src/utils/mod.rs
findings:
  critical: 0
  warning: 2
  info: 6
  total: 8
status: issues_found
---

# Phase 2: Code Review Report

**Reviewed:** 2026-04-25
**Depth:** standard
**Files Reviewed:** 13
**Status:** issues_found

## Summary

La fase 2 introduce el endpoint `POST /api/notify` con un set coherente de medidas de privacidad: validación previa al logging, correlador BLAKE3 con salt aleatoria por proceso (nunca persistida), middleware `X-Request-Id` con scope estricto a `/notify`, payload silencioso FCM separado (apns-priority 5, apns-push-type background), dispatch desacoplado vía `tokio::spawn` con `Arc<Semaphore>(50)` y drop silencioso al saturarse.

La revisión NO ha encontrado vulnerabilidades de seguridad críticas. El contrato siempre-202, el scoping del middleware, la salt en memoria, el `try_acquire_owned()` con manejo de error, y el log redaction están implementados correctamente y respetan las anti-restricciones (CRIT-2/3/6, OOS-11). Los hallazgos son dos warnings menores (imports no usados detectados por `cargo check`) y seis info de menor impacto: un campo `Cargo.toml` heredado, headers APNs no esenciales pero recomendados, redundancia en re-derivación, falta de validación contra pubkeys con mayúsculas, secret hardcodeado en `deploy-fly.sh` (ya documentado como inerte por encripción desactivada — flagueado para visibilidad), y dead-code en `Cargo.toml` (deps no usadas en esta fase).

El contrato de privacidad del endpoint es sólido: la validación de `trade_pubkey` ocurre antes de cualquier log que la referencie (línea 54 antes de línea 64 en `notify.rs`), el handler emite `info!` sólo con el correlador opaco, y el camino spawn-saturado emite un `warn!` sin pubkey alguna (línea 103 `notify.rs`). El scoping del middleware está implementado vía `web::resource("/notify").wrap(...)` (línea 56-60 `routes.rs`), evitando la fuga a `/register`/`/unregister`/`/info`/`/health`/`/status` que retiene su comportamiento previo.

## Warnings

### WR-01: Imports no usados en `src/push/fcm.rs` y `src/push/unifiedpush.rs`

**File:** `src/push/fcm.rs:3` y `src/push/unifiedpush.rs:3`
**Issue:** La línea `use reqwest::Client;` quedó remanente tras el cambio del campo `client: Client` a `client: Arc<reqwest::Client>` en la fase 2 (commit usa el path completo `reqwest::Client` en su lugar). Esto produce una warning activa en `cargo check`:

```
warning: unused import: `reqwest::Client`
 --> src/push/fcm.rs:3:5
warning: unused import: `reqwest::Client`
 --> src/push/unifiedpush.rs:3:5
```

Si el proyecto adopta `#![deny(warnings)]` o `cargo clippy -- -D warnings` en CI a futuro, esto rompería la build. Ahora mismo es ruido en la salida de `cargo check`/`cargo build`.

**Fix:** Eliminar la línea en ambos archivos:

```rust
// src/push/fcm.rs:3 — DELETE
- use reqwest::Client;

// src/push/unifiedpush.rs:3 — DELETE
- use reqwest::Client;
```

`reqwest::Client` se sigue usando como tipo `Arc<reqwest::Client>` con path completo en la struct y en el constructor; no se requiere import alguno.

---

### WR-02: Header `x-request-id` no se añade a respuestas de error propagadas vía `?`

**File:** `src/api/notify.rs:117-132`
**Issue:** El middleware `request_id_mw` propaga errores de `next.call(req).await?` con el operador `?`. En ese path, la rama posterior que inserta el header `x-request-id` en la respuesta NO se ejecuta. Si en el futuro algún middleware encadenado o un extractor produce un `Err(actix_web::Error)` (en lugar de un `Ok(ServiceResponse)` con status 4xx — que es el comportamiento actual de `web::Json` malformado), el cliente no verá el correlador en esa respuesta de error.

En la práctica actual de actix-web 4.x, el extractor `web::Json` retorna `Ok(ServiceResponse)` con 400 (no `Err`) cuando el JSON no parsea, así que el camino de `?` está raramente ejercitado. El issue es defensivo / forward-looking, no un bug en producción hoy.

**Fix:** Si se quiere garantía en todas las respuestas (incluidas las de error propagadas), capturar el `Result` y añadir el header en ambos brazos. Ejemplo:

```rust
let id = uuid::Uuid::new_v4().to_string();
let header_value = HeaderValue::from_str(&id)
    .expect("uuid string is always valid header value");
let header_name = HeaderName::from_static("x-request-id");

let result = next.call(req).await;
match result {
    Ok(mut res) => {
        res.headers_mut().insert(header_name, header_value);
        Ok(res)
    }
    Err(e) => {
        // Errores de actix se convierten en respuesta 500 más adelante;
        // el header se perdería de todas formas con el `?` actual.
        // Para el caso 400-de-extractor (que ya entra como Ok), está cubierto.
        Err(e)
    }
}
```

Alternativa más simple: dejar como está y añadir un comentario explicando que en errores propagados el header no se incluye, lo que también es aceptable porque en tales casos el cliente ya no tiene control de la respuesta. Marcar como "decisión consciente" si ese es el caso.

## Info

### IN-01: Dependencia `tokio-tungstenite` declarada pero no usada por la fase

**File:** `Cargo.toml:12`
**Issue:** `tokio-tungstenite = "0.21"` está declarada en el manifest. La revisión del scope (`grep -r "tokio_tungstenite\|tungstenite" src/`) no encuentra usos en la fase 2 ni en el resto del crate (el tráfico Nostr fluye por `nostr-sdk`). Esto se documenta en `CLAUDE.md` como "declared but not used", pero sigue contribuyendo al tiempo de compilación y al footprint del binario.

**Fix:** Fuera de scope para esta fase (no se quiere modificar deps sin aprobación explícita per CLAUDE.md global). Tracked como mejora futura: si efectivamente no se usa en ningún punto del crate, puede removerse en una fase de cleanup dedicada.

---

### IN-02: Header APNs `apns-expiration` ausente en payload silencioso FCM

**File:** `src/push/fcm.rs:226-251` (`build_silent_payload_for_notify`)
**Issue:** El payload silencioso usa `apns-priority: 5` y `apns-push-type: background`, lo cual es correcto para wakes silenciosos. Sin embargo, no incluye `apns-expiration`. Apple recomienda explícitamente que los push silenciosos especifiquen un TTL (con valor 0 — entregar inmediatamente o descartar). Sin `apns-expiration`, el comportamiento por defecto puede variar por configuración del operador APNs.

Esto NO es un bug — el push se entrega — pero un `apns-expiration` explícito aumenta la predictibilidad de la entrega y reduce el riesgo de que pushes "viejos" lleguen al dispositivo cuando el contexto del trade ya cambió.

**Fix:** Añadir el header en `build_silent_payload_for_notify`:

```rust
"apns": {
    "headers": {
        "apns-priority": "5",
        "apns-push-type": "background",
        "apns-expiration": "0"
    },
    ...
}
```

Tratar como mejora opcional, no bloqueante.

---

### IN-03: Re-derivación redundante de `log_pubkey` dentro del spawn

**File:** `src/api/notify.rs:64, 81`
**Issue:** `log_pk` ya se derivó en línea 64 (handler outer) y está disponible como `String` capturable por valor. La línea 81 lo recalcula dentro del `tokio::spawn` (`task_log_pk = log_pubkey(&salt, &pubkey)`). El cómputo es determinista (salt y pubkey no cambian), así que el resultado es idéntico al ya derivado.

El comentario de la línea 79-80 justifica la re-derivación: "to keep task-side log lines independent of outer-scope state". Esto es defendible estilísticamente, pero dado que la salt y la pubkey YA están movidas dentro del spawn por `Arc::clone` y `clone()`, el `log_pk` outer también podría haberse `clone()`-ado al spawn.

Coste: una llamada extra a `blake3::keyed_hash` por request. Con 50 permits y throughput sostenido eso es ~50/segundo de hashes redundantes — negligible, pero gratis.

**Fix:** Mantener la implementación actual si la justificación de "state independence" se valora — es defendible. Si se prefiere economía:

```rust
let log_pk_for_task = log_pk.clone(); // o reutilizar el mismo binding
tokio::spawn(async move {
    let _permit = permit;
    if let Some(token) = token_store.get(&pubkey).await {
        match dispatcher.dispatch_silent(&token).await {
            Ok(_) => info!("notify: dispatched pk={}", log_pk_for_task),
            Err(e) => warn!("notify: dispatch failed pk={} err={}", log_pk_for_task, e),
        }
    }
});
```

No es bug; es opcional.

---

### IN-04: Validación de pubkey acepta mayúsculas mezcladas

**File:** `src/api/notify.rs:54` y `src/api/routes.rs:98, 159`
**Issue:** La validación es `len() == 64 && hex::decode(...).is_ok()`. `hex::decode` acepta tanto minúsculas como mayúsculas (`0xab` y `0xAB` decodifican a lo mismo). Esto significa que `"ABCDEF...123"` y `"abcdef...123"` representan la misma pubkey pero generan correlatores `log_pubkey` distintos (BLAKE3 trabaja sobre bytes UTF-8, no sobre el valor decodificado).

Esto puede causar "ghost pubkeys" en los logs: el mismo dispositivo con la misma pubkey en diferentes capitalizaciones aparecerá como dos correlatores distintos. El runbook `docs/verification/dispute-chat.md:137` ya menciona "sin mayúsculas/minúsculas mezcladas" como precondición operacional, lo que confirma el conocimiento del issue.

Tampoco se hace `.to_lowercase()` antes de pasar al `token_store.get(&pubkey)`, así que un cliente que registra con `"abc..."` y notifica con `"ABC..."` quedará como pubkey no-registrada (no hay match), y el handler retorna 202 normalmente — privacidad preservada, pero el push no llega.

**Fix:** Si es un comportamiento deseado (estricto byte-for-byte), documentarlo. Si se desea normalización, normalizar a lowercase tras la validación:

```rust
if req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err() {
    return HttpResponse::BadRequest().json(NotifyError { ... });
}
let trade_pubkey = req.trade_pubkey.to_lowercase();
let log_pk = log_pubkey(&state.notify_log_salt, &trade_pubkey);
// pasar `trade_pubkey` al spawn en vez de `req.trade_pubkey.clone()`.
```

Cambio de comportamiento existente — requiere coordinación con `register_token` en `routes.rs:98` para mantener consistencia (si una se normaliza, la otra debe hacerlo también, o la lookup falla).

Tratar como issue de consistencia operacional, no de seguridad.

---

### IN-05: `SERVER_PRIVATE_KEY` hardcodeado en `deploy-fly.sh`

**File:** `deploy-fly.sh:30`
**Issue:** El script tiene una clave privada hex de 64 caracteres en texto plano. Per la memoria del proyecto (`~/.claude/projects/.../memory/MEMORY.md`), esto se considera "inerte" porque el módulo crypto está gated `#[allow(dead_code)]` y la encripción está deshabilitada.

El riesgo latente: si en una fase futura (Phase 4 / encripción habilitada) se reactiva el path crypto sin re-generar y rotar la clave en producción, se publicaría un servicio cuya clave privada está en el repo público. El script también vive en disco en máquinas de operadores y puede entrar en backups/screenshots accidentalmente.

**Fix:** Tracked como riesgo conocido. Antes de habilitar Phase 4:
1. Generar nueva clave privada en producción.
2. Rotar via `flyctl secrets set SERVER_PRIVATE_KEY=...` desde un canal seguro (no commit).
3. Eliminar la línea hardcodeada de `deploy-fly.sh` y reemplazarla con un placeholder o lectura desde env del operador.

No requiere acción en esta fase. Reportado para visibilidad de stakeholders del milestone.

---

### IN-06: Dead-code warnings preexistentes acumulándose

**File:** múltiples — `src/push/fcm.rs:51` (`config` unused), `src/push/unifiedpush.rs:23` (`config` unused field), `src/push/dispatcher.rs:12` (`backend` unused field), `src/utils/batching.rs:3` (`BatchingManager` unused), `src/store/mod.rs:108` (`count` unused), etc.
**Issue:** `cargo check` produce 21 warnings. La mayoría son preexistentes (no introducidos en esta fase) y reflejan código gated para futuras fases (`crypto/`, `batching.rs`) o campos no usados en deserialización (`ServiceAccount.project_id`).

El issue específico introducido en fase 2: `FcmPush::new(config: Config, ...)` y `UnifiedPushService::new(config: Config, ...)` reciben un `Config` que ya no se almacena en `FcmPush` (lee de env directamente líneas 52-54). El `config` parameter de `FcmPush::new` es completamente unused — `cargo check` lo reporta como `warning: unused variable: config`.

**Fix:** Para `FcmPush::new` específicamente (introducido por la fase con la signatura nueva):

```rust
// src/push/fcm.rs:51
pub fn new(_config: Config, client: Arc<reqwest::Client>) -> Self {
    // ... (resto igual)
}
```

O eliminar el parámetro de la signatura si no se planea usarlo (rompe call-site en `main.rs:73` — pero esa es la única invocación). Tratar como cleanup opcional.

Para los warnings preexistentes (`config` en `UnifiedPushService`, `BatchingManager`, etc.), están fuera del scope de esta revisión (son artefactos de fases anteriores).

---

_Reviewed: 2026-04-25_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
