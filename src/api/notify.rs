use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::header::{HeaderName, HeaderValue},
    middleware::Next,
    web, Error, HttpResponse, Responder,
};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;

use crate::api::routes::AppState;
use crate::utils::log_pubkey::log_pubkey;

/// Request body for POST /api/notify.
///
/// Privacy contract:
/// - Single field, by design (anti-OOS-11: no sender_pubkey, no signature,
///   no Idempotency-Key, no auth header).
/// - Body is parsed to this struct via serde; serde rejects malformed JSON
///   with an automatic 400 response, satisfying anti-CRIT-2 / D-01.
#[derive(Deserialize)]
pub struct NotifyRequest {
    pub trade_pubkey: String,
}

/// 400-only response shape for /api/notify.
///
/// Defined locally (NOT a re-import of routes::RegisterResponse) per
/// PATTERNS.md Pitfall 5 — keeps cross-file COMPAT-1 coupling at zero.
/// Same operator-visible JSON shape as RegisterResponse minus the optional
/// `platform` field.
#[derive(Serialize)]
struct NotifyError {
    success: bool,
    message: String,
}

/// Sender-triggered silent push to the device registered for `trade_pubkey`.
///
/// Privacy contract:
/// - Always returns 202 on parse-valid input. Never differentiates registered
///   vs unregistered pubkeys (anti-CRIT-2 enumeration oracle).
/// - 400 only on JSON parse failure or pubkey-validation failure.
/// - Dispatch happens in tokio::spawn detached from the response, bounded
///   by Arc<Semaphore> with 50 permits (anti-CRIT-6 + anti-CONC-1).
/// - Best-effort: FCM 200 means "Google accepted", not "device woke" (FCM-2).
pub async fn notify_token(
    state: web::Data<AppState>,
    req: web::Json<NotifyRequest>,
) -> impl Responder {
    // D-12 step 2: validate pubkey format. Mirrors src/api/routes.rs:86 exactly.
    if req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err() {
        warn!("notify: invalid trade_pubkey format");
        return HttpResponse::BadRequest().json(NotifyError {
            success: false,
            message: "Invalid trade_pubkey format (expected 64 hex characters)"
                .to_string(),
        });
    }

    // D-12 step 3: structured log via log_pubkey only.
    let log_pk = log_pubkey(&state.notify_log_salt, &req.trade_pubkey);
    info!("notify: request received pk={}", log_pk);

    // D-12 step 4: bounded spawn via Semaphore.
    match Arc::clone(&state.semaphore).try_acquire_owned() {
        Ok(permit) => {
            // D-12 step 5: spawn closure owns Arc clones; no &state, no &req.
            let dispatcher = Arc::clone(&state.dispatcher);
            let token_store = Arc::clone(&state.token_store);
            let salt = Arc::clone(&state.notify_log_salt);
            let pubkey = req.trade_pubkey.clone();

            tokio::spawn(async move {
                let _permit = permit; // dropped at task end; releases slot.

                // Re-derive opaque correlator inside the spawn so the
                // task-side log lines do not depend on outer-scope state.
                let task_log_pk = log_pubkey(&salt, &pubkey);

                // CONC-2-safe: get() drops the RwLock before returning.
                if let Some(token) = token_store.get(&pubkey).await {
                    match dispatcher.dispatch_silent(&token).await {
                        Ok(_outcome) => info!(
                            "notify: dispatched pk={}",
                            task_log_pk
                        ),
                        Err(e) => warn!(
                            "notify: dispatch failed pk={} err={}",
                            task_log_pk, e
                        ),
                    }
                }
                // None case (pubkey not registered): silently no-op.
                // Caller already received 202 (anti-CRIT-2 / anti-CRIT-6).
                // No log line — that would be an oracle.
            });
        }
        Err(_) => {
            // No permit available. Pubkey NOT in this log line (anti-CRIT-3).
            warn!("notify: spawn pool saturated, dropping dispatch");
        }
    }

    // D-12 step 6: always 202 on parse-valid input.
    HttpResponse::Accepted().json(json!({"accepted": true}))
}

/// X-Request-Id middleware scoped to the /api/notify resource only (D-13).
///
/// - Strips any inbound `X-Request-Id` header (privacy: client cannot
///   correlate its own requests with server state).
/// - Generates a server-side UUIDv4 per request.
/// - Inserts the generated ID into the response headers.
pub async fn request_id_mw(
    mut req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<impl MessageBody>, Error> {
    req.headers_mut().remove("x-request-id");

    let id = uuid::Uuid::new_v4().to_string();
    let mut res = next.call(req).await?;

    res.headers_mut().insert(
        HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&id)
            .expect("uuid string is always valid header value"),
    );
    Ok(res)
}
