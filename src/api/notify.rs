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

use governor::clock::Clock;
use crate::api::rate_limit::rate_limited_response;
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

    // D-12 step 4: per-pubkey rate-limit check BEFORE semaphore acquisition.
    // Per anti-RL-2 (D-13): byte-identical 429 to the per-IP middleware via
    // the shared rate_limited_response helper.
    if let Err(not_until) = state.per_pubkey_limiter.check_key(&req.trade_pubkey) {
        let retry_after_secs = not_until
            .wait_time_from(governor::clock::DefaultClock::default().now())
            .as_secs()
            .max(1);
        return rate_limited_response(retry_after_secs);
    }

    // D-12 step 5: bounded spawn via Semaphore.
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test, web, App};
    use crate::api::routes::configure;
    use crate::api::test_support::{
        make_app_state, make_test_components, build_test_actix_app,
        register_test_pubkey, StubPushService, TEST_PUBKEY, TEST_PUBKEY_2,
    };
    use crate::store::Platform;
    use std::sync::Arc;
    use uuid::Uuid;

    /// D-24 #1: Registered pubkey + valid body → 202, stub recorded one call
    /// for the registered Android platform.
    #[actix_web::test]
    async fn notify_registered_pubkey_dispatches() {
        let stub = Arc::new(StubPushService::new(vec![Platform::Android]));
        let (state, per_ip_limiter) = make_app_state(stub.clone());

        // Pre-register the pubkey before building the service.
        register_test_pubkey(&state, TEST_PUBKEY).await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state))
                .app_data(web::Data::new(per_ip_limiter))
                .configure(configure),
        )
        .await;

        let req = test::TestRequest::post()
            .uri("/api/notify")
            .insert_header(("Fly-Client-IP", "1.2.3.4"))
            .set_json(serde_json::json!({"trade_pubkey": TEST_PUBKEY}))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // The dispatch happens in tokio::spawn — yield to let it run.
        for _ in 0..20 {
            tokio::task::yield_now().await;
            if !stub.calls.lock().await.is_empty() {
                break;
            }
        }

        let calls = stub.calls.lock().await;
        assert_eq!(calls.len(), 1, "stub should record exactly 1 dispatch");
        assert_eq!(calls[0].0, "test_fcm_token");
        assert_eq!(calls[0].1, Platform::Android);
    }

    /// D-24 #2: Unregistered pubkey → 202 (anti-CRIT-2 always-202),
    /// stub recorded zero calls.
    #[actix_web::test]
    async fn notify_unregistered_pubkey_no_dispatch() {
        let c = make_test_components();
        let stub = c.stub.clone();
        let app = test::init_service(build_test_actix_app(c)).await;

        let req = test::TestRequest::post()
            .uri("/api/notify")
            .insert_header(("Fly-Client-IP", "1.2.3.4"))
            .set_json(serde_json::json!({"trade_pubkey": TEST_PUBKEY_2}))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED, "anti-CRIT-2 always-202");

        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
        let calls = stub.calls.lock().await;
        assert!(calls.is_empty(), "no dispatch for unregistered pubkey");
    }

    /// D-24 #3: Malformed body — three sub-cases (non-hex, wrong length, missing field).
    #[actix_web::test]
    async fn notify_malformed_body_returns_400() {
        let c = make_test_components();
        let app = test::init_service(build_test_actix_app(c)).await;

        // Sub-case A: pubkey too short.
        let req = test::TestRequest::post()
            .uri("/api/notify")
            .insert_header(("Fly-Client-IP", "1.2.3.4"))
            .set_json(serde_json::json!({"trade_pubkey": "tooshort"}))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Sub-case B: 64 chars but not hex.
        let bad_hex: String = "z".repeat(64);
        let req = test::TestRequest::post()
            .uri("/api/notify")
            .insert_header(("Fly-Client-IP", "1.2.3.4"))
            .set_json(serde_json::json!({"trade_pubkey": bad_hex}))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Sub-case C: missing field — serde rejects with 400 automatically.
        let req = test::TestRequest::post()
            .uri("/api/notify")
            .insert_header(("Fly-Client-IP", "1.2.3.4"))
            .insert_header(("Content-Type", "application/json"))
            .set_payload("{}")
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// D-25 NOTIFY-04 regression: every /notify response (202/400) carries a
    /// server-generated UUIDv4 x-request-id header; inbound X-Request-Id from
    /// the client is overwritten.
    #[actix_web::test]
    async fn notify_x_request_id_always_uuidv4_and_overwrites_client_value() {
        let c = make_test_components();
        let app = test::init_service(build_test_actix_app(c)).await;

        // 202 path — inbound X-Request-Id from client must be overwritten.
        let req = test::TestRequest::post()
            .uri("/api/notify")
            .insert_header(("Fly-Client-IP", "1.2.3.4"))
            .insert_header(("X-Request-Id", "spoofed-by-client-12345"))
            .set_json(serde_json::json!({"trade_pubkey": TEST_PUBKEY}))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let id_value = resp
            .headers()
            .get("x-request-id")
            .expect("x-request-id header MUST be present on every /notify response")
            .to_str()
            .unwrap();
        assert_ne!(id_value, "spoofed-by-client-12345", "client value must be overwritten");
        assert!(Uuid::parse_str(id_value).is_ok(), "x-request-id must be UUIDv4 parseable");

        // 400 path — header MUST also be present.
        let req = test::TestRequest::post()
            .uri("/api/notify")
            .insert_header(("Fly-Client-IP", "1.2.3.4"))
            .set_json(serde_json::json!({"trade_pubkey": "tooshort"}))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let id_value = resp
            .headers()
            .get("x-request-id")
            .expect("x-request-id header MUST be on 400 too (request_id_mw is outermost)")
            .to_str()
            .unwrap();
        assert!(Uuid::parse_str(id_value).is_ok());
    }
}
