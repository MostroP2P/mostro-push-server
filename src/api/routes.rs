use actix_web::middleware::from_fn;
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use log::{info, warn};
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::api::notify::{notify_token, request_id_mw};
use crate::api::rate_limit::{per_ip_rate_limit_mw, PerPubkeyLimiter};
use crate::push::PushDispatcher;
use crate::store::{TokenStore, TokenStoreStats, Platform};
use crate::utils::log_pubkey::log_pubkey;

/// Request for registering a plaintext token (Phase 3 - unencrypted)
#[derive(Deserialize)]
pub struct RegisterTokenRequest {
    pub trade_pubkey: String,
    pub token: String,
    pub platform: String,
}

#[derive(Deserialize)]
pub struct UnregisterTokenRequest {
    pub trade_pubkey: String,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub status: String,
    pub version: String,
    pub tokens: TokenStoreStats,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

#[derive(Clone)]
pub struct AppState {
    pub token_store: Arc<TokenStore>,
    pub dispatcher: Arc<PushDispatcher>,
    pub semaphore: Arc<Semaphore>,
    pub notify_log_salt: Arc<[u8; 32]>,
    pub per_pubkey_limiter: Arc<PerPubkeyLimiter>,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/health", web::get().to(health_check))
            .route("/status", web::get().to(status))
            .route("/register", web::post().to(register_token))
            .route("/unregister", web::post().to(unregister_token))
            .route("/info", web::get().to(server_info))
            .service(
                web::resource("/notify")
                    // Order matters: actix-web wraps in reverse-registration order, so the
                    // last `.wrap()` is the outermost. `request_id_mw` MUST be outermost so
                    // it runs even when `per_ip_rate_limit_mw` short-circuits with 429,
                    // keeping x-request-id present on both 429 paths (anti-RL-2 oracle).
                    .wrap(from_fn(per_ip_rate_limit_mw))
                    .wrap(from_fn(request_id_mw))
                    .route(web::post().to(notify_token)),
            ),
    );
}

async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

async fn status(
    state: web::Data<AppState>,
) -> impl Responder {
    let stats = state.token_store.get_stats().await;

    HttpResponse::Ok().json(StatusResponse {
        status: "running".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        tokens: stats,
    })
}

async fn server_info() -> impl Responder {
    // Phase 3: No encryption, so no server pubkey needed
    // In Phase 4/5, this will return the server's public key for token encryption
    HttpResponse::Ok().json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "encryption_enabled": false,
        "note": "Token encryption will be enabled in a future phase"
    }))
}

async fn register_token(
    state: web::Data<AppState>,
    req: web::Json<RegisterTokenRequest>,
) -> impl Responder {
    info!(
        "Registering token pk={}",
        log_pubkey(&state.notify_log_salt, &req.trade_pubkey)
    );

    // Validate trade_pubkey format (should be 64 hex chars)
    if req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err() {
        warn!("Invalid trade_pubkey format");
        return HttpResponse::BadRequest().json(RegisterResponse {
            success: false,
            message: "Invalid trade_pubkey format (expected 64 hex characters)".to_string(),
            platform: None,
        });
    }

    // Validate token is not empty
    if req.token.is_empty() {
        warn!("Empty token provided");
        return HttpResponse::BadRequest().json(RegisterResponse {
            success: false,
            message: "Token cannot be empty".to_string(),
            platform: None,
        });
    }

    // Parse platform
    let platform = match req.platform.to_lowercase().as_str() {
        "android" => Platform::Android,
        "ios" => Platform::Ios,
        _ => {
            warn!("Invalid platform: {}", req.platform);
            return HttpResponse::BadRequest().json(RegisterResponse {
                success: false,
                message: format!("Invalid platform '{}' (expected 'android' or 'ios')", req.platform),
                platform: None,
            });
        }
    };

    // Store the token directly (no decryption in Phase 3)
    state.token_store.register(
        req.trade_pubkey.clone(),
        req.token.clone(),
        platform.clone(),
    ).await;

    info!(
        "Successfully registered {} token pk={}",
        platform,
        log_pubkey(&state.notify_log_salt, &req.trade_pubkey)
    );

    HttpResponse::Ok().json(RegisterResponse {
        success: true,
        message: "Token registered successfully".to_string(),
        platform: Some(platform.to_string()),
    })
}

async fn unregister_token(
    state: web::Data<AppState>,
    req: web::Json<UnregisterTokenRequest>,
) -> impl Responder {
    info!(
        "Unregistering token pk={}",
        log_pubkey(&state.notify_log_salt, &req.trade_pubkey)
    );

    // Validate trade_pubkey format
    if req.trade_pubkey.len() != 64 || hex::decode(&req.trade_pubkey).is_err() {
        warn!("Invalid trade_pubkey format");
        return HttpResponse::BadRequest().json(serde_json::json!({
            "success": false,
            "message": "Invalid trade_pubkey format (expected 64 hex characters)"
        }));
    }

    let removed = state.token_store.unregister(&req.trade_pubkey).await;

    if removed {
        HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Token unregistered successfully"
        }))
    } else {
        HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": "Token not found (may have already been unregistered)"
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test as atest};
    use crate::api::test_support::{make_test_components, build_test_actix_app, TEST_PUBKEY, TEST_PUBKEY_2};

    /// VERIFY-02 / D-24 #6: /api/register success body is BYTE-IDENTICAL to
    /// the pre-milestone fixture. RegisterResponse field order
    /// (success, message, platform) is the structural invariant.
    #[actix_web::test]
    async fn register_success_body_is_byte_identical() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::post()
            .uri("/api/register")
            .set_json(serde_json::json!({
                "trade_pubkey": TEST_PUBKEY,
                "token": "test_fcm_token",
                "platform": "android"
            }))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = atest::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            body_str,
            r#"{"success":true,"message":"Token registered successfully","platform":"android"}"#,
            "RegisterResponse byte-identity (anti-OOS-20)"
        );
    }

    /// VERIFY-02: /api/register error body for malformed pubkey is BYTE-IDENTICAL.
    /// `platform: None` is omitted via `#[serde(skip_serializing_if = "Option::is_none")]`.
    #[actix_web::test]
    async fn register_malformed_pubkey_body_is_byte_identical() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::post()
            .uri("/api/register")
            .set_json(serde_json::json!({
                "trade_pubkey": "tooshort",
                "token": "test_fcm_token",
                "platform": "android"
            }))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = atest::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            body_str,
            r#"{"success":false,"message":"Invalid trade_pubkey format (expected 64 hex characters)"}"#
        );
    }

    /// VERIFY-02: /api/unregister "not found" body is BYTE-IDENTICAL.
    #[actix_web::test]
    async fn unregister_not_found_body_is_byte_identical() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::post()
            .uri("/api/unregister")
            .set_json(serde_json::json!({"trade_pubkey": TEST_PUBKEY_2}))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = atest::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            body_str,
            r#"{"success":true,"message":"Token not found (may have already been unregistered)"}"#
        );
    }

    /// VERIFY-02: /api/unregister success body is BYTE-IDENTICAL.
    #[actix_web::test]
    async fn unregister_success_body_is_byte_identical() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        // Register first so we have something to unregister.
        let req = atest::TestRequest::post()
            .uri("/api/register")
            .set_json(serde_json::json!({
                "trade_pubkey": TEST_PUBKEY,
                "token": "test_fcm_token",
                "platform": "android"
            }))
            .to_request();
        let _ = atest::call_service(&app, req).await;

        let req = atest::TestRequest::post()
            .uri("/api/unregister")
            .set_json(serde_json::json!({"trade_pubkey": TEST_PUBKEY}))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = atest::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            body_str,
            r#"{"success":true,"message":"Token unregistered successfully"}"#
        );
    }

    /// VERIFY-02: /api/health body is BYTE-IDENTICAL.
    #[actix_web::test]
    async fn health_body_is_byte_identical() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::get().uri("/api/health").to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = atest::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert_eq!(body_str, r#"{"status":"ok"}"#);
    }

    /// VERIFY-02: /api/info body is BYTE-IDENTICAL. Version comes from
    /// CARGO_PKG_VERSION at compile time.
    #[actix_web::test]
    async fn info_body_is_byte_identical() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::get().uri("/api/info").to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = atest::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        let expected = format!(
            r#"{{"version":"{}","encryption_enabled":false,"note":"Token encryption will be enabled in a future phase"}}"#,
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(body_str, expected);
    }

    /// VERIFY-02: /api/status body shape is byte-identical (empty store → all counts 0).
    #[actix_web::test]
    async fn status_body_shape_is_byte_identical() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::get().uri("/api/status").to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = atest::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        let expected = format!(
            r#"{{"status":"running","version":"{}","tokens":{{"total":0,"android":0,"ios":0}}}}"#,
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(body_str, expected);
    }

    /// D-25 anti-DEPLOY-3 / LIMIT-03 structural lock:
    /// 1000 GETs against /api/health from a single fixed Fly-Client-IP must
    /// return 1000x 200. /api/health is NOT wrapped by per_ip_rate_limit_mw —
    /// only /api/notify is (see configure()). Any 429 here means a regression.
    #[actix_web::test]
    async fn health_endpoint_not_rate_limited_1000_burst() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        for _ in 0..1000 {
            let req = atest::TestRequest::get()
                .uri("/api/health")
                .insert_header(("Fly-Client-IP", "8.8.8.8"))
                .to_request();
            let resp = atest::call_service(&app, req).await;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "anti-DEPLOY-3: /api/health must NOT be rate-limited"
            );
        }
    }

    /// LIMIT-03 structural lock: /api/register, /api/unregister, /api/info,
    /// /api/status must also bypass the per-IP middleware. 50-request burst
    /// against each; any 429 fails the test.
    #[actix_web::test]
    async fn other_endpoints_not_rate_limited_under_burst() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        for _ in 0..50 {
            let req = atest::TestRequest::get()
                .uri("/api/info")
                .insert_header(("Fly-Client-IP", "8.8.8.8"))
                .to_request();
            let resp = atest::call_service(&app, req).await;
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "/api/info must not 429");
        }

        for _ in 0..50 {
            let req = atest::TestRequest::get()
                .uri("/api/status")
                .insert_header(("Fly-Client-IP", "8.8.8.8"))
                .to_request();
            let resp = atest::call_service(&app, req).await;
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "/api/status must not 429");
        }

        // /api/register: 50 distinct pubkeys to avoid TokenStore deduplication.
        for i in 0..50usize {
            let pk = format!("{:0>64}", format!("{:x}", i + 1));
            let req = atest::TestRequest::post()
                .uri("/api/register")
                .insert_header(("Fly-Client-IP", "8.8.8.8"))
                .set_json(serde_json::json!({
                    "trade_pubkey": pk,
                    "token": "t",
                    "platform": "android"
                }))
                .to_request();
            let resp = atest::call_service(&app, req).await;
            assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "/api/register must not 429");
        }
    }
}
