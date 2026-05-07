use actix_web::middleware::from_fn;
use actix_web::{web, HttpResponse, Responder};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::api::notify::{notify_token, request_id_mw};
use crate::api::rate_limit::{per_ip_rate_limit_mw, PerPubkeyLimiter};
use crate::push::PushDispatcher;
use crate::store::{Platform, TokenStore, TokenStoreStats};
use crate::utils::log_pubkey::log_pubkey;

/// Request for registering a plaintext token (Phase 3 - unencrypted).
///
/// `mostro_pubkey` is the hex pubkey (64 chars) of the Mostro instance the
/// client is using. It is optional on the wire to keep the JSON shape
/// backward-compatible, but it is REQUIRED in practice when the trusted
/// Mostro pubkey whitelist is non-empty (see `AppState::trusted_mostro_pubkeys`).
/// When the whitelist is empty the field is ignored.
#[derive(Deserialize)]
pub struct RegisterTokenRequest {
    pub trade_pubkey: String,
    pub token: String,
    pub platform: String,
    #[serde(default)]
    pub mostro_pubkey: Option<String>,
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
    /// Whitelist of trusted Mostro instance pubkeys (hex, 64 chars), kept
    /// in lowercase by `trusted_pubkeys::load`.
    pub trusted_mostro_pubkeys: Arc<HashSet<String>>,
    /// Runtime feature flag from `TRUSTED_WHITELIST_ENABLED`. The filter on
    /// `/api/register` only activates when this is `true` AND
    /// `trusted_mostro_pubkeys` is non-empty. With the flag off (the
    /// default), `mostro_pubkey` is ignored even if the embedded JSON has
    /// entries, which keeps rollout staged with the mobile client.
    pub trusted_whitelist_enabled: bool,
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

async fn status(state: web::Data<AppState>) -> impl Responder {
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
                message: format!(
                    "Invalid platform '{}' (expected 'android' or 'ios')",
                    req.platform
                ),
                platform: None,
            });
        }
    };

    // Trusted Mostro instance whitelist filter.
    //
    // Activation requires BOTH the runtime feature flag
    // (`TRUSTED_WHITELIST_ENABLED`, default false) AND a non-empty embedded
    // whitelist. Either side off => permissive mode and `mostro_pubkey` is
    // ignored. The flag is what allows the JSON to be shipped populated
    // while keeping the new 403 path off until the mobile client supports
    // sending the field.
    //
    // Honor-system filter: there is no cryptographic proof that the device
    // actually uses the declared instance. This will be hardened in a
    // future phase when registration carries a daemon-issued signature.
    //
    // 403 messages distinguish two cases so the mobile client can tell
    // "you didn't send the field" from "the value you sent isn't on the
    // list" without parsing logs:
    //   - missing field    -> "Mostro instance pubkey required"
    //   - untrusted value  -> "Mostro instance not trusted"
    if state.trusted_whitelist_enabled && !state.trusted_mostro_pubkeys.is_empty() {
        match req.mostro_pubkey.as_deref() {
            None => {
                warn!("Register denied: mostro_pubkey missing while whitelist active");
                return HttpResponse::Forbidden().json(RegisterResponse {
                    success: false,
                    message: "Mostro instance pubkey required".to_string(),
                    platform: None,
                });
            }
            Some(mostro_pk) => {
                if mostro_pk.len() != 64 || hex::decode(mostro_pk).is_err() {
                    warn!("Invalid mostro_pubkey format");
                    return HttpResponse::BadRequest().json(RegisterResponse {
                        success: false,
                        message: "Invalid mostro_pubkey format (expected 64 hex characters)"
                            .to_string(),
                        platform: None,
                    });
                }
                // Canonicalize at the HTTP boundary: hex::decode accepts mixed
                // case but HashSet::contains is byte-exact, so an uppercase but
                // otherwise valid pubkey would falsely 403. trusted_pubkeys::load
                // also lowercases on the whitelist side; normalize here so the
                // invariant holds in both directions.
                if !state
                    .trusted_mostro_pubkeys
                    .contains(&mostro_pk.to_ascii_lowercase())
                {
                    warn!("Register denied: untrusted Mostro instance");
                    return HttpResponse::Forbidden().json(RegisterResponse {
                        success: false,
                        message: "Mostro instance not trusted".to_string(),
                        platform: None,
                    });
                }
            }
        }
    }

    // Store the token directly (no decryption in Phase 3)
    state
        .token_store
        .register(
            req.trade_pubkey.clone(),
            req.token.clone(),
            platform.clone(),
        )
        .await;

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
    use crate::api::test_support::{
        build_test_actix_app, make_app_state_with_whitelist, make_test_components,
        make_test_components_with_trusted_whitelist, make_test_components_with_whitelist_disabled,
        StubPushService, TestAppComponents, TEST_PUBKEY, TEST_PUBKEY_2, TRUSTED_MOSTRO_PUBKEY,
        UNTRUSTED_MOSTRO_PUBKEY,
    };
    use crate::store::Platform;
    use actix_web::{http::StatusCode, test as atest};

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
            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "/api/info must not 429"
            );
        }

        for _ in 0..50 {
            let req = atest::TestRequest::get()
                .uri("/api/status")
                .insert_header(("Fly-Client-IP", "8.8.8.8"))
                .to_request();
            let resp = atest::call_service(&app, req).await;
            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "/api/status must not 429"
            );
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
            assert_ne!(
                resp.status(),
                StatusCode::TOO_MANY_REQUESTS,
                "/api/register must not 429"
            );
        }
    }

    /// Whitelist active, declared mostro_pubkey is in the list -> 200.
    #[actix_web::test]
    async fn register_with_trusted_mostro_pubkey_succeeds() {
        let c = make_test_components_with_trusted_whitelist();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::post()
            .uri("/api/register")
            .set_json(serde_json::json!({
                "trade_pubkey": TEST_PUBKEY,
                "token": "test_fcm_token",
                "platform": "android",
                "mostro_pubkey": TRUSTED_MOSTRO_PUBKEY
            }))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = atest::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            body_str,
            r#"{"success":true,"message":"Token registered successfully","platform":"android"}"#
        );
    }

    /// PR #23 review regression: an uppercase pubkey that lowercases to a
    /// trusted entry must succeed. `hex::decode` accepts mixed case at the
    /// 400 gate, and the handler must canonicalize to lowercase before the
    /// 403 whitelist check so it agrees with `trusted_pubkeys::load`, which
    /// stores entries in lowercase.
    #[actix_web::test]
    async fn register_with_uppercase_trusted_mostro_pubkey_succeeds() {
        let c = make_test_components_with_trusted_whitelist();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let uppercase = TRUSTED_MOSTRO_PUBKEY.to_ascii_uppercase();
        assert_ne!(
            uppercase, TRUSTED_MOSTRO_PUBKEY,
            "fixture must contain at least one hex letter for this test to be meaningful"
        );

        let req = atest::TestRequest::post()
            .uri("/api/register")
            .set_json(serde_json::json!({
                "trade_pubkey": TEST_PUBKEY,
                "token": "test_fcm_token",
                "platform": "android",
                "mostro_pubkey": uppercase
            }))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Whitelist active, declared mostro_pubkey NOT in the list -> 403.
    #[actix_web::test]
    async fn register_with_untrusted_mostro_pubkey_returns_403() {
        let c = make_test_components_with_trusted_whitelist();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::post()
            .uri("/api/register")
            .set_json(serde_json::json!({
                "trade_pubkey": TEST_PUBKEY,
                "token": "test_fcm_token",
                "platform": "android",
                "mostro_pubkey": UNTRUSTED_MOSTRO_PUBKEY
            }))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = atest::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            body_str,
            r#"{"success":false,"message":"Mostro instance not trusted"}"#
        );
    }

    /// Whitelist active, mostro_pubkey field omitted -> 403 with the
    /// distinct "required" message (vs. "not trusted" for unknown values).
    /// Splitting the messages lets the mobile client tell apart "you didn't
    /// send the field" from "the value you sent isn't whitelisted" without
    /// parsing logs.
    #[actix_web::test]
    async fn register_without_mostro_pubkey_when_flag_enabled_returns_403_with_required_message() {
        let c = make_test_components_with_trusted_whitelist();
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
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body = atest::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            body_str,
            r#"{"success":false,"message":"Mostro instance pubkey required"}"#
        );
    }

    /// Whitelist active, mostro_pubkey malformed -> 400 (distinct from 403).
    #[actix_web::test]
    async fn register_with_malformed_mostro_pubkey_returns_400() {
        let c = make_test_components_with_trusted_whitelist();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::post()
            .uri("/api/register")
            .set_json(serde_json::json!({
                "trade_pubkey": TEST_PUBKEY,
                "token": "test_fcm_token",
                "platform": "android",
                "mostro_pubkey": "tooshort"
            }))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = atest::read_body(resp).await;
        let body_str = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            body_str,
            r#"{"success":false,"message":"Invalid mostro_pubkey format (expected 64 hex characters)"}"#
        );
    }

    /// Whitelist empty (default), mostro_pubkey field absent -> 200. Confirms
    /// permissive mode does not require the new field. Distinct from
    /// register_success_body_is_byte_identical: that test guards the response
    /// fixture; this one guards the whitelist-disabled control flow.
    #[actix_web::test]
    async fn register_without_mostro_pubkey_when_whitelist_empty_succeeds() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::post()
            .uri("/api/register")
            .set_json(serde_json::json!({
                "trade_pubkey": TEST_PUBKEY_2,
                "token": "test_fcm_token",
                "platform": "android"
            }))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Rollout-safety regression: even with a populated whitelist, when the
    /// runtime feature flag (`TRUSTED_WHITELIST_ENABLED`) is OFF the filter
    /// must NOT reject a client that sends an untrusted `mostro_pubkey`. The
    /// field is ignored end-to-end. This is what allows the binary to ship
    /// with the JSON populated before the mobile client knows how to send
    /// the field.
    #[actix_web::test]
    async fn register_with_trusted_pubkey_but_flag_disabled_ignores_field() {
        let c = make_test_components_with_whitelist_disabled();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::post()
            .uri("/api/register")
            .set_json(serde_json::json!({
                "trade_pubkey": TEST_PUBKEY,
                "token": "test_fcm_token",
                "platform": "android",
                "mostro_pubkey": UNTRUSTED_MOSTRO_PUBKEY
            }))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "filter must be inert when TRUSTED_WHITELIST_ENABLED is false"
        );
    }

    /// Same as above but with the field absent. Permissive when the flag is
    /// off, even if the embedded list has entries.
    #[actix_web::test]
    async fn register_without_mostro_pubkey_when_flag_disabled_succeeds() {
        let c = make_test_components_with_whitelist_disabled();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let req = atest::TestRequest::post()
            .uri("/api/register")
            .set_json(serde_json::json!({
                "trade_pubkey": TEST_PUBKEY_2,
                "token": "test_fcm_token",
                "platform": "android"
            }))
            .to_request();
        let resp = atest::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Activation-matrix coverage. The filter must reject ONLY in the
    /// (flag=true, list=non-empty) cell and only when the field is missing
    /// or untrusted; every other combination must succeed. Encodes the
    /// activation rule directly: filter ⇔ flag ∧ list ∧ (missing ∨ untrusted).
    #[actix_web::test]
    async fn whitelist_activation_matrix() {
        struct Case {
            label: &'static str,
            flag_enabled: bool,
            whitelist_populated: bool,
            field: Option<&'static str>, // None => omit, Some => send
            expected: StatusCode,
        }

        // Distinct trade pubkeys per case so the in-memory store doesn't
        // dedupe registrations and confuse a later case.
        let cases = [
            Case {
                label: "flag=off, list=empty, no field",
                flag_enabled: false,
                whitelist_populated: false,
                field: None,
                expected: StatusCode::OK,
            },
            Case {
                label: "flag=off, list=non-empty, no field",
                flag_enabled: false,
                whitelist_populated: true,
                field: None,
                expected: StatusCode::OK,
            },
            Case {
                label: "flag=on, list=empty, no field",
                flag_enabled: true,
                whitelist_populated: false,
                field: None,
                expected: StatusCode::OK,
            },
            Case {
                label: "flag=on, list=non-empty, trusted field",
                flag_enabled: true,
                whitelist_populated: true,
                field: Some(TRUSTED_MOSTRO_PUBKEY),
                expected: StatusCode::OK,
            },
            Case {
                label: "flag=on, list=non-empty, untrusted field",
                flag_enabled: true,
                whitelist_populated: true,
                field: Some(UNTRUSTED_MOSTRO_PUBKEY),
                expected: StatusCode::FORBIDDEN,
            },
            Case {
                label: "flag=on, list=non-empty, missing field",
                flag_enabled: true,
                whitelist_populated: true,
                field: None,
                expected: StatusCode::FORBIDDEN,
            },
        ];

        for (i, case) in cases.iter().enumerate() {
            let stub = std::sync::Arc::new(StubPushService::new(vec![Platform::Android]));
            let mut whitelist = std::collections::HashSet::new();
            if case.whitelist_populated {
                whitelist.insert(TRUSTED_MOSTRO_PUBKEY.to_string());
            }
            let (state, per_ip_limiter) = make_app_state_with_whitelist(
                stub.clone(),
                std::sync::Arc::new(whitelist),
                case.flag_enabled,
            );
            let components = TestAppComponents {
                state,
                per_ip_limiter,
                stub,
            };
            let app = atest::init_service(build_test_actix_app(components)).await;

            let trade_pk = format!("{:0>64x}", i + 100);
            let mut body = serde_json::json!({
                "trade_pubkey": trade_pk,
                "token": "test_fcm_token",
                "platform": "android",
            });
            if let Some(pk) = case.field {
                body["mostro_pubkey"] = serde_json::Value::String(pk.to_string());
            }
            let req = atest::TestRequest::post()
                .uri("/api/register")
                .set_json(&body)
                .to_request();
            let resp = atest::call_service(&app, req).await;
            assert_eq!(
                resp.status(),
                case.expected,
                "matrix case {} ({}) expected {} got {}",
                i,
                case.label,
                case.expected,
                resp.status()
            );
        }
    }
}
