use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use log::{info, warn};
use std::sync::Arc;

use crate::store::{TokenStore, TokenStoreStats, Platform};

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
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/health", web::get().to(health_check))
            .route("/status", web::get().to(status))
            .route("/register", web::post().to(register_token))
            .route("/unregister", web::post().to(unregister_token))
            .route("/info", web::get().to(server_info))
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
    info!("Registering token for trade_pubkey: {}...",
        &req.trade_pubkey[..16.min(req.trade_pubkey.len())]);

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
        "Successfully registered {} token for trade_pubkey: {}...",
        platform,
        &req.trade_pubkey[..16]
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
    info!("Unregistering token for trade_pubkey: {}...",
        &req.trade_pubkey[..16.min(req.trade_pubkey.len())]);

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
