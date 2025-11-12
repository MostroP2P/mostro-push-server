use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use log::{info, error};
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::push::{PushService, UnifiedPushService};

#[derive(Deserialize)]
pub struct RegisterEndpointRequest {
    pub device_id: String,
    pub endpoint_url: String,
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub status: String,
    pub version: String,
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api")
            .route("/health", web::get().to(health_check))
            .route("/status", web::get().to(status))
            .route("/register", web::post().to(register_endpoint))
            .route("/unregister", web::post().to(unregister_endpoint))
            .route("/test", web::post().to(send_test_notification))
    );
}

async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

async fn status() -> impl Responder {
    HttpResponse::Ok().json(StatusResponse {
        status: "running".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn register_endpoint(
    req: web::Json<RegisterEndpointRequest>,
    unifiedpush: web::Data<Arc<UnifiedPushService>>,
) -> impl Responder {
    info!("Registering endpoint for device: {}", req.device_id);

    match unifiedpush.register_endpoint(
        req.device_id.clone(),
        req.endpoint_url.clone(),
    ).await {
        Ok(_) => {
            info!("Successfully registered endpoint for device: {}", req.device_id);
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Endpoint registered successfully"
            }))
        }
        Err(e) => {
            error!("Failed to register endpoint: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to register endpoint: {}", e)
            }))
        }
    }
}

async fn unregister_endpoint(
    req: web::Json<RegisterEndpointRequest>,
    unifiedpush: web::Data<Arc<UnifiedPushService>>,
) -> impl Responder {
    info!("Unregistering endpoint for device: {}", req.device_id);

    match unifiedpush.unregister_endpoint(&req.device_id).await {
        Ok(_) => {
            info!("Successfully unregistered endpoint for device: {}", req.device_id);
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "Endpoint unregistered successfully"
            }))
        }
        Err(e) => {
            error!("Failed to unregister endpoint: {}", e);
            HttpResponse::InternalServerError().json(serde_json::json!({
                "success": false,
                "error": format!("Failed to unregister endpoint: {}", e)
            }))
        }
    }
}

async fn send_test_notification(
    push_services: web::Data<Arc<Mutex<Vec<Box<dyn PushService>>>>>,
) -> impl Responder {
    info!("Sending test notification through all push services");

    let services = push_services.lock().await;
    let mut success_count = 0;
    let mut error_count = 0;

    for service in services.iter() {
        match service.send_silent_push().await {
            Ok(_) => {
                success_count += 1;
            }
            Err(e) => {
                error!("Failed to send test notification: {}", e);
                error_count += 1;
            }
        }
    }

    if error_count == 0 {
        HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "message": format!("Test notification sent through {} service(s)", success_count)
        }))
    } else {
        HttpResponse::InternalServerError().json(serde_json::json!({
            "success": false,
            "message": format!("{} succeeded, {} failed", success_count, error_count)
        }))
    }
}
