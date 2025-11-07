use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use log::info;

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
) -> impl Responder {
    info!("Registering endpoint for device: {}", req.device_id);
    // TODO: Store endpoint in push service
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Endpoint registered"
    }))
}

async fn unregister_endpoint(
    req: web::Json<RegisterEndpointRequest>,
) -> impl Responder {
    info!("Unregistering endpoint for device: {}", req.device_id);
    // TODO: Remove endpoint from push service
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Endpoint unregistered"
    }))
}

async fn send_test_notification() -> impl Responder {
    info!("Sending test notification");
    // TODO: Trigger test notification
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": "Test notification sent"
    }))
}
