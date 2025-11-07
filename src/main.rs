use actix_web::{web, App, HttpServer};
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;

mod config;
mod nostr;
mod push;
mod api;
mod utils;

use config::Config;
use nostr::NostrListener;
use push::{PushService, FcmPush, UnifiedPushService};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    dotenv::dotenv().ok();

    info!("Starting Mostro Push Backend...");

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");

    // Initialize push services
    let mut push_services: Vec<Box<dyn PushService>> = Vec::new();

    if config.push.fcm_enabled {
        info!("Initializing FCM push service");
        push_services.push(Box::new(FcmPush::new(config.clone())));
    }

    if config.push.unifiedpush_enabled {
        info!("Initializing UnifiedPush service");
        push_services.push(Box::new(UnifiedPushService::new(config.clone())));
    }

    let push_services = Arc::new(Mutex::new(push_services));

    // Start Nostr listener in background
    let nostr_listener = NostrListener::new(config.clone(), push_services.clone());
    tokio::spawn(async move {
        nostr_listener.start().await;
    });

    // Start HTTP API server
    let server_addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Starting HTTP server on {}", server_addr);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(push_services.clone()))
            .configure(api::routes::configure)
    })
    .bind(server_addr)?
    .run()
    .await
}
