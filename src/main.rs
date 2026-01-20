use actix_web::{web, App, HttpServer};
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;

mod config;
mod nostr;
mod push;
mod api;
mod store;
mod utils;

// Keep crypto module for future Phase 4 implementation
#[allow(dead_code)]
mod crypto;

use api::routes::AppState;
use config::Config;
use nostr::NostrListener;
use push::{PushService, FcmPush, UnifiedPushService};
use store::TokenStore;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    dotenv::dotenv().ok();

    info!("Starting Mostro Push Backend v{}...", env!("CARGO_PKG_VERSION"));
    info!("Phase 3: Token registration without encryption");
    info!("Encryption will be enabled in Phase 4");

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");

    // Initialize token store
    let token_store = Arc::new(TokenStore::new(config.store.token_ttl_hours));

    // Start cleanup task
    store::start_cleanup_task(token_store.clone(), config.store.cleanup_interval_hours);
    info!("Token store initialized (TTL: {}h, cleanup interval: {}h)",
        config.store.token_ttl_hours,
        config.store.cleanup_interval_hours
    );

    // Initialize push services
    let mut push_services: Vec<Box<dyn PushService>> = Vec::new();

    // Keep UnifiedPush service separate for endpoint management
    let unifiedpush_service = Arc::new(UnifiedPushService::new(config.clone()));

    // Load existing endpoints from disk
    if let Err(e) = unifiedpush_service.load_endpoints().await {
        log::error!("Failed to load UnifiedPush endpoints: {}", e);
    }

    // Initialize FCM service if enabled
    if config.push.fcm_enabled {
        info!("Initializing FCM push service");
        let fcm_service = Arc::new(FcmPush::new(config.clone()));

        // Try to initialize FCM authentication (optional - may fail if no credentials)
        match fcm_service.init().await {
            Ok(_) => {
                info!("FCM service initialized successfully");
                push_services.push(Box::new(Arc::clone(&fcm_service)));
            }
            Err(e) => {
                log::warn!("Failed to initialize FCM service: {}", e);
                log::warn!("FCM notifications will be disabled. Set FIREBASE_SERVICE_ACCOUNT_PATH to enable.");
            }
        }
    }

    if config.push.unifiedpush_enabled {
        info!("Initializing UnifiedPush service");
        push_services.push(Box::new(Arc::clone(&unifiedpush_service)));
    }

    let push_services = Arc::new(Mutex::new(push_services));

    // Start Nostr listener in background
    let nostr_listener = NostrListener::new(
        config.clone(),
        push_services.clone(),
        token_store.clone(),
    ).expect("Failed to initialize Nostr listener - check MOSTRO_PUBKEY");

    tokio::spawn(async move {
        nostr_listener.start().await;
    });

    // Create app state for HTTP handlers
    let app_state = AppState {
        token_store: token_store.clone(),
    };

    // Start HTTP API server
    let server_addr = format!("{}:{}", config.server.host, config.server.port);
    info!("Starting HTTP server on {}", server_addr);
    info!("API endpoints:");
    info!("  GET  /api/health     - Health check");
    info!("  GET  /api/status     - Server status with token stats");
    info!("  GET  /api/info       - Server info");
    info!("  POST /api/register   - Register token (plaintext)");
    info!("  POST /api/unregister - Unregister token");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .configure(api::routes::configure)
    })
    .bind(server_addr)?
    .run()
    .await
}
