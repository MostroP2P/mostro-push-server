use actix_web::{web, App, HttpServer};
use log::info;
use rand::RngCore;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

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
use push::{FcmPush, PushDispatcher, PushService, UnifiedPushService};
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

    // PRIV-01 / SC #5: shared log salt for privacy-safe pubkey correlators
    // across all modules (notify, register/unregister, store, listener).
    // Random per process, in-memory only, never persisted, never logged.
    // Salt regeneration on every restart is the explicit privacy property.
    let mut salt_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let notify_log_salt: Arc<[u8; 32]> = Arc::new(salt_bytes);

    // Initialize token store
    let token_store = Arc::new(TokenStore::new(
        config.store.token_ttl_hours,
        notify_log_salt.clone(),
    ));

    // Start cleanup task
    store::start_cleanup_task(token_store.clone(), config.store.cleanup_interval_hours);
    info!("Token store initialized (TTL: {}h, cleanup interval: {}h)",
        config.store.token_ttl_hours,
        config.store.cleanup_interval_hours
    );

    // Single shared reqwest::Client with explicit timeouts. Bounds outbound
    // FCM/UnifiedPush calls so a hung remote endpoint cannot tie up tokio
    // worker threads under sustained load. Per Phase 2 D-07.
    let http_client = Arc::new(
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .build()
            .expect("reqwest::Client build never fails on default config"),
    );

    // Initialize push services
    let mut push_services: Vec<(Arc<dyn PushService>, &'static str)> = Vec::new();

    // Keep UnifiedPush service separate for endpoint management
    let unifiedpush_service = Arc::new(UnifiedPushService::new(config.clone(), Arc::clone(&http_client)));

    // Load existing endpoints from disk
    if let Err(e) = unifiedpush_service.load_endpoints().await {
        log::error!("Failed to load UnifiedPush endpoints: {}", e);
    }

    // Initialize FCM service if enabled
    if config.push.fcm_enabled {
        info!("Initializing FCM push service");
        let fcm_service = Arc::new(FcmPush::new(config.clone(), Arc::clone(&http_client)));

        // Try to initialize FCM authentication (optional - may fail if no credentials)
        match fcm_service.init().await {
            Ok(_) => {
                info!("FCM service initialized successfully");
                push_services.push((Arc::clone(&fcm_service) as Arc<dyn PushService>, "fcm"));
            }
            Err(e) => {
                log::warn!("Failed to initialize FCM service: {}", e);
                log::warn!("FCM notifications will be disabled. Set FIREBASE_SERVICE_ACCOUNT_PATH to enable.");
            }
        }
    }

    if config.push.unifiedpush_enabled {
        info!("Initializing UnifiedPush service");
        push_services.push((Arc::clone(&unifiedpush_service) as Arc<dyn PushService>, "unifiedpush"));
    }

    let dispatcher = Arc::new(PushDispatcher::new(push_services));

    // D-09 + D-03: bound the /api/notify spawn pile to 50 in-flight tasks.
    // On saturation, the handler silently drops (warn! log without pubkey).
    let notify_semaphore: Arc<Semaphore> = Arc::new(Semaphore::new(50));

    // Start Nostr listener in background
    let nostr_listener = NostrListener::new(
        config.clone(),
        dispatcher.clone(),
        token_store.clone(),
        notify_log_salt.clone(),
    ).expect("Failed to initialize Nostr listener - check MOSTRO_PUBKEY");

    tokio::spawn(async move {
        nostr_listener.start().await;
    });

    // Create app state for HTTP handlers
    let app_state = AppState {
        token_store: token_store.clone(),
        dispatcher: dispatcher.clone(),
        semaphore: notify_semaphore.clone(),
        notify_log_salt: notify_log_salt.clone(),
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
    info!("  POST /api/notify     - Trigger silent push (best-effort)");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .configure(api::routes::configure)
    })
    .bind(server_addr)?
    .run()
    .await
}
