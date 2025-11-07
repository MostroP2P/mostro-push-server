# Backend Rust para UnifiedPush - Mostro Mobile

Este documento describe la implementación de un backend independiente en Rust para soportar notificaciones push a través de UnifiedPush, compatible con usuarios de GrapheneOS y otros sistemas sin Google Play Services.

## Overview

El backend escucha eventos kind 1059 en Nostr relays y envía notificaciones push a través de:
1. **Firebase Cloud Messaging (FCM)** - Para dispositivos con Google Play Services
2. **UnifiedPush** - Para dispositivos sin Google Play Services (GrapheneOS, LineageOS, etc.)

## Arquitectura

```
┌─────────────────┐
│  Nostr Relays   │
│ (kind 1059)     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Rust Backend   │
│  - WebSocket    │
│  - Event batch  │
│  - HTTP API     │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
┌─────┐   ┌──────────┐
│ FCM │   │UnifiedPush│
└──┬──┘   └────┬─────┘
   │           │
   ▼           ▼
[Android]   [GrapheneOS]
```

## Dependencias (Cargo.toml)

```toml
[package]
name = "mostro-push-backend"
version = "0.1.0"
edition = "2021"

[dependencies]
# Web framework
actix-web = "4.4"
actix-rt = "2.9"

# WebSocket client for Nostr
tokio-tungstenite = "0.21"
tokio = { version = "1.35", features = ["full"] }

# JSON handling
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"

# HTTP client for FCM and UnifiedPush
reqwest = { version = "0.11", features = ["json"] }

# Nostr
nostr-sdk = "0.27"

# Logging
env_logger = "0.11"
log = "0.4"

# Configuration
config = "0.14"
dotenv = "0.15"

# Async utilities
futures = "0.3"
async-trait = "0.1"

# Time handling
chrono = "0.4"

# Rate limiting
governor = "0.6"

[dev-dependencies]
mockito = "1.2"
```

## Estructura del Proyecto

```
mostro-push-backend/
├── Cargo.toml
├── .env.example
├── config.toml
├── src/
│   ├── main.rs
│   ├── config.rs
│   ├── nostr/
│   │   ├── mod.rs
│   │   ├── listener.rs
│   │   └── event.rs
│   ├── push/
│   │   ├── mod.rs
│   │   ├── fcm.rs
│   │   └── unifiedpush.rs
│   ├── api/
│   │   ├── mod.rs
│   │   └── routes.rs
│   └── utils/
│       ├── mod.rs
│       ├── batching.rs
│       └── rate_limit.rs
├── tests/
│   ├── integration_test.rs
│   └── mock_relay.rs
└── README.md
```

## Configuración (.env.example)

```bash
# Nostr Configuration
NOSTR_RELAYS=wss://relay.mostro.network

# Firebase Configuration (optional, for FCM support)
FIREBASE_PROJECT_ID=mostro-test
FIREBASE_SERVICE_ACCOUNT_PATH=/path/to/service-account.json

# UnifiedPush Configuration
UNIFIEDPUSH_ENABLED=true

# Server Configuration
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Rate Limiting
RATE_LIMIT_PER_MINUTE=60
BATCH_DELAY_SECONDS=5
COOLDOWN_SECONDS=60

# Logging
RUST_LOG=info
```

## config.toml

```toml
[nostr]
relays = ["wss://relay.mostro.network"]
subscription_id = "mostro-push-listener"
event_kinds = [1059]

[push]
fcm_enabled = true
unifiedpush_enabled = true
batch_delay_ms = 5000
cooldown_ms = 60000

[server]
host = "0.0.0.0"
port = 8080

[rate_limit]
max_per_minute = 60
```

## Implementación Principal

### src/main.rs

```rust
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
```

### src/config.rs

```rust
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub nostr: NostrConfig,
    pub push: PushConfig,
    pub server: ServerConfig,
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NostrConfig {
    pub relays: Vec<String>,
    pub subscription_id: String,
    pub event_kinds: Vec<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PushConfig {
    pub fcm_enabled: bool,
    pub unifiedpush_enabled: bool,
    pub batch_delay_ms: u64,
    pub cooldown_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub max_per_minute: u32,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let relays = env::var("NOSTR_RELAYS")?
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Ok(Config {
            nostr: NostrConfig {
                relays,
                subscription_id: "mostro-push-listener".to_string(),
                event_kinds: vec![1059],
            },
            push: PushConfig {
                fcm_enabled: env::var("FCM_ENABLED")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
                unifiedpush_enabled: env::var("UNIFIEDPUSH_ENABLED")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
                batch_delay_ms: env::var("BATCH_DELAY_MS")
                    .unwrap_or_else(|_| "5000".to_string())
                    .parse()?,
                cooldown_ms: env::var("COOLDOWN_MS")
                    .unwrap_or_else(|_| "60000".to_string())
                    .parse()?,
            },
            server: ServerConfig {
                host: env::var("SERVER_HOST")
                    .unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()?,
            },
            rate_limit: RateLimitConfig {
                max_per_minute: env::var("RATE_LIMIT_PER_MINUTE")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()?,
            },
        })
    }
}
```

### src/nostr/listener.rs

```rust
use log::{info, error, warn};
use nostr_sdk::prelude::*;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

use crate::config::Config;
use crate::push::PushService;
use crate::utils::batching::BatchingManager;

pub struct NostrListener {
    config: Config,
    push_services: Arc<Mutex<Vec<Box<dyn PushService>>>>,
    batching_manager: Arc<Mutex<BatchingManager>>,
}

impl NostrListener {
    pub fn new(
        config: Config,
        push_services: Arc<Mutex<Vec<Box<dyn PushService>>>>,
    ) -> Self {
        let batching_manager = Arc::new(Mutex::new(
            BatchingManager::new(config.push.batch_delay_ms)
        ));

        Self {
            config,
            push_services,
            batching_manager,
        }
    }

    pub async fn start(&self) {
        loop {
            match self.connect_and_listen().await {
                Ok(_) => {
                    warn!("Nostr connection closed, reconnecting in 5 seconds...");
                }
                Err(e) => {
                    error!("Error in Nostr listener: {}, reconnecting in 10 seconds...", e);
                    sleep(Duration::from_secs(10)).await;
                }
            }
            sleep(Duration::from_secs(5)).await;
        }
    }

    async fn connect_and_listen(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Connecting to Nostr relays...");

        // Create Nostr client
        let keys = Keys::generate();
        let client = Client::new(&keys);

        // Add relays
        for relay_url in &self.config.nostr.relays {
            client.add_relay(relay_url).await?;
            info!("Added relay: {}", relay_url);
        }

        // Connect to all relays
        client.connect().await;

        // Create filter for kind 1059 events (last 5 minutes)
        let since = Timestamp::now() - Duration::from_secs(300);
        let filter = Filter::new()
            .kinds(vec![Kind::Custom(1059)])
            .since(since);

        // Subscribe to events
        client.subscribe(vec![filter], None).await;
        info!("Subscribed to kind 1059 events");

        // Handle incoming events
        let batching_manager = self.batching_manager.clone();
        let push_services = self.push_services.clone();

        client
            .handle_notifications(|notification| async {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::Custom(1059) {
                        info!("Received kind 1059 event: {}", event.id);

                        // Trigger batched notification
                        let mut manager = batching_manager.lock().await;
                        if manager.should_send().await {
                            drop(manager);

                            // Send notifications through all push services
                            let services = push_services.lock().await;
                            for service in services.iter() {
                                if let Err(e) = service.send_silent_push().await {
                                    error!("Failed to send push notification: {}", e);
                                }
                            }
                        }
                    }
                }
                Ok(false)
            })
            .await?;

        Ok(())
    }
}
```

### src/push/mod.rs

```rust
use async_trait::async_trait;

pub mod fcm;
pub mod unifiedpush;

pub use fcm::FcmPush;
pub use unifiedpush::UnifiedPushService;

#[async_trait]
pub trait PushService: Send + Sync {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>>;
}
```

### src/push/fcm.rs

```rust
use async_trait::async_trait;
use log::{info, error};
use reqwest::Client;
use serde_json::json;

use crate::config::Config;
use super::PushService;

pub struct FcmPush {
    config: Config,
    client: Client,
    access_token: String,
}

impl FcmPush {
    pub fn new(config: Config) -> Self {
        // TODO: Implement OAuth2 token fetching from service account
        let access_token = "".to_string(); // Get from Firebase Admin SDK

        Self {
            config,
            client: Client::new(),
            access_token,
        }
    }

    async fn get_access_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        // TODO: Implement OAuth2 token refresh using service account JSON
        // For now, return empty string
        Ok(self.access_token.clone())
    }
}

#[async_trait]
impl PushService for FcmPush {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>> {
        let token = self.get_access_token().await?;

        let fcm_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            std::env::var("FIREBASE_PROJECT_ID")?
        );

        let payload = json!({
            "message": {
                "topic": "mostro_notifications",
                "data": {
                    "type": "silent_wake",
                    "timestamp": chrono::Utc::now().timestamp().to_string()
                },
                "android": {
                    "priority": "high"
                },
                "apns": {
                    "headers": {
                        "apns-priority": "10"
                    },
                    "payload": {
                        "aps": {
                            "content-available": 1
                        }
                    }
                }
            }
        });

        let response = self.client
            .post(&fcm_url)
            .bearer_auth(&token)
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            info!("FCM notification sent successfully");
            Ok(())
        } else {
            error!("FCM error: {}", response.text().await?);
            Err("FCM send failed".into())
        }
    }
}
```

### src/push/unifiedpush.rs

```rust
use async_trait::async_trait;
use log::{info, error};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::config::Config;
use super::PushService;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedPushEndpoint {
    pub device_id: String,
    pub endpoint_url: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
}

pub struct UnifiedPushService {
    config: Config,
    client: Client,
    endpoints: RwLock<HashMap<String, UnifiedPushEndpoint>>,
}

impl UnifiedPushService {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            client: Client::new(),
            endpoints: RwLock::new(HashMap::new()),
        }
    }

    pub async fn register_endpoint(
        &self,
        device_id: String,
        endpoint_url: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let endpoint = UnifiedPushEndpoint {
            device_id: device_id.clone(),
            endpoint_url,
            registered_at: chrono::Utc::now(),
        };

        let mut endpoints = self.endpoints.write().await;
        endpoints.insert(device_id, endpoint);

        info!("Registered UnifiedPush endpoint");
        Ok(())
    }

    pub async fn unregister_endpoint(
        &self,
        device_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut endpoints = self.endpoints.write().await;
        endpoints.remove(device_id);

        info!("Unregistered UnifiedPush endpoint");
        Ok(())
    }
}

#[async_trait]
impl PushService for UnifiedPushService {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>> {
        let endpoints = self.endpoints.read().await;

        if endpoints.is_empty() {
            info!("No UnifiedPush endpoints registered");
            return Ok(());
        }

        let payload = serde_json::json!({
            "type": "silent_wake",
            "timestamp": chrono::Utc::now().timestamp()
        });

        for endpoint in endpoints.values() {
            match self.client
                .post(&endpoint.endpoint_url)
                .json(&payload)
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        info!("UnifiedPush notification sent to {}", endpoint.device_id);
                    } else {
                        error!("UnifiedPush error for {}: {}",
                            endpoint.device_id, response.status());
                    }
                }
                Err(e) => {
                    error!("Failed to send UnifiedPush to {}: {}",
                        endpoint.device_id, e);
                }
            }
        }

        Ok(())
    }
}
```

### src/utils/batching.rs

```rust
use tokio::time::{sleep, Duration, Instant};

pub struct BatchingManager {
    batch_delay_ms: u64,
    last_sent: Option<Instant>,
    pending_send: Option<tokio::task::JoinHandle<()>>,
}

impl BatchingManager {
    pub fn new(batch_delay_ms: u64) -> Self {
        Self {
            batch_delay_ms,
            last_sent: None,
            pending_send: None,
        }
    }

    pub async fn should_send(&mut self) -> bool {
        // Check if there's already a pending send
        if self.pending_send.is_some() {
            return false;
        }

        // Check cooldown
        if let Some(last_sent) = self.last_sent {
            if last_sent.elapsed().as_millis() < 60000 {
                return false;
            }
        }

        // Schedule send after batch delay
        self.last_sent = Some(Instant::now());
        true
    }
}
```

### src/api/routes.rs

```rust
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
```

## Testing

### tests/integration_test.rs

```rust
#[cfg(test)]
mod tests {
    use actix_web::{test, App};
    use mostro_push_backend::api;

    #[actix_web::test]
    async fn test_health_check() {
        let app = test::init_service(
            App::new().configure(api::routes::configure)
        ).await;

        let req = test::TestRequest::get()
            .uri("/api/health")
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }

    #[actix_web::test]
    async fn test_register_endpoint() {
        let app = test::init_service(
            App::new().configure(api::routes::configure)
        ).await;

        let req = test::TestRequest::post()
            .uri("/api/register")
            .set_json(&serde_json::json!({
                "device_id": "test-device",
                "endpoint_url": "https://push.example.com/endpoint"
            }))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success());
    }
}
```

## Deployment

### Docker

**Dockerfile:**

```dockerfile
FROM rust:1.75 as builder

WORKDIR /usr/src/app
COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/app/target/release/mostro-push-backend /usr/local/bin/

ENV RUST_LOG=info

CMD ["mostro-push-backend"]
```

**docker-compose.yml:**

```yaml
version: '3.8'

services:
  push-backend:
    build: .
    ports:
      - "8080:8080"
    environment:
      - NOSTR_RELAYS=wss://relay.mostro.network
      - SERVER_HOST=0.0.0.0
      - SERVER_PORT=8080
      - FCM_ENABLED=true
      - UNIFIEDPUSH_ENABLED=true
      - FIREBASE_PROJECT_ID=mostro-test
      - RUST_LOG=info
    volumes:
      - ./firebase-service-account.json:/app/firebase-service-account.json:ro
    restart: unless-stopped
```

### Systemd Service

**mostro-push-backend.service:**

```ini
[Unit]
Description=Mostro Push Backend
After=network.target

[Service]
Type=simple
User=mostro
WorkingDirectory=/opt/mostro-push-backend
Environment="RUST_LOG=info"
EnvironmentFile=/opt/mostro-push-backend/.env
ExecStart=/opt/mostro-push-backend/mostro-push-backend
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Manual Testing

### 1. Start the Backend

```bash
# Clone and build
git clone <repo-url>
cd mostro-push-backend

# Copy environment file
cp .env.example .env

# Edit .env with your configuration
nano .env

# Run
cargo run
```

### 2. Test Health Check

```bash
curl http://localhost:8080/api/health
# Expected: {"status":"ok"}
```

### 3. Test Status

```bash
curl http://localhost:8080/api/status
# Expected: {"status":"running","version":"0.1.0"}
```

### 4. Register UnifiedPush Endpoint

```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "device_id": "test-device-123",
    "endpoint_url": "https://push.example.com/YOUR_ENDPOINT"
  }'
# Expected: {"success":true,"message":"Endpoint registered"}
```

### 5. Send Test Notification

```bash
curl -X POST http://localhost:8080/api/test
# Expected: {"success":true,"message":"Test notification sent"}
```

### 6. Monitor Logs

```bash
# Check if connected to Nostr relay
tail -f /var/log/mostro-push-backend/app.log

# Expected logs:
# INFO Connecting to relay: wss://relay.mostro.network
# INFO Connected to wss://relay.mostro.network
# INFO Subscribed to kind 1059 events
```

### 7. Test with Real Nostr Event

Use a Nostr client to send a kind 1059 event to the relay, then check logs:

```bash
# Should see:
# INFO Received kind 1059 event: <event_id>
# INFO Notification scheduled in 5000ms
# INFO Batch delay completed - sending notification
# INFO FCM notification sent successfully
# INFO UnifiedPush notification sent to test-device-123
```

## Performance Testing

### Load Test with `wrk`

```bash
# Install wrk
sudo apt install wrk

# Test health endpoint
wrk -t4 -c100 -d30s http://localhost:8080/api/health

# Expected: ~10k+ requests/sec
```

### Simulate Multiple Events

```rust
// tests/load_test.rs
use tokio;

#[tokio::test]
async fn simulate_event_burst() {
    // Send 100 events in 1 second
    for _ in 0..100 {
        // Simulate event arrival
        // Should result in only 1 notification due to batching
    }
}
```

## Migration Path from Cloud Functions

1. **Phase 1:** Deploy Rust backend alongside Cloud Functions
2. **Phase 2:** Add UnifiedPush support to mobile app
3. **Phase 3:** Redirect GrapheneOS users to Rust backend
4. **Phase 4:** Gradually migrate all users
5. **Phase 5:** Deprecate Cloud Functions

## Monitoring

### Metrics to Track

- WebSocket connection uptime
- Events received per minute
- Notifications sent per minute
- Failed notification delivery rate
- Batch efficiency (events batched / notifications sent)

### Prometheus Integration (Optional)

Add to `Cargo.toml`:
```toml
prometheus = "0.13"
actix-web-prom = "0.7"
```

Expose metrics at `/metrics` endpoint.

## Security Considerations

1. **TLS Required:** Use Let's Encrypt for HTTPS
2. **Rate Limiting:** Already implemented with cooldown
3. **Authentication:** Consider adding API keys for endpoint registration
4. **Firewall:** Only expose port 8080
5. **Service Account:** Protect Firebase service account JSON (0600 permissions)

## Resources

- UnifiedPush Spec: https://unifiedpush.org/developers/spec/
- Nostr SDK Rust: https://docs.rs/nostr-sdk/
- Actix Web: https://actix.rs/docs/
- FCM v1 API: https://firebase.google.com/docs/cloud-messaging/migrate-v1

## TODO

- [ ] Implement OAuth2 token refresh for FCM
- [ ] Add database for persistent endpoint storage
- [ ] Implement retry logic for failed deliveries
- [ ] Add metrics and monitoring
- [ ] Implement authentication for API endpoints
- [ ] Add support for multiple Mostro instances
- [ ] Create Ansible playbook for deployment
- [ ] Add integration tests with mock Nostr relay

---

**Last Updated:** 2025-11-07
**Status:** Specification Complete - Ready for Implementation
