use async_trait::async_trait;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;

use super::PushService;
use crate::config::Config;
use crate::store::Platform;

pub const UNIFIEDPUSH_ENDPOINTS_MAX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedPushEndpoint {
    pub device_id: String,
    pub endpoint_url: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
}

pub struct UnifiedPushService {
    // Held for future settings (custom relays, retry policy) that the
    // service does not yet read.
    #[allow(dead_code)]
    config: Config,
    client: Arc<reqwest::Client>,
    endpoints: RwLock<HashMap<String, UnifiedPushEndpoint>>,
    storage_path: PathBuf,
}

impl UnifiedPushService {
    pub fn new(config: Config, client: Arc<reqwest::Client>) -> Self {
        let storage_path = PathBuf::from("data/unifiedpush_endpoints.json");

        Self {
            config,
            client,
            endpoints: RwLock::new(HashMap::new()),
            storage_path,
        }
    }

    /// Load endpoints from disk on startup
    pub async fn load_endpoints(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create data directory if it doesn't exist
        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        let metadata = match fs::metadata(&self.storage_path).await {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                info!("No existing endpoints file found, starting fresh");
                return Ok(());
            }
            Err(e) => {
                warn!("Failed to stat endpoints file: {}", e);
                return Ok(());
            }
        };

        if metadata.len() > UNIFIEDPUSH_ENDPOINTS_MAX_BYTES {
            error!(
                "UnifiedPush endpoints file too large ({} bytes > {} bytes), starting with empty store",
                metadata.len(),
                UNIFIEDPUSH_ENDPOINTS_MAX_BYTES
            );
            self.endpoints.write().await.clear();
            return Ok(());
        }

        // Read and deserialize endpoints
        match fs::read_to_string(&self.storage_path).await {
            Ok(content) => {
                let loaded_endpoints: HashMap<String, UnifiedPushEndpoint> =
                    serde_json::from_str(&content)?;

                let mut endpoints = self.endpoints.write().await;
                *endpoints = loaded_endpoints;

                info!("Loaded {} UnifiedPush endpoints from disk", endpoints.len());
                Ok(())
            }
            Err(e) => {
                warn!("Failed to load endpoints from disk: {}", e);
                Ok(())
            }
        }
    }

    /// Save endpoints to disk
    #[allow(dead_code)]
    async fn save_endpoints(&self) -> Result<(), Box<dyn std::error::Error>> {
        let endpoints = self.endpoints.read().await;
        let content = serde_json::to_string_pretty(&*endpoints)?;

        // Write to temporary file first, then rename for atomic write
        let temp_path = self.storage_path.with_extension("tmp");
        fs::write(&temp_path, content).await?;
        fs::rename(&temp_path, &self.storage_path).await?;

        Ok(())
    }

    // Reserved API: invoked once UnifiedPush registration endpoints land.
    #[allow(dead_code)]
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

        {
            let mut endpoints = self.endpoints.write().await;
            endpoints.insert(device_id.clone(), endpoint);
        }

        // Persist to disk
        self.save_endpoints().await?;

        info!("Registered UnifiedPush endpoint for device: {}", device_id);
        Ok(())
    }

    // Reserved API: invoked once UnifiedPush registration endpoints land.
    #[allow(dead_code)]
    pub async fn unregister_endpoint(
        &self,
        device_id: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        {
            let mut endpoints = self.endpoints.write().await;
            endpoints.remove(device_id);
        }

        // Persist to disk
        self.save_endpoints().await?;

        info!(
            "Unregistered UnifiedPush endpoint for device: {}",
            device_id
        );
        Ok(())
    }
}

#[async_trait]
impl PushService for UnifiedPushService {
    async fn send_to_token(
        &self,
        device_token: &str,
        _platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // For UnifiedPush, the device_token IS the endpoint URL
        let payload = serde_json::json!({
            "type": "silent_wake",
            "timestamp": chrono::Utc::now().timestamp()
        });

        debug!(
            "Sending UnifiedPush to endpoint: {}...",
            &device_token[..30.min(device_token.len())]
        );

        let response = self.client.post(device_token).json(&payload).send().await?;

        if response.status().is_success() {
            info!("UnifiedPush notification sent successfully");
            Ok(())
        } else {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            error!("UnifiedPush error: {} - {}", status, error_text);
            Err(format!("UnifiedPush send failed: {}", status).into())
        }
    }

    fn supports_platform(&self, platform: &Platform) -> bool {
        // UnifiedPush is primarily for Android (GrapheneOS, LineageOS, etc.)
        matches!(platform, Platform::Android)
    }
}

#[cfg(test)]
mod tests {
    use super::{UnifiedPushEndpoint, UnifiedPushService, UNIFIEDPUSH_ENDPOINTS_MAX_BYTES};
    use crate::config::{
        Config, CryptoConfig, NostrConfig, NotifyRateLimitConfig, PushConfig, RateLimitConfig,
        ServerConfig, StoreConfig,
    };
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn test_config() -> Config {
        Config {
            nostr: NostrConfig {
                relays: vec!["wss://relay.example.com".to_string()],
                subscription_id: "test".to_string(),
                event_kinds: vec![1059],
            },
            push: PushConfig {
                fcm_enabled: false,
                unifiedpush_enabled: true,
                batch_delay_ms: 5000,
                cooldown_ms: 60000,
            },
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            rate_limit: RateLimitConfig { max_per_minute: 60 },
            crypto: CryptoConfig {
                server_private_key: "1".repeat(64),
            },
            store: StoreConfig {
                token_ttl_hours: 48,
                cleanup_interval_hours: 1,
            },
            notify_rate_limit: NotifyRateLimitConfig {
                per_pubkey_per_min: 30,
                per_ip_per_min: 120,
                cleanup_interval_secs: 60,
                pubkey_limiter_soft_cap: 100_000,
                trust_proxy_headers: false,
            },
            trusted_whitelist_enabled: false,
        }
    }

    fn temp_storage_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mostro-push-unifiedpush-test-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn service_with_storage_path(path: PathBuf) -> UnifiedPushService {
        UnifiedPushService {
            config: test_config(),
            client: Arc::new(reqwest::Client::new()),
            endpoints: tokio::sync::RwLock::new(HashMap::new()),
            storage_path: path,
        }
    }

    #[tokio::test]
    async fn oversized_endpoint_file_starts_with_empty_store() {
        let path = temp_storage_path("oversized.json");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(100 * 1024 * 1024)
            .unwrap();

        let service = service_with_storage_path(path.clone());
        service.endpoints.write().await.insert(
            "preexisting".to_string(),
            UnifiedPushEndpoint {
                device_id: "preexisting".to_string(),
                endpoint_url: "https://push.example.com/preexisting".to_string(),
                registered_at: chrono::Utc::now(),
            },
        );
        assert!(
            service.endpoints.read().await.contains_key("preexisting"),
            "test setup must start with an in-memory endpoint"
        );

        service.load_endpoints().await.unwrap();

        assert!(
            service.endpoints.read().await.is_empty(),
            "oversized endpoint file must not be read into memory"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[tokio::test]
    async fn one_megabyte_endpoint_file_loads_normally() {
        let path = temp_storage_path("valid.json");
        let large_url = format!(
            "https://push.example.com/{}",
            "a".repeat((1024 * 1024) - 512)
        );
        let mut endpoints = HashMap::new();
        endpoints.insert(
            "device-1".to_string(),
            UnifiedPushEndpoint {
                device_id: "device-1".to_string(),
                endpoint_url: large_url.clone(),
                registered_at: chrono::Utc::now(),
            },
        );
        let content = serde_json::to_string(&endpoints).unwrap();
        assert!(content.len() > 1024 * 1024 - 1024);
        assert!(content.len() < UNIFIEDPUSH_ENDPOINTS_MAX_BYTES as usize);
        tokio::fs::write(&path, content).await.unwrap();

        let service = service_with_storage_path(path.clone());
        service.load_endpoints().await.unwrap();

        let loaded = service.endpoints.read().await;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get("device-1").unwrap().endpoint_url, large_url);
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }
}
