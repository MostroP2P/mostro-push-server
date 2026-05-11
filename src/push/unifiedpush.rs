use async_trait::async_trait;
use log::{debug, error, info, warn};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::RwLock;

use super::PushService;
use crate::config::Config;
use crate::store::Platform;
use crate::utils::log_pubkey::log_pubkey;

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
    log_salt: Arc<[u8; 32]>,
}

impl UnifiedPushService {
    pub fn new(config: Config, client: Arc<reqwest::Client>) -> Self {
        let storage_path = PathBuf::from("data/unifiedpush_endpoints.json");
        let mut salt_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt_bytes);

        Self {
            config,
            client,
            endpoints: RwLock::new(HashMap::new()),
            storage_path,
            log_salt: Arc::new(salt_bytes),
        }
    }

    fn log_device_id(&self, device_id: &str) -> String {
        log_unifiedpush_identifier(self.log_salt.as_ref(), device_id)
    }

    /// Load endpoints from disk on startup
    pub async fn load_endpoints(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Create data directory if it doesn't exist
        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent).await?;
        }

        // Check if file exists
        if !self.storage_path.exists() {
            info!("No existing endpoints file found, starting fresh");
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

        info!(
            "Registered UnifiedPush endpoint device={}",
            self.log_device_id(&device_id)
        );
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
            "Unregistered UnifiedPush endpoint device={}",
            self.log_device_id(device_id)
        );
        Ok(())
    }
}

fn log_unifiedpush_identifier(salt: &[u8; 32], value: &str) -> String {
    log_pubkey(salt, value)
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

        debug!("Sending UnifiedPush notification");

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
    use super::log_unifiedpush_identifier;

    #[test]
    fn unifiedpush_log_identifier_is_stable_and_redacted() {
        let salt = [7u8; 32];
        let device_id = "device-secret-123";

        let first = log_unifiedpush_identifier(&salt, device_id);
        let second = log_unifiedpush_identifier(&salt, device_id);

        assert_eq!(first, second);
        assert_eq!(first.len(), 8);
        assert_ne!(first, device_id);
        assert!(
            !device_id.contains(&first),
            "hashed log identifier must not be a raw device_id substring"
        );
    }
}
