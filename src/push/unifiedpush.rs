use async_trait::async_trait;
use log::{info, error, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::sync::RwLock;
use tokio::fs;

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
    storage_path: PathBuf,
}

impl UnifiedPushService {
    pub fn new(config: Config) -> Self {
        let storage_path = PathBuf::from("data/unifiedpush_endpoints.json");

        Self {
            config,
            client: Client::new(),
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
    async fn save_endpoints(&self) -> Result<(), Box<dyn std::error::Error>> {
        let endpoints = self.endpoints.read().await;
        let content = serde_json::to_string_pretty(&*endpoints)?;

        // Write to temporary file first, then rename for atomic write
        let temp_path = self.storage_path.with_extension("tmp");
        fs::write(&temp_path, content).await?;
        fs::rename(&temp_path, &self.storage_path).await?;

        Ok(())
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

        {
            let mut endpoints = self.endpoints.write().await;
            endpoints.insert(device_id.clone(), endpoint);
        }

        // Persist to disk
        self.save_endpoints().await?;

        info!("Registered UnifiedPush endpoint for device: {}", device_id);
        Ok(())
    }

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

        info!("Unregistered UnifiedPush endpoint for device: {}", device_id);
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
