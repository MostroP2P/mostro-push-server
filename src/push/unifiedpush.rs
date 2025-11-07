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
