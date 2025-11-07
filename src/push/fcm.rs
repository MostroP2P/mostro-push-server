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
