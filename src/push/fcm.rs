use async_trait::async_trait;
use log::{info, error, debug, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::crypto::Platform;
use super::PushService;

#[derive(Debug, Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    project_id: String,
}

#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

struct CachedToken {
    token: String,
    expires_at: u64,
}

pub struct FcmPush {
    client: Client,
    service_account: Option<ServiceAccount>,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
    project_id: String,
}

impl FcmPush {
    pub fn new(config: Config) -> Self {
        let service_account_path = std::env::var("FIREBASE_SERVICE_ACCOUNT_PATH").ok();
        let project_id = std::env::var("FIREBASE_PROJECT_ID")
            .unwrap_or_else(|_| "mostro".to_string());
        
        let service_account = service_account_path.and_then(|path| {
            match fs::read_to_string(&path) {
                Ok(content) => {
                    match serde_json::from_str::<ServiceAccount>(&content) {
                        Ok(sa) => {
                            info!("Loaded Firebase service account for {}", sa.client_email);
                            Some(sa)
                        }
                        Err(e) => {
                            error!("Failed to parse service account JSON: {}", e);
                            None
                        }
                    }
                }
                Err(e) => {
                    warn!("Could not read service account file {}: {}", path, e);
                    None
                }
            }
        });

        Self {
            client: Client::new(),
            service_account,
            cached_token: Arc::new(RwLock::new(None)),
            project_id,
        }
    }

    /// Initialize FCM service - validates that we can get an access token
    pub async fn init(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.service_account.is_none() {
            return Err("No service account configured".into());
        }
        // Try to get an access token to validate credentials
        self.get_access_token().await?;
        Ok(())
    }

    async fn get_access_token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        // Check cached token
        {
            let cache = self.cached_token.read().await;
            if let Some(ref cached) = *cache {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)?
                    .as_secs();
                // Refresh 60 seconds before expiry
                if cached.expires_at > now + 60 {
                    return Ok(cached.token.clone());
                }
            }
        }

        // Need to refresh token
        let sa = self.service_account.as_ref()
            .ok_or("No service account configured")?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        let claims = Claims {
            iss: sa.client_email.clone(),
            scope: "https://www.googleapis.com/auth/firebase.messaging".to_string(),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            iat: now,
            exp: now + 3600, // 1 hour
        };

        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(sa.private_key.as_bytes())?;
        let jwt = encode(&header, &claims, &key)?;

        // Exchange JWT for access token
        let response = self.client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &jwt),
            ])
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("OAuth2 token exchange failed: {}", error_text).into());
        }

        let token_response: TokenResponse = response.json().await?;
        
        // Cache the token
        {
            let mut cache = self.cached_token.write().await;
            *cache = Some(CachedToken {
                token: token_response.access_token.clone(),
                expires_at: now + token_response.expires_in,
            });
        }

        info!("Obtained new FCM access token, expires in {}s", token_response.expires_in);
        Ok(token_response.access_token)
    }

    fn build_silent_payload_for_token(device_token: &str) -> serde_json::Value {
        json!({
            "message": {
                "token": device_token,
                "data": {
                    "type": "silent_wake",
                    "source": "mostro-push-server",
                    "timestamp": chrono::Utc::now().timestamp().to_string()
                },
                "android": {
                    "priority": "high"
                },
                "apns": {
                    "headers": {
                        "apns-priority": "10",
                        "apns-push-type": "background"
                    },
                    "payload": {
                        "aps": {
                            "content-available": 1
                        }
                    }
                }
            }
        })
    }
}

#[async_trait]
impl PushService for FcmPush {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>> {
        let token = self.get_access_token().await
            .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

        let fcm_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
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
            info!("FCM topic notification sent successfully");
            Ok(())
        } else {
            error!("FCM error: {}", response.text().await?);
            Err("FCM send failed".into())
        }
    }

    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let auth_token = self.get_access_token().await
            .map_err(|e| -> Box<dyn std::error::Error> { e.to_string().into() })?;

        let fcm_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );

        let payload = Self::build_silent_payload_for_token(device_token);

        debug!("Sending FCM to token: {}...", &device_token[..20.min(device_token.len())]);

        let response = self.client
            .post(&fcm_url)
            .bearer_auth(&auth_token)
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            info!("FCM notification sent to {} device", platform);
            Ok(())
        } else {
            let error_text = response.text().await?;
            error!("FCM error for {} device: {}", platform, error_text);
            Err(format!("FCM send failed: {}", error_text).into())
        }
    }

    fn supports_platform(&self, platform: &Platform) -> bool {
        matches!(platform, Platform::Android | Platform::Ios)
    }
}
