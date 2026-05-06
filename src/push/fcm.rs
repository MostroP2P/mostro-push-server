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
use crate::store::Platform;
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
    client: Arc<reqwest::Client>,
    service_account: Option<ServiceAccount>,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
    project_id: String,
}

impl FcmPush {
    pub fn new(config: Config, client: Arc<reqwest::Client>) -> Self {
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
            client,
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

    /// Build FCM payload with notification fallback
    ///
    /// Strategy:
    /// - Sends both `notification` (fallback) and `data` (for app processing)
    /// - Uses a fixed tag "mostro-trade" so notifications can be replaced
    /// - When app is alive: background service shows detailed notification with same tag,
    ///   which REPLACES the generic FCM notification
    /// - When app is killed: FCM shows generic notification as fallback
    fn build_payload_for_token(device_token: &str) -> serde_json::Value {
        json!({
            "message": {
                "token": device_token,
                // Notification field - shown by FCM when app is killed (fallback)
                "notification": {
                    "title": "Mostro",
                    "body": "You have an update on your trade"
                },
                // Data field - used by app to process when awake
                "data": {
                    "type": "trade_update",
                    "source": "mostro-push-server",
                    "timestamp": chrono::Utc::now().timestamp().to_string()
                },
                // Android-specific config
                "android": {
                    "priority": "high",
                    "notification": {
                        // Tag allows replacing notification with same tag
                        "tag": "mostro-trade",
                        // Use default channel (app should create "mostro_notifications" channel)
                        "channel_id": "mostro_notifications",
                        // Don't show if app is in foreground
                        "default_vibrate_timings": true
                    }
                },
                // iOS-specific config
                "apns": {
                    "headers": {
                        "apns-priority": "10",
                        "apns-collapse-id": "mostro-trade"
                    },
                    "payload": {
                        "aps": {
                            "alert": {
                                "title": "Mostro",
                                "body": "You have an update on your trade"
                            },
                            "content-available": 1,
                            "mutable-content": 1,
                            "thread-id": "mostro-trade"
                        }
                    }
                }
            }
        })
    }

    /// Silent push payload for the /api/notify chat-wake path.
    ///
    /// Data-only (no `alert`, no notification fallback) so iOS does not
    /// throttle the app for high-frequency silent pushes
    /// (apns-priority: 5 + apns-push-type: background per Apple's docs).
    /// Distinct from `build_payload_for_token` (Mostro daemon events at
    /// apns-priority: 10 with an alert fallback). Do NOT merge:
    /// the two paths have fundamentally different frequency profiles
    /// (chat = continuous, daemon events = sporadic).
    fn build_silent_payload_for_notify(device_token: &str) -> serde_json::Value {
        json!({
            "message": {
                "token": device_token,
                "data": {
                    "type": "chat_wake",
                    "source": "mostro-push-server",
                    "timestamp": chrono::Utc::now().timestamp().to_string()
                },
                "android": {
                    "priority": "high"
                },
                "apns": {
                    "headers": {
                        "apns-priority": "5",
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
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let auth_token = self.get_access_token().await?;

        let fcm_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );

        let payload = Self::build_payload_for_token(device_token);

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

    async fn send_silent_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let auth_token = self.get_access_token().await?;

        let fcm_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );

        let payload = Self::build_silent_payload_for_notify(device_token);

        debug!("Sending FCM silent to token: {}...", &device_token[..20.min(device_token.len())]);

        let response = self.client
            .post(&fcm_url)
            .bearer_auth(&auth_token)
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            info!("FCM silent notification sent to {} device", platform);
            Ok(())
        } else {
            let error_text = response.text().await?;
            error!("FCM silent error for {} device: {}", platform, error_text);
            Err(format!("FCM silent send failed: {}", error_text).into())
        }
    }

    fn supports_platform(&self, platform: &Platform) -> bool {
        matches!(platform, Platform::Android | Platform::Ios)
    }
}
