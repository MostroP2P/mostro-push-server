use async_trait::async_trait;
use log::{info, error, warn};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::fs;

use crate::config::Config;
use super::PushService;

#[derive(Debug, Deserialize)]
struct ServiceAccount {
    #[serde(rename = "type")]
    account_type: String,
    project_id: String,
    private_key: String,
    client_email: String,
    token_uri: String,
}

#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

#[derive(Clone)]
struct CachedToken {
    token: String,
    expires_at: u64,
}

pub struct FcmPush {
    config: Config,
    client: Client,
    service_account: Arc<Mutex<Option<ServiceAccount>>>,
    cached_token: Arc<Mutex<Option<CachedToken>>>,
    firebase_project_id: String,
}

impl FcmPush {
    pub fn new(config: Config) -> Self {
        // Get Firebase project ID from environment
        let firebase_project_id = std::env::var("FIREBASE_PROJECT_ID")
            .unwrap_or_else(|_| "mostro-test".to_string());

        Self {
            config,
            client: Client::new(),
            service_account: Arc::new(Mutex::new(None)),
            cached_token: Arc::new(Mutex::new(None)),
            firebase_project_id,
        }
    }

    /// Initialize by loading service account from file
    pub async fn init(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Initializing FCM authentication...");

        let path = std::env::var("FIREBASE_SERVICE_ACCOUNT_PATH")?;
        info!("Loading service account from: {}", path);

        let content = fs::read_to_string(&path).await?;
        let account: ServiceAccount = serde_json::from_str(&content)?;

        let mut service_account = self.service_account.lock().await;
        *service_account = Some(account);

        info!("FCM authentication initialized successfully");
        Ok(())
    }

    /// Get a valid OAuth2 access token (handles refresh automatically)
    async fn get_access_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        // Check if we have a valid cached token
        {
            let cached = self.cached_token.lock().await;
            if let Some(token) = cached.as_ref() {
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                // Return cached token if it's still valid (with 5 minute buffer)
                if token.expires_at > now + 300 {
                    return Ok(token.token.clone());
                }
            }
        }

        // Need to fetch new token
        info!("Fetching new FCM access token...");
        let new_token = self.fetch_new_token().await?;

        // Cache the token
        {
            let mut cached = self.cached_token.lock().await;
            *cached = Some(new_token.clone());
        }

        Ok(new_token.token)
    }

    /// Fetch a new access token from Google OAuth
    async fn fetch_new_token(&self) -> Result<CachedToken, Box<dyn std::error::Error>> {
        let account = self.service_account.lock().await;
        let account = account.as_ref()
            .ok_or("Service account not loaded. Call init() first.")?;

        // Create JWT claims
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let claims = Claims {
            iss: account.client_email.clone(),
            scope: "https://www.googleapis.com/auth/firebase.messaging".to_string(),
            aud: account.token_uri.clone(),
            exp: now + 3600, // 1 hour
            iat: now,
        };

        // Encode JWT
        let header = Header::new(Algorithm::RS256);
        let encoding_key = EncodingKey::from_rsa_pem(account.private_key.as_bytes())?;
        let jwt = encode(&header, &claims, &encoding_key)?;

        // Exchange JWT for access token
        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ];

        let response = self.client
            .post(&account.token_uri)
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(format!("Token exchange failed: {}", error_text).into());
        }

        let token_response: TokenResponse = response.json().await?;

        Ok(CachedToken {
            token: token_response.access_token,
            expires_at: now + token_response.expires_in,
        })
    }
}

#[async_trait]
impl PushService for FcmPush {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>> {
        // Skip if FCM is not initialized (optional service)
        if self.service_account.lock().await.is_none() {
            warn!("FCM service account not loaded, skipping FCM push");
            return Ok(());
        }

        let token = self.get_access_token().await?;

        let fcm_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.firebase_project_id
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
