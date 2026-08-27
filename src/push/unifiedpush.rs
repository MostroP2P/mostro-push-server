use async_trait::async_trait;
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::sync::RwLock;

use super::PushService;
use crate::config::Config;
use crate::store::Platform;

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
    /// Builds the HTTP client this backend must use.
    ///
    /// Deliberately NOT the shared client from `main.rs`. `reqwest` defaults to
    /// `Policy::limited(10)`, and the endpoint URL is attacker-supplied, so a
    /// registered endpoint could answer `302 Location: http://169.254.169.254/`
    /// and walk the request straight past `endpoint_guard`, which only ever
    /// sees the first hop. A push endpoint has no legitimate reason to
    /// redirect, so redirects are refused outright.
    ///
    /// FCM stays on the shared client: it talks to a fixed Google endpoint with
    /// a token this server mints, not to a URL a caller chose.
    ///
    /// Timeouts mirror the shared client (2 s connect, 5 s total) so this
    /// backend keeps the same bound on tying up worker threads.
    pub fn build_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(5))
            .pool_idle_timeout(Some(Duration::from_secs(90)))
            .build()
            .expect("reqwest::Client build never fails on this config")
    }

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
        // For UnifiedPush, the device_token IS the endpoint URL, so this is the
        // request-forgery boundary: everything reachable from here was supplied
        // by an unauthenticated caller. Validate before any outbound traffic.
        if let Err(reason) = crate::push::endpoint_guard::validate_endpoint(device_token).await {
            warn!("UnifiedPush endpoint refused: {}", reason);
            return Err(format!("UnifiedPush endpoint refused: {}", reason).into());
        }

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
    use super::*;
    use crate::config::{
        Config, CryptoConfig, NostrConfig, NotifyRateLimitConfig, PushConfig, RateLimitConfig,
        ServerConfig, StoreConfig,
    };

    /// Minimal config built by hand rather than through `Config::from_env`,
    /// which would race with the env-mutating tests in `src/config.rs`.
    fn test_config() -> Config {
        Config {
            nostr: NostrConfig {
                relays: vec!["wss://relay.example.com".to_string()],
                subscription_id: "test".to_string(),
                event_kinds: vec![1059, 14],
            },
            push: PushConfig {
                fcm_enabled: false,
                unifiedpush_enabled: true,
                batch_delay_ms: 5000,
                cooldown_ms: 60000,
            },
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 8080,
            },
            rate_limit: RateLimitConfig { max_per_minute: 60 },
            crypto: CryptoConfig {
                server_private_key: "00".repeat(32),
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

    fn test_service() -> UnifiedPushService {
        UnifiedPushService::new(test_config(), Arc::new(UnifiedPushService::build_client()))
    }

    /// The guard living in `endpoint_guard` is only useful if the dispatch path
    /// actually calls it. The unit tests over `validate_endpoint` would all
    /// still pass if this call site were deleted, so assert on the refusal
    /// message: a missing guard would surface as a reqwest connection error
    /// instead, which reads very differently.
    #[tokio::test]
    async fn send_to_token_refuses_non_public_endpoints() {
        let service = test_service();

        for token in [
            "http://169.254.169.254/latest/meta-data/",
            "https://169.254.169.254/latest/meta-data/",
            "https://127.0.0.1:8080/",
            "https://[::ffff:169.254.169.254]/",
            "https://10.0.0.1/push",
            "https://localhost/push",
        ] {
            let err = service
                .send_to_token(token, &Platform::Android)
                .await
                .expect_err("dispatch MUST refuse a non-public endpoint");

            assert!(
                err.to_string().starts_with("UnifiedPush endpoint refused"),
                "expected the guard to reject {token}, got: {err}"
            );
        }
    }

    /// An opaque value (an FCM token that reached the wrong backend) must not
    /// be handed to reqwest to interpret.
    #[tokio::test]
    async fn send_to_token_refuses_opaque_tokens() {
        let service = test_service();
        let err = service
            .send_to_token("d1PxYz8QRk-2vQ1sAbCdEf", &Platform::Android)
            .await
            .expect_err("dispatch MUST refuse an opaque token");

        assert!(err.to_string().starts_with("UnifiedPush endpoint refused"));
    }

    /// `endpoint_guard` only ever inspects the first hop, so the client must
    /// not chase a second one. Without this, a registered endpoint answering
    /// `302 Location: http://169.254.169.254/` walks the request straight past
    /// the guard and the whole SSRF fix is one HTTP header away from useless.
    ///
    /// The guard refuses loopback endpoints, so this exercises the client
    /// configuration directly rather than going through `send_to_token`: the
    /// client policy is the property under test.
    #[tokio::test]
    async fn dispatch_client_refuses_to_follow_redirects() {
        let mut server = mockito::Server::new_async().await;
        let base = server.url();

        let second_hop = server
            .mock("GET", "/internal-secret")
            .with_status(200)
            .with_body("METADATA_LEAKED")
            .expect(0)
            .create_async()
            .await;

        let _redirector = server
            .mock("POST", "/push")
            .with_status(302)
            .with_header("location", &format!("{base}/internal-secret"))
            .create_async()
            .await;

        let response = UnifiedPushService::build_client()
            .post(format!("{base}/push"))
            .json(&serde_json::json!({"type": "silent_wake"}))
            .send()
            .await
            .expect("the request itself must still succeed");

        assert_eq!(
            response.status(),
            302,
            "the redirect must be surfaced, not followed"
        );
        let body = response.text().await.unwrap_or_default();
        assert!(
            !body.contains("METADATA_LEAKED"),
            "the second hop's body must never be reached, got: {body}"
        );

        // The strongest assertion: the second hop was never requested at all.
        second_hop.assert_async().await;
    }

    #[test]
    fn unifiedpush_supports_android_only() {
        let service = test_service();
        assert!(service.supports_platform(&Platform::Android));
        assert!(!service.supports_platform(&Platform::Ios));
    }
}
