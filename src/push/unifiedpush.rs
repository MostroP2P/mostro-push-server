use async_trait::async_trait;
use log::{debug, error, info, warn};
use regex::Regex;
use reqwest::dns::{Addrs, Resolve, Resolving};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
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
    allowed_hosts_regex: Option<Regex>,
}

impl UnifiedPushService {
    pub fn new(config: Config, client: Arc<reqwest::Client>) -> Self {
        let storage_path = PathBuf::from("data/unifiedpush_endpoints.json");
        let allowed_hosts_regex = config
            .push
            .unifiedpush_allowed_hosts_regex
            .as_deref()
            .map(Regex::new)
            .transpose()
            .expect("UNIFIEDPUSH_ALLOWED_HOSTS_REGEX was validated during config load");

        Self {
            config,
            client,
            endpoints: RwLock::new(HashMap::new()),
            storage_path,
            allowed_hosts_regex,
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
        validate_endpoint_url(&endpoint_url, self.allowed_hosts_regex.as_ref())?;

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
        let endpoint_url = validate_endpoint_url(device_token, self.allowed_hosts_regex.as_ref())?;

        // For UnifiedPush, the device_token IS the endpoint URL
        let payload = serde_json::json!({
            "type": "silent_wake",
            "timestamp": chrono::Utc::now().timestamp()
        });

        debug!(
            "Sending UnifiedPush to endpoint: {}...",
            &device_token[..30.min(device_token.len())]
        );

        let response = self.client.post(endpoint_url).json(&payload).send().await?;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnifiedPushEndpointError {
    InvalidUrl,
    UnsupportedScheme,
    MissingHost,
    LocalHostName,
    PrivateIpAddress,
    HostNotAllowed,
    NoPublicDnsAddress,
}

impl std::fmt::Display for UnifiedPushEndpointError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidUrl => "invalid UnifiedPush endpoint URL",
            Self::UnsupportedScheme => "UnifiedPush endpoint URL must use https",
            Self::MissingHost => "UnifiedPush endpoint URL must include a host",
            Self::LocalHostName => "UnifiedPush endpoint host is local",
            Self::PrivateIpAddress => "UnifiedPush endpoint host resolves to a private address",
            Self::HostNotAllowed => "UnifiedPush endpoint host is not allowed",
            Self::NoPublicDnsAddress => "UnifiedPush endpoint host has no public DNS address",
        };
        f.write_str(message)
    }
}

impl std::error::Error for UnifiedPushEndpointError {}

pub fn token_looks_like_unifiedpush_url(token: &str) -> bool {
    token.contains("://")
}

pub fn validate_endpoint_url(
    endpoint_url: &str,
    allowed_hosts_regex: Option<&Regex>,
) -> Result<reqwest::Url, UnifiedPushEndpointError> {
    let url =
        reqwest::Url::parse(endpoint_url).map_err(|_| UnifiedPushEndpointError::InvalidUrl)?;

    if url.scheme() != "https" {
        return Err(UnifiedPushEndpointError::UnsupportedScheme);
    }

    let host = url
        .host_str()
        .ok_or(UnifiedPushEndpointError::MissingHost)?
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if is_local_hostname(&host) {
        return Err(UnifiedPushEndpointError::LocalHostName);
    }

    let ip_host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(&host);

    if let Ok(ip) = ip_host.parse::<IpAddr>() {
        if !is_public_ip(ip) {
            return Err(UnifiedPushEndpointError::PrivateIpAddress);
        }
    }

    if let Some(allowed_hosts_regex) = allowed_hosts_regex {
        if !allowed_hosts_regex.is_match(&host) {
            return Err(UnifiedPushEndpointError::HostNotAllowed);
        }
    }

    Ok(url)
}

fn is_local_hostname(host: &str) -> bool {
    host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || octets[0] == 0
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
        || octets[0] >= 240)
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(ipv4) = ip.to_ipv4_mapped() {
        return is_public_ipv4(ipv4);
    }

    let segments = ip.segments();
    if segments[..6] == [0, 0, 0, 0, 0, 0] {
        return false;
    }

    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] == 0x2001 && segments[1] == 0x0db8))
}

#[derive(Debug, Default)]
pub struct PublicDnsResolver;

impl Resolve for PublicDnsResolver {
    fn resolve(&self, name: hyper::client::connect::dns::Name) -> Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let host_for_lookup = host.clone();
            let resolved = tokio::task::spawn_blocking(move || {
                (host_for_lookup.as_str(), 0)
                    .to_socket_addrs()
                    .map(|addrs| addrs.collect::<Vec<_>>())
            })
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;

            let public_addrs: Vec<_> = resolved
                .into_iter()
                .filter(|addr| is_public_ip(addr.ip()))
                .collect();

            if public_addrs.is_empty() {
                Err(format!("{}: {}", UnifiedPushEndpointError::NoPublicDnsAddress, host).into())
            } else {
                Ok(Box::new(public_addrs.into_iter()) as Addrs)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        CryptoConfig, NostrConfig, NotifyRateLimitConfig, PushConfig, RateLimitConfig,
        ServerConfig, StoreConfig,
    };

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
                unifiedpush_allowed_hosts_regex: None,
                batch_delay_ms: 5000,
                cooldown_ms: 60000,
            },
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
            },
            rate_limit: RateLimitConfig { max_per_minute: 60 },
            crypto: CryptoConfig {
                server_private_key:
                    "0000000000000000000000000000000000000000000000000000000000000001".to_string(),
            },
            store: StoreConfig {
                token_ttl_hours: 48,
                cleanup_interval_hours: 1,
            },
            notify_rate_limit: NotifyRateLimitConfig {
                per_pubkey_per_min: 30,
                per_ip_per_min: 120,
                cleanup_interval_secs: 60,
                pubkey_limiter_soft_cap: 100000,
                trust_proxy_headers: false,
            },
            trusted_whitelist_enabled: false,
        }
    }

    #[test]
    fn validates_unifiedpush_acceptance_examples() {
        assert!(validate_endpoint_url("https://up.example.com/push", None).is_ok());
        assert_eq!(
            validate_endpoint_url("http://169.254.169.254/latest", None).unwrap_err(),
            UnifiedPushEndpointError::UnsupportedScheme
        );
        assert_eq!(
            validate_endpoint_url("file:///etc/passwd", None).unwrap_err(),
            UnifiedPushEndpointError::UnsupportedScheme
        );
    }

    #[test]
    fn rejects_private_and_local_unifiedpush_endpoints() {
        for endpoint in [
            "https://169.254.169.254/latest",
            "https://127.0.0.1/push",
            "https://10.0.0.1/push",
            "https://172.16.0.1/push",
            "https://192.168.1.10/push",
            "https://[::1]/push",
            "https://[fc00::1]/push",
            "https://[fe80::1]/push",
            "https://localhost/push",
            "https://relay.local/push",
        ] {
            assert!(
                validate_endpoint_url(endpoint, None).is_err(),
                "{endpoint} must be rejected"
            );
        }
    }

    #[test]
    fn optional_host_allowlist_is_enforced() {
        let allowed = Regex::new(r"(^|\.)example\.com$").unwrap();
        assert!(validate_endpoint_url("https://up.example.com/push", Some(&allowed)).is_ok());
        assert_eq!(
            validate_endpoint_url("https://evil.test/push", Some(&allowed)).unwrap_err(),
            UnifiedPushEndpointError::HostNotAllowed
        );
    }

    #[test]
    fn public_ip_classifier_blocks_internal_ranges() {
        for ip in [
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fc00::1".parse().unwrap()),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("::ffff:127.0.0.1".parse().unwrap()),
            IpAddr::V6("::ffff:10.0.0.1".parse().unwrap()),
        ] {
            assert!(!is_public_ip(ip), "{ip} must not be public");
        }

        assert!(is_public_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_public_ip(IpAddr::V6(
            "2606:4700:4700::1111".parse().unwrap()
        )));
    }

    #[tokio::test]
    async fn send_to_token_revalidates_endpoint_before_dispatch() {
        let service = UnifiedPushService::new(test_config(), Arc::new(reqwest::Client::new()));
        let err = service
            .send_to_token(
                "https://169.254.169.254/latest/meta-data",
                &Platform::Android,
            )
            .await
            .expect_err("private endpoint must be rejected before reqwest dispatch");

        assert!(err.to_string().contains("private address"));
    }
}
