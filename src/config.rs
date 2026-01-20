use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub nostr: NostrConfig,
    pub push: PushConfig,
    pub server: ServerConfig,
    pub rate_limit: RateLimitConfig,
    pub crypto: CryptoConfig,
    pub store: StoreConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NostrConfig {
    pub relays: Vec<String>,
    pub subscription_id: String,
    pub event_kinds: Vec<u64>,
    pub mostro_pubkey: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PushConfig {
    pub fcm_enabled: bool,
    pub unifiedpush_enabled: bool,
    pub batch_delay_ms: u64,
    pub cooldown_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RateLimitConfig {
    pub max_per_minute: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CryptoConfig {
    pub server_private_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StoreConfig {
    pub token_ttl_hours: u64,
    pub cleanup_interval_hours: u64,
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let relays = env::var("NOSTR_RELAYS")?
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        // Read Mostro instance public key from environment
        let mostro_pubkey = env::var("MOSTRO_PUBKEY")
            .unwrap_or_else(|_| {
                // Default to the main Mostro instance pubkey
                "82fa8cb978b43c79b2156585bac2c011176a21d2aead6d9f7c575c005be88390".to_string()
            });

        Ok(Config {
            nostr: NostrConfig {
                relays,
                subscription_id: "mostro-push-listener".to_string(),
                event_kinds: vec![1059],
                mostro_pubkey: env::var("MOSTRO_PUBKEY")
                    .unwrap_or_else(|_| "dbe0b1be7aafd3cfba92d7463571bf438f09d24f4e021d9fe208ed0ab5823711".to_string()),
            },
            push: PushConfig {
                fcm_enabled: env::var("FCM_ENABLED")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
                unifiedpush_enabled: env::var("UNIFIEDPUSH_ENABLED")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
                batch_delay_ms: env::var("BATCH_DELAY_MS")
                    .unwrap_or_else(|_| "5000".to_string())
                    .parse()?,
                cooldown_ms: env::var("COOLDOWN_MS")
                    .unwrap_or_else(|_| "60000".to_string())
                    .parse()?,
            },
            server: ServerConfig {
                host: env::var("SERVER_HOST")
                    .unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: env::var("SERVER_PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()?,
            },
            rate_limit: RateLimitConfig {
                max_per_minute: env::var("RATE_LIMIT_PER_MINUTE")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()?,
            },
            // Phase 3: Crypto config is optional (encryption disabled)
            // Phase 4 will require SERVER_PRIVATE_KEY
            crypto: CryptoConfig {
                server_private_key: env::var("SERVER_PRIVATE_KEY")
                    .unwrap_or_else(|_| "0000000000000000000000000000000000000000000000000000000000000001".to_string()),
            },
            store: StoreConfig {
                token_ttl_hours: env::var("TOKEN_TTL_HOURS")
                    .unwrap_or_else(|_| "48".to_string())
                    .parse()?,
                cleanup_interval_hours: env::var("CLEANUP_INTERVAL_HOURS")
                    .unwrap_or_else(|_| "1".to_string())
                    .parse()?,
            },
        })
    }
}
