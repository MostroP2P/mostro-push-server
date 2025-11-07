use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub nostr: NostrConfig,
    pub push: PushConfig,
    pub server: ServerConfig,
    pub rate_limit: RateLimitConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NostrConfig {
    pub relays: Vec<String>,
    pub subscription_id: String,
    pub event_kinds: Vec<u64>,
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

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let relays = env::var("NOSTR_RELAYS")?
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Ok(Config {
            nostr: NostrConfig {
                relays,
                subscription_id: "mostro-push-listener".to_string(),
                event_kinds: vec![1059],
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
        })
    }
}
