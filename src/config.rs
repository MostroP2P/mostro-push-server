use log::info;
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
    pub notify_rate_limit: NotifyRateLimitConfig,
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
pub struct NotifyRateLimitConfig {
    pub per_pubkey_per_min: u32,        // NOTIFY_RATE_PER_PUBKEY_PER_MIN, default 30 (D-01)
    pub per_ip_per_min: u32,            // NOTIFY_RATE_PER_IP_PER_MIN, default 120 (D-02)
    pub cleanup_interval_secs: u64,     // NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS, default 60 (D-16)
    pub pubkey_limiter_soft_cap: usize, // NOTIFY_PUBKEY_LIMITER_SOFT_CAP, default 100000 (D-17)
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
            notify_rate_limit: NotifyRateLimitConfig {
                per_pubkey_per_min: {
                    let v: u32 = match env::var("NOTIFY_RATE_PER_PUBKEY_PER_MIN") {
                        Ok(s) => s.parse()?,
                        Err(_) => {
                            info!("NOTIFY_RATE_PER_PUBKEY_PER_MIN unset, using default 30");
                            30
                        }
                    };
                    if v == 0 {
                        return Err("NOTIFY_RATE_PER_PUBKEY_PER_MIN must be > 0, got 0".into());
                    }
                    v
                },
                per_ip_per_min: {
                    let v: u32 = match env::var("NOTIFY_RATE_PER_IP_PER_MIN") {
                        Ok(s) => s.parse()?,
                        Err(_) => {
                            info!("NOTIFY_RATE_PER_IP_PER_MIN unset, using default 120");
                            120
                        }
                    };
                    if v == 0 {
                        return Err("NOTIFY_RATE_PER_IP_PER_MIN must be > 0, got 0".into());
                    }
                    v
                },
                cleanup_interval_secs: env::var("NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS")
                    .unwrap_or_else(|_| "60".to_string())
                    .parse()?,
                pubkey_limiter_soft_cap: env::var("NOTIFY_PUBKEY_LIMITER_SOFT_CAP")
                    .unwrap_or_else(|_| "100000".to_string())
                    .parse()?,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serializes env-mutating tests in this module; prevents races between
    // tests that call std::env::set_var / remove_var on the same keys.
    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    /// D-04: NOTIFY_RATE_PER_PUBKEY_PER_MIN=0 must be rejected by Config::from_env
    /// with a chained error message containing "must be > 0".
    #[test]
    fn rejects_zero_per_pubkey_rate() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::set_var("NOTIFY_RATE_PER_PUBKEY_PER_MIN", "0");
        std::env::set_var("NOTIFY_RATE_PER_IP_PER_MIN", "120");
        std::env::set_var("NOSTR_RELAYS", "wss://relay.example.com");
        std::env::set_var("MOSTRO_PUBKEY", "0".repeat(64));

        let result = Config::from_env();

        std::env::remove_var("NOTIFY_RATE_PER_PUBKEY_PER_MIN");
        std::env::remove_var("NOTIFY_RATE_PER_IP_PER_MIN");
        std::env::remove_var("NOSTR_RELAYS");
        std::env::remove_var("MOSTRO_PUBKEY");

        let err = result.expect_err("Config::from_env MUST reject NOTIFY_RATE_PER_PUBKEY_PER_MIN=0");
        let msg = err.to_string();
        assert!(
            msg.contains("NOTIFY_RATE_PER_PUBKEY_PER_MIN must be > 0"),
            "expected D-04 error message, got: {}",
            msg
        );
    }

    /// D-04: NOTIFY_RATE_PER_IP_PER_MIN=0 must be rejected by Config::from_env.
    #[test]
    fn rejects_zero_per_ip_rate() {
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::set_var("NOTIFY_RATE_PER_PUBKEY_PER_MIN", "30");
        std::env::set_var("NOTIFY_RATE_PER_IP_PER_MIN", "0");
        std::env::set_var("NOSTR_RELAYS", "wss://relay.example.com");
        std::env::set_var("MOSTRO_PUBKEY", "0".repeat(64));

        let result = Config::from_env();

        std::env::remove_var("NOTIFY_RATE_PER_PUBKEY_PER_MIN");
        std::env::remove_var("NOTIFY_RATE_PER_IP_PER_MIN");
        std::env::remove_var("NOSTR_RELAYS");
        std::env::remove_var("MOSTRO_PUBKEY");

        let err = result.expect_err("Config::from_env MUST reject NOTIFY_RATE_PER_IP_PER_MIN=0");
        let msg = err.to_string();
        assert!(
            msg.contains("NOTIFY_RATE_PER_IP_PER_MIN must be > 0"),
            "expected D-04 error message, got: {}",
            msg
        );
    }
}
