use log::info;
use serde::Deserialize;
use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub nostr: NostrConfig,
    pub push: PushConfig,
    pub server: ServerConfig,
    // Loaded for env symmetry; superseded by `notify_rate_limit` on the hot
    // path. Kept so the legacy RATE_LIMIT_PER_MINUTE knob still parses.
    #[allow(dead_code)]
    pub rate_limit: RateLimitConfig,
    // Reserved for the encrypted-token registration phase (see src/crypto).
    #[allow(dead_code)]
    pub crypto: CryptoConfig,
    pub store: StoreConfig,
    pub notify_rate_limit: NotifyRateLimitConfig,
    /// Runtime feature flag for the trusted-Mostro-instance whitelist on
    /// `/api/register`. Sourced from `TRUSTED_WHITELIST_ENABLED`, default
    /// `false`. The filter only activates when this is `true` AND the
    /// embedded whitelist (`config/trusted_mostro_pubkeys.json`) is
    /// non-empty; otherwise the `mostro_pubkey` field is ignored. This
    /// indirection lets the binary ship with the JSON populated while
    /// keeping the new 403 path off until the mobile client is rolled out.
    pub trusted_whitelist_enabled: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NostrConfig {
    pub relays: Vec<String>,
    // Carried in the typed config for parity with the Nostr listener wiring;
    // the listener currently hardcodes its own subscription id and event kinds.
    #[allow(dead_code)]
    pub subscription_id: String,
    #[allow(dead_code)]
    pub event_kinds: Vec<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PushConfig {
    pub fcm_enabled: bool,
    pub unifiedpush_enabled: bool,
    // Reserved for the dispatcher batching/cooldown work (see utils/batching).
    #[allow(dead_code)]
    pub batch_delay_ms: u64,
    #[allow(dead_code)]
    pub cooldown_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct RateLimitConfig {
    pub max_per_minute: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NotifyRateLimitConfig {
    pub per_pubkey_per_min: u32, // NOTIFY_RATE_PER_PUBKEY_PER_MIN, default 30 (D-01)
    pub per_ip_per_min: u32,     // NOTIFY_RATE_PER_IP_PER_MIN, default 120 (D-02)
    pub cleanup_interval_secs: u64, // NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS, default 60 (D-16)
    pub pubkey_limiter_soft_cap: usize, // NOTIFY_PUBKEY_LIMITER_SOFT_CAP, default 100000 (D-17)
    // NOTIFY_TRUST_PROXY_HEADERS, default false. Set to true ONLY when the
    // server sits behind a proxy that overwrites Fly-Client-IP / X-Forwarded-For
    // (e.g. Fly.io edge). Otherwise an attacker can rotate those headers per
    // request to bypass the per-IP limiter.
    pub trust_proxy_headers: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct CryptoConfig {
    pub server_private_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StoreConfig {
    pub token_ttl_hours: u64,
    pub cleanup_interval_hours: u64,
    /// `TOKEN_STORE_PATH`: SQLite file that persists registrations across
    /// restarts. Unset keeps them in memory only.
    pub path: Option<PathBuf>,
    /// `TOKEN_STORE_KEY`: 32-byte hex key sealing the persisted device
    /// tokens. Required when `path` is set.
    pub key: Option<Secret>,
}

/// A configuration value that must never reach a log. `Config` derives
/// `Debug`, so this type prints as redacted instead of its content.
#[derive(Clone, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Config {
    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let relays = env::var("NOSTR_RELAYS")?
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let token_store_path = env::var("TOKEN_STORE_PATH")
            .ok()
            .filter(|path| !path.trim().is_empty())
            .map(PathBuf::from);
        let token_store_key = env::var("TOKEN_STORE_KEY")
            .ok()
            .filter(|key| !key.trim().is_empty())
            .map(Secret);
        // Persisting without the key would either fail later or store tokens
        // in the clear; refuse to start instead.
        if token_store_path.is_some() && token_store_key.is_none() {
            return Err("TOKEN_STORE_KEY must be set when TOKEN_STORE_PATH is".into());
        }

        Ok(Config {
            nostr: NostrConfig {
                relays,
                subscription_id: "mostro-push-listener".to_string(),
                event_kinds: vec![1059, 14],
            },
            push: PushConfig {
                fcm_enabled: env::var("FCM_ENABLED")
                    .unwrap_or_else(|_| "true".to_string())
                    .parse()?,
                // Default false: the UnifiedPush dispatch path POSTs to the
                // client-supplied device token treated as a URL, so enabling
                // the backend by omission opens an SSRF surface. Operators
                // opt in explicitly.
                unifiedpush_enabled: env::var("UNIFIEDPUSH_ENABLED")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()?,
                batch_delay_ms: env::var("BATCH_DELAY_MS")
                    .unwrap_or_else(|_| "5000".to_string())
                    .parse()?,
                cooldown_ms: env::var("COOLDOWN_MS")
                    .unwrap_or_else(|_| "60000".to_string())
                    .parse()?,
            },
            server: ServerConfig {
                host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
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
                server_private_key: env::var("SERVER_PRIVATE_KEY").unwrap_or_else(|_| {
                    "0000000000000000000000000000000000000000000000000000000000000001".to_string()
                }),
            },
            store: StoreConfig {
                token_ttl_hours: env::var("TOKEN_TTL_HOURS")
                    .unwrap_or_else(|_| "48".to_string())
                    .parse()?,
                cleanup_interval_hours: env::var("CLEANUP_INTERVAL_HOURS")
                    .unwrap_or_else(|_| "1".to_string())
                    .parse()?,
                path: token_store_path,
                key: token_store_key,
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
                // Default false: if the server is reachable directly by clients
                // (no trusted proxy), Fly-Client-IP / X-Forwarded-For are
                // attacker-controlled and would let any client rotate the
                // per-IP rate-limit bucket on every request.
                trust_proxy_headers: env::var("NOTIFY_TRUST_PROXY_HEADERS")
                    .unwrap_or_else(|_| "false".to_string())
                    .parse()?,
            },
            // Default false: ship the binary with the embedded whitelist
            // populated but the 403 path off, so the mobile client can be
            // rolled out before the filter starts rejecting clients that
            // still don't send `mostro_pubkey`.
            trusted_whitelist_enabled: env::var("TRUSTED_WHITELIST_ENABLED")
                .unwrap_or_else(|_| "false".to_string())
                .parse()?,
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

    /// Snapshots the listed variables on construction and restores them on
    /// drop, so a test cannot leak its own values into the next one nor leave
    /// a variable unset when the suite runs with it configured. Restoring on
    /// drop also survives a panic between the mutation and the assertion.
    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn new(keys: &[&'static str]) -> Self {
            Self {
                saved: keys.iter().map(|k| (*k, env::var(k).ok())).collect(),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    /// D-04: NOTIFY_RATE_PER_PUBKEY_PER_MIN=0 must be rejected by Config::from_env
    /// with a chained error message containing "must be > 0".
    #[test]
    fn rejects_zero_per_pubkey_rate() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _env = EnvGuard::new(&[
            "NOTIFY_RATE_PER_PUBKEY_PER_MIN",
            "NOTIFY_RATE_PER_IP_PER_MIN",
            "NOSTR_RELAYS",
        ]);
        std::env::set_var("NOTIFY_RATE_PER_PUBKEY_PER_MIN", "0");
        std::env::set_var("NOTIFY_RATE_PER_IP_PER_MIN", "120");
        std::env::set_var("NOSTR_RELAYS", "wss://relay.example.com");

        let err = Config::from_env()
            .expect_err("Config::from_env MUST reject NOTIFY_RATE_PER_PUBKEY_PER_MIN=0");
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
        let _lock = ENV_MUTEX.lock().unwrap();
        let _env = EnvGuard::new(&[
            "NOTIFY_RATE_PER_PUBKEY_PER_MIN",
            "NOTIFY_RATE_PER_IP_PER_MIN",
            "NOSTR_RELAYS",
        ]);
        std::env::set_var("NOTIFY_RATE_PER_PUBKEY_PER_MIN", "30");
        std::env::set_var("NOTIFY_RATE_PER_IP_PER_MIN", "0");
        std::env::set_var("NOSTR_RELAYS", "wss://relay.example.com");

        let err = Config::from_env()
            .expect_err("Config::from_env MUST reject NOTIFY_RATE_PER_IP_PER_MIN=0");
        let msg = err.to_string();
        assert!(
            msg.contains("NOTIFY_RATE_PER_IP_PER_MIN must be > 0"),
            "expected D-04 error message, got: {}",
            msg
        );
    }

    /// UnifiedPush must be opt-in. Its dispatch path POSTs to the
    /// client-supplied device token treated as a URL, so a deployment that
    /// simply forgets the variable must not end up with the backend live.
    #[test]
    fn unifiedpush_defaults_to_disabled() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _env = EnvGuard::new(&["UNIFIEDPUSH_ENABLED", "NOSTR_RELAYS"]);
        std::env::remove_var("UNIFIEDPUSH_ENABLED");
        std::env::set_var("NOSTR_RELAYS", "wss://relay.example.com");

        let config = Config::from_env().expect("Config::from_env MUST succeed on defaults");
        assert!(
            !config.push.unifiedpush_enabled,
            "UNIFIEDPUSH_ENABLED MUST default to false"
        );
    }

    /// The opt-in still works: setting the variable explicitly enables it.
    #[test]
    fn unifiedpush_honours_explicit_opt_in() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _env = EnvGuard::new(&["UNIFIEDPUSH_ENABLED", "NOSTR_RELAYS"]);
        std::env::set_var("UNIFIEDPUSH_ENABLED", "true");
        std::env::set_var("NOSTR_RELAYS", "wss://relay.example.com");

        let config = Config::from_env().expect("Config::from_env MUST succeed on explicit opt-in");
        assert!(
            config.push.unifiedpush_enabled,
            "UNIFIEDPUSH_ENABLED=true MUST enable the backend"
        );
    }

    /// FCM keeps its permissive default: it does not take a client-supplied
    /// URL, so the fail-open concern that motivates the UnifiedPush default
    /// does not apply, and flipping it would change existing deployments.
    #[test]
    fn fcm_default_is_unchanged() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _env = EnvGuard::new(&["FCM_ENABLED", "NOSTR_RELAYS"]);
        std::env::remove_var("FCM_ENABLED");
        std::env::set_var("NOSTR_RELAYS", "wss://relay.example.com");

        let config = Config::from_env().expect("Config::from_env MUST succeed on defaults");
        assert!(
            config.push.fcm_enabled,
            "FCM_ENABLED MUST keep defaulting to true"
        );
    }

    #[test]
    fn token_store_path_requires_a_key() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _env = EnvGuard::new(&["TOKEN_STORE_PATH", "TOKEN_STORE_KEY", "NOSTR_RELAYS"]);
        std::env::set_var("NOSTR_RELAYS", "wss://relay.example.com");
        std::env::set_var("TOKEN_STORE_PATH", "/app/data/tokens.db");
        std::env::remove_var("TOKEN_STORE_KEY");

        let err = Config::from_env().expect_err("a store path without a key MUST be rejected");
        assert!(err.to_string().contains("TOKEN_STORE_KEY must be set"));
    }

    #[test]
    fn token_store_defaults_to_memory_only() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _env = EnvGuard::new(&["TOKEN_STORE_PATH", "TOKEN_STORE_KEY", "NOSTR_RELAYS"]);
        std::env::set_var("NOSTR_RELAYS", "wss://relay.example.com");
        std::env::remove_var("TOKEN_STORE_PATH");
        std::env::remove_var("TOKEN_STORE_KEY");

        let config = Config::from_env().expect("Config::from_env MUST succeed on defaults");
        assert!(config.store.path.is_none());
        assert!(config.store.key.is_none());
    }

    #[test]
    fn token_store_key_never_appears_in_debug_output() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _env = EnvGuard::new(&["TOKEN_STORE_PATH", "TOKEN_STORE_KEY", "NOSTR_RELAYS"]);
        let key = "ab".repeat(32);
        std::env::set_var("NOSTR_RELAYS", "wss://relay.example.com");
        std::env::set_var("TOKEN_STORE_PATH", "/app/data/tokens.db");
        std::env::set_var("TOKEN_STORE_KEY", &key);

        let config = Config::from_env().expect("path and key together MUST be accepted");
        assert_eq!(config.store.key.as_ref().unwrap().expose(), key);
        assert!(!format!("{:?}", config).contains(&key));
    }
}
