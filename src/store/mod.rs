use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use serde::Serialize;
use std::collections::HashMap;
use tokio::sync::RwLock;

/// Platform identifier for push notifications
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Platform {
    Android,
    Ios,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Android => write!(f, "android"),
            Platform::Ios => write!(f, "ios"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RegisteredToken {
    pub device_token: String,
    pub platform: Platform,
    pub registered_at: DateTime<Utc>,
}

pub struct TokenStore {
    tokens: RwLock<HashMap<String, RegisteredToken>>,
    ttl_hours: u64,
}

impl TokenStore {
    pub fn new(ttl_hours: u64) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            ttl_hours,
        }
    }

    pub async fn register(
        &self,
        trade_pubkey: String,
        device_token: String,
        platform: Platform,
    ) {
        let token = RegisteredToken {
            device_token,
            platform,
            registered_at: Utc::now(),
        };

        let mut tokens = self.tokens.write().await;
        tokens.insert(trade_pubkey.clone(), token);

        info!(
            "Registered token for trade_pubkey: {}... (total: {})",
            &trade_pubkey[..16.min(trade_pubkey.len())],
            tokens.len()
        );
    }

    pub async fn unregister(&self, trade_pubkey: &str) -> bool {
        let mut tokens = self.tokens.write().await;
        let removed = tokens.remove(trade_pubkey).is_some();

        if removed {
            info!(
                "Unregistered token for trade_pubkey: {}... (total: {})",
                &trade_pubkey[..16.min(trade_pubkey.len())],
                tokens.len()
            );
        } else {
            debug!(
                "Token not found for trade_pubkey: {}...",
                &trade_pubkey[..16.min(trade_pubkey.len())]
            );
        }

        removed
    }

    pub async fn get(&self, trade_pubkey: &str) -> Option<RegisteredToken> {
        let tokens = self.tokens.read().await;
        tokens.get(trade_pubkey).cloned()
    }

    pub async fn cleanup_expired(&self) -> usize {
        let mut tokens = self.tokens.write().await;
        let now = Utc::now();
        let ttl = chrono::Duration::hours(self.ttl_hours as i64);

        let initial_count = tokens.len();
        tokens.retain(|_, token| {
            now.signed_duration_since(token.registered_at) < ttl
        });

        let removed = initial_count - tokens.len();
        if removed > 0 {
            info!("Cleaned up {} expired tokens (remaining: {})", removed, tokens.len());
        }

        removed
    }

    pub async fn count(&self) -> usize {
        self.tokens.read().await.len()
    }

    pub async fn get_stats(&self) -> TokenStoreStats {
        let tokens = self.tokens.read().await;
        let mut android_count = 0;
        let mut ios_count = 0;

        for token in tokens.values() {
            match token.platform {
                Platform::Android => android_count += 1,
                Platform::Ios => ios_count += 1,
            }
        }

        TokenStoreStats {
            total: tokens.len(),
            android: android_count,
            ios: ios_count,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenStoreStats {
    pub total: usize,
    pub android: usize,
    pub ios: usize,
}

pub fn start_cleanup_task(store: std::sync::Arc<TokenStore>, interval_hours: u64) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(
            tokio::time::Duration::from_secs(interval_hours * 3600)
        );

        loop {
            interval.tick().await;
            let removed = store.cleanup_expired().await;
            if removed > 0 {
                warn!("Periodic cleanup removed {} expired tokens", removed);
            }
        }
    });
}
