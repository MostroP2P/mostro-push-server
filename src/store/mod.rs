use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use crate::utils::log_pubkey::log_pubkey;

pub mod cipher;
pub mod sqlite;

use sqlite::{LoadReport, PersistError, SqliteStore};

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
    log_salt: Arc<[u8; 32]>,
    /// Durable copy of `tokens`; `None` keeps registrations in memory only.
    persistence: Option<SqliteStore>,
    /// Held across a mutation and its durable write, so concurrent register
    /// and unregister calls reach the database in the order they changed
    /// memory. Readers only take `tokens` and never wait on the disk.
    write_order: Mutex<()>,
}

impl TokenStore {
    /// In-memory store: registrations are lost on restart.
    pub fn new(ttl_hours: u64, log_salt: Arc<[u8; 32]>) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            ttl_hours,
            log_salt,
            persistence: None,
            write_order: Mutex::new(()),
        }
    }

    /// Store backed by `db`: live registrations are loaded from it, and every
    /// later change is written to it.
    pub fn persistent(
        ttl_hours: u64,
        log_salt: Arc<[u8; 32]>,
        db: SqliteStore,
    ) -> Result<(Self, LoadReport), PersistError> {
        let cutoff = Utc::now() - chrono::Duration::hours(ttl_hours as i64);
        let (entries, report) = db.load(cutoff)?;
        let store = Self {
            tokens: RwLock::new(entries.into_iter().collect()),
            ttl_hours,
            log_salt,
            persistence: Some(db),
            write_order: Mutex::new(()),
        };
        Ok((store, report))
    }

    pub async fn register(&self, trade_pubkey: String, device_token: String, platform: Platform) {
        let token = RegisteredToken {
            device_token,
            platform,
            registered_at: Utc::now(),
        };

        let _order = self.write_order.lock().await;
        let total = {
            let mut tokens = self.tokens.write().await;
            tokens.insert(trade_pubkey.clone(), token.clone());
            tokens.len()
        };
        let log_pk = log_pubkey(&self.log_salt, &trade_pubkey);
        info!("Registered token pk={} (total: {})", log_pk, total);

        if let Some(db) = &self.persistence {
            // The registration still works from memory; only a restart loses it.
            if let Err(e) = db.upsert(trade_pubkey, token).await {
                error!("Failed to persist token pk={}: {}", log_pk, e);
            }
        }
    }

    pub async fn unregister(&self, trade_pubkey: &str) -> bool {
        let _order = self.write_order.lock().await;
        let (removed, total) = {
            let mut tokens = self.tokens.write().await;
            (tokens.remove(trade_pubkey).is_some(), tokens.len())
        };
        let log_pk = log_pubkey(&self.log_salt, trade_pubkey);

        if removed {
            info!("Unregistered token pk={} (total: {})", log_pk, total);
        } else {
            debug!("Token not found pk={}", log_pk);
        }

        if let Some(db) = &self.persistence {
            // Deleted even when absent from memory, so no stale row survives.
            if let Err(e) = db.delete(trade_pubkey.to_string()).await {
                error!("Failed to delete persisted token pk={}: {}", log_pk, e);
            }
        }

        removed
    }

    pub async fn get(&self, trade_pubkey: &str) -> Option<RegisteredToken> {
        let tokens = self.tokens.read().await;
        tokens.get(trade_pubkey).cloned()
    }

    pub async fn cleanup_expired(&self) -> usize {
        let _order = self.write_order.lock().await;
        let now = Utc::now();
        let ttl = chrono::Duration::hours(self.ttl_hours as i64);

        let (removed, remaining) = {
            let mut tokens = self.tokens.write().await;
            let initial_count = tokens.len();
            tokens.retain(|_, token| now.signed_duration_since(token.registered_at) < ttl);
            (initial_count - tokens.len(), tokens.len())
        };
        if removed > 0 {
            info!(
                "Cleaned up {} expired tokens (remaining: {})",
                removed, remaining
            );
        }

        if let Some(db) = &self.persistence {
            if let Err(e) = db.delete_expired(now - ttl).await {
                error!("Failed to delete expired persisted tokens: {}", e);
            }
        }

        removed
    }

    // Exposed for diagnostics and future admin tooling; not yet wired into
    // any handler.
    #[allow(dead_code)]
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
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(interval_hours * 3600));

        loop {
            interval.tick().await;
            let removed = store.cleanup_expired().await;
            if removed > 0 {
                warn!("Periodic cleanup removed {} expired tokens", removed);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::cipher::TokenCipher;
    use super::sqlite::SqliteStore;
    use super::*;
    use std::path::PathBuf;

    const KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const OTHER_KEY: &str = "0202020202020202020202020202020202020202020202020202020202020202";
    const PK_A: &str = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345abc";
    const PK_B: &str = "b1b2c3d4e5f67890123456789012345678901234567890123456789012345abc";
    const TOKEN_A: &str = "fcm-token-for-device-a:APA91bHexampleA";
    const TOKEN_B: &str = "fcm-token-for-device-b:APA91bHexampleB";

    /// A database path unique to one test; the file and its WAL/SHM
    /// companions are removed on drop.
    struct TempDb(PathBuf);

    impl TempDb {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "mostro-push-store-test-{}.db",
                uuid::Uuid::new_v4()
            )))
        }

        /// Every byte SQLite wrote for this database.
        fn all_bytes(&self) -> Vec<u8> {
            ["", "-wal", "-shm"]
                .iter()
                .filter_map(|suffix| std::fs::read(format!("{}{}", self.0.display(), suffix)).ok())
                .flatten()
                .collect()
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{}", self.0.display(), suffix));
            }
        }
    }

    fn salt() -> Arc<[u8; 32]> {
        Arc::new([7u8; 32])
    }

    fn open(db: &TempDb, key: &str, ttl_hours: u64) -> (TokenStore, LoadReport) {
        let sqlite = SqliteStore::open(&db.0, TokenCipher::from_hex(key).unwrap()).unwrap();
        TokenStore::persistent(ttl_hours, salt(), sqlite).unwrap()
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    #[tokio::test]
    async fn registrations_survive_a_restart() {
        let db = TempDb::new();
        {
            let (store, _) = open(&db, KEY, 48);
            store
                .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
                .await;
            store
                .register(PK_B.into(), TOKEN_B.into(), Platform::Ios)
                .await;
        }

        let (store, report) = open(&db, KEY, 48);

        assert_eq!(report.restored, 2);
        let a = store.get(PK_A).await.unwrap();
        assert_eq!(a.device_token, TOKEN_A);
        assert_eq!(a.platform, Platform::Android);
        let b = store.get(PK_B).await.unwrap();
        assert_eq!(b.device_token, TOKEN_B);
        assert_eq!(b.platform, Platform::Ios);
    }

    #[tokio::test]
    async fn re_registering_replaces_the_persisted_token() {
        let db = TempDb::new();
        {
            let (store, _) = open(&db, KEY, 48);
            store
                .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
                .await;
            store
                .register(PK_A.into(), TOKEN_B.into(), Platform::Android)
                .await;
        }

        let (store, report) = open(&db, KEY, 48);

        assert_eq!(report.restored, 1);
        assert_eq!(store.get(PK_A).await.unwrap().device_token, TOKEN_B);
    }

    #[tokio::test]
    async fn unregister_deletes_the_persisted_row() {
        let db = TempDb::new();
        {
            let (store, _) = open(&db, KEY, 48);
            store
                .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
                .await;
            assert!(store.unregister(PK_A).await);
        }

        let (store, report) = open(&db, KEY, 48);

        assert_eq!(report.restored, 0);
        assert!(store.get(PK_A).await.is_none());
    }

    #[tokio::test]
    async fn expired_rows_are_purged_when_loading() {
        let db = TempDb::new();
        {
            let sqlite = SqliteStore::open(&db.0, TokenCipher::from_hex(KEY).unwrap()).unwrap();
            let old = RegisteredToken {
                device_token: TOKEN_A.into(),
                platform: Platform::Android,
                registered_at: Utc::now() - chrono::Duration::hours(49),
            };
            sqlite.upsert(PK_A.into(), old).await.unwrap();
            let fresh = RegisteredToken {
                device_token: TOKEN_B.into(),
                platform: Platform::Android,
                registered_at: Utc::now(),
            };
            sqlite.upsert(PK_B.into(), fresh).await.unwrap();
        }

        let (store, report) = open(&db, KEY, 48);

        assert_eq!(report.expired, 1);
        assert_eq!(report.restored, 1);
        assert!(store.get(PK_A).await.is_none());
        assert!(store.get(PK_B).await.is_some());
    }

    #[tokio::test]
    async fn cleanup_deletes_expired_rows_from_disk() {
        let db = TempDb::new();
        {
            // A zero TTL expires everything registered before the cleanup.
            let (store, _) = open(&db, KEY, 0);
            store
                .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
                .await;
            tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
            assert_eq!(store.cleanup_expired().await, 1);
        }

        let (store, report) = open(&db, KEY, 48);

        assert_eq!(report.restored, 0);
        assert!(store.get(PK_A).await.is_none());
    }

    #[tokio::test]
    async fn a_changed_key_discards_every_row() {
        let db = TempDb::new();
        {
            let (store, _) = open(&db, KEY, 48);
            store
                .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
                .await;
        }

        let (store, report) = open(&db, OTHER_KEY, 48);
        assert!(report.key_changed);
        assert_eq!(report.restored, 0);
        assert!(store.get(PK_A).await.is_none());
        drop(store);

        // The new key is now the recorded one.
        let (_, report) = open(&db, OTHER_KEY, 48);
        assert!(!report.key_changed);
    }

    #[tokio::test]
    async fn unreadable_rows_are_discarded() {
        let db = TempDb::new();
        {
            let (store, _) = open(&db, KEY, 48);
            store
                .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
                .await;
            store
                .register(PK_B.into(), TOKEN_B.into(), Platform::Android)
                .await;
        }
        rusqlite::Connection::open(&db.0)
            .unwrap()
            .execute(
                "UPDATE tokens SET token_ct = x'00' WHERE trade_pubkey = ?1",
                [PK_A],
            )
            .unwrap();

        let (store, report) = open(&db, KEY, 48);

        assert_eq!(report.discarded, 1);
        assert_eq!(report.restored, 1);
        assert!(store.get(PK_A).await.is_none());
        assert!(store.get(PK_B).await.is_some());
    }

    #[tokio::test]
    async fn the_database_never_holds_a_device_token_in_clear() {
        let db = TempDb::new();
        let (store, _) = open(&db, KEY, 48);
        store
            .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
            .await;

        // Checked while the connection is open, WAL included.
        assert!(!contains(&db.all_bytes(), TOKEN_A));
        drop(store);
        assert!(!contains(&db.all_bytes(), TOKEN_A));
    }

    #[tokio::test]
    async fn unregistered_rows_leave_no_trace_on_disk() {
        let db = TempDb::new();
        {
            let (store, _) = open(&db, KEY, 48);
            store
                .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
                .await;
            store
                .register(PK_B.into(), TOKEN_B.into(), Platform::Android)
                .await;
            store.unregister(PK_A).await;
        }
        // Reopening checkpoints the WAL into the file.
        drop(open(&db, KEY, 48));

        let bytes = db.all_bytes();
        assert!(!contains(&bytes, PK_A), "secure_delete must zero the row");
        assert!(contains(&bytes, PK_B));
    }

    #[tokio::test]
    async fn in_memory_store_keeps_working_without_persistence() {
        let store = TokenStore::new(48, salt());
        store
            .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
            .await;
        assert_eq!(store.get(PK_A).await.unwrap().device_token, TOKEN_A);
        assert!(store.unregister(PK_A).await);
        assert!(store.get(PK_A).await.is_none());
    }
}
