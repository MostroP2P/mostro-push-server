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
    /// A browser registered through FCM Web Push; delivered by FCM only.
    Web,
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Android => write!(f, "android"),
            Platform::Ios => write!(f, "ios"),
            Platform::Web => write!(f, "web"),
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
    /// Registrations accepted for new trade pubkeys. Bounds memory and disk
    /// use against unauthenticated floods of made-up pubkeys.
    max_tokens: usize,
}

/// Default for `MAX_TOKENS`, well above the ~800 live registrations seen in
/// production.
pub const DEFAULT_MAX_TOKENS: usize = 50_000;

/// A new trade pubkey was refused because the store holds `max_tokens`.
#[derive(Debug, PartialEq, Eq)]
pub struct StoreFull;

impl std::fmt::Display for StoreFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "token store is full")
    }
}

impl std::error::Error for StoreFull {}

impl TokenStore {
    /// In-memory store: registrations are lost on restart.
    pub fn new(ttl_hours: u64, log_salt: Arc<[u8; 32]>) -> Self {
        Self {
            tokens: RwLock::new(HashMap::new()),
            ttl_hours,
            log_salt,
            persistence: None,
            write_order: Mutex::new(()),
            max_tokens: DEFAULT_MAX_TOKENS,
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
            max_tokens: DEFAULT_MAX_TOKENS,
        };
        Ok((store, report))
    }

    /// Caps registrations for new trade pubkeys; see [`StoreFull`].
    pub fn with_max_tokens(mut self, max_tokens: usize) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    /// Registers or refreshes `trade_pubkey`. Refreshing an existing entry is
    /// always accepted, so a full store never cuts off a device already
    /// registered; only new pubkeys are refused.
    pub async fn register(
        &self,
        trade_pubkey: String,
        device_token: String,
        platform: Platform,
    ) -> Result<(), StoreFull> {
        let token = RegisteredToken {
            device_token,
            platform,
            registered_at: Utc::now(),
        };
        let log_pk = log_pubkey(&self.log_salt, &trade_pubkey);

        let _order = self.write_order.lock().await;
        let total = {
            let mut tokens = self.tokens.write().await;
            if tokens.len() >= self.max_tokens && !tokens.contains_key(&trade_pubkey) {
                warn!(
                    "Token store full ({} entries), refusing pk={}",
                    tokens.len(),
                    log_pk
                );
                return Err(StoreFull);
            }
            tokens.insert(trade_pubkey.clone(), token.clone());
            tokens.len()
        };
        info!("Registered token pk={} (total: {})", log_pk, total);

        if let Some(db) = &self.persistence {
            // The registration still works from memory; only a restart loses it.
            if let Err(e) = db.upsert(trade_pubkey, token).await {
                error!("Failed to persist token pk={}: {}", log_pk, e);
            }
        }
        Ok(())
    }

    /// Removes `trade_pubkey` and reports whether it was registered.
    ///
    /// With persistence the row is deleted from disk first. If that fails,
    /// memory is left untouched and the error is returned: acknowledging the
    /// unregister anyway would let the next restart restore the registration.
    pub async fn unregister(&self, trade_pubkey: &str) -> Result<bool, PersistError> {
        let _order = self.write_order.lock().await;
        let log_pk = log_pubkey(&self.log_salt, trade_pubkey);

        if let Some(db) = &self.persistence {
            // Deleted even when absent from memory, so no stale row survives.
            if let Err(e) = db.delete(trade_pubkey.to_string()).await {
                error!("Failed to delete persisted token pk={}: {}", log_pk, e);
                return Err(e);
            }
        }

        let (removed, total) = {
            let mut tokens = self.tokens.write().await;
            (tokens.remove(trade_pubkey).is_some(), tokens.len())
        };
        if removed {
            info!("Unregistered token pk={} (total: {})", log_pk, total);
        } else {
            debug!("Token not found pk={}", log_pk);
        }

        Ok(removed)
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
        let mut web_count = 0;

        for token in tokens.values() {
            match token.platform {
                Platform::Android => android_count += 1,
                Platform::Ios => ios_count += 1,
                Platform::Web => web_count += 1,
            }
        }

        TokenStoreStats {
            total: tokens.len(),
            android: android_count,
            ios: ios_count,
            web: web_count,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TokenStoreStats {
    pub total: usize,
    pub android: usize,
    pub ios: usize,
    /// Omitted while zero, so `/api/status` stays byte-identical to the
    /// pre-1.1 fixtures until a browser actually registers (hard constraint 3).
    #[serde(skip_serializing_if = "is_zero")]
    pub web: usize,
}

fn is_zero(count: &usize) -> bool {
    *count == 0
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
                .await
                .unwrap();
            store
                .register(PK_B.into(), TOKEN_B.into(), Platform::Ios)
                .await
                .unwrap();
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
    async fn a_web_registration_survives_a_restart() {
        let db = TempDb::new();
        {
            let (store, _) = open(&db, KEY, 48);
            store
                .register(PK_A.into(), TOKEN_A.into(), Platform::Web)
                .await
                .unwrap();
        }

        let (store, report) = open(&db, KEY, 48);

        assert_eq!(report.restored, 1);
        assert_eq!(report.discarded, 0);
        let a = store.get(PK_A).await.unwrap();
        assert_eq!(a.device_token, TOKEN_A);
        assert_eq!(a.platform, Platform::Web);
    }

    #[tokio::test]
    async fn stats_count_each_platform() {
        let store = TokenStore::new(48, salt());
        store
            .register(PK_A.into(), TOKEN_A.into(), Platform::Web)
            .await
            .unwrap();
        store
            .register(PK_B.into(), TOKEN_B.into(), Platform::Android)
            .await
            .unwrap();

        let stats = store.get_stats().await;

        assert_eq!(stats.total, 2);
        assert_eq!(stats.android, 1);
        assert_eq!(stats.ios, 0);
        assert_eq!(stats.web, 1);
    }

    #[test]
    fn stats_omit_web_only_while_it_is_zero() {
        let mut stats = TokenStoreStats {
            total: 1,
            android: 1,
            ios: 0,
            web: 0,
        };
        assert_eq!(
            serde_json::to_string(&stats).unwrap(),
            r#"{"total":1,"android":1,"ios":0}"#
        );

        stats.total = 2;
        stats.web = 1;
        assert_eq!(
            serde_json::to_string(&stats).unwrap(),
            r#"{"total":2,"android":1,"ios":0,"web":1}"#
        );
    }

    #[tokio::test]
    async fn re_registering_replaces_the_persisted_token() {
        let db = TempDb::new();
        {
            let (store, _) = open(&db, KEY, 48);
            store
                .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
                .await
                .unwrap();
            store
                .register(PK_A.into(), TOKEN_B.into(), Platform::Android)
                .await
                .unwrap();
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
                .await
                .unwrap();
            assert!(store.unregister(PK_A).await.unwrap());
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
                .await
                .unwrap();
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
                .await
                .unwrap();
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
                .await
                .unwrap();
            store
                .register(PK_B.into(), TOKEN_B.into(), Platform::Android)
                .await
                .unwrap();
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
            .await
            .unwrap();

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
                .await
                .unwrap();
            store
                .register(PK_B.into(), TOKEN_B.into(), Platform::Android)
                .await
                .unwrap();
            store.unregister(PK_A).await.unwrap();
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
            .await
            .unwrap();
        assert_eq!(store.get(PK_A).await.unwrap().device_token, TOKEN_A);
        assert!(store.unregister(PK_A).await.unwrap());
        assert!(store.get(PK_A).await.is_none());
    }

    #[tokio::test]
    async fn a_full_store_refuses_new_pubkeys_but_accepts_refreshes() {
        let store = TokenStore::new(48, salt()).with_max_tokens(1);
        store
            .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
            .await
            .unwrap();

        assert_eq!(
            store
                .register(PK_B.into(), TOKEN_B.into(), Platform::Android)
                .await,
            Err(StoreFull)
        );
        assert!(store.get(PK_B).await.is_none());

        // A registered device can always refresh, even with the store full.
        store
            .register(PK_A.into(), TOKEN_B.into(), Platform::Android)
            .await
            .unwrap();
        assert_eq!(store.get(PK_A).await.unwrap().device_token, TOKEN_B);

        // Unregistering frees the slot.
        store.unregister(PK_A).await.unwrap();
        store
            .register(PK_B.into(), TOKEN_B.into(), Platform::Android)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_refused_registration_is_not_persisted() {
        let db = TempDb::new();
        {
            let (store, _) = open(&db, KEY, 48);
            let store = store.with_max_tokens(1);
            store
                .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
                .await
                .unwrap();
            assert!(store
                .register(PK_B.into(), TOKEN_B.into(), Platform::Android)
                .await
                .is_err());
        }

        let (store, report) = open(&db, KEY, 48);

        assert_eq!(report.restored, 1);
        assert!(store.get(PK_B).await.is_none());
    }

    /// Makes every DELETE on `tokens` fail, like a full or failing disk.
    fn inject_delete_failure(db: &TempDb) {
        rusqlite::Connection::open(&db.0)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_delete BEFORE DELETE ON tokens
                 BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END;",
            )
            .unwrap();
    }

    fn clear_delete_failure(db: &TempDb) {
        rusqlite::Connection::open(&db.0)
            .unwrap()
            .execute_batch("DROP TRIGGER fail_delete;")
            .unwrap();
    }

    #[tokio::test]
    async fn a_failed_durable_delete_is_reported_and_changes_nothing() {
        let db = TempDb::new();
        let (store, _) = open(&db, KEY, 48);
        store
            .register(PK_A.into(), TOKEN_A.into(), Platform::Android)
            .await
            .unwrap();

        inject_delete_failure(&db);
        assert!(store.unregister(PK_A).await.is_err());
        // Still registered, in memory and on disk, so nothing claimed a
        // deletion that a restart would undo.
        assert!(store.get(PK_A).await.is_some());

        clear_delete_failure(&db);
        assert!(store.unregister(PK_A).await.unwrap());
        drop(store);

        let (store, report) = open(&db, KEY, 48);
        assert_eq!(report.restored, 0);
        assert!(store.get(PK_A).await.is_none());
    }
}
