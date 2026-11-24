//! Devices watching a Mostro node for new disputes.
//!
//! [`TokenStore`](super::TokenStore) maps one trade pubkey to one device. A
//! dispute is announced by the node and names no solver, so it goes to every
//! device that asked to watch that node: this store is node → devices.
//!
//! In memory always, and mirrored to SQLite when the token store is. Reads
//! never touch the disk.

use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use super::sqlite::{PersistError, SqliteStore, WatcherLoadReport};
use super::Platform;
use crate::utils::log_pubkey::log_pubkey;

/// How long a watch lasts since it was last asked for.
pub const WATCH_TTL_DAYS: i64 = 30;

/// Default for `MAX_WATCHERS_PER_NODE`. Far above the solvers a node has: the
/// cap bounds the fan-out of one dispute, and a list that is easy to fill
/// locks the real solvers out.
pub const DEFAULT_MAX_WATCHERS_PER_NODE: usize = 1_000;

/// Default for `MAX_WATCHERS`, across every node.
pub const DEFAULT_MAX_WATCHERS: usize = 10_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Watcher {
    pub device_token: String,
    pub platform: Platform,
    pub watched_at: DateTime<Utc>,
}

/// Why a watch was not stored.
#[derive(Debug)]
pub enum WatchError {
    /// A new watch was refused: the node's list, or the whole store, is full.
    Full,
    /// The watch could not be written to disk, and nothing was changed.
    Persist(PersistError),
}

impl std::fmt::Display for WatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatchError::Full => write!(f, "watcher store is full"),
            WatchError::Persist(e) => write!(f, "watch not persisted: {}", e),
        }
    }
}

impl std::error::Error for WatchError {}

/// Node pubkey → device token → watcher.
type Nodes = HashMap<String, HashMap<String, Watcher>>;

pub struct WatcherStore {
    nodes: RwLock<Nodes>,
    log_salt: Arc<[u8; 32]>,
    /// Durable copy of `nodes`; `None` keeps the watches in memory only.
    persistence: Option<SqliteStore>,
    /// Held across a mutation and its durable write, as in `TokenStore`.
    write_order: Mutex<()>,
    max_per_node: usize,
    max_total: usize,
}

impl WatcherStore {
    /// In-memory store: watches are lost on restart.
    pub fn new(log_salt: Arc<[u8; 32]>) -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            log_salt,
            persistence: None,
            write_order: Mutex::new(()),
            max_per_node: DEFAULT_MAX_WATCHERS_PER_NODE,
            max_total: DEFAULT_MAX_WATCHERS,
        }
    }

    /// Store backed by `db`: live watches are loaded from it, and every later
    /// change is written to it.
    pub fn persistent(
        log_salt: Arc<[u8; 32]>,
        db: SqliteStore,
    ) -> Result<(Self, WatcherLoadReport), PersistError> {
        let (entries, report) = db.load_watchers(Utc::now() - ttl())?;
        let mut nodes = Nodes::new();
        for (mostro_pubkey, watcher) in entries {
            nodes
                .entry(mostro_pubkey)
                .or_default()
                .insert(watcher.device_token.clone(), watcher);
        }
        let store = Self {
            nodes: RwLock::new(nodes),
            persistence: Some(db),
            ..Self::new(log_salt)
        };
        Ok((store, report))
    }

    /// Caps new watches, per node and in total; see [`WatchError::Full`].
    pub fn with_caps(mut self, max_per_node: usize, max_total: usize) -> Self {
        self.max_per_node = max_per_node;
        self.max_total = max_total;
        self
    }

    /// Whether `device_token` already watches `mostro_pubkey`.
    pub async fn is_watching(&self, mostro_pubkey: &str, device_token: &str) -> bool {
        self.nodes
            .read()
            .await
            .get(mostro_pubkey)
            .is_some_and(|devices| devices.contains_key(device_token))
    }

    /// Whether a new device could watch `mostro_pubkey` right now. Asked
    /// before the token is checked with FCM, so a full list costs no request;
    /// [`watch`](Self::watch) decides again when it stores.
    pub async fn has_room(&self, mostro_pubkey: &str) -> bool {
        has_room(
            &*self.nodes.read().await,
            mostro_pubkey,
            self.max_per_node,
            self.max_total,
        )
    }

    /// Adds `device_token` to the watchers of `mostro_pubkey`, or renews its
    /// lifetime. Renewing is always accepted, so a full list never cuts off a
    /// device already on it; only new watches are refused.
    ///
    /// With persistence the row is written first. If that fails, memory is
    /// left untouched and the error is returned: a watch lasts 30 days, so
    /// acknowledging one that the next restart drops would leave a solver
    /// without notifications and unaware of it.
    pub async fn watch(
        &self,
        mostro_pubkey: String,
        device_token: String,
        platform: Platform,
    ) -> Result<(), WatchError> {
        let watcher = Watcher {
            device_token,
            platform,
            watched_at: Utc::now(),
        };
        let log_node = log_pubkey(&self.log_salt, &mostro_pubkey);

        // Every change holds `write_order`, so what is decided here still
        // holds when the watch is inserted below.
        let _order = self.write_order.lock().await;
        let renewed = {
            let nodes = self.nodes.read().await;
            let renewed = nodes
                .get(&mostro_pubkey)
                .is_some_and(|devices| devices.contains_key(&watcher.device_token));
            if !renewed && !has_room(&nodes, &mostro_pubkey, self.max_per_node, self.max_total) {
                warn!("Watcher store full, refusing a watch of node={}", log_node);
                return Err(WatchError::Full);
            }
            renewed
        };

        if let Some(db) = &self.persistence {
            if let Err(e) = db
                .upsert_watcher(mostro_pubkey.clone(), watcher.clone())
                .await
            {
                error!("Failed to persist a watch of node={}: {}", log_node, e);
                return Err(WatchError::Persist(e));
            }
        }

        let on_node = {
            let mut nodes = self.nodes.write().await;
            let devices = nodes.entry(mostro_pubkey).or_default();
            devices.insert(watcher.device_token.clone(), watcher);
            devices.len()
        };
        if renewed {
            debug!("Renewed a watch of node={}", log_node);
        } else {
            info!("Watching node={} (devices: {})", log_node, on_node);
        }
        Ok(())
    }

    /// Removes the watch and reports whether it existed.
    ///
    /// With persistence the row is deleted from disk first. If that fails,
    /// memory is left untouched and the error is returned: acknowledging the
    /// unwatch anyway would let the next restart restore it.
    pub async fn unwatch(
        &self,
        mostro_pubkey: &str,
        device_token: &str,
    ) -> Result<bool, PersistError> {
        let _order = self.write_order.lock().await;
        let log_node = log_pubkey(&self.log_salt, mostro_pubkey);

        if let Some(db) = &self.persistence {
            // Deleted even when absent from memory, so no stale row survives.
            if let Err(e) = db.delete_watcher(mostro_pubkey, device_token).await {
                error!(
                    "Failed to delete a persisted watch of node={}: {}",
                    log_node, e
                );
                return Err(e);
            }
        }

        let removed = {
            let mut nodes = self.nodes.write().await;
            let removed = nodes
                .get_mut(mostro_pubkey)
                .is_some_and(|devices| devices.remove(device_token).is_some());
            if nodes.get(mostro_pubkey).is_some_and(HashMap::is_empty) {
                nodes.remove(mostro_pubkey);
            }
            removed
        };
        if removed {
            info!("Stopped watching node={}", log_node);
        } else {
            debug!("No such watch of node={}", log_node);
        }
        Ok(removed)
    }

    /// Drops the watches of every node that is not in `trusted`, and reports
    /// how many. A node taken off the trusted list is never rung for again
    /// and its watches cannot be renewed, so nothing is kept of them.
    pub async fn forget_untrusted(&self, trusted: &HashSet<String>) -> usize {
        let _order = self.write_order.lock().await;

        let untrusted: Vec<(String, usize)> = {
            let mut nodes = self.nodes.write().await;
            let untrusted: Vec<String> = nodes
                .keys()
                .filter(|node| !trusted.contains(*node))
                .cloned()
                .collect();
            untrusted
                .into_iter()
                .filter_map(|node| nodes.remove(&node).map(|devices| (node, devices.len())))
                .collect()
        };

        let mut removed = 0;
        for (node, devices) in untrusted {
            removed += devices;
            let log_node = log_pubkey(&self.log_salt, &node);
            warn!(
                "Dropped {} dispute watches of node={}, which is not trusted",
                devices, log_node
            );
            if let Some(db) = &self.persistence {
                // Left on disk, they are dropped again at the next start.
                if let Err(e) = db.delete_watchers_of(node).await {
                    error!("Failed to delete the watches of node={}: {}", log_node, e);
                }
            }
        }
        removed
    }

    pub async fn cleanup_expired(&self) -> usize {
        let _order = self.write_order.lock().await;
        let cutoff = Utc::now() - ttl();

        let removed = {
            let mut nodes = self.nodes.write().await;
            let before = total(&nodes);
            for devices in nodes.values_mut() {
                devices.retain(|_, watcher| watcher.watched_at >= cutoff);
            }
            nodes.retain(|_, devices| !devices.is_empty());
            before - total(&nodes)
        };
        if removed > 0 {
            info!("Cleaned up {} expired dispute watches", removed);
        }

        if let Some(db) = &self.persistence {
            if let Err(e) = db.delete_expired_watchers(cutoff).await {
                error!("Failed to delete expired persisted watches: {}", e);
            }
        }
        removed
    }

    #[cfg(test)]
    pub async fn count(&self) -> usize {
        total(&*self.nodes.read().await)
    }
}

fn ttl() -> chrono::Duration {
    chrono::Duration::days(WATCH_TTL_DAYS)
}

fn total(nodes: &Nodes) -> usize {
    nodes.values().map(HashMap::len).sum()
}

fn has_room(nodes: &Nodes, mostro_pubkey: &str, max_per_node: usize, max_total: usize) -> bool {
    let on_node = nodes.get(mostro_pubkey).map_or(0, HashMap::len);
    on_node < max_per_node && total(nodes) < max_total
}

pub fn start_cleanup_task(store: Arc<WatcherStore>, interval_hours: u64) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(interval_hours * 3600));

        loop {
            interval.tick().await;
            store.cleanup_expired().await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::super::cipher::TokenCipher;
    use super::super::TokenStore;
    use super::*;
    use std::path::PathBuf;

    const KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const OTHER_KEY: &str = "0202020202020202020202020202020202020202020202020202020202020202";
    const NODE_A: &str = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345abc";
    const NODE_B: &str = "b1b2c3d4e5f67890123456789012345678901234567890123456789012345abc";
    const TOKEN_1: &str = "fcm-token-for-device-1:APA91bHexample1";
    const TOKEN_2: &str = "fcm-token-for-device-2:APA91bHexample2";
    const TOKEN_3: &str = "fcm-token-for-device-3:APA91bHexample3";

    fn salt() -> Arc<[u8; 32]> {
        Arc::new([7u8; 32])
    }

    async fn watch(store: &WatcherStore, node: &str, token: &str) -> Result<(), WatchError> {
        store
            .watch(node.into(), token.into(), Platform::Android)
            .await
    }

    /// Moves a watch into the past, in memory.
    async fn age(store: &WatcherStore, node: &str, token: &str, days: i64) {
        let mut nodes = store.nodes.write().await;
        let watcher = nodes.get_mut(node).unwrap().get_mut(token).unwrap();
        watcher.watched_at = Utc::now() - chrono::Duration::days(days);
    }

    #[tokio::test]
    async fn a_device_watches_a_node_and_stops() {
        let store = WatcherStore::new(salt());
        assert!(!store.is_watching(NODE_A, TOKEN_1).await);

        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        assert!(store.is_watching(NODE_A, TOKEN_1).await);
        // A watch is of one node, by one device.
        assert!(!store.is_watching(NODE_B, TOKEN_1).await);
        assert!(!store.is_watching(NODE_A, TOKEN_2).await);

        assert!(store.unwatch(NODE_A, TOKEN_1).await.unwrap());
        assert!(!store.is_watching(NODE_A, TOKEN_1).await);
        assert!(!store.unwatch(NODE_A, TOKEN_1).await.unwrap());
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn one_device_can_watch_several_nodes() {
        let store = WatcherStore::new(salt());
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_B, TOKEN_1).await.unwrap();
        assert_eq!(store.count().await, 2);

        assert!(store.unwatch(NODE_A, TOKEN_1).await.unwrap());
        assert!(store.is_watching(NODE_B, TOKEN_1).await);
    }

    #[tokio::test]
    async fn watching_again_renews_the_lifetime_and_adds_nothing() {
        let store = WatcherStore::new(salt());
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        age(&store, NODE_A, TOKEN_1, WATCH_TTL_DAYS - 1).await;

        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        assert_eq!(store.count().await, 1);

        // It would have expired tomorrow; renewed, it does not.
        assert_eq!(store.cleanup_expired().await, 0);
        let nodes = store.nodes.read().await;
        let age = Utc::now() - nodes[NODE_A][TOKEN_1].watched_at;
        assert!(age < chrono::Duration::minutes(1));
    }

    #[tokio::test]
    async fn a_watch_expires_thirty_days_after_it_was_last_asked_for() {
        let store = WatcherStore::new(salt());
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_A, TOKEN_2).await.unwrap();
        age(&store, NODE_A, TOKEN_1, WATCH_TTL_DAYS + 1).await;
        age(&store, NODE_A, TOKEN_2, WATCH_TTL_DAYS - 1).await;

        assert_eq!(store.cleanup_expired().await, 1);
        assert!(!store.is_watching(NODE_A, TOKEN_1).await);
        assert!(store.is_watching(NODE_A, TOKEN_2).await);
    }

    #[tokio::test]
    async fn the_watches_of_a_node_that_is_no_longer_trusted_are_dropped() {
        let store = WatcherStore::new(salt());
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_A, TOKEN_2).await.unwrap();
        watch(&store, NODE_B, TOKEN_1).await.unwrap();

        let trusted = HashSet::from([NODE_B.to_string()]);
        assert_eq!(store.forget_untrusted(&trusted).await, 2);
        assert!(!store.is_watching(NODE_A, TOKEN_1).await);
        assert!(store.is_watching(NODE_B, TOKEN_1).await);
        assert_eq!(store.forget_untrusted(&trusted).await, 0);
    }

    #[tokio::test]
    async fn a_full_node_refuses_new_devices_but_renews_its_own() {
        let store = WatcherStore::new(salt()).with_caps(2, 10);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_A, TOKEN_2).await.unwrap();

        assert!(!store.has_room(NODE_A).await);
        assert!(matches!(
            watch(&store, NODE_A, TOKEN_3).await,
            Err(WatchError::Full)
        ));
        assert!(!store.is_watching(NODE_A, TOKEN_3).await);

        // A device already on the list is never cut off by the cap.
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        // Another node has its own list.
        assert!(store.has_room(NODE_B).await);
        watch(&store, NODE_B, TOKEN_3).await.unwrap();

        // A place frees up when a device leaves.
        assert!(store.unwatch(NODE_A, TOKEN_2).await.unwrap());
        watch(&store, NODE_A, TOKEN_3).await.unwrap();
    }

    #[tokio::test]
    async fn a_full_store_refuses_new_watches_on_every_node() {
        let store = WatcherStore::new(salt()).with_caps(10, 2);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_B, TOKEN_1).await.unwrap();

        assert!(!store.has_room(NODE_A).await);
        assert!(!store.has_room(NODE_B).await);
        assert!(matches!(
            watch(&store, NODE_A, TOKEN_2).await,
            Err(WatchError::Full)
        ));
        watch(&store, NODE_B, TOKEN_1).await.unwrap();
        assert_eq!(store.count().await, 2);
    }

    /// A database path unique to one test; the file and its WAL/SHM
    /// companions are removed on drop.
    struct TempDb(PathBuf);

    impl TempDb {
        fn new() -> Self {
            Self(std::env::temp_dir().join(format!(
                "mostro-push-watchers-test-{}.db",
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

        fn sql(&self, sql: &str) {
            rusqlite::Connection::open(&self.0)
                .unwrap()
                .execute_batch(sql)
                .unwrap();
        }

        fn query<T: rusqlite::types::FromSql>(&self, sql: &str) -> T {
            rusqlite::Connection::open(&self.0)
                .unwrap()
                .query_row(sql, [], |row| row.get(0))
                .unwrap()
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{}", self.0.display(), suffix));
            }
        }
    }

    fn sqlite(db: &TempDb, key: &str) -> SqliteStore {
        SqliteStore::open(&db.0, TokenCipher::from_hex(key).unwrap()).unwrap()
    }

    fn open(db: &TempDb, key: &str) -> (WatcherStore, WatcherLoadReport) {
        WatcherStore::persistent(salt(), sqlite(db, key)).unwrap()
    }

    fn contains(haystack: &[u8], needle: &str) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
    }

    #[tokio::test]
    async fn watches_survive_a_restart() {
        let db = TempDb::new();
        let (store, report) = open(&db, KEY);
        assert_eq!(report, WatcherLoadReport::default());
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_A, TOKEN_2).await.unwrap();
        watch(&store, NODE_B, TOKEN_1).await.unwrap();
        drop(store);

        let (store, report) = open(&db, KEY);
        assert_eq!(report.restored, 3);
        assert!(store.is_watching(NODE_A, TOKEN_1).await);
        assert!(store.is_watching(NODE_A, TOKEN_2).await);
        assert!(store.is_watching(NODE_B, TOKEN_1).await);
        let nodes = store.nodes.read().await;
        assert_eq!(nodes[NODE_A][TOKEN_1].platform, Platform::Android);
    }

    #[tokio::test]
    async fn an_unwatch_survives_a_restart() {
        let db = TempDb::new();
        let (store, _) = open(&db, KEY);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_A, TOKEN_2).await.unwrap();
        assert!(store.unwatch(NODE_A, TOKEN_1).await.unwrap());
        drop(store);

        let (store, report) = open(&db, KEY);
        assert_eq!(report.restored, 1);
        assert!(!store.is_watching(NODE_A, TOKEN_1).await);
        assert!(store.is_watching(NODE_A, TOKEN_2).await);
    }

    #[tokio::test]
    async fn the_file_holds_no_token_and_does_not_link_a_device_across_nodes() {
        let db = TempDb::new();
        let (store, _) = open(&db, KEY);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_B, TOKEN_1).await.unwrap();
        drop(store);

        assert!(!contains(&db.all_bytes(), TOKEN_1));
        // The same device on two nodes: nothing stored is equal between its
        // two rows.
        for column in ["id", "nonce", "token_ct"] {
            let distinct: i64 = db.query(&format!("SELECT COUNT(DISTINCT {column}) FROM watchers"));
            assert_eq!(distinct, 2, "{column}");
        }
    }

    #[tokio::test]
    async fn renewing_updates_the_row_instead_of_adding_one() {
        let db = TempDb::new();
        let (store, _) = open(&db, KEY);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        db.sql("UPDATE watchers SET watched_at = 1000");

        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        drop(store);

        assert_eq!(db.query::<i64>("SELECT COUNT(*) FROM watchers"), 1);
        assert!(db.query::<i64>("SELECT watched_at FROM watchers") > 1000);
    }

    #[tokio::test]
    async fn expired_watches_are_purged_at_startup_and_by_the_cleanup() {
        let db = TempDb::new();
        let (store, _) = open(&db, KEY);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_A, TOKEN_2).await.unwrap();
        drop(store);
        let long_ago = (Utc::now() - chrono::Duration::days(WATCH_TTL_DAYS + 1)).timestamp();
        db.sql(&format!(
            "UPDATE watchers SET watched_at = {long_ago}
             WHERE id = (SELECT id FROM watchers LIMIT 1)"
        ));

        let (store, report) = open(&db, KEY);
        assert_eq!(report.expired, 1);
        assert_eq!(report.restored, 1);
        assert_eq!(db.query::<i64>("SELECT COUNT(*) FROM watchers"), 1);

        // The periodic cleanup deletes the row too, not only the entry.
        let token = if store.is_watching(NODE_A, TOKEN_1).await {
            TOKEN_1
        } else {
            TOKEN_2
        };
        age(&store, NODE_A, token, WATCH_TTL_DAYS + 1).await;
        db.sql(&format!("UPDATE watchers SET watched_at = {long_ago}"));
        assert_eq!(store.cleanup_expired().await, 1);
        assert_eq!(db.query::<i64>("SELECT COUNT(*) FROM watchers"), 0);
    }

    #[tokio::test]
    async fn rows_that_cannot_be_read_are_discarded() {
        let db = TempDb::new();
        let (store, _) = open(&db, KEY);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_A, TOKEN_2).await.unwrap();
        watch(&store, NODE_B, TOKEN_3).await.unwrap();
        drop(store);
        // One row whose ciphertext was damaged, and one filed under an id
        // that is not its own: it could never be renewed or deleted.
        db.sql(&format!(
            "UPDATE watchers SET token_ct = x'00' WHERE mostro_pubkey = '{NODE_B}';
             UPDATE watchers SET id = x'ABCD'
             WHERE id = (SELECT id FROM watchers WHERE mostro_pubkey = '{NODE_A}' LIMIT 1);"
        ));

        let (store, report) = open(&db, KEY);
        assert_eq!(report.discarded, 2);
        assert_eq!(report.restored, 1);
        assert_eq!(store.count().await, 1);
        assert_eq!(db.query::<i64>("SELECT COUNT(*) FROM watchers"), 1);
    }

    #[tokio::test]
    async fn a_changed_key_discards_watches_and_registrations_together() {
        for watchers_load_first in [false, true] {
            let db = TempDb::new();
            {
                let sqlite = sqlite(&db, KEY);
                let (tokens, _) = TokenStore::persistent(48, salt(), sqlite.clone()).unwrap();
                let (watchers, _) = WatcherStore::persistent(salt(), sqlite).unwrap();
                tokens
                    .register(NODE_B.into(), TOKEN_2.into(), Platform::Android)
                    .await
                    .unwrap();
                watch(&watchers, NODE_A, TOKEN_1).await.unwrap();
            }

            let sqlite = sqlite(&db, OTHER_KEY);
            let (token_report, watcher_report) = if watchers_load_first {
                let (_, w) = WatcherStore::persistent(salt(), sqlite.clone()).unwrap();
                let (_, t) = TokenStore::persistent(48, salt(), sqlite).unwrap();
                (t, w)
            } else {
                let (_, t) = TokenStore::persistent(48, salt(), sqlite.clone()).unwrap();
                let (_, w) = WatcherStore::persistent(salt(), sqlite).unwrap();
                (t, w)
            };

            // Whichever load ran first found the change and wiped both.
            assert_eq!(watcher_report.key_changed, watchers_load_first);
            assert_eq!(token_report.key_changed, !watchers_load_first);
            assert_eq!(watcher_report.restored, 0);
            assert_eq!(token_report.restored, 0);
            // Wiped, not left to fail row by row.
            assert_eq!(watcher_report.discarded, 0);
            assert_eq!(token_report.discarded, 0);
            assert_eq!(db.query::<i64>("SELECT COUNT(*) FROM watchers"), 0);
            assert_eq!(db.query::<i64>("SELECT COUNT(*) FROM tokens"), 0);
        }
    }

    #[tokio::test]
    async fn dropping_an_untrusted_node_deletes_its_rows() {
        let db = TempDb::new();
        let (store, _) = open(&db, KEY);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_A, TOKEN_2).await.unwrap();
        watch(&store, NODE_B, TOKEN_1).await.unwrap();

        let trusted = HashSet::from([NODE_B.to_string()]);
        assert_eq!(store.forget_untrusted(&trusted).await, 2);
        drop(store);

        assert_eq!(db.query::<i64>("SELECT COUNT(*) FROM watchers"), 1);
        let (store, report) = open(&db, KEY);
        assert_eq!(report.restored, 1);
        assert!(store.is_watching(NODE_B, TOKEN_1).await);
    }

    /// A file written before the `watchers` table existed.
    #[tokio::test]
    async fn a_schema_1_file_gains_the_table_and_keeps_its_registrations() {
        let db = TempDb::new();
        {
            let (tokens, _) = TokenStore::persistent(48, salt(), sqlite(&db, KEY)).unwrap();
            tokens
                .register(NODE_B.into(), TOKEN_2.into(), Platform::Android)
                .await
                .unwrap();
        }
        db.sql("DROP TABLE watchers; PRAGMA user_version = 1;");

        let sqlite = sqlite(&db, KEY);
        let (tokens, token_report) = TokenStore::persistent(48, salt(), sqlite.clone()).unwrap();
        let (watchers, watcher_report) = WatcherStore::persistent(salt(), sqlite).unwrap();

        assert_eq!(db.query::<i64>("PRAGMA user_version"), 2);
        assert_eq!(token_report.restored, 1);
        assert!(!token_report.key_changed);
        assert_eq!(tokens.get(NODE_B).await.unwrap().device_token, TOKEN_2);
        assert_eq!(watcher_report, WatcherLoadReport::default());
        watch(&watchers, NODE_A, TOKEN_1).await.unwrap();
        assert_eq!(db.query::<i64>("SELECT COUNT(*) FROM watchers"), 1);
    }

    #[test]
    fn a_file_of_a_newer_schema_is_refused() {
        let db = TempDb::new();
        drop(sqlite(&db, KEY));
        db.sql("PRAGMA user_version = 3;");

        let result = SqliteStore::open(&db.0, TokenCipher::from_hex(KEY).unwrap());
        assert!(matches!(result, Err(PersistError::UnsupportedSchema(3))));
    }

    #[tokio::test]
    async fn a_watch_the_disk_refused_is_reported_and_changes_nothing() {
        let db = TempDb::new();
        let (store, _) = open(&db, KEY);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        let first = store.nodes.read().await[NODE_A][TOKEN_1].watched_at;

        db.sql(
            "CREATE TRIGGER fail_insert BEFORE INSERT ON watchers
             BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;
             CREATE TRIGGER fail_update BEFORE UPDATE ON watchers
             BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;",
        );
        // A new watch is not kept in memory when it did not reach the disk.
        assert!(matches!(
            watch(&store, NODE_A, TOKEN_2).await,
            Err(WatchError::Persist(_))
        ));
        assert!(!store.is_watching(NODE_A, TOKEN_2).await);
        // A renewal that did not reach the disk leaves the watch as it was.
        assert!(matches!(
            watch(&store, NODE_A, TOKEN_1).await,
            Err(WatchError::Persist(_))
        ));
        assert_eq!(store.nodes.read().await[NODE_A][TOKEN_1].watched_at, first);

        db.sql("DROP TRIGGER fail_insert; DROP TRIGGER fail_update;");
        watch(&store, NODE_A, TOKEN_2).await.unwrap();
        drop(store);
        let (_, report) = open(&db, KEY);
        assert_eq!(report.restored, 2);
    }

    /// One device renewing several nodes at once must not write rows that
    /// share a moment: that would group them as surely as a shared id.
    #[tokio::test]
    async fn the_file_keeps_the_day_of_a_watch_and_not_its_moment() {
        let db = TempDb::new();
        let (store, _) = open(&db, KEY);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_B, TOKEN_1).await.unwrap();
        drop(store);

        let today = Utc::now().timestamp() / 86_400 * 86_400;
        assert_eq!(
            db.query::<i64>("SELECT COUNT(*) FROM watchers WHERE watched_at % 86400 = 0"),
            2
        );
        assert_eq!(
            db.query::<i64>("SELECT MAX(watched_at) FROM watchers"),
            today
        );

        // Restored from the start of its day: it can only expire early.
        let (store, _) = open(&db, KEY);
        let restored = store.nodes.read().await[NODE_A][TOKEN_1].watched_at;
        assert_eq!(restored.timestamp(), today);
    }

    #[tokio::test]
    async fn a_failed_durable_delete_is_reported_and_changes_nothing() {
        let db = TempDb::new();
        let (store, _) = open(&db, KEY);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();

        db.sql(
            "CREATE TRIGGER fail_delete BEFORE DELETE ON watchers
             BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END;",
        );
        assert!(store.unwatch(NODE_A, TOKEN_1).await.is_err());
        // Still watching, in memory and on disk, so nothing claimed a
        // deletion that a restart would undo.
        assert!(store.is_watching(NODE_A, TOKEN_1).await);

        db.sql("DROP TRIGGER fail_delete;");
        assert!(store.unwatch(NODE_A, TOKEN_1).await.unwrap());
        drop(store);

        let (store, report) = open(&db, KEY);
        assert_eq!(report.restored, 0);
        assert!(!store.is_watching(NODE_A, TOKEN_1).await);
    }
}
