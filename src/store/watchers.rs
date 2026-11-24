//! Devices watching a Mostro node for new disputes.
//!
//! [`TokenStore`](super::TokenStore) maps one trade pubkey to one device. A
//! dispute is announced by the node and names no solver, so it goes to every
//! device that asked to watch that node: this store is node → devices.
//!
//! Kept in memory.

use chrono::{DateTime, Utc};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::Platform;
use crate::utils::log_pubkey::log_pubkey;

/// How long a watch lasts since it was last asked for.
pub const WATCH_TTL_DAYS: i64 = 30;

/// Default for `MAX_WATCHERS_PER_NODE`.
pub const DEFAULT_MAX_WATCHERS_PER_NODE: usize = 100;

/// Default for `MAX_WATCHERS`, across every node.
pub const DEFAULT_MAX_WATCHERS: usize = 10_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Watcher {
    pub device_token: String,
    pub platform: Platform,
    pub watched_at: DateTime<Utc>,
}

/// A new watch was refused: the node's list, or the whole store, is full.
#[derive(Debug, PartialEq, Eq)]
pub struct WatchersFull;

impl std::fmt::Display for WatchersFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "watcher store is full")
    }
}

impl std::error::Error for WatchersFull {}

/// Node pubkey → device token → watcher.
type Nodes = HashMap<String, HashMap<String, Watcher>>;

pub struct WatcherStore {
    nodes: RwLock<Nodes>,
    log_salt: Arc<[u8; 32]>,
    max_per_node: usize,
    max_total: usize,
}

impl WatcherStore {
    pub fn new(log_salt: Arc<[u8; 32]>) -> Self {
        Self {
            nodes: RwLock::new(HashMap::new()),
            log_salt,
            max_per_node: DEFAULT_MAX_WATCHERS_PER_NODE,
            max_total: DEFAULT_MAX_WATCHERS,
        }
    }

    /// Caps new watches, per node and in total; see [`WatchersFull`].
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
    pub async fn watch(
        &self,
        mostro_pubkey: String,
        device_token: String,
        platform: Platform,
    ) -> Result<(), WatchersFull> {
        let watcher = Watcher {
            device_token,
            platform,
            watched_at: Utc::now(),
        };
        let log_node = log_pubkey(&self.log_salt, &mostro_pubkey);

        let (renewed, on_node) = {
            let mut nodes = self.nodes.write().await;
            let renewed = nodes
                .get(&mostro_pubkey)
                .is_some_and(|devices| devices.contains_key(&watcher.device_token));
            if !renewed && !has_room(&nodes, &mostro_pubkey, self.max_per_node, self.max_total) {
                warn!("Watcher store full, refusing a watch of node={}", log_node);
                return Err(WatchersFull);
            }
            let devices = nodes.entry(mostro_pubkey.clone()).or_default();
            devices.insert(watcher.device_token.clone(), watcher.clone());
            (renewed, devices.len())
        };
        if renewed {
            debug!("Renewed a watch of node={}", log_node);
        } else {
            info!("Watching node={} (devices: {})", log_node, on_node);
        }
        Ok(())
    }

    /// Removes the watch and reports whether it existed.
    pub async fn unwatch(&self, mostro_pubkey: &str, device_token: &str) -> bool {
        let log_node = log_pubkey(&self.log_salt, mostro_pubkey);
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
        removed
    }

    pub async fn cleanup_expired(&self) -> usize {
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
    use super::*;

    const NODE_A: &str = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345abc";
    const NODE_B: &str = "b1b2c3d4e5f67890123456789012345678901234567890123456789012345abc";
    const TOKEN_1: &str = "fcm-token-for-device-1:APA91bHexample1";
    const TOKEN_2: &str = "fcm-token-for-device-2:APA91bHexample2";
    const TOKEN_3: &str = "fcm-token-for-device-3:APA91bHexample3";

    fn salt() -> Arc<[u8; 32]> {
        Arc::new([7u8; 32])
    }

    async fn watch(store: &WatcherStore, node: &str, token: &str) -> Result<(), WatchersFull> {
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

        assert!(store.unwatch(NODE_A, TOKEN_1).await);
        assert!(!store.is_watching(NODE_A, TOKEN_1).await);
        assert!(!store.unwatch(NODE_A, TOKEN_1).await);
        assert_eq!(store.count().await, 0);
    }

    #[tokio::test]
    async fn one_device_can_watch_several_nodes() {
        let store = WatcherStore::new(salt());
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_B, TOKEN_1).await.unwrap();
        assert_eq!(store.count().await, 2);

        assert!(store.unwatch(NODE_A, TOKEN_1).await);
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
    async fn a_full_node_refuses_new_devices_but_renews_its_own() {
        let store = WatcherStore::new(salt()).with_caps(2, 10);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_A, TOKEN_2).await.unwrap();

        assert!(!store.has_room(NODE_A).await);
        assert_eq!(watch(&store, NODE_A, TOKEN_3).await, Err(WatchersFull));
        assert!(!store.is_watching(NODE_A, TOKEN_3).await);

        // A device already on the list is never cut off by the cap.
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        // Another node has its own list.
        assert!(store.has_room(NODE_B).await);
        watch(&store, NODE_B, TOKEN_3).await.unwrap();

        // A place frees up when a device leaves.
        assert!(store.unwatch(NODE_A, TOKEN_2).await);
        watch(&store, NODE_A, TOKEN_3).await.unwrap();
    }

    #[tokio::test]
    async fn a_full_store_refuses_new_watches_on_every_node() {
        let store = WatcherStore::new(salt()).with_caps(10, 2);
        watch(&store, NODE_A, TOKEN_1).await.unwrap();
        watch(&store, NODE_B, TOKEN_1).await.unwrap();

        assert!(!store.has_room(NODE_A).await);
        assert!(!store.has_room(NODE_B).await);
        assert_eq!(watch(&store, NODE_A, TOKEN_2).await, Err(WatchersFull));
        watch(&store, NODE_B, TOKEN_1).await.unwrap();
        assert_eq!(store.count().await, 2);
    }
}
