use futures::StreamExt;
use governor::{Quota, RateLimiter};
use log::{debug, error, info, warn};
use nostr_sdk::prelude::*;
use std::collections::{HashMap, HashSet};
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

use crate::api::rate_limit::{start_keyed_limiter_cleanup_task, PerPubkeyLimiter};
use crate::config::Config;
use crate::push::{DispatchError, DispatchOutcome, PushDispatcher, PushKind};
use crate::store::watchers::{Watcher, WatcherStore};
use crate::store::{RegisteredToken, TokenStore};
use crate::utils::log_pubkey::log_pubkey;

/// Upper bound on push dispatches the listener keeps in flight. Separate
/// from the `/api/notify` semaphore so neither path can starve the other.
const MAX_IN_FLIGHT_DISPATCHES: usize = 50;

/// Pushes one trade pubkey may trigger per minute, also the burst. A real
/// trade gets about ten updates over its whole life and two or three in the
/// same minute at most; the limit only stops a node or relay replaying one
/// trade's events in a loop. Nodes are not limited: every trade has its own
/// budget.
const PUSHES_PER_TRADE_PER_MIN: u32 = 10;

/// How far from now, either way, the `created_at` of a dispute event may be.
/// Older, it is a replay: the subscription asks for the last ten minutes on
/// every reconnect, and a relay may send more than it was asked for. The
/// event's own `created_at` is read, not its `published_at` tag: it is when
/// the node signed this `initiated` revision, and what a relay's `since`
/// compares.
const DISPUTE_FRESHNESS: Duration = Duration::from_secs(10 * 60);

/// How long a dispute that was seen is remembered, so it rings once. More
/// than twice [`DISPUTE_FRESHNESS`]: an event stops being fresh before its
/// dispute is forgotten, even when it was signed with a clock running ahead.
const DISPUTE_MEMORY: Duration = Duration::from_secs(30 * 60);

/// Disputes remembered at once. Only trusted nodes add to it, one entry per
/// dispute; when it is full a new dispute does not ring.
const MAX_REMEMBERED_DISPUTES: usize = 10_000;

/// Longest `d` tag taken as a dispute id. mostrod's is a UUID.
const MAX_DISPUTE_ID_BYTES: usize = 64;

/// Dispute pushes one node may trigger per minute, also the burst. The push
/// names no dispute and replaces the one before it on the device, so more
/// would tell a solver nothing new; the limit stops a node that misbehaves
/// from ringing its solvers without end.
const DISPUTE_PUSHES_PER_NODE_PER_MIN: u32 = 5;

pub struct NostrListener {
    config: Config,
    handler: EventHandler,
}

impl NostrListener {
    /// `trusted_mostro_pubkeys` are the Mostro nodes whose events may trigger a
    /// push (`config/trusted_mostro_pubkeys.json`). An empty list is an error:
    /// the listener would subscribe to nothing and silently send no push.
    pub fn new(
        config: Config,
        dispatcher: Arc<PushDispatcher>,
        token_store: Arc<TokenStore>,
        watcher_store: Arc<WatcherStore>,
        log_salt: Arc<[u8; 32]>,
        trusted_mostro_pubkeys: &HashSet<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let trusted_authors = parse_trusted_authors(trusted_mostro_pubkeys)?;
        Ok(Self {
            config,
            handler: EventHandler::new(
                dispatcher,
                token_store,
                watcher_store,
                log_salt,
                trusted_authors,
                MAX_IN_FLIGHT_DISPATCHES,
            ),
        })
    }

    pub async fn start(&self) {
        // Only registered pubkeys ever get a bucket, so the map stays bounded
        // by MAX_TOKENS; the sweep drops buckets that refilled.
        start_keyed_limiter_cleanup_task(
            self.handler.per_trade_limiter.clone(),
            Duration::from_secs(self.config.notify_rate_limit.cleanup_interval_secs),
            self.config.notify_rate_limit.pubkey_limiter_soft_cap,
            "listener-trade",
        );

        loop {
            match self.connect_and_listen().await {
                Ok(_) => {
                    warn!("Nostr connection closed, reconnecting in 5 seconds...");
                }
                Err(e) => {
                    error!(
                        "Error in Nostr listener: {}, reconnecting in 10 seconds...",
                        e
                    );
                    sleep(Duration::from_secs(10)).await;
                }
            }
            sleep(Duration::from_secs(5)).await;
        }
    }

    async fn connect_and_listen(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!("Connecting to Nostr relays...");

        // Create Nostr client. It never publishes, so it needs no signer.
        let client = Client::new();

        // Add relays
        for relay_url in &self.config.nostr.relays {
            client.add_relay(relay_url.clone()).await?;
            info!("Added relay: {}", relay_url);
        }

        // Connect to all relays
        client.connect().await;

        // Only Mostro nodes on the trusted list address trade updates to a
        // trade pubkey, and nostr-sdk verifies every event's id and signature
        // before delivering it, so the author cannot be forged. Filtering here
        // keeps relays from streaming every other kind-14 DM on the network,
        // and stops anyone else from triggering a push by tagging a
        // registered trade pubkey. Chat envelopes are addressed to a
        // conversation key, not a trade pubkey, and reach devices through
        // `/api/notify` instead.
        let since = Timestamp::now() - Duration::from_secs(60);
        let filter = subscription_filter(self.handler.trusted_authors.iter().copied(), since);

        // Open the notification channel BEFORE subscribing: the stream only
        // carries what arrives after this call, so subscribing first would
        // drop every event received in between.
        let mut notifications = client.notifications();

        let output = client.subscribe(filter).await?;
        ensure_subscribed(&output, "kind 14 events")?;

        // A dispute is announced to nobody in particular: the node publishes
        // it, and the devices watching that node are rung. The window reaches
        // back as far as an event still counts as fresh, so a dispute opened
        // while this server was restarting or reconnecting is not missed.
        let dispute_since = Timestamp::now() - DISPUTE_FRESHNESS;
        let dispute_filter = dispute_subscription_filter(
            self.handler.trusted_authors.iter().copied(),
            dispute_since,
        );
        let output = client.subscribe(dispute_filter).await?;
        ensure_subscribed(&output, "new disputes (kind 38386)")?;

        while let Some(notification) = notifications.next().await {
            if let ClientNotification::Event { event, .. } = notification {
                self.handler.handle(*event).await;
            }
        }

        Ok(())
    }
}

/// Logs per-relay subscription failures and errors out when no relay accepted
/// the subscription. nostr-sdk drops a subscription on every relay where
/// sending the REQ failed and never resends it, so continuing would wait
/// forever on a stream that receives nothing; the error sends `start()`
/// through its reconnect path instead.
fn ensure_subscribed(
    output: &Output<SubscriptionId>,
    what: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for (relay, reason) in &output.failed {
        warn!("Subscription failed on relay {}: {}", relay, reason);
    }
    info!(
        "Subscribed to {} from trusted Mostro nodes on {} of {} relays",
        what,
        output.success.len(),
        output.success.len() + output.failed.len()
    );
    if output.success.is_empty() {
        return Err(format!("subscription to {} failed on every relay", what).into());
    }
    Ok(())
}

/// Parses the trusted list into public keys, rejecting an empty list.
fn parse_trusted_authors(
    trusted_mostro_pubkeys: &HashSet<String>,
) -> Result<HashSet<PublicKey>, Box<dyn std::error::Error>> {
    if trusted_mostro_pubkeys.is_empty() {
        return Err(
            "no trusted Mostro nodes in config/trusted_mostro_pubkeys.json: \
             the listener would never send a push"
                .into(),
        );
    }
    trusted_mostro_pubkeys
        .iter()
        .map(|pk| {
            PublicKey::from_hex(pk)
                .map_err(|e| format!("invalid trusted Mostro pubkey {}: {}", pk, e).into())
        })
        .collect()
}

/// Kind-14 events authored by the trusted Mostro nodes, from `since` on.
fn subscription_filter(authors: impl IntoIterator<Item = PublicKey>, since: Timestamp) -> Filter {
    Filter::new()
        .kind(Kind::PrivateDirectMessage)
        .authors(authors)
        .since(since)
}

/// Kind-38386 events authored by the trusted Mostro nodes that announce a
/// dispute nobody took yet (`s` = `initiated`), from `since` on.
fn dispute_subscription_filter(
    authors: impl IntoIterator<Item = PublicKey>,
    since: Timestamp,
) -> Filter {
    Filter::new()
        .kind(Kind::Custom(KIND_DISPUTE))
        .authors(authors)
        .custom_tag(SingleLetterTag::LOWERCASE_S, DISPUTE_STATUS_INITIATED)
        .since(since)
}

/// The disputes seen lately, by node and dispute id, so each rings once.
#[derive(Default)]
struct SeenDisputes {
    seen: HashMap<(PublicKey, String), Instant>,
}

impl SeenDisputes {
    /// Whether the dispute is new, remembering it from `now` if so. `false`
    /// also when it cannot be remembered because the memory is full: a
    /// dispute that would ring again on every replay must not ring at all.
    fn first_time(&mut self, node: PublicKey, dispute_id: &str, now: Instant) -> bool {
        let key = (node, dispute_id.to_string());
        if let Some(seen_at) = self.seen.get(&key) {
            if now.duration_since(*seen_at) < DISPUTE_MEMORY {
                return false;
            }
        }
        if self.seen.len() >= MAX_REMEMBERED_DISPUTES {
            self.seen
                .retain(|_, seen_at| now.duration_since(*seen_at) < DISPUTE_MEMORY);
            if self.seen.len() >= MAX_REMEMBERED_DISPUTES {
                return false;
            }
        }
        self.seen.insert(key, now);
        true
    }
}

/// Matches a watched event to a registered device and dispatches its push.
struct EventHandler {
    dispatcher: Arc<PushDispatcher>,
    token_store: Arc<TokenStore>,
    watcher_store: Arc<WatcherStore>,
    log_salt: Arc<[u8; 32]>,
    /// Checked again per event: a relay may ignore the subscription filter.
    trusted_authors: HashSet<PublicKey>,
    permits: Arc<Semaphore>,
    per_trade_limiter: Arc<PerPubkeyLimiter>,
    /// Keyed by node. Only a trusted node ever gets a bucket, so the map is
    /// bounded by the trusted list and needs no sweep.
    per_node_dispute_limiter: PerPubkeyLimiter,
    seen_disputes: Mutex<SeenDisputes>,
}

impl EventHandler {
    fn new(
        dispatcher: Arc<PushDispatcher>,
        token_store: Arc<TokenStore>,
        watcher_store: Arc<WatcherStore>,
        log_salt: Arc<[u8; 32]>,
        trusted_authors: HashSet<PublicKey>,
        max_in_flight: usize,
    ) -> Self {
        Self {
            dispatcher,
            token_store,
            watcher_store,
            log_salt,
            trusted_authors,
            permits: Arc::new(Semaphore::new(max_in_flight)),
            per_trade_limiter: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(PUSHES_PER_TRADE_PER_MIN).expect("non-zero constant"),
            ))),
            per_node_dispute_limiter: RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(DISPUTE_PUSHES_PER_NODE_PER_MIN).expect("non-zero constant"),
            )),
            seen_disputes: Mutex::new(SeenDisputes::default()),
        }
    }

    async fn handle(&self, event: Event) {
        if event.kind.as_u16() == KIND_DISPUTE {
            self.handle_dispute(event).await;
            return;
        }
        if !is_watched_kind(event.kind) {
            return;
        }
        if !self.trusted_authors.contains(&event.pubkey) {
            debug!(
                "Ignoring kind 14 event {} from an untrusted author",
                event.id
            );
            return;
        }
        info!("Received protocol v2 (kind 14) event: {}", event.id);

        let Some(trade_pubkey) = extract_recipient(&event) else {
            warn!("No 'p' tag found in kind 14 event {}", event.id);
            return;
        };

        let log_pk = log_pubkey(&self.log_salt, &trade_pubkey);
        info!("Event recipient (p tag) pk={}", log_pk);

        let Some(registered_token) = self.token_store.get(&trade_pubkey).await else {
            debug!("No registered token pk={}", log_pk);
            return;
        };
        if self.per_trade_limiter.check_key(&trade_pubkey).is_err() {
            warn!(
                "Push limit reached for pk={}, dropping event {}",
                log_pk, event.id
            );
            return;
        }
        info!(
            "MATCH! Found registered token pk={}, sending push to {} device",
            log_pk, registered_token.platform
        );

        // Each push runs in its own task so a slow backend (a UnifiedPush
        // endpoint is chosen by whoever registered it) cannot stall events
        // from every relay. When every permit is taken the push is dropped
        // rather than awaited: waiting here would stop the loop draining
        // nostr-sdk's bounded notification channel, which then discards
        // events from all relays without a trace.
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            warn!(
                "Dispatch pool saturated, dropping push for event {} pk={}",
                event.id, log_pk
            );
            return;
        };
        let dispatcher = self.dispatcher.clone();
        tokio::spawn(async move {
            dispatch_and_log(&dispatcher, &registered_token, event.id).await;
            drop(permit);
        });
    }
}

impl EventHandler {
    async fn handle_dispute(&self, event: Event) {
        let Some(watchers) = self.admit_dispute(&event).await else {
            return;
        };
        info!(
            "New dispute in event {} node={}: {} devices to ring",
            event.id,
            log_pubkey(&self.log_salt, &event.pubkey.to_hex()),
            watchers.len()
        );
    }

    /// The devices to ring for a dispute event, or `None` when it must not
    /// ring: it is not a new dispute of a trusted node, it already rang, the
    /// node spent its allowance, or nobody watches the node.
    async fn admit_dispute(&self, event: &Event) -> Option<Vec<Watcher>> {
        if !self.trusted_authors.contains(&event.pubkey) {
            debug!(
                "Ignoring dispute event {} from an untrusted author",
                event.id
            );
            return None;
        }
        // A relay may ignore the `#s` filter, and the node replaces this
        // event when the dispute is taken or closed.
        if tag_value(event, "s") != Some(DISPUTE_STATUS_INITIATED) {
            return None;
        }
        let node = event.pubkey.to_hex();
        let log_node = log_pubkey(&self.log_salt, &node);
        let Some(dispute_id) =
            tag_value(event, "d").filter(|id| !id.is_empty() && id.len() <= MAX_DISPUTE_ID_BYTES)
        else {
            warn!(
                "Dispute event {} node={} has no usable 'd' tag",
                event.id, log_node
            );
            return None;
        };
        if !is_fresh(event.created_at, Timestamp::now()) {
            debug!(
                "Ignoring dispute event {} node={}: not signed in the last minutes",
                event.id, log_node
            );
            return None;
        }
        // Remembered before the limit below: a dispute that was dropped must
        // not ring later, out of nowhere, when a relay sends it again.
        let first_time = self
            .seen_disputes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .first_time(event.pubkey, dispute_id, Instant::now());
        if !first_time {
            debug!(
                "Dispute of event {} node={} already seen",
                event.id, log_node
            );
            return None;
        }
        if self.per_node_dispute_limiter.check_key(&node).is_err() {
            warn!(
                "Dispute push limit reached for node={}, dropping event {}",
                log_node, event.id
            );
            return None;
        }
        let watchers = self.watcher_store.watchers_of(&node).await;
        if watchers.is_empty() {
            debug!("Nobody watches node={} for disputes", log_node);
            return None;
        }
        Some(watchers)
    }
}

/// Whether a dispute event was signed within [`DISPUTE_FRESHNESS`] of `now`.
/// A date ahead of the clock is held to the same distance: accepted without
/// one, an event dated far ahead would stay fresh until long after its
/// dispute was forgotten, and ring again on a replay.
fn is_fresh(created_at: Timestamp, now: Timestamp) -> bool {
    created_at.as_secs().abs_diff(now.as_secs()) <= DISPUTE_FRESHNESS.as_secs()
}

/// The value of the event's first `name` tag.
fn tag_value<'a>(event: &'a Event, name: &str) -> Option<&'a str> {
    event.tags.iter().find_map(|tag| match tag.as_slice() {
        [tag_name, value, ..] if tag_name == name => Some(value.as_str()),
        _ => None,
    })
}

async fn dispatch_and_log(
    dispatcher: &PushDispatcher,
    registered_token: &RegisteredToken,
    event_id: EventId,
) {
    match dispatcher
        .dispatch(PushKind::TradeUpdate, registered_token)
        .await
    {
        Ok(DispatchOutcome::Delivered { backend: _ }) => {
            info!("Push sent successfully for event {}", event_id);
        }
        Err(DispatchError::NoBackendForPlatform) => {
            error!(
                "Push dropped for event {}: no backend for {} devices",
                event_id, registered_token.platform
            );
        }
        Err(DispatchError::AllBackendsFailed { errors }) => {
            for err in errors {
                error!("Failed to send push: {}", err);
            }
        }
    }
}

/// Matched on the number because nostr-sdk parses 14 into the named
/// `Kind::PrivateDirectMessage` variant, which a `Kind::Custom(14)` pattern
/// would never match even though `PartialEq` treats the two as equal.
const KIND_PROTOCOL_V2: u16 = 14;

/// A dispute of a Mostro node (mostro-core `NOSTR_DISPUTE_EVENT_KIND`): an
/// addressable event the node replaces as the dispute moves on.
const KIND_DISPUTE: u16 = 38386;

/// The `s` tag of a dispute no solver took yet.
const DISPUTE_STATUS_INITIATED: &str = "initiated";

/// Mostro protocol v2: nodes address trade updates to the trade pubkey in the
/// `p` tag of a signed kind-14 event. Gift Wrap (kind 1059, protocol v1) is no
/// longer used by any Mostro node nor the mobile app.
fn is_watched_kind(kind: Kind) -> bool {
    kind.as_u16() == KIND_PROTOCOL_V2
}

/// Extracts the recipient trade pubkey from the event's first `p` tag.
fn extract_recipient(event: &Event) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let tag_slice = tag.as_slice();
        if tag_slice.len() >= 2 && tag_slice[0] == "p" {
            Some(tag_slice[1].clone())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::{PushError, PushService};
    use crate::store::Platform;
    use async_trait::async_trait;
    use tokio::sync::{mpsc, Notify};

    const SLOW_DEVICE: &str = "slow-device";
    const FAST_DEVICE: &str = "fast-device";
    const DELIVERY_WAIT: Duration = Duration::from_secs(2);
    const BLOCKED_WAIT: Duration = Duration::from_millis(200);

    /// Push backend that holds `SLOW_DEVICE` sends until `release` fires and
    /// reports every completed send on `delivered`.
    struct GatedPushService {
        release: Arc<Notify>,
        delivered: mpsc::UnboundedSender<String>,
    }

    #[async_trait]
    impl PushService for GatedPushService {
        async fn send(
            &self,
            _kind: PushKind,
            device_token: &str,
            _platform: &Platform,
        ) -> Result<(), PushError> {
            if device_token == SLOW_DEVICE {
                self.release.notified().await;
            }
            let _ = self.delivered.send(device_token.to_string());
            Ok(())
        }

        fn supports(&self, _kind: PushKind, _platform: &Platform) -> bool {
            true
        }
    }

    struct Fixture {
        handler: EventHandler,
        release: Arc<Notify>,
        delivered: mpsc::UnboundedReceiver<String>,
        watchers: Arc<WatcherStore>,
        /// The only trusted Mostro node.
        node: Keys,
        slow_recipient: Keys,
        fast_recipient: Keys,
    }

    async fn fixture(max_in_flight: usize) -> Fixture {
        let salt = Arc::new([7u8; 32]);
        let release = Arc::new(Notify::new());
        let (tx, delivered) = mpsc::unbounded_channel();
        let service: Arc<dyn PushService> = Arc::new(GatedPushService {
            release: release.clone(),
            delivered: tx,
        });
        let dispatcher = Arc::new(PushDispatcher::new(vec![(service, "gated")]));
        let store = Arc::new(TokenStore::new(24, salt.clone()));
        let watchers = Arc::new(WatcherStore::new(salt.clone()));

        let slow_recipient = Keys::generate();
        let fast_recipient = Keys::generate();
        store
            .register(
                slow_recipient.public_key().to_hex(),
                SLOW_DEVICE.to_string(),
                Platform::Android,
            )
            .await
            .unwrap();
        store
            .register(
                fast_recipient.public_key().to_hex(),
                FAST_DEVICE.to_string(),
                Platform::Android,
            )
            .await
            .unwrap();

        let node = Keys::generate();
        let trusted = HashSet::from([node.public_key()]);
        Fixture {
            handler: EventHandler::new(
                dispatcher,
                store,
                watchers.clone(),
                salt,
                trusted,
                max_in_flight,
            ),
            watchers,
            release,
            delivered,
            node,
            slow_recipient,
            fast_recipient,
        }
    }

    /// An event of `kind` signed by `author` and addressed to `recipient`.
    fn event(kind: Kind, author: &Keys, recipient: &Keys) -> Event {
        EventBuilder::new(kind, "ciphertext")
            .tags([Tag::public_key(recipient.public_key())])
            .finalize(author)
            .unwrap()
    }

    impl Fixture {
        /// A trade update from the trusted node to `recipient`.
        fn update_to(&self, recipient: &Keys) -> Event {
            event(Kind::PrivateDirectMessage, &self.node, recipient)
        }
    }

    const DISPUTE_ID: &str = "4f6c2c0e-7d3b-4c57-9f0e-2a1b3c4d5e6f";
    const OTHER_DISPUTE_ID: &str = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
    const WATCHER_1: &str = "watcher-1";
    const WATCHER_2: &str = "watcher-2";

    fn custom_tag(name: &str, value: &str) -> Tag {
        Tag::custom(name, [value])
    }

    /// A dispute event as mostrod builds it, with `created_at` as given.
    fn dispute_event(author: &Keys, tags: Vec<Tag>, created_at: Timestamp) -> Event {
        EventBuilder::new(Kind::Custom(KIND_DISPUTE), "")
            .tags(tags)
            .custom_created_at(created_at)
            .finalize(author)
            .unwrap()
    }

    fn dispute_tags(dispute_id: &str, status: &str, opened_at: Timestamp) -> Vec<Tag> {
        vec![
            Tag::identifier(dispute_id),
            custom_tag("s", status),
            custom_tag("initiator", "buyer"),
            custom_tag("published_at", &opened_at.as_secs().to_string()),
            custom_tag("z", "dispute"),
        ]
    }

    /// A dispute `author` opened just now.
    fn new_dispute(author: &Keys, dispute_id: &str) -> Event {
        let now = Timestamp::now();
        dispute_event(author, dispute_tags(dispute_id, "initiated", now), now)
    }

    fn minutes_ago(minutes: u64) -> Timestamp {
        Timestamp::now() - Duration::from_secs(minutes * 60)
    }

    fn tokens(watchers: Option<Vec<Watcher>>) -> Option<Vec<String>> {
        let mut tokens: Vec<String> = watchers?.into_iter().map(|w| w.device_token).collect();
        tokens.sort();
        Some(tokens)
    }

    impl Fixture {
        async fn watch(&self, node: &Keys, device_token: &str) {
            self.watchers
                .watch(
                    node.public_key().to_hex(),
                    device_token.to_string(),
                    Platform::Android,
                )
                .await
                .unwrap();
        }

        /// Trusts a second node and returns it.
        fn trust_another_node(&mut self) -> Keys {
            let node = Keys::generate();
            self.handler.trusted_authors.insert(node.public_key());
            node
        }
    }

    #[tokio::test]
    async fn a_new_dispute_is_for_every_device_watching_its_node() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        let other_node = f.trust_another_node();
        f.watch(&f.node, WATCHER_1).await;
        f.watch(&f.node, WATCHER_2).await;
        f.watch(&other_node, "watcher-of-the-other-node").await;

        let admitted = f
            .handler
            .admit_dispute(&new_dispute(&f.node, DISPUTE_ID))
            .await;

        assert_eq!(
            tokens(admitted),
            Some(vec![WATCHER_1.to_string(), WATCHER_2.to_string()])
        );
    }

    #[tokio::test]
    async fn a_dispute_of_an_untrusted_author_is_ignored() {
        let f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        // Anyone can publish a kind 38386; a device may even be watching the
        // key, left from before it was taken off the trusted list.
        let stranger = Keys::generate();
        f.watch(&stranger, WATCHER_1).await;

        let admitted = f
            .handler
            .admit_dispute(&new_dispute(&stranger, DISPUTE_ID))
            .await;

        assert_eq!(admitted, None);
    }

    #[tokio::test]
    async fn only_an_initiated_dispute_is_admitted() {
        let f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        f.watch(&f.node, WATCHER_1).await;
        let now = Timestamp::now();

        // What the node publishes when the dispute is taken and when it ends.
        for status in ["in-progress", "settled", "seller-refunded", "released", ""] {
            let event = dispute_event(&f.node, dispute_tags(DISPUTE_ID, status, now), now);
            assert_eq!(f.handler.admit_dispute(&event).await, None, "{status}");
        }
        let without_status = dispute_event(&f.node, vec![Tag::identifier(DISPUTE_ID)], now);
        assert_eq!(f.handler.admit_dispute(&without_status).await, None);

        // None of them spent the dispute: its `initiated` event still rings.
        let admitted = f
            .handler
            .admit_dispute(&new_dispute(&f.node, DISPUTE_ID))
            .await;
        assert!(admitted.is_some());
    }

    #[tokio::test]
    async fn a_dispute_without_a_usable_id_is_ignored() {
        let f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        f.watch(&f.node, WATCHER_1).await;
        let now = Timestamp::now();

        let no_id = dispute_event(&f.node, vec![custom_tag("s", "initiated")], now);
        assert_eq!(f.handler.admit_dispute(&no_id).await, None);
        let empty_id = new_dispute(&f.node, "");
        assert_eq!(f.handler.admit_dispute(&empty_id).await, None);
        let long_id = new_dispute(&f.node, &"a".repeat(MAX_DISPUTE_ID_BYTES + 1));
        assert_eq!(f.handler.admit_dispute(&long_id).await, None);

        let longest_id = new_dispute(&f.node, &"a".repeat(MAX_DISPUTE_ID_BYTES));
        assert!(f.handler.admit_dispute(&longest_id).await.is_some());
    }

    #[tokio::test]
    async fn a_dispute_event_that_is_not_recent_is_ignored() {
        let f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        f.watch(&f.node, WATCHER_1).await;

        // A replay: the relay sends again what the node signed a while ago.
        let signed_at = minutes_ago(11);
        let stale = dispute_event(
            &f.node,
            dispute_tags(DISPUTE_ID, "initiated", signed_at),
            signed_at,
        );
        assert_eq!(f.handler.admit_dispute(&stale).await, None);

        // Dated ahead of this server's clock by more than the window.
        let ahead = Timestamp::now() + Duration::from_secs(11 * 60);
        let early = dispute_event(
            &f.node,
            dispute_tags(OTHER_DISPUTE_ID, "initiated", ahead),
            ahead,
        );
        assert_eq!(f.handler.admit_dispute(&early).await, None);
    }

    #[tokio::test]
    async fn a_dispute_signed_a_few_minutes_ago_is_admitted() {
        let f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        f.watch(&f.node, WATCHER_1).await;

        // Opened while this server was restarting.
        let signed_at = minutes_ago(9);
        let event = dispute_event(
            &f.node,
            dispute_tags(DISPUTE_ID, "initiated", signed_at),
            signed_at,
        );

        assert!(f.handler.admit_dispute(&event).await.is_some());
    }

    /// Freshness is the event's `created_at`, when the node signed this
    /// revision. A new `initiated` revision of a dispute opened long ago is
    /// not a flow mostrod normally takes, but if it happens it must ring.
    #[tokio::test]
    async fn a_new_initiated_revision_of_an_old_dispute_is_admitted() {
        let f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        f.watch(&f.node, WATCHER_1).await;

        let opened_at = minutes_ago(3 * 24 * 60);
        let event = dispute_event(
            &f.node,
            dispute_tags(DISPUTE_ID, "initiated", opened_at),
            Timestamp::now(),
        );

        assert!(f.handler.admit_dispute(&event).await.is_some());
    }

    #[tokio::test]
    async fn a_dispute_is_admitted_once() {
        let f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        f.watch(&f.node, WATCHER_1).await;
        let event = new_dispute(&f.node, DISPUTE_ID);

        assert!(f.handler.admit_dispute(&event).await.is_some());
        // The same event from another relay, or after a reconnect.
        assert_eq!(f.handler.admit_dispute(&event).await, None);
        // Another event of the same dispute, a minute later.
        let again = dispute_event(
            &f.node,
            dispute_tags(DISPUTE_ID, "initiated", Timestamp::now()),
            Timestamp::now() + Duration::from_secs(60),
        );
        assert_eq!(f.handler.admit_dispute(&again).await, None);

        // Another dispute is another matter.
        let other = new_dispute(&f.node, OTHER_DISPUTE_ID);
        assert!(f.handler.admit_dispute(&other).await.is_some());
    }

    #[tokio::test]
    async fn two_nodes_may_use_the_same_dispute_id() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        let other_node = f.trust_another_node();
        f.watch(&f.node, WATCHER_1).await;
        f.watch(&other_node, WATCHER_2).await;

        let first = f
            .handler
            .admit_dispute(&new_dispute(&f.node, DISPUTE_ID))
            .await;
        let second = f
            .handler
            .admit_dispute(&new_dispute(&other_node, DISPUTE_ID))
            .await;

        assert_eq!(tokens(first), Some(vec![WATCHER_1.to_string()]));
        assert_eq!(tokens(second), Some(vec![WATCHER_2.to_string()]));
    }

    #[tokio::test]
    async fn a_dispute_of_a_node_nobody_watches_is_ignored() {
        let f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;

        let admitted = f
            .handler
            .admit_dispute(&new_dispute(&f.node, DISPUTE_ID))
            .await;

        assert_eq!(admitted, None);
    }

    fn numbered_dispute(node: &Keys, number: u32) -> Event {
        new_dispute(node, &format!("dispute-{number}"))
    }

    #[tokio::test]
    async fn dispute_pushes_are_limited_per_node_per_minute() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        let other_node = f.trust_another_node();
        f.watch(&f.node, WATCHER_1).await;
        f.watch(&other_node, WATCHER_2).await;

        for number in 0..DISPUTE_PUSHES_PER_NODE_PER_MIN {
            let event = numbered_dispute(&f.node, number);
            assert!(f.handler.admit_dispute(&event).await.is_some());
        }
        let one_more = numbered_dispute(&f.node, DISPUTE_PUSHES_PER_NODE_PER_MIN);
        assert_eq!(f.handler.admit_dispute(&one_more).await, None);

        // A node that floods spends only its own allowance.
        let admitted = f
            .handler
            .admit_dispute(&new_dispute(&other_node, DISPUTE_ID))
            .await;
        assert!(admitted.is_some());
    }

    #[tokio::test]
    async fn a_dispute_dropped_by_the_limit_does_not_ring_later() {
        let f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        f.watch(&f.node, WATCHER_1).await;
        for number in 0..DISPUTE_PUSHES_PER_NODE_PER_MIN {
            f.handler
                .admit_dispute(&numbered_dispute(&f.node, number))
                .await;
        }
        let dropped = new_dispute(&f.node, DISPUTE_ID);
        assert_eq!(f.handler.admit_dispute(&dropped).await, None);

        // It is remembered as seen, so a replay finds it spent.
        let mut seen = f.handler.seen_disputes.lock().unwrap();
        assert!(!seen.first_time(f.node.public_key(), DISPUTE_ID, Instant::now()));
    }

    #[test]
    fn a_seen_dispute_is_forgotten_after_a_while() {
        let node = Keys::generate().public_key();
        let mut seen = SeenDisputes::default();
        let start = Instant::now();

        assert!(seen.first_time(node, DISPUTE_ID, start));
        let just_before = start + DISPUTE_MEMORY - Duration::from_secs(1);
        assert!(!seen.first_time(node, DISPUTE_ID, just_before));
        assert!(seen.first_time(node, DISPUTE_ID, start + DISPUTE_MEMORY));
    }

    #[test]
    fn a_full_memory_of_disputes_admits_no_new_one_until_some_are_forgotten() {
        let node = Keys::generate().public_key();
        let mut seen = SeenDisputes::default();
        let start = Instant::now();
        for number in 0..MAX_REMEMBERED_DISPUTES {
            assert!(seen.first_time(node, &format!("dispute-{number}"), start));
        }

        let soon = start + Duration::from_secs(60);
        assert!(!seen.first_time(node, DISPUTE_ID, soon));
        // Refused, it was not remembered either.
        assert_eq!(seen.seen.len(), MAX_REMEMBERED_DISPUTES);

        let later = start + DISPUTE_MEMORY;
        assert!(seen.first_time(node, DISPUTE_ID, later));
        assert_eq!(seen.seen.len(), 1);
    }

    #[test]
    fn the_memory_of_disputes_outlasts_every_fresh_event() {
        // An event is fresh from ten minutes before its date to ten after.
        assert!(DISPUTE_MEMORY > 2 * DISPUTE_FRESHNESS);
    }

    #[test]
    fn freshness_is_ten_minutes_either_way() {
        let now = Timestamp::from(1_700_000_000);
        let window = DISPUTE_FRESHNESS.as_secs();

        assert!(is_fresh(now, now));
        assert!(is_fresh(Timestamp::from(now.as_secs() - window), now));
        assert!(!is_fresh(Timestamp::from(now.as_secs() - window - 1), now));
        assert!(is_fresh(Timestamp::from(now.as_secs() + window), now));
        assert!(!is_fresh(Timestamp::from(now.as_secs() + window + 1), now));
    }

    #[test]
    fn dispute_subscription_asks_only_for_initiated_disputes_of_trusted_nodes() {
        let node = Keys::generate().public_key();
        let since = Timestamp::from(1_700_000_000);

        let filter = dispute_subscription_filter([node], since);

        assert_eq!(
            filter.kinds,
            Some([Kind::Custom(38386)].into_iter().collect())
        );
        assert_eq!(filter.authors, Some([node].into_iter().collect()));
        assert_eq!(filter.since, Some(since));
        assert_eq!(
            filter.generic_tags.get(&SingleLetterTag::LOWERCASE_S),
            Some(&["initiated".to_string()].into_iter().collect())
        );
        assert_eq!(filter.generic_tags.len(), 1);
    }

    #[tokio::test]
    async fn slow_push_does_not_delay_the_next_event() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;

        tokio::time::timeout(DELIVERY_WAIT, async {
            f.handler.handle(f.update_to(&f.slow_recipient)).await;
            f.handler.handle(f.update_to(&f.fast_recipient)).await;
        })
        .await
        .expect("handle() must not wait for the push to finish");

        let first = tokio::time::timeout(DELIVERY_WAIT, f.delivered.recv()).await;
        assert_eq!(first.unwrap().as_deref(), Some(FAST_DEVICE));

        f.release.notify_one();
        let second = tokio::time::timeout(DELIVERY_WAIT, f.delivered.recv()).await;
        assert_eq!(second.unwrap().as_deref(), Some(SLOW_DEVICE));
    }

    #[tokio::test]
    async fn saturated_dispatch_drops_the_push_without_blocking() {
        let mut f = fixture(1).await;
        f.handler.handle(f.update_to(&f.slow_recipient)).await;

        tokio::time::timeout(
            DELIVERY_WAIT,
            f.handler.handle(f.update_to(&f.fast_recipient)),
        )
        .await
        .expect("a saturated dispatcher must not block the notification loop");
        let dropped = tokio::time::timeout(BLOCKED_WAIT, f.delivered.recv()).await;
        assert!(dropped.is_err(), "push beyond the cap must be dropped");

        f.release.notify_one();
        let slow = tokio::time::timeout(DELIVERY_WAIT, f.delivered.recv()).await;
        assert_eq!(slow.unwrap().as_deref(), Some(SLOW_DEVICE));

        f.handler.handle(f.update_to(&f.fast_recipient)).await;
        let fast = tokio::time::timeout(DELIVERY_WAIT, f.delivered.recv()).await;
        assert_eq!(fast.unwrap().as_deref(), Some(FAST_DEVICE));
    }

    fn subscribe_output(succeeded: &[&str], failed: &[&str]) -> Output<SubscriptionId> {
        let url = |u: &&str| RelayUrl::parse(u).unwrap();
        Output {
            value: SubscriptionId::generate(),
            success: succeeded.iter().map(|u| (url(u), ())).collect(),
            failed: failed
                .iter()
                .map(|u| (url(u), "can't send message".to_string()))
                .collect(),
        }
    }

    #[test]
    fn subscription_on_some_relays_is_accepted() {
        let output = subscribe_output(&["wss://a.example"], &["wss://b.example"]);
        assert!(ensure_subscribed(&output, "events").is_ok());
    }

    #[test]
    fn subscription_failed_on_every_relay_forces_a_reconnect() {
        let output = subscribe_output(&[], &["wss://a.example", "wss://b.example"]);
        assert!(ensure_subscribed(&output, "events").is_err());
    }

    #[tokio::test]
    async fn unregistered_recipient_dispatches_nothing() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;

        f.handler.handle(f.update_to(&Keys::generate())).await;

        let got = tokio::time::timeout(BLOCKED_WAIT, f.delivered.recv()).await;
        assert!(got.is_err());
    }

    #[tokio::test]
    async fn event_from_an_untrusted_author_is_ignored() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;

        // Anyone can tag a registered trade pubkey; only the node may wake it.
        let forged = event(
            Kind::PrivateDirectMessage,
            &Keys::generate(),
            &f.fast_recipient,
        );
        f.handler.handle(forged).await;

        let got = tokio::time::timeout(BLOCKED_WAIT, f.delivered.recv()).await;
        assert!(got.is_err(), "untrusted authors must not trigger a push");
    }

    #[tokio::test]
    async fn gift_wrap_from_a_trusted_node_is_ignored() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;

        let gift_wrap = event(Kind::GiftWrap, &f.node, &f.fast_recipient);
        f.handler.handle(gift_wrap).await;

        let got = tokio::time::timeout(BLOCKED_WAIT, f.delivered.recv()).await;
        assert!(got.is_err(), "protocol v1 Gift Wraps are no longer watched");
    }

    #[tokio::test]
    async fn trade_update_from_the_trusted_node_is_delivered() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;

        f.handler.handle(f.update_to(&f.fast_recipient)).await;

        let got = tokio::time::timeout(DELIVERY_WAIT, f.delivered.recv()).await;
        assert_eq!(got.unwrap().as_deref(), Some(FAST_DEVICE));
    }

    #[test]
    fn subscription_asks_only_for_kind_14_from_trusted_nodes() {
        let node = Keys::generate().public_key();
        let since = Timestamp::from(1_700_000_000);

        let filter = subscription_filter([node], since);

        assert_eq!(
            filter.kinds,
            Some([Kind::PrivateDirectMessage].into_iter().collect())
        );
        assert_eq!(filter.authors, Some([node].into_iter().collect()));
        assert_eq!(filter.since, Some(since));
    }

    #[test]
    fn an_empty_trusted_list_is_rejected() {
        assert!(parse_trusted_authors(&HashSet::new()).is_err());
    }

    #[test]
    fn a_trusted_key_that_is_not_a_pubkey_is_rejected() {
        let invalid = HashSet::from(["zz".repeat(32)]);
        assert!(parse_trusted_authors(&invalid).is_err());
    }

    #[test]
    fn the_embedded_trusted_list_parses() {
        let trusted = parse_trusted_authors(&crate::trusted_pubkeys::load()).unwrap();
        assert!(!trusted.is_empty());
    }

    #[test]
    fn only_protocol_v2_kind_is_watched() {
        // Inbound events arrive as the named variant, not as Custom.
        assert!(is_watched_kind(Kind::from_u16(14)));
        assert!(is_watched_kind(Kind::Custom(14)));
        assert!(!is_watched_kind(Kind::from_u16(1059)));
        assert!(!is_watched_kind(Kind::Custom(1)));
        assert!(!is_watched_kind(Kind::Custom(38385)));
    }

    #[test]
    fn extract_recipient_returns_first_p_tag() {
        let keys = Keys::generate();
        let recipient = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(14), "ciphertext")
            .tags([Tag::public_key(recipient.public_key())])
            .finalize(&keys)
            .unwrap();

        assert_eq!(
            extract_recipient(&event),
            Some(recipient.public_key().to_string())
        );
    }

    #[test]
    fn extract_recipient_returns_none_without_p_tag() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(14), "ciphertext")
            .finalize(&keys)
            .unwrap();

        assert_eq!(extract_recipient(&event), None);
    }

    #[tokio::test]
    async fn pushes_per_trade_are_limited_per_minute() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;

        for _ in 0..PUSHES_PER_TRADE_PER_MIN {
            f.handler.handle(f.update_to(&f.fast_recipient)).await;
        }
        for _ in 0..PUSHES_PER_TRADE_PER_MIN {
            let got = tokio::time::timeout(DELIVERY_WAIT, f.delivered.recv()).await;
            assert_eq!(got.unwrap().as_deref(), Some(FAST_DEVICE));
        }

        // One more within the same minute is dropped.
        f.handler.handle(f.update_to(&f.fast_recipient)).await;
        let dropped = tokio::time::timeout(BLOCKED_WAIT, f.delivered.recv()).await;
        assert!(
            dropped.is_err(),
            "the burst above the limit must be dropped"
        );
    }

    #[tokio::test]
    async fn the_limit_is_per_trade_not_per_node() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;
        for _ in 0..PUSHES_PER_TRADE_PER_MIN {
            f.handler.handle(f.update_to(&f.fast_recipient)).await;
            tokio::time::timeout(DELIVERY_WAIT, f.delivered.recv())
                .await
                .unwrap();
        }

        // The same node still reaches every other trade.
        f.release.notify_one();
        f.handler.handle(f.update_to(&f.slow_recipient)).await;
        let got = tokio::time::timeout(DELIVERY_WAIT, f.delivered.recv()).await;
        assert_eq!(got.unwrap().as_deref(), Some(SLOW_DEVICE));
    }
}
