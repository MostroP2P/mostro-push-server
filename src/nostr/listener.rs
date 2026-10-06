use futures::StreamExt;
use governor::{Quota, RateLimiter};
use log::{debug, error, info, warn};
use nostr_sdk::prelude::*;
use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

use crate::api::rate_limit::{start_keyed_limiter_cleanup_task, PerPubkeyLimiter};
use crate::config::Config;
use crate::push::{DispatchError, DispatchOutcome, PushDispatcher};
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
        log_salt: Arc<[u8; 32]>,
        trusted_mostro_pubkeys: &HashSet<String>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let trusted_authors = parse_trusted_authors(trusted_mostro_pubkeys)?;
        Ok(Self {
            config,
            handler: EventHandler::new(
                dispatcher,
                token_store,
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
        ensure_subscribed(&output)?;

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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    for (relay, reason) in &output.failed {
        warn!("Subscription failed on relay {}: {}", relay, reason);
    }
    info!(
        "Subscribed to kind 14 events from trusted Mostro nodes on {} of {} relays",
        output.success.len(),
        output.success.len() + output.failed.len()
    );
    if output.success.is_empty() {
        return Err("subscription failed on every relay".into());
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

/// Matches a watched event to a registered device and dispatches its push.
struct EventHandler {
    dispatcher: Arc<PushDispatcher>,
    token_store: Arc<TokenStore>,
    log_salt: Arc<[u8; 32]>,
    /// Checked again per event: a relay may ignore the subscription filter.
    trusted_authors: HashSet<PublicKey>,
    permits: Arc<Semaphore>,
    per_trade_limiter: Arc<PerPubkeyLimiter>,
}

impl EventHandler {
    fn new(
        dispatcher: Arc<PushDispatcher>,
        token_store: Arc<TokenStore>,
        log_salt: Arc<[u8; 32]>,
        trusted_authors: HashSet<PublicKey>,
        max_in_flight: usize,
    ) -> Self {
        Self {
            dispatcher,
            token_store,
            log_salt,
            trusted_authors,
            permits: Arc::new(Semaphore::new(max_in_flight)),
            per_trade_limiter: Arc::new(RateLimiter::keyed(Quota::per_minute(
                NonZeroU32::new(PUSHES_PER_TRADE_PER_MIN).expect("non-zero constant"),
            ))),
        }
    }

    async fn handle(&self, event: Event) {
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

async fn dispatch_and_log(
    dispatcher: &PushDispatcher,
    registered_token: &RegisteredToken,
    event_id: EventId,
) {
    match dispatcher.dispatch(registered_token).await {
        Ok(DispatchOutcome::Delivered { backend: _ }) => {
            info!("Push sent successfully for event {}", event_id);
        }
        // Silent on purpose: no backend is configured for the platform.
        Err(DispatchError::NoBackendForPlatform) => {}
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
    use crate::push::PushService;
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
        async fn send_to_token(
            &self,
            device_token: &str,
            _platform: &Platform,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            if device_token == SLOW_DEVICE {
                self.release.notified().await;
            }
            let _ = self.delivered.send(device_token.to_string());
            Ok(())
        }

        fn supports_platform(&self, _platform: &Platform) -> bool {
            true
        }
    }

    struct Fixture {
        handler: EventHandler,
        release: Arc<Notify>,
        delivered: mpsc::UnboundedReceiver<String>,
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
            handler: EventHandler::new(dispatcher, store, salt, trusted, max_in_flight),
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
        assert!(ensure_subscribed(&output).is_ok());
    }

    #[test]
    fn subscription_failed_on_every_relay_forces_a_reconnect() {
        let output = subscribe_output(&[], &["wss://a.example", "wss://b.example"]);
        assert!(ensure_subscribed(&output).is_err());
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
