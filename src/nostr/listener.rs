use futures::StreamExt;
use log::{debug, error, info, warn};
use nostr_sdk::prelude::*;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::{sleep, Duration};

use crate::config::Config;
use crate::push::{DispatchError, DispatchOutcome, PushDispatcher};
use crate::store::{RegisteredToken, TokenStore};
use crate::utils::log_pubkey::log_pubkey;

/// Upper bound on push dispatches the listener keeps in flight. Separate
/// from the `/api/notify` semaphore so neither path can starve the other.
const MAX_IN_FLIGHT_DISPATCHES: usize = 50;

pub struct NostrListener {
    config: Config,
    handler: EventHandler,
}

impl NostrListener {
    pub fn new(
        config: Config,
        dispatcher: Arc<PushDispatcher>,
        token_store: Arc<TokenStore>,
        log_salt: Arc<[u8; 32]>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            config,
            handler: EventHandler::new(dispatcher, token_store, log_salt, MAX_IN_FLIGHT_DISPATCHES),
        })
    }

    pub async fn start(&self) {
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

        // DO NOT add .authors(...) to this Filter. Two reasons:
        //  1. Gift Wrap (NIP-59, kind 1059) wraps each event with an EPHEMERAL outer key.
        //     The outer pubkey is never the Mostro daemon — filtering by author would drop everything.
        //  2. Admin DMs in disputes are sent directly user-to-user, NOT through the Mostro daemon.
        //     A mostro_pubkey author filter would silently drop every dispute notification.
        // See PROJECT.md anti-requirement OOS-19 / PITFALLS CRIT-1.
        //
        // Kind 14 is Mostro protocol v2 (NIP-44 direct): daemons advertising
        // protocol_version=2 address the trade pubkey in the `p` tag of a
        // signed kind-14 event instead of a Gift Wrap. It is matched by `p`
        // tag only, like kind 1059 — pushes fire solely for registered trade
        // pubkeys, so no author filter is needed here either.
        let since = Timestamp::now() - Duration::from_secs(60);
        let filter = Filter::new().kinds(watched_kinds()).since(since);

        // Open the notification channel BEFORE subscribing: the stream only
        // carries what arrives after this call, so subscribing first would
        // drop every event received in between.
        let mut notifications = client.notifications();

        let output = client.subscribe(filter).await?;
        for (relay, reason) in &output.failed {
            warn!("Subscription failed on relay {}: {}", relay, reason);
        }
        info!(
            "Subscribed to kind 1059 (Gift Wrap) and kind 14 (protocol v2) events on {} of {} relays",
            output.success.len(),
            output.success.len() + output.failed.len()
        );

        while let Some(notification) = notifications.next().await {
            if let ClientNotification::Event { event, .. } = notification {
                self.handler.handle(*event).await;
            }
        }

        Ok(())
    }
}

/// Matches a watched event to a registered device and dispatches its push.
struct EventHandler {
    dispatcher: Arc<PushDispatcher>,
    token_store: Arc<TokenStore>,
    log_salt: Arc<[u8; 32]>,
    permits: Arc<Semaphore>,
}

impl EventHandler {
    fn new(
        dispatcher: Arc<PushDispatcher>,
        token_store: Arc<TokenStore>,
        log_salt: Arc<[u8; 32]>,
        max_in_flight: usize,
    ) -> Self {
        Self {
            dispatcher,
            token_store,
            log_salt,
            permits: Arc::new(Semaphore::new(max_in_flight)),
        }
    }

    async fn handle(&self, event: Event) {
        if !is_watched_kind(event.kind) {
            return;
        }
        info!("Received {} event: {}", kind_label(event.kind), event.id);

        let Some(trade_pubkey) = extract_recipient(&event) else {
            warn!(
                "No 'p' tag found in {} event {}",
                kind_label(event.kind),
                event.id
            );
            return;
        };

        let log_pk = log_pubkey(&self.log_salt, &trade_pubkey);
        info!("Event recipient (p tag) pk={}", log_pk);

        let Some(registered_token) = self.token_store.get(&trade_pubkey).await else {
            debug!("No registered token pk={}", log_pk);
            return;
        };
        info!(
            "MATCH! Found registered token pk={}, sending push to {} device",
            log_pk, registered_token.platform
        );

        // Each push runs in its own task so a slow backend (a UnifiedPush
        // endpoint is chosen by whoever registered it) cannot stall events
        // from every relay. Waiting for a permit applies backpressure
        // instead of dropping the push.
        let Ok(permit) = self.permits.clone().acquire_owned().await else {
            error!(
                "Dispatch semaphore closed, dropping push for event {}",
                event.id
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

/// Watched kinds are held as `u16` because nostr-sdk parses 1059 and 14 into
/// the named `Kind::GiftWrap` and `Kind::PrivateDirectMessage` variants. A
/// `Kind::Custom(14)` *pattern* therefore never matches an inbound event, even
/// though `Kind`'s `PartialEq` compares the two as equal (it compares
/// `as_u16()`). Matching on the number keeps equality and pattern matching
/// from disagreeing.
const KIND_GIFT_WRAP: u16 = 1059;
const KIND_PROTOCOL_V2: u16 = 14;

/// Event kinds the listener subscribes to and dispatches on:
/// - 1059 — Gift Wrap (NIP-59), Mostro protocol v1 and dispute admin DMs.
/// - 14 — NIP-44 direct message, Mostro protocol v2 (daemons advertising
///   `protocol_version=2` reply with signed kind-14 events addressed to the
///   trade pubkey in the `p` tag instead of a Gift Wrap).
fn watched_kinds() -> Vec<Kind> {
    vec![
        Kind::from_u16(KIND_GIFT_WRAP),
        Kind::from_u16(KIND_PROTOCOL_V2),
    ]
}

fn is_watched_kind(kind: Kind) -> bool {
    matches!(kind.as_u16(), KIND_GIFT_WRAP | KIND_PROTOCOL_V2)
}

fn kind_label(kind: Kind) -> &'static str {
    match kind.as_u16() {
        KIND_GIFT_WRAP => "Gift Wrap (kind 1059)",
        KIND_PROTOCOL_V2 => "protocol v2 (kind 14)",
        _ => "unexpected kind",
    }
}

/// Extracts the recipient trade pubkey from the first `p` tag, shared by both
/// watched kinds (v1 Gift Wrap and v2 NIP-44 direct address the recipient the
/// same way).
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
            .await;
        store
            .register(
                fast_recipient.public_key().to_hex(),
                FAST_DEVICE.to_string(),
                Platform::Android,
            )
            .await;

        Fixture {
            handler: EventHandler::new(dispatcher, store, salt, max_in_flight),
            release,
            delivered,
            slow_recipient,
            fast_recipient,
        }
    }

    fn gift_wrap_to(recipient: &Keys) -> Event {
        EventBuilder::new(Kind::GiftWrap, "ciphertext")
            .tags([Tag::public_key(recipient.public_key())])
            .finalize(&Keys::generate())
            .unwrap()
    }

    #[tokio::test]
    async fn slow_push_does_not_delay_the_next_event() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;

        tokio::time::timeout(DELIVERY_WAIT, async {
            f.handler.handle(gift_wrap_to(&f.slow_recipient)).await;
            f.handler.handle(gift_wrap_to(&f.fast_recipient)).await;
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
    async fn in_flight_dispatches_are_capped() {
        let mut f = fixture(1).await;
        f.handler.handle(gift_wrap_to(&f.slow_recipient)).await;

        let blocked = tokio::time::timeout(
            BLOCKED_WAIT,
            f.handler.handle(gift_wrap_to(&f.fast_recipient)),
        )
        .await;
        assert!(blocked.is_err(), "second dispatch must wait for a permit");
        assert!(f.delivered.try_recv().is_err());

        f.release.notify_one();
        let slow = tokio::time::timeout(DELIVERY_WAIT, f.delivered.recv()).await;
        assert_eq!(slow.unwrap().as_deref(), Some(SLOW_DEVICE));

        f.handler.handle(gift_wrap_to(&f.fast_recipient)).await;
        let fast = tokio::time::timeout(DELIVERY_WAIT, f.delivered.recv()).await;
        assert_eq!(fast.unwrap().as_deref(), Some(FAST_DEVICE));
    }

    #[tokio::test]
    async fn unregistered_recipient_dispatches_nothing() {
        let mut f = fixture(MAX_IN_FLIGHT_DISPATCHES).await;

        f.handler.handle(gift_wrap_to(&Keys::generate())).await;

        let got = tokio::time::timeout(BLOCKED_WAIT, f.delivered.recv()).await;
        assert!(got.is_err());
    }

    #[test]
    fn watched_kinds_include_gift_wrap_and_protocol_v2() {
        assert!(is_watched_kind(Kind::Custom(1059)));
        assert!(is_watched_kind(Kind::Custom(14)));
        // Inbound events arrive as the named variants, not as Custom.
        assert!(is_watched_kind(Kind::from_u16(1059)));
        assert!(is_watched_kind(Kind::from_u16(14)));
    }

    /// Regression guard for the 0.45 migration: `kind_label` used to match on
    /// `Kind::Custom(..)` patterns, which never match the named variants the
    /// SDK produces for inbound events. Every watched event logged as
    /// "unexpected kind" while still dispatching correctly.
    #[test]
    fn kind_label_names_both_watched_kinds_however_constructed() {
        for kind in [Kind::from_u16(1059), Kind::Custom(1059)] {
            assert_eq!(kind_label(kind), "Gift Wrap (kind 1059)");
        }
        for kind in [Kind::from_u16(14), Kind::Custom(14)] {
            assert_eq!(kind_label(kind), "protocol v2 (kind 14)");
        }
        assert_eq!(kind_label(Kind::from_u16(1)), "unexpected kind");
    }

    #[test]
    fn unrelated_kinds_are_not_watched() {
        assert!(!is_watched_kind(Kind::Custom(1)));
        assert!(!is_watched_kind(Kind::Custom(38385)));
        assert!(!is_watched_kind(Kind::Custom(10002)));
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
}
