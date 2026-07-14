use log::{debug, error, info, warn};
use nostr_sdk::prelude::*;
use std::sync::Arc;
use tokio::time::{sleep, Duration};

use crate::config::Config;
use crate::push::{DispatchError, DispatchOutcome, PushDispatcher};
use crate::store::TokenStore;
use crate::utils::log_pubkey::log_pubkey;

pub struct NostrListener {
    config: Config,
    dispatcher: Arc<PushDispatcher>,
    token_store: Arc<TokenStore>,
    log_salt: Arc<[u8; 32]>,
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
            dispatcher,
            token_store,
            log_salt,
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

        // Create Nostr client
        let keys = Keys::generate();
        let client = Client::new(&keys);

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

        // Subscribe to events
        client.subscribe(vec![filter]).await;
        info!("Subscribed to kind 1059 (Gift Wrap) and kind 14 (protocol v2) events on relay");

        // Handle incoming events
        let token_store = self.token_store.clone();
        let dispatcher = self.dispatcher.clone();
        let log_salt = self.log_salt.clone();

        client
            .handle_notifications(|notification| async {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if is_watched_kind(event.kind) {
                        // Log every watched event received
                        info!(
                            "Received {} event: {}",
                            kind_label(event.kind),
                            event.id
                        );

                        // Extract recipient from 'p' tag
                        let recipient_pubkey = extract_recipient(&event);

                        if let Some(trade_pubkey) = recipient_pubkey {
                            let log_pk = log_pubkey(&log_salt, &trade_pubkey);
                            info!("Event recipient (p tag) pk={}", log_pk);

                            // Look up token in store
                            if let Some(registered_token) = token_store.get(&trade_pubkey).await {
                                info!(
                                    "MATCH! Found registered token pk={}, sending push to {} device",
                                    log_pk,
                                    registered_token.platform
                                );

                                // Dispatch via PushDispatcher (lock-free; iteration protocol owned by dispatcher).
                                match dispatcher.dispatch(&registered_token).await {
                                    Ok(DispatchOutcome::Delivered { backend: _ }) => {
                                        info!("Push sent successfully for event {}", event.id);
                                    }
                                    Err(DispatchError::NoBackendForPlatform) => {
                                        // Preserve existing observable behaviour: today's loop simply
                                        // exits silently when no service supports the platform.
                                        // Phase 2's /api/notify handler will distinguish this case.
                                    }
                                    Err(DispatchError::AllBackendsFailed { errors }) => {
                                        for err in errors {
                                            error!("Failed to send push: {}", err);
                                        }
                                    }
                                }
                            } else {
                                debug!("No registered token pk={}", log_pk);
                            }
                        } else {
                            warn!(
                                "No 'p' tag found in {} event {}",
                                kind_label(event.kind),
                                event.id
                            );
                        }
                    }
                }
                Ok(false)
            })
            .await?;

        Ok(())
    }
}

/// Event kinds the listener subscribes to and dispatches on:
/// - 1059 — Gift Wrap (NIP-59), Mostro protocol v1 and dispute admin DMs.
/// - 14 — NIP-44 direct message, Mostro protocol v2 (daemons advertising
///   `protocol_version=2` reply with signed kind-14 events addressed to the
///   trade pubkey in the `p` tag instead of a Gift Wrap).
fn watched_kinds() -> Vec<Kind> {
    vec![Kind::Custom(1059), Kind::Custom(14)]
}

fn is_watched_kind(kind: Kind) -> bool {
    watched_kinds().contains(&kind)
}

fn kind_label(kind: Kind) -> &'static str {
    match kind {
        Kind::Custom(1059) => "Gift Wrap (kind 1059)",
        Kind::Custom(14) => "protocol v2 (kind 14)",
        _ => "unexpected kind",
    }
}

/// Extracts the recipient trade pubkey from the first `p` tag, shared by both
/// watched kinds (v1 Gift Wrap and v2 NIP-44 direct address the recipient the
/// same way).
fn extract_recipient(event: &Event) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let tag_vec = tag.as_vec();
        if tag_vec.len() >= 2 && tag_vec[0] == "p" {
            Some(tag_vec[1].clone())
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watched_kinds_include_gift_wrap_and_protocol_v2() {
        assert!(is_watched_kind(Kind::Custom(1059)));
        assert!(is_watched_kind(Kind::Custom(14)));
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
        let event = EventBuilder::new(
            Kind::Custom(14),
            "ciphertext",
            [Tag::public_key(recipient.public_key())],
        )
        .to_event(&keys)
        .unwrap();

        assert_eq!(
            extract_recipient(&event),
            Some(recipient.public_key().to_string())
        );
    }

    #[test]
    fn extract_recipient_returns_none_without_p_tag() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(14), "ciphertext", [])
            .to_event(&keys)
            .unwrap();

        assert_eq!(extract_recipient(&event), None);
    }
}
