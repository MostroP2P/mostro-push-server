use log::{info, error, warn, debug};
use nostr_sdk::prelude::*;
use std::str::FromStr;
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
    mostro_pubkey: String,
    log_salt: Arc<[u8; 32]>,
}

impl NostrListener {
    pub fn new(
        config: Config,
        dispatcher: Arc<PushDispatcher>,
        token_store: Arc<TokenStore>,
        log_salt: Arc<[u8; 32]>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Validate the pubkey format
        let mostro_pubkey = config.nostr.mostro_pubkey.clone();
        if mostro_pubkey.len() != 64 {
            return Err("Invalid MOSTRO_PUBKEY format (expected 64 hex characters)".into());
        }
        // Validate it's valid hex by trying to parse it
        XOnlyPublicKey::from_str(&mostro_pubkey)
            .map_err(|_| "Invalid MOSTRO_PUBKEY (not a valid public key)")?;

        Ok(Self {
            config,
            dispatcher,
            token_store,
            mostro_pubkey,
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
                    error!("Error in Nostr listener: {}, reconnecting in 10 seconds...", e);
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
        let since = Timestamp::now() - Duration::from_secs(60);
        let filter = Filter::new()
            .kinds(vec![Kind::Custom(1059)])
            .since(since);

        // Subscribe to events
        client.subscribe(vec![filter]).await;
        info!("Subscribed to kind 1059 (Gift Wrap) events on relay");

        // Handle incoming events
        let token_store = self.token_store.clone();
        let dispatcher = self.dispatcher.clone();
        let log_salt = self.log_salt.clone();

        client
            .handle_notifications(|notification| async {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::Custom(1059) {
                        // Log every Gift Wrap event received
                        info!("Received Gift Wrap (kind 1059) event: {}", event.id);

                        // Extract recipient from 'p' tag
                        let recipient_pubkey = event.tags.iter()
                            .find_map(|tag| {
                                let tag_vec = tag.as_vec();
                                if tag_vec.len() >= 2 && tag_vec[0] == "p" {
                                    Some(tag_vec[1].clone())
                                } else {
                                    None
                                }
                            });

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
                            warn!("No 'p' tag found in Gift Wrap event {}", event.id);
                        }
                    }
                }
                Ok(false)
            })
            .await?;

        Ok(())
    }
}
