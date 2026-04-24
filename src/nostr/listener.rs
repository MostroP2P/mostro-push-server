use log::{info, error, warn, debug};
use nostr_sdk::prelude::*;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

use crate::config::Config;
use crate::push::PushService;
use crate::store::TokenStore;

pub struct NostrListener {
    config: Config,
    push_services: Arc<Mutex<Vec<Box<dyn PushService>>>>,
    token_store: Arc<TokenStore>,
    mostro_pubkey: String,
}

impl NostrListener {
    pub fn new(
        config: Config,
        push_services: Arc<Mutex<Vec<Box<dyn PushService>>>>,
        token_store: Arc<TokenStore>,
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
            push_services,
            token_store,
            mostro_pubkey,
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

        // Create filter for kind 1059 (Gift Wrap) events
        // Note: We don't filter by author because Gift Wrap uses ephemeral keys
        // The actual sender (Mostro) is encrypted inside. We filter by 'p' tag later.
        let since = Timestamp::now() - Duration::from_secs(60);
        let filter = Filter::new()
            .kinds(vec![Kind::Custom(1059)])
            .since(since);

        // Subscribe to events
        client.subscribe(vec![filter]).await;
        info!("Subscribed to kind 1059 (Gift Wrap) events on relay");

        // Handle incoming events
        let token_store = self.token_store.clone();
        let push_services = self.push_services.clone();

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
                            info!("Event recipient (p tag): {}...", &trade_pubkey[..16.min(trade_pubkey.len())]);

                            // Look up token in store
                            if let Some(registered_token) = token_store.get(&trade_pubkey).await {
                                info!(
                                    "MATCH! Found registered token for {}..., sending push to {} device",
                                    &trade_pubkey[..16],
                                    registered_token.platform
                                );

                                // Send push notification to the specific device
                                let services = push_services.lock().await;
                                for service in services.iter() {
                                    if service.supports_platform(&registered_token.platform) {
                                        match service.send_to_token(
                                            &registered_token.device_token,
                                            &registered_token.platform,
                                        ).await {
                                            Ok(_) => {
                                                info!("Push sent successfully for event {}", event.id);
                                                break; // Only need one service to succeed
                                            }
                                            Err(e) => {
                                                error!("Failed to send push: {}", e);
                                            }
                                        }
                                    }
                                }
                            } else {
                                debug!("No registered token for {}...", &trade_pubkey[..16.min(trade_pubkey.len())]);
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
