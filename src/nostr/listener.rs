use log::{info, error, warn};
use nostr_sdk::prelude::*;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{sleep, Duration};

use crate::config::Config;
use crate::push::PushService;
use crate::utils::batching::BatchingManager;

pub struct NostrListener {
    config: Config,
    push_services: Arc<Mutex<Vec<Box<dyn PushService>>>>,
    batching_manager: Arc<Mutex<BatchingManager>>,
}

impl NostrListener {
    pub fn new(
        config: Config,
        push_services: Arc<Mutex<Vec<Box<dyn PushService>>>>,
    ) -> Self {
        let batching_manager = Arc::new(Mutex::new(
            BatchingManager::new(config.push.batch_delay_ms)
        ));

        Self {
            config,
            push_services,
            batching_manager,
        }
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

        // Create filter for kind 1059 events from Mostro instance
        // Filter by author (Mostro pubkey) to only get events FROM this Mostro instance
        // This implements Option B: Silent Push Global approach
        let since = Timestamp::now() - Duration::from_secs(300);
        let pubkey_bytes = ::hex::decode(&self.config.nostr.mostro_pubkey)?;
        let mostro_pubkey = XOnlyPublicKey::from_slice(&pubkey_bytes)?;

        let filter = Filter::new()
            .kinds(vec![Kind::Custom(1059)])
            .author(mostro_pubkey)
            .since(since);

        // Subscribe to events
        client.subscribe(vec![filter]).await;
        info!(
            "Subscribed to kind 1059 events from Mostro instance: {}",
            &self.config.nostr.mostro_pubkey[..16]
        );

        // Handle incoming events
        let batching_manager = self.batching_manager.clone();
        let push_services = self.push_services.clone();

        client
            .handle_notifications(|notification| async {
                if let RelayPoolNotification::Event { event, .. } = notification {
                    if event.kind == Kind::Custom(1059) {
                        info!("Received kind 1059 event: {}", event.id);

                        // Trigger batched notification
                        let mut manager = batching_manager.lock().await;
                        if manager.should_send().await {
                            drop(manager);

                            // Send notifications through all push services
                            let services = push_services.lock().await;
                            for service in services.iter() {
                                if let Err(e) = service.send_silent_push().await {
                                    error!("Failed to send push notification: {}", e);
                                }
                            }
                        }
                    }
                }
                Ok(false)
            })
            .await?;

        Ok(())
    }
}
