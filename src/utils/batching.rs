use tokio::time::Instant;

pub struct BatchingManager {
    batch_delay_ms: u64,
    last_sent: Option<Instant>,
    pending_send: Option<tokio::task::JoinHandle<()>>,
}

impl BatchingManager {
    pub fn new(batch_delay_ms: u64) -> Self {
        Self {
            batch_delay_ms,
            last_sent: None,
            pending_send: None,
        }
    }

    pub async fn should_send(&mut self) -> bool {
        // Check if there's already a pending send
        if self.pending_send.is_some() {
            return false;
        }

        // Check cooldown
        if let Some(last_sent) = self.last_sent {
            if last_sent.elapsed().as_millis() < 60000 {
                return false;
            }
        }

        // Schedule send after batch delay
        self.last_sent = Some(Instant::now());
        true
    }
}
