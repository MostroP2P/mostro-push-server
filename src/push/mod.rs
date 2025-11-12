use async_trait::async_trait;
use std::sync::Arc;

pub mod fcm;
pub mod unifiedpush;

pub use fcm::FcmPush;
pub use unifiedpush::UnifiedPushService;

#[async_trait]
pub trait PushService: Send + Sync {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>>;
}

// Implement PushService for Arc<UnifiedPushService> to allow shared ownership
#[async_trait]
impl PushService for Arc<UnifiedPushService> {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>> {
        (**self).send_silent_push().await
    }
}
