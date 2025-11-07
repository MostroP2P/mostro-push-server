use async_trait::async_trait;

pub mod fcm;
pub mod unifiedpush;

pub use fcm::FcmPush;
pub use unifiedpush::UnifiedPushService;

#[async_trait]
pub trait PushService: Send + Sync {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>>;
}
