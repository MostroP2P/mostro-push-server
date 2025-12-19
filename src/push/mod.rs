use async_trait::async_trait;
use std::sync::Arc;

pub mod fcm;
pub mod unifiedpush;

pub use fcm::FcmPush;
pub use unifiedpush::UnifiedPushService;

use crate::crypto::Platform;

#[async_trait]
pub trait PushService: Send + Sync {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>>;
    
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error>>;
    
    fn supports_platform(&self, platform: &Platform) -> bool;
}

// Implement PushService for Arc<UnifiedPushService> to allow shared ownership
#[async_trait]
impl PushService for Arc<UnifiedPushService> {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>> {
        (**self).send_silent_push().await
    }
    
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error>> {
        (**self).send_to_token(device_token, platform).await
    }
    
    fn supports_platform(&self, platform: &Platform) -> bool {
        (**self).supports_platform(platform)
    }
}

// Implement PushService for Arc<FcmPush> to allow shared ownership
#[async_trait]
impl PushService for Arc<FcmPush> {
    async fn send_silent_push(&self) -> Result<(), Box<dyn std::error::Error>> {
        (**self).send_silent_push().await
    }
    
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error>> {
        (**self).send_to_token(device_token, platform).await
    }
    
    fn supports_platform(&self, platform: &Platform) -> bool {
        (**self).supports_platform(platform)
    }
}
