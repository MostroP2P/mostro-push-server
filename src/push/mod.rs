use async_trait::async_trait;
use std::sync::Arc;

pub mod dispatcher;
pub mod endpoint_guard;
pub mod fcm;
pub mod unifiedpush;

pub use dispatcher::{DispatchError, DispatchOutcome, PushDispatcher};
pub use fcm::FcmPush;
pub use unifiedpush::UnifiedPushService;

use crate::store::Platform;

/// What a push tells the device. It decides the payload each backend sends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushKind {
    /// A trusted Mostro node addressed a trade update to a registered trade
    /// pubkey: a visible notification.
    TradeUpdate,
    /// `/api/notify`: a silent, data-only wake.
    ChatWake,
}

#[async_trait]
pub trait PushService: Send + Sync {
    async fn send(
        &self,
        kind: PushKind,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn supports_platform(&self, platform: &Platform) -> bool;
}

// Implement PushService for Arc<UnifiedPushService> to allow shared ownership
#[async_trait]
impl PushService for Arc<UnifiedPushService> {
    async fn send(
        &self,
        kind: PushKind,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        (**self).send(kind, device_token, platform).await
    }

    fn supports_platform(&self, platform: &Platform) -> bool {
        (**self).supports_platform(platform)
    }
}

// Implement PushService for Arc<FcmPush> to allow shared ownership
#[async_trait]
impl PushService for Arc<FcmPush> {
    async fn send(
        &self,
        kind: PushKind,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        (**self).send(kind, device_token, platform).await
    }

    fn supports_platform(&self, platform: &Platform) -> bool {
        (**self).supports_platform(platform)
    }
}
