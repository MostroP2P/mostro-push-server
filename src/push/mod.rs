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

// `#[async_trait]` marks each generated method `#[must_use]` although the
// boxed future it returns already is; clippy 1.99 reports that as
// `double_must_use` on code this crate does not write. The trait stays on
// async_trait because the dispatcher holds it as `dyn PushService`.
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait PushService: Send + Sync {
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Silent (data-only, low-priority) push variant for /api/notify.
    ///
    /// Default delegates to `send_to_token`. Backends that need a
    /// distinct silent payload (e.g. FcmPush per Phase 2 D-05) override
    /// this method. UnifiedPush has no per-payload distinction and uses
    /// the default.
    async fn send_silent_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.send_to_token(device_token, platform).await
    }

    fn supports_platform(&self, platform: &Platform) -> bool;
}

// Implement PushService for Arc<UnifiedPushService> to allow shared ownership
#[async_trait]
impl PushService for Arc<UnifiedPushService> {
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        (**self).send_to_token(device_token, platform).await
    }

    async fn send_silent_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        (**self).send_silent_to_token(device_token, platform).await
    }

    fn supports_platform(&self, platform: &Platform) -> bool {
        (**self).supports_platform(platform)
    }
}

// Implement PushService for Arc<FcmPush> to allow shared ownership
#[async_trait]
impl PushService for Arc<FcmPush> {
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        (**self).send_to_token(device_token, platform).await
    }

    async fn send_silent_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        (**self).send_silent_to_token(device_token, platform).await
    }

    fn supports_platform(&self, platform: &Platform) -> bool {
        (**self).supports_platform(platform)
    }
}
