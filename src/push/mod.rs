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
    /// A trusted Mostro node opened a dispute: a visible notification for
    /// the devices watching that node. Android only, through FCM.
    // Sent by the dispute watchers, which are not wired yet.
    #[allow(dead_code)]
    DisputeNew,
}

/// Why a backend did not deliver a push.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushErrorKind {
    /// The token no longer names a device (FCM `UNREGISTERED`). It will not
    /// work again.
    Unregistered,
    /// The backend refused the request as malformed, the token included (FCM
    /// `INVALID_ARGUMENT`).
    InvalidArgument,
    /// The token was issued for another sender (FCM `SENDER_ID_MISMATCH`):
    /// it belongs to another Firebase project.
    SenderMismatch,
    /// The backend could not be reached, or asked to be tried again later.
    /// It says nothing about the token.
    Unavailable,
    Other,
}

/// A failed push: what went wrong, and the text for the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushError {
    // Read by the dispute fan-out and the token check, which are not wired
    // yet; today every caller only logs the error.
    #[allow(dead_code)]
    pub kind: PushErrorKind,
    detail: String,
}

impl PushError {
    pub fn new(kind: PushErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for PushError {}

#[async_trait]
pub trait PushService: Send + Sync {
    async fn send(
        &self,
        kind: PushKind,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), PushError>;

    /// Whether this backend delivers a push of `kind` to `platform`.
    fn supports(&self, kind: PushKind, platform: &Platform) -> bool;
}

// Implement PushService for Arc<UnifiedPushService> to allow shared ownership
#[async_trait]
impl PushService for Arc<UnifiedPushService> {
    async fn send(
        &self,
        kind: PushKind,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), PushError> {
        (**self).send(kind, device_token, platform).await
    }

    fn supports(&self, kind: PushKind, platform: &Platform) -> bool {
        (**self).supports(kind, platform)
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
    ) -> Result<(), PushError> {
        (**self).send(kind, device_token, platform).await
    }

    fn supports(&self, kind: PushKind, platform: &Platform) -> bool {
        (**self).supports(kind, platform)
    }
}
