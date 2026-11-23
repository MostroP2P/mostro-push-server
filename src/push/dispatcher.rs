use std::sync::Arc;

use crate::push::{PushError, PushKind, PushService};
use crate::store::RegisteredToken;

pub struct PushDispatcher {
    services: Arc<[Arc<dyn PushService>]>,
    backend_names: Arc<[&'static str]>,
}

pub enum DispatchOutcome {
    // `backend` is populated for downstream telemetry/logging callers that
    // are not yet wired up; the dispatcher already records the value.
    Delivered {
        #[allow(dead_code)]
        backend: &'static str,
    },
}

#[derive(Debug)]
pub enum DispatchError {
    /// No backend takes this push: the platform has no backend at all, none
    /// of them sends this kind, or none accepts a token of this shape.
    NoBackendForPlatform,
    AllBackendsFailed {
        errors: Vec<PushError>,
    },
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::NoBackendForPlatform => {
                write!(f, "no push backend takes this kind, platform and token")
            }
            DispatchError::AllBackendsFailed { errors } => {
                let errors: Vec<String> = errors.iter().map(ToString::to_string).collect();
                write!(f, "all push backends failed: [{}]", errors.join("; "))
            }
        }
    }
}

impl std::error::Error for DispatchError {}

impl PushDispatcher {
    pub fn new(services: Vec<(Arc<dyn PushService>, &'static str)>) -> Self {
        let (svcs, names): (Vec<_>, Vec<_>) = services.into_iter().unzip();
        Self {
            services: svcs.into(),
            backend_names: names.into(),
        }
    }

    /// Sends a push of `kind` through the first backend that supports it on
    /// the device's platform, takes a token of that shape, and delivers it.
    /// A backend that does not take the token never sees it.
    pub async fn dispatch(
        &self,
        kind: PushKind,
        token: &RegisteredToken,
    ) -> Result<DispatchOutcome, DispatchError> {
        let mut errors: Vec<PushError> = Vec::new();
        let mut attempted = false;

        for (idx, service) in self.services.iter().enumerate() {
            if !service.supports(kind, &token.platform)
                || !service.accepts_token(&token.device_token)
            {
                continue;
            }
            attempted = true;
            match service
                .send(kind, &token.device_token, &token.platform)
                .await
            {
                Ok(()) => {
                    return Ok(DispatchOutcome::Delivered {
                        backend: self.backend_names[idx],
                    });
                }
                Err(e) => {
                    errors.push(e);
                }
            }
        }

        if !attempted {
            Err(DispatchError::NoBackendForPlatform)
        } else {
            Err(DispatchError::AllBackendsFailed { errors })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::test_support::StubPushService;
    use crate::store::Platform;

    fn android_token() -> RegisteredToken {
        RegisteredToken {
            device_token: "token".to_string(),
            platform: Platform::Android,
            registered_at: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    async fn a_backend_that_does_not_send_the_kind_is_skipped() {
        let mut wake_only = StubPushService::new(vec![Platform::Android]);
        wake_only.unsupported_kinds = vec![PushKind::DisputeNew];
        let wake_only = Arc::new(wake_only);
        let every_kind = Arc::new(StubPushService::new(vec![Platform::Android]));
        let dispatcher = PushDispatcher::new(vec![
            (Arc::clone(&wake_only) as Arc<dyn PushService>, "wake-only"),
            (
                Arc::clone(&every_kind) as Arc<dyn PushService>,
                "every-kind",
            ),
        ]);

        let outcome = dispatcher
            .dispatch(PushKind::DisputeNew, &android_token())
            .await;

        assert!(matches!(
            outcome,
            Ok(DispatchOutcome::Delivered {
                backend: "every-kind"
            })
        ));
        assert!(wake_only.calls.lock().await.is_empty());
        assert_eq!(every_kind.calls.lock().await.len(), 1);

        // The same backend still takes the kinds it sends.
        let outcome = dispatcher
            .dispatch(PushKind::ChatWake, &android_token())
            .await;
        assert!(matches!(
            outcome,
            Ok(DispatchOutcome::Delivered {
                backend: "wake-only"
            })
        ));
    }

    /// As FCM before UnifiedPush: the endpoint URL goes only to the backend
    /// that takes URLs, and an opaque token still reaches the first one.
    #[tokio::test]
    async fn a_backend_that_does_not_take_the_token_never_sees_it() {
        let mut opaque_only = StubPushService::new(vec![Platform::Android]);
        opaque_only.refuses_urls = true;
        let opaque_only = Arc::new(opaque_only);
        let any_token = Arc::new(StubPushService::new(vec![Platform::Android]));
        let dispatcher = PushDispatcher::new(vec![
            (
                Arc::clone(&opaque_only) as Arc<dyn PushService>,
                "opaque-only",
            ),
            (Arc::clone(&any_token) as Arc<dyn PushService>, "any-token"),
        ]);

        let mut endpoint = android_token();
        endpoint.device_token = "https://ntfy.sh/upAbCdEf123456".to_string();
        let outcome = dispatcher.dispatch(PushKind::TradeUpdate, &endpoint).await;

        assert!(matches!(
            outcome,
            Ok(DispatchOutcome::Delivered {
                backend: "any-token"
            })
        ));
        assert!(opaque_only.calls.lock().await.is_empty());

        let outcome = dispatcher
            .dispatch(PushKind::TradeUpdate, &android_token())
            .await;
        assert!(matches!(
            outcome,
            Ok(DispatchOutcome::Delivered {
                backend: "opaque-only"
            })
        ));
    }

    #[tokio::test]
    async fn a_kind_no_backend_sends_reaches_none() {
        let mut wake_only = StubPushService::new(vec![Platform::Android]);
        wake_only.unsupported_kinds = vec![PushKind::DisputeNew];
        let wake_only = Arc::new(wake_only);
        let dispatcher = PushDispatcher::new(vec![(
            Arc::clone(&wake_only) as Arc<dyn PushService>,
            "wake-only",
        )]);

        let outcome = dispatcher
            .dispatch(PushKind::DisputeNew, &android_token())
            .await;

        assert!(matches!(outcome, Err(DispatchError::NoBackendForPlatform)));
        assert!(wake_only.calls.lock().await.is_empty());
    }
}
