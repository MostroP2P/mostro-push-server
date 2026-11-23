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
    NoBackendForPlatform,
    AllBackendsFailed { errors: Vec<PushError> },
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchError::NoBackendForPlatform => {
                write!(f, "no push backend supports this platform")
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

    /// Sends a push of `kind` through the first backend that supports the
    /// device's platform and accepts it.
    pub async fn dispatch(
        &self,
        kind: PushKind,
        token: &RegisteredToken,
    ) -> Result<DispatchOutcome, DispatchError> {
        let mut errors: Vec<PushError> = Vec::new();
        let mut attempted = false;

        for (idx, service) in self.services.iter().enumerate() {
            if !service.supports_platform(&token.platform) {
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
