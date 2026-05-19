use std::collections::HashSet;
use std::num::NonZeroU32;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};

use actix_web::{web, App};
use async_trait::async_trait;
use governor::{Quota, RateLimiter};
use rand::RngCore;

use crate::api::rate_limit::{
    PerIpLimiter, PerPubkeyLimiter, TrustProxyHeaders, IP_BURST, PUBKEY_BURST,
};
use crate::api::routes::{configure, json_config, AppState};
use crate::push::{PushDispatcher, PushService};
use crate::store::{Platform, TokenStore};

/// Stub PushService recording every dispatch call (D-23).
///
/// `calls`: shared record of (device_token, platform) per invocation.
/// `supports`: platforms for which `supports_platform` returns true.
/// `fail`: when true, `send_to_token` returns an error.
pub struct StubPushService {
    pub calls: Arc<Mutex<Vec<(String, Platform)>>>,
    pub supports: Vec<Platform>,
    pub fail: bool,
}

impl StubPushService {
    pub fn new(supports: Vec<Platform>) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            supports,
            fail: false,
        }
    }
}

#[async_trait]
impl PushService for StubPushService {
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.calls
            .lock()
            .await
            .push((device_token.to_string(), platform.clone()));
        if self.fail {
            Err("stub forced failure".into())
        } else {
            Ok(())
        }
    }

    // send_silent_to_token uses the trait default (delegates to send_to_token).

    fn supports_platform(&self, platform: &Platform) -> bool {
        self.supports.contains(platform)
    }
}

/// Per-pubkey quota for tests: 30/min burst PUBKEY_BURST (mirrors production D-01).
pub fn test_per_pubkey_quota() -> Quota {
    Quota::per_minute(NonZeroU32::new(30).unwrap())
        .allow_burst(NonZeroU32::new(PUBKEY_BURST).unwrap())
}

/// Per-IP quota for tests: 120/min burst IP_BURST (mirrors production D-02).
pub fn test_per_ip_quota() -> Quota {
    Quota::per_minute(NonZeroU32::new(120).unwrap()).allow_burst(NonZeroU32::new(IP_BURST).unwrap())
}

/// Build a test AppState + per-IP limiter pair using fresh in-memory limiters.
/// Returns (state, per_ip_limiter) so callers can assert against the stub.
///
/// Defaults `trusted_mostro_pubkeys` to an empty set and
/// `trusted_whitelist_enabled` to `false` (permissive mode). Tests exercising
/// the whitelist must override this via [`make_app_state_with_whitelist`].
pub fn make_app_state(stub: Arc<StubPushService>) -> (AppState, Arc<PerIpLimiter>) {
    make_app_state_with_whitelist(stub, Arc::new(HashSet::new()), false)
}

/// Variant of [`make_app_state`] that injects an explicit trusted-Mostro
/// whitelist and feature-flag value. The filter on /api/register only fires
/// when `trusted_whitelist_enabled` is `true` AND `trusted_mostro_pubkeys`
/// is non-empty.
pub fn make_app_state_with_whitelist(
    stub: Arc<StubPushService>,
    trusted_mostro_pubkeys: Arc<HashSet<String>>,
    trusted_whitelist_enabled: bool,
) -> (AppState, Arc<PerIpLimiter>) {
    let services: Vec<(Arc<dyn PushService>, &'static str)> =
        vec![(stub.clone() as Arc<dyn PushService>, "stub")];
    let dispatcher = Arc::new(PushDispatcher::new(services));

    let mut salt_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt_bytes);
    let notify_log_salt: Arc<[u8; 32]> = Arc::new(salt_bytes);

    let token_store = Arc::new(TokenStore::new(48, notify_log_salt.clone()));
    let semaphore = Arc::new(Semaphore::new(50));

    let per_pubkey_limiter: Arc<PerPubkeyLimiter> =
        Arc::new(RateLimiter::keyed(test_per_pubkey_quota()));
    let per_ip_limiter: Arc<PerIpLimiter> = Arc::new(RateLimiter::keyed(test_per_ip_quota()));

    let state = AppState {
        token_store,
        dispatcher,
        semaphore,
        notify_log_salt,
        per_pubkey_limiter,
        trusted_mostro_pubkeys,
        trusted_whitelist_enabled,
    };

    (state, per_ip_limiter)
}

/// Components returned by `make_test_app` so tests can call `build_actix_app`
/// and assert against the stub after exercising the service.
///
/// This avoids the `actix_http::Request` type annotation problem — the opaque
/// `impl Service<Request, ...>` type returned by `test::init_service` cannot be
/// annotated without a direct dep on `actix-http`. Each test calls `build_actix_app`
/// to construct the service inline, which lets type inference resolve the concrete type.
pub struct TestAppComponents {
    pub state: AppState,
    pub per_ip_limiter: Arc<PerIpLimiter>,
    pub stub: Arc<StubPushService>,
}

/// Build the components needed to construct a test actix-web service.
/// Call `test::init_service(build_actix_app(&components))` in each test.
///
/// Convenience for tests that don't need to register pubkeys ahead of time.
/// Defaults to an empty trusted-Mostro whitelist (permissive mode).
pub fn make_test_components() -> TestAppComponents {
    let stub = Arc::new(StubPushService::new(vec![Platform::Android]));
    let (state, per_ip_limiter) = make_app_state(stub.clone());
    TestAppComponents {
        state,
        per_ip_limiter,
        stub,
    }
}

/// Variant of [`make_test_components`] with the trusted-Mostro whitelist
/// pre-populated with [`TRUSTED_MOSTRO_PUBKEY`] AND the runtime feature flag
/// turned on. Use for tests exercising the active /api/register whitelist
/// filter. For tests that exercise the flag-disabled path with a non-empty
/// whitelist, use [`make_test_components_with_whitelist_disabled`].
pub fn make_test_components_with_trusted_whitelist() -> TestAppComponents {
    let stub = Arc::new(StubPushService::new(vec![Platform::Android]));
    let mut whitelist = HashSet::new();
    whitelist.insert(TRUSTED_MOSTRO_PUBKEY.to_string());
    let (state, per_ip_limiter) =
        make_app_state_with_whitelist(stub.clone(), Arc::new(whitelist), true);
    TestAppComponents {
        state,
        per_ip_limiter,
        stub,
    }
}

/// Variant with the trusted-Mostro whitelist populated but the runtime
/// feature flag turned OFF. Used to assert that the filter is genuinely
/// inert when the flag is false even when the embedded JSON ships with
/// entries — i.e. that the rollout safety property holds.
pub fn make_test_components_with_whitelist_disabled() -> TestAppComponents {
    let stub = Arc::new(StubPushService::new(vec![Platform::Android]));
    let mut whitelist = HashSet::new();
    whitelist.insert(TRUSTED_MOSTRO_PUBKEY.to_string());
    let (state, per_ip_limiter) =
        make_app_state_with_whitelist(stub.clone(), Arc::new(whitelist), false);
    TestAppComponents {
        state,
        per_ip_limiter,
        stub,
    }
}

/// Build an `App` from test components, ready for `test::init_service(...)`.
/// Each test calls `test::init_service(build_test_actix_app(c))` to obtain
/// the opaque `impl Service<Request, ...>` whose type is inferred by the compiler.
pub fn build_test_actix_app(
    c: TestAppComponents,
) -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    App::new()
        .app_data(web::Data::new(c.state))
        .app_data(web::Data::new(c.per_ip_limiter))
        .app_data(json_config())
        // Existing rate-limit tests inject Fly-Client-IP / X-Forwarded-For
        // and expect the middleware to honour them; mirror that by enabling
        // the proxy-trust flag here. Tests covering the default-false bypass
        // guard build their own App and override this with `false`.
        .app_data(web::Data::new(TrustProxyHeaders(true)))
        .configure(configure)
}

/// Macro to initialise the test app and extract the stub in a single expression.
/// Usage in tests:
/// ```ignore
/// let (app, stub) = make_test_app!();
/// ```
#[macro_export]
macro_rules! make_test_app {
    () => {{
        let c = $crate::api::test_support::make_test_components();
        let stub = c.stub.clone();
        let app =
            actix_web::test::init_service($crate::api::test_support::build_test_actix_app(c)).await;
        (app, stub)
    }};
}

/// Deterministic 64-hex pubkey fixture used across tests.
pub const TEST_PUBKEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// Second distinct 64-hex pubkey fixture (canonical "unregistered but format-valid").
pub const TEST_PUBKEY_2: &str = "2222222222222222222222222222222222222222222222222222222222222222";

/// 64-hex Mostro instance pubkey that whitelist-aware tests treat as trusted.
pub const TRUSTED_MOSTRO_PUBKEY: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// 64-hex Mostro instance pubkey that whitelist-aware tests treat as untrusted.
pub const UNTRUSTED_MOSTRO_PUBKEY: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// Produce a deterministic 64-hex pubkey from an integer seed.
/// Used by per-IP tests that rotate pubkeys to avoid the per-pubkey limiter
/// (burst 10) firing before the per-IP limiter (burst 30).
///
/// `seed_hex_pubkey(7)` → "0000000000000000000000000000000000000000000000000000000000000007"
pub fn seed_hex_pubkey(seed: u64) -> String {
    format!("{:0>64x}", seed)
}

/// Register a pubkey in the token store with the Android stub token.
pub async fn register_test_pubkey(state: &AppState, pubkey: &str) {
    state
        .token_store
        .register(
            pubkey.to_string(),
            "test_fcm_token".to_string(),
            Platform::Android,
        )
        .await;
}
