use async_trait::async_trait;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use log::{debug, error, info, warn};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, RwLock};
use tokio::time::sleep;

use super::PushService;
use crate::config::Config;
use crate::store::Platform;

#[derive(Debug, Deserialize)]
struct ServiceAccount {
    client_email: String,
    private_key: String,
    // Deserialized for fixture validation and future logging; the runtime
    // project id comes from the FIREBASE_PROJECT_ID env var below.
    #[allow(dead_code)]
    project_id: String,
}

#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
}

struct CachedToken {
    token: String,
    expires_at: u64,
}

/// Google's OAuth2 token endpoint. Also the `aud` claim of the signed JWT,
/// which Google validates, so it stays fixed even when the request target is
/// pointed elsewhere in tests.
const OAUTH_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// Attempts per token exchange, first one included.
const OAUTH_MAX_ATTEMPTS: u32 = 3;

/// Per-attempt timeout, deliberately tighter than the shared client's 5 s.
///
/// The retry sequence runs while the caller holds one of the 50 `/api/notify`
/// semaphore permits, and that handler drops the dispatch *silently* when the
/// pool saturates. Three attempts at the client's 5 s would pin a permit for
/// ~15 s and turn a Google outage into a far higher silent-drop rate than no
/// retry at all. 2 s per attempt keeps the worst case near the 5 s a single
/// failed exchange already cost before retries existed.
const OAUTH_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// Base delay for the exponential backoff between attempts.
const OAUTH_BACKOFF_BASE_MS: u64 = 200;

/// One failed exchange, and whether trying again could plausibly help.
struct OauthAttemptError {
    message: String,
    retryable: bool,
}

pub struct FcmPush {
    client: Arc<reqwest::Client>,
    service_account: Option<ServiceAccount>,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
    /// Serialises token refreshes. Without it, every concurrent dispatch that
    /// misses the cache mints its own JWT and calls Google independently, so
    /// adding retries would multiply an outage by the number of in-flight
    /// dispatches. Single-flight is what makes the retry safe, not a separate
    /// optimisation.
    refresh_lock: Mutex<()>,
    /// Where the token exchange is POSTed. Fixed in production; overridden by
    /// tests so the retry behaviour can be exercised against a local server.
    oauth_token_url: String,
    project_id: String,
}

impl FcmPush {
    // `config` is accepted for symmetry with `UnifiedPushService::new` and to
    // keep call sites stable; FCM currently sources its settings from env vars.
    #[allow(unused_variables)]
    pub fn new(config: Config, client: Arc<reqwest::Client>) -> Self {
        let service_account_path = std::env::var("FIREBASE_SERVICE_ACCOUNT_PATH").ok();
        let project_id =
            std::env::var("FIREBASE_PROJECT_ID").unwrap_or_else(|_| "mostro".to_string());

        let service_account =
            service_account_path.and_then(|path| match fs::read_to_string(&path) {
                Ok(content) => match serde_json::from_str::<ServiceAccount>(&content) {
                    Ok(sa) => {
                        info!("Loaded Firebase service account for {}", sa.client_email);
                        Some(sa)
                    }
                    Err(e) => {
                        error!("Failed to parse service account JSON: {}", e);
                        None
                    }
                },
                Err(e) => {
                    warn!("Could not read service account file {}: {}", path, e);
                    None
                }
            });

        Self {
            client,
            service_account,
            cached_token: Arc::new(RwLock::new(None)),
            refresh_lock: Mutex::new(()),
            oauth_token_url: OAUTH_TOKEN_URL.to_string(),
            project_id,
        }
    }

    /// Initialize FCM service - validates that we can get an access token
    pub async fn init(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.service_account.is_none() {
            return Err("No service account configured".into());
        }
        // Try to get an access token to validate credentials
        self.get_access_token().await?;
        Ok(())
    }

    /// Returns a valid access token, refreshing it at most once at a time.
    async fn get_access_token(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(token) = self.cached_token_if_fresh().await {
            return Ok(token);
        }

        // Single-flight: only one refresh runs at a time, and everyone else
        // reuses its result rather than starting their own.
        let _refresh = self.refresh_lock.lock().await;

        // Another task may have refreshed while we waited for the lock.
        if let Some(token) = self.cached_token_if_fresh().await {
            return Ok(token);
        }

        self.refresh_access_token().await
    }

    /// The cached token, if it is still comfortably valid.
    ///
    /// Treated as stale 60 s before its real expiry so a token cannot lapse
    /// mid-flight between this check and the FCM call that uses it.
    async fn cached_token_if_fresh(&self) -> Option<String> {
        let cache = self.cached_token.read().await;
        let cached = cache.as_ref()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

        (cached.expires_at > now + 60).then(|| cached.token.clone())
    }

    /// Mints a JWT and exchanges it.
    ///
    /// Caller must hold `refresh_lock`.
    async fn refresh_access_token(
        &self,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let jwt = self.build_jwt(now)?;

        self.exchange_with_retry(&jwt, now).await
    }

    /// Signs the assertion Google exchanges for an access token.
    ///
    /// Split from the exchange so the retry policy can be exercised without
    /// RSA key material: credential handling and transport behaviour are
    /// independent concerns and fail for unrelated reasons.
    fn build_jwt(&self, now: u64) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let sa = self
            .service_account
            .as_ref()
            .ok_or("No service account configured")?;

        let claims = Claims {
            iss: sa.client_email.clone(),
            scope: "https://www.googleapis.com/auth/firebase.messaging".to_string(),
            aud: OAUTH_TOKEN_URL.to_string(),
            iat: now,
            exp: now + 3600, // 1 hour
        };

        let header = Header::new(Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(sa.private_key.as_bytes())?;
        Ok(encode(&header, &claims, &key)?)
    }

    /// Exchanges an assertion, retrying only failures a second try could fix.
    async fn exchange_with_retry(
        &self,
        jwt: &str,
        now: u64,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut attempt = 1;
        loop {
            match self.exchange_jwt(jwt).await {
                Ok(token_response) => {
                    {
                        let mut cache = self.cached_token.write().await;
                        *cache = Some(CachedToken {
                            token: token_response.access_token.clone(),
                            expires_at: now + token_response.expires_in,
                        });
                    }

                    if attempt > 1 {
                        info!("FCM OAuth2 token exchange succeeded on attempt {}", attempt);
                    }
                    info!(
                        "Obtained new FCM access token, expires in {}s",
                        token_response.expires_in
                    );
                    return Ok(token_response.access_token);
                }
                Err(err) => {
                    if !err.retryable || attempt >= OAUTH_MAX_ATTEMPTS {
                        error!(
                            "FCM OAuth2 token exchange failed after {} attempt(s): {}",
                            attempt, err.message
                        );
                        return Err(err.message.into());
                    }

                    let delay = oauth_backoff(attempt);
                    warn!(
                        "FCM OAuth2 attempt {}/{} failed ({}); retrying in {} ms",
                        attempt,
                        OAUTH_MAX_ATTEMPTS,
                        err.message,
                        delay.as_millis()
                    );
                    sleep(delay).await;
                    attempt += 1;
                }
            }
        }
    }

    /// A single token exchange, classified for retryability.
    ///
    /// A 4xx other than 429 means the credentials, clock or scope are wrong;
    /// repeating the same request cannot fix any of those, so it fails fast
    /// instead of spending the caller's semaphore permit on it.
    async fn exchange_jwt(&self, jwt: &str) -> Result<TokenResponse, OauthAttemptError> {
        let response = self
            .client
            .post(&self.oauth_token_url)
            .timeout(OAUTH_ATTEMPT_TIMEOUT)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", jwt),
            ])
            .send()
            .await
            .map_err(|e| OauthAttemptError {
                retryable: !e.is_builder(),
                message: format!("OAuth2 request failed: {}", e),
            })?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(OauthAttemptError {
                retryable: status.is_server_error()
                    || status == reqwest::StatusCode::TOO_MANY_REQUESTS,
                message: format!("OAuth2 token exchange failed ({}): {}", status, body),
            });
        }

        response.json().await.map_err(|e| OauthAttemptError {
            // A malformed success body is not something a retry repairs.
            retryable: false,
            message: format!("OAuth2 response was not valid JSON: {}", e),
        })
    }

    /// Build FCM payload with notification fallback
    ///
    /// Strategy:
    /// - Sends both `notification` (fallback) and `data` (for app processing)
    /// - Uses a fixed tag "mostro-trade" so notifications can be replaced
    /// - When app is alive: background service shows detailed notification with same tag,
    ///   which REPLACES the generic FCM notification
    /// - When app is killed: FCM shows generic notification as fallback
    fn build_payload_for_token(device_token: &str) -> serde_json::Value {
        json!({
            "message": {
                "token": device_token,
                // Notification field - shown by FCM when app is killed (fallback)
                "notification": {
                    "title": "Mostro",
                    "body": "You have an update on your trade"
                },
                // Data field - used by app to process when awake
                "data": {
                    "type": "trade_update",
                    "source": "mostro-push-server",
                    "timestamp": chrono::Utc::now().timestamp().to_string()
                },
                // Android-specific config
                "android": {
                    "priority": "high",
                    "notification": {
                        // Tag allows replacing notification with same tag
                        "tag": "mostro-trade",
                        // Use default channel (app should create "mostro_notifications" channel)
                        "channel_id": "mostro_notifications",
                        // Don't show if app is in foreground
                        "default_vibrate_timings": true
                    }
                },
                // iOS-specific config
                "apns": {
                    "headers": {
                        "apns-priority": "10",
                        "apns-collapse-id": "mostro-trade"
                    },
                    "payload": {
                        "aps": {
                            "alert": {
                                "title": "Mostro",
                                "body": "You have an update on your trade"
                            },
                            "content-available": 1,
                            "mutable-content": 1,
                            "thread-id": "mostro-trade"
                        }
                    }
                }
            }
        })
    }

    /// Silent push payload for the /api/notify chat-wake path.
    ///
    /// Data-only (no `alert`, no notification fallback) so iOS does not
    /// throttle the app for high-frequency silent pushes
    /// (apns-priority: 5 + apns-push-type: background per Apple's docs).
    /// Distinct from `build_payload_for_token` (Mostro daemon events at
    /// apns-priority: 10 with an alert fallback). Do NOT merge:
    /// the two paths have fundamentally different frequency profiles
    /// (chat = continuous, daemon events = sporadic).
    fn build_silent_payload_for_notify(device_token: &str) -> serde_json::Value {
        json!({
            "message": {
                "token": device_token,
                "data": {
                    "type": "chat_wake",
                    "source": "mostro-push-server",
                    "timestamp": chrono::Utc::now().timestamp().to_string()
                },
                "android": {
                    "priority": "high"
                },
                "apns": {
                    "headers": {
                        "apns-priority": "5",
                        "apns-push-type": "background"
                    },
                    "payload": {
                        "aps": {
                            "content-available": 1
                        }
                    }
                }
            }
        })
    }
}

#[async_trait]
impl PushService for FcmPush {
    async fn send_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let auth_token = self.get_access_token().await?;

        let fcm_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );

        let payload = Self::build_payload_for_token(device_token);

        debug!(
            "Sending FCM to token: {}...",
            &device_token[..20.min(device_token.len())]
        );

        let response = self
            .client
            .post(&fcm_url)
            .bearer_auth(&auth_token)
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            info!("FCM notification sent to {} device", platform);
            Ok(())
        } else {
            let error_text = response.text().await?;
            error!("FCM error for {} device: {}", platform, error_text);
            Err(format!("FCM send failed: {}", error_text).into())
        }
    }

    async fn send_silent_to_token(
        &self,
        device_token: &str,
        platform: &Platform,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let auth_token = self.get_access_token().await?;

        let fcm_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );

        let payload = Self::build_silent_payload_for_notify(device_token);

        debug!(
            "Sending FCM silent to token: {}...",
            &device_token[..20.min(device_token.len())]
        );

        let response = self
            .client
            .post(&fcm_url)
            .bearer_auth(&auth_token)
            .json(&payload)
            .send()
            .await?;

        if response.status().is_success() {
            info!("FCM silent notification sent to {} device", platform);
            Ok(())
        } else {
            let error_text = response.text().await?;
            error!("FCM silent error for {} device: {}", platform, error_text);
            Err(format!("FCM silent send failed: {}", error_text).into())
        }
    }

    fn supports_platform(&self, platform: &Platform) -> bool {
        matches!(platform, Platform::Android | Platform::Ios)
    }
}

/// Exponential backoff with full jitter for the OAuth2 retry loop.
///
/// Single-flight already caps this process to one exchange in flight, so the
/// jitter is not about self-contention: it spreads the retries of several
/// server instances that would otherwise recover from the same outage in
/// lockstep and hit Google together.
fn oauth_backoff(attempt: u32) -> Duration {
    let base = OAUTH_BACKOFF_BASE_MS * 2u64.pow(attempt.saturating_sub(1));
    let jitter = rand::thread_rng().gen_range(0..=base / 2);
    Duration::from_millis(base + jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `exchange_with_retry` never touches the service account, so these tests
    /// need no RSA key material: the assertion is passed in already signed.
    fn test_service(oauth_token_url: String) -> FcmPush {
        FcmPush {
            client: Arc::new(reqwest::Client::new()),
            service_account: None,
            cached_token: Arc::new(RwLock::new(None)),
            refresh_lock: Mutex::new(()),
            oauth_token_url,
            project_id: "test-project".to_string(),
        }
    }

    const TOKEN_BODY: &str = r#"{"access_token":"ya29.test","expires_in":3600}"#;

    #[tokio::test]
    async fn retries_a_transient_failure_and_then_succeeds() {
        let mut server = mockito::Server::new_async().await;
        let fail = server
            .mock("POST", "/token")
            .with_status(503)
            .expect(1)
            .create_async()
            .await;
        let ok = server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(TOKEN_BODY)
            .expect(1)
            .create_async()
            .await;

        let service = test_service(format!("{}/token", server.url()));
        let token = service
            .exchange_with_retry("dummy.jwt.value", 0)
            .await
            .expect("a 503 followed by a 200 must succeed");

        assert_eq!(token, "ya29.test");
        fail.assert_async().await;
        ok.assert_async().await;
    }

    #[tokio::test]
    async fn gives_up_after_the_attempt_budget() {
        let mut server = mockito::Server::new_async().await;
        let always_failing = server
            .mock("POST", "/token")
            .with_status(503)
            .expect(OAUTH_MAX_ATTEMPTS as usize)
            .create_async()
            .await;

        let service = test_service(format!("{}/token", server.url()));
        let err = service
            .exchange_with_retry("dummy.jwt.value", 0)
            .await
            .expect_err("a permanently failing endpoint must surface an error");

        assert!(err.to_string().contains("503"), "got: {err}");
        // Exactly the budget: not fewer, and crucially not more.
        always_failing.assert_async().await;
    }

    /// Bad credentials, a skewed clock or a wrong scope all surface as 4xx.
    /// Repeating the identical request cannot fix any of them, and the caller
    /// is holding an `/api/notify` semaphore permit while it waits.
    #[tokio::test]
    async fn does_not_retry_client_errors() {
        let mut server = mockito::Server::new_async().await;
        let once = server
            .mock("POST", "/token")
            .with_status(400)
            .with_body(r#"{"error":"invalid_grant"}"#)
            .expect(1)
            .create_async()
            .await;

        let service = test_service(format!("{}/token", server.url()));
        let err = service
            .exchange_with_retry("dummy.jwt.value", 0)
            .await
            .expect_err("a 400 must fail");

        assert!(err.to_string().contains("400"), "got: {err}");
        once.assert_async().await;
    }

    /// 429 is the one 4xx worth retrying: it is explicitly a "try again" signal.
    #[tokio::test]
    async fn retries_rate_limiting() {
        let mut server = mockito::Server::new_async().await;
        let throttled = server
            .mock("POST", "/token")
            .with_status(429)
            .expect(1)
            .create_async()
            .await;
        let ok = server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(TOKEN_BODY)
            .expect(1)
            .create_async()
            .await;

        let service = test_service(format!("{}/token", server.url()));
        assert!(service
            .exchange_with_retry("dummy.jwt.value", 0)
            .await
            .is_ok());
        throttled.assert_async().await;
        ok.assert_async().await;
    }

    #[tokio::test]
    async fn a_successful_exchange_populates_the_cache() {
        let mut server = mockito::Server::new_async().await;
        let _ok = server
            .mock("POST", "/token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(TOKEN_BODY)
            .create_async()
            .await;

        let service = test_service(format!("{}/token", server.url()));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        service
            .exchange_with_retry("dummy.jwt.value", now)
            .await
            .unwrap();

        assert_eq!(
            service.cached_token_if_fresh().await,
            Some("ya29.test".to_string()),
            "a fresh token must be served from cache without another exchange"
        );
    }

    /// A token within 60 s of expiry is treated as stale, so it cannot lapse
    /// between the cache check and the FCM call that uses it.
    #[tokio::test]
    async fn a_nearly_expired_token_is_not_served_from_cache() {
        let service = test_service("http://unused.invalid/token".to_string());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        *service.cached_token.write().await = Some(CachedToken {
            token: "stale".to_string(),
            expires_at: now + 30,
        });
        assert_eq!(service.cached_token_if_fresh().await, None);

        *service.cached_token.write().await = Some(CachedToken {
            token: "fresh".to_string(),
            expires_at: now + 600,
        });
        assert_eq!(
            service.cached_token_if_fresh().await,
            Some("fresh".to_string())
        );
    }

    #[test]
    fn backoff_grows_and_carries_jitter_within_bounds() {
        for attempt in 1..=OAUTH_MAX_ATTEMPTS {
            let base = OAUTH_BACKOFF_BASE_MS * 2u64.pow(attempt - 1);
            let delay = oauth_backoff(attempt).as_millis() as u64;
            assert!(
                (base..=base + base / 2).contains(&delay),
                "attempt {attempt}: {delay} ms outside [{}, {}]",
                base,
                base + base / 2
            );
        }
    }

    /// The property the whole retry design turns on. The sequence runs while
    /// the caller holds one of the 50 `/api/notify` permits, and that handler
    /// drops dispatches *silently* once the pool saturates. If a future change
    /// raises the attempt count or the per-attempt timeout, a Google outage
    /// starts costing more notifications than having no retry at all, with
    /// nothing user-visible to say so. This test is the tripwire.
    #[test]
    fn worst_case_retry_budget_stays_close_to_the_pre_retry_cost() {
        let backoff_ceiling_ms: u64 = (1..OAUTH_MAX_ATTEMPTS)
            .map(|attempt| {
                let base = OAUTH_BACKOFF_BASE_MS * 2u64.pow(attempt - 1);
                base + base / 2
            })
            .sum();

        let worst_case =
            OAUTH_ATTEMPT_TIMEOUT * OAUTH_MAX_ATTEMPTS + Duration::from_millis(backoff_ceiling_ms);

        assert!(
            worst_case <= Duration::from_secs(7),
            "worst-case OAuth retry budget is {worst_case:?}; a permit held that \
             long turns an outage into silent /api/notify drops"
        );
    }
}
