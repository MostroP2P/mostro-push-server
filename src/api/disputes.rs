//! `/api/disputes/watch` and `/api/disputes/unwatch`: a device asks to be told
//! when a Mostro node opens a dispute, or stops asking.
//!
//! A watch names a node, never a solver: no key of the caller is involved.
//! The push that follows a dispute is sent by the Nostr listener.

use actix_web::http::StatusCode;
use actix_web::{web, HttpResponse, Responder};
use log::{info, warn};
use serde::Deserialize;
use serde_json::json;

use crate::api::rate_limit::rate_limited_response;
use crate::api::routes::{AppState, MAX_TOKEN_BYTES};
use crate::push::endpoint_guard::{classify_token, TokenShape};
use crate::push::PushErrorKind;
use crate::store::Platform;
use crate::utils::log_pubkey::log_pubkey;

#[derive(Deserialize)]
pub struct WatchRequest {
    pub mostro_pubkey: String,
    pub token: String,
    pub platform: String,
}

#[derive(Deserialize)]
pub struct UnwatchRequest {
    pub mostro_pubkey: String,
    pub token: String,
}

/// `Retry-After` sent when a watcher list is full: watches expire on the
/// hourly cleanup.
const WATCHERS_FULL_RETRY_AFTER_SECS: u64 = 3600;

fn succeeded() -> HttpResponse {
    HttpResponse::Ok().json(json!({"success": true}))
}

fn refused(status: StatusCode, message: &str) -> HttpResponse {
    HttpResponse::build(status).json(json!({"success": false, "message": message}))
}

const INVALID_NODE: &str = "Invalid mostro_pubkey format (expected 64 hex characters)";

/// The node's pubkey in the form the trusted list and the store keep it, or
/// `None` for one that is not 64 hex characters.
fn parse_node(mostro_pubkey: &str) -> Option<String> {
    if mostro_pubkey.len() != 64 || hex::decode(mostro_pubkey).is_err() {
        warn!("Invalid mostro_pubkey format");
        return None;
    }
    // `hex::decode` takes either case; everything past here compares bytes.
    Some(mostro_pubkey.to_ascii_lowercase())
}

/// Why a token cannot be an FCM token, decided without any network: empty,
/// too long, or an `http(s)` URL (a UnifiedPush endpoint, which a dispute
/// push is never sent to).
fn token_shape_fault(token: &str) -> Option<&'static str> {
    if token.is_empty() {
        Some("Token cannot be empty")
    } else if token.len() > MAX_TOKEN_BYTES {
        Some("Token exceeds maximum length")
    } else if classify_token(token) != TokenShape::Opaque {
        Some("Invalid token")
    } else {
        None
    }
}

pub async fn watch_disputes(
    state: web::Data<AppState>,
    req: web::Json<WatchRequest>,
) -> impl Responder {
    let Some(node) = parse_node(&req.mostro_pubkey) else {
        return refused(StatusCode::BAD_REQUEST, INVALID_NODE);
    };
    if let Some(fault) = token_shape_fault(&req.token) {
        return refused(StatusCode::BAD_REQUEST, fault);
    }
    if !req.platform.eq_ignore_ascii_case("android") {
        return refused(
            StatusCode::BAD_REQUEST,
            "Invalid platform (expected 'android')",
        );
    }
    let log_node = log_pubkey(&state.notify_log_salt, &node);

    // Always enforced, whatever `TRUSTED_WHITELIST_ENABLED` says: the
    // listener only rings for the nodes on the list.
    if !state.trusted_mostro_pubkeys.contains(&node) {
        warn!("Watch denied: untrusted Mostro instance");
        return refused(StatusCode::FORBIDDEN, "Mostro instance not trusted");
    }

    // A device already on the list renews its watch without being checked
    // again, and whatever the caps say.
    if !state.watcher_store.is_watching(&node, &req.token).await {
        if !state.watcher_store.has_room(&node).await {
            return rate_limited_response(WATCHERS_FULL_RETRY_AFTER_SECS);
        }

        // Without this check anyone could fill a node's list with invented
        // tokens and lock its solvers out.
        let Some(checker) = &state.token_checker else {
            warn!("Watch of node={} refused: FCM is not available", log_node);
            return refused(
                StatusCode::SERVICE_UNAVAILABLE,
                "Token could not be checked",
            );
        };
        if let Err(e) = checker.check_token(&req.token).await {
            return match e.kind {
                PushErrorKind::Unregistered
                | PushErrorKind::InvalidArgument
                | PushErrorKind::SenderMismatch => {
                    info!(
                        "Watch of node={} refused: FCM does not know the token ({:?})",
                        log_node, e.kind
                    );
                    refused(StatusCode::BAD_REQUEST, "Invalid token")
                }
                PushErrorKind::Unavailable | PushErrorKind::Other => {
                    warn!(
                        "Watch of node={} refused: the token could not be checked ({:?})",
                        log_node, e.kind
                    );
                    refused(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Token could not be checked",
                    )
                }
            };
        }
    }

    if state
        .watcher_store
        .watch(node, req.token.clone(), Platform::Android)
        .await
        .is_err()
    {
        // The list filled up while the token was being checked.
        return rate_limited_response(WATCHERS_FULL_RETRY_AFTER_SECS);
    }
    succeeded()
}

pub async fn unwatch_disputes(
    state: web::Data<AppState>,
    req: web::Json<UnwatchRequest>,
) -> impl Responder {
    let Some(node) = parse_node(&req.mostro_pubkey) else {
        return refused(StatusCode::BAD_REQUEST, INVALID_NODE);
    };
    if let Some(fault) = token_shape_fault(&req.token) {
        return refused(StatusCode::BAD_REQUEST, fault);
    }

    match state.watcher_store.unwatch(&node, &req.token).await {
        // The same answer whether or not the watch existed.
        Ok(_) => succeeded(),
        // The durable delete failed and the watch is still in place, so
        // success would be a lie a restart exposes.
        Err(_) => refused(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use actix_web::{http::StatusCode, test as atest};
    use serde_json::{json, Value};

    use crate::api::rate_limit::REGISTER_IP_BURST;
    use crate::api::test_support::{
        build_test_actix_app, make_test_components, make_test_components_with_trusted_whitelist,
        make_test_components_with_whitelist_disabled, StubTokenChecker, TestAppComponents,
        TRUSTED_MOSTRO_PUBKEY, UNTRUSTED_MOSTRO_PUBKEY,
    };
    use crate::push::PushErrorKind;
    use crate::store::cipher::TokenCipher;
    use crate::store::sqlite::SqliteStore;
    use crate::store::watchers::WatcherStore;

    const TOKEN: &str = "fcm-token-for-device-1:APA91bHexample1";
    const OTHER_TOKEN: &str = "fcm-token-for-device-2:APA91bHexample2";

    /// A server that trusts [`TRUSTED_MOSTRO_PUBKEY`] and whose FCM answers
    /// every token check with `refuses_with`.
    fn components(
        refuses_with: Option<PushErrorKind>,
    ) -> (TestAppComponents, Arc<StubTokenChecker>) {
        let mut c = make_test_components_with_trusted_whitelist();
        let checker = Arc::new(StubTokenChecker::new(refuses_with));
        c.state.token_checker = Some(checker.clone());
        (c, checker)
    }

    fn watch_body(node: &str, token: &str) -> Value {
        json!({"mostro_pubkey": node, "token": token, "platform": "android"})
    }

    fn post(uri: &str, body: Value) -> atest::TestRequest {
        atest::TestRequest::post()
            .uri(uri)
            .insert_header(("Fly-Client-IP", "8.8.8.8"))
            .set_json(body)
    }

    /// Sends one request and returns its status, `Retry-After` and body.
    macro_rules! send {
        ($app:expr, $uri:expr, $body:expr) => {{
            let resp = atest::call_service(&$app, post($uri, $body).to_request()).await;
            let status = resp.status();
            let retry_after = resp
                .headers()
                .get("Retry-After")
                .map(|v| v.to_str().unwrap().to_string());
            let body = atest::read_body(resp).await;
            (
                status,
                retry_after,
                String::from_utf8(body.to_vec()).unwrap(),
            )
        }};
    }

    #[actix_web::test]
    async fn a_watch_is_checked_stored_and_answered_with_success_alone() {
        let (c, checker) = components(None);
        let watchers = c.state.watcher_store.clone();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let (status, _, body) = send!(
            app,
            "/api/disputes/watch",
            watch_body(TRUSTED_MOSTRO_PUBKEY, TOKEN)
        );

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"{"success":true}"#);
        assert!(watchers.is_watching(TRUSTED_MOSTRO_PUBKEY, TOKEN).await);
        assert_eq!(checker.calls(), 1);
    }

    #[actix_web::test]
    async fn watching_again_renews_without_asking_fcm() {
        let (c, checker) = components(None);
        let watchers = c.state.watcher_store.clone();
        let app = atest::init_service(build_test_actix_app(c)).await;

        for _ in 0..3 {
            let (status, _, body) = send!(
                app,
                "/api/disputes/watch",
                watch_body(TRUSTED_MOSTRO_PUBKEY, TOKEN)
            );
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, r#"{"success":true}"#);
        }

        assert_eq!(checker.calls(), 1);
        assert_eq!(watchers.count().await, 1);
    }

    #[actix_web::test]
    async fn the_node_pubkey_is_taken_in_either_case() {
        let (c, _) = components(None);
        let watchers = c.state.watcher_store.clone();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let upper = TRUSTED_MOSTRO_PUBKEY.to_ascii_uppercase();
        let (status, _, _) = send!(app, "/api/disputes/watch", watch_body(&upper, TOKEN));
        assert_eq!(status, StatusCode::OK);
        assert!(watchers.is_watching(TRUSTED_MOSTRO_PUBKEY, TOKEN).await);

        let (status, _, _) = send!(
            app,
            "/api/disputes/unwatch",
            json!({"mostro_pubkey": upper, "token": TOKEN})
        );
        assert_eq!(status, StatusCode::OK);
        assert_eq!(watchers.count().await, 0);
    }

    /// The listener only rings for trusted nodes, so the list is enforced
    /// here whatever `TRUSTED_WHITELIST_ENABLED` says.
    #[actix_web::test]
    async fn a_node_off_the_trusted_list_is_refused_whatever_the_flag() {
        for mut c in [
            make_test_components_with_trusted_whitelist(),
            make_test_components_with_whitelist_disabled(),
            // An empty list trusts no node.
            make_test_components(),
        ] {
            let checker = Arc::new(StubTokenChecker::new(None));
            c.state.token_checker = Some(checker.clone());
            let watchers = c.state.watcher_store.clone();
            let app = atest::init_service(build_test_actix_app(c)).await;

            let (status, _, body) = send!(
                app,
                "/api/disputes/watch",
                watch_body(UNTRUSTED_MOSTRO_PUBKEY, TOKEN)
            );

            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(
                body,
                r#"{"success":false,"message":"Mostro instance not trusted"}"#
            );
            assert_eq!(checker.calls(), 0);
            assert_eq!(watchers.count().await, 0);
        }
    }

    #[actix_web::test]
    async fn a_trusted_node_is_accepted_with_the_register_flag_off() {
        let mut c = make_test_components_with_whitelist_disabled();
        c.state.token_checker = Some(Arc::new(StubTokenChecker::new(None)));
        let app = atest::init_service(build_test_actix_app(c)).await;

        let (status, _, _) = send!(
            app,
            "/api/disputes/watch",
            watch_body(TRUSTED_MOSTRO_PUBKEY, TOKEN)
        );
        assert_eq!(status, StatusCode::OK);
    }

    #[actix_web::test]
    async fn malformed_input_is_a_400_and_reaches_neither_fcm_nor_the_store() {
        let long_token = "t".repeat(super::MAX_TOKEN_BYTES + 1);
        let cases = [
            (
                json!({"mostro_pubkey": "abc", "token": TOKEN, "platform": "android"}),
                "Invalid mostro_pubkey format (expected 64 hex characters)",
            ),
            (
                json!({"mostro_pubkey": "z".repeat(64), "token": TOKEN, "platform": "android"}),
                "Invalid mostro_pubkey format (expected 64 hex characters)",
            ),
            (
                watch_body(TRUSTED_MOSTRO_PUBKEY, ""),
                "Token cannot be empty",
            ),
            (
                watch_body(TRUSTED_MOSTRO_PUBKEY, &long_token),
                "Token exceeds maximum length",
            ),
            // A UnifiedPush endpoint, and a URL the endpoint guard refuses.
            (
                watch_body(TRUSTED_MOSTRO_PUBKEY, "https://ntfy.sh/upAbCdEf123456"),
                "Invalid token",
            ),
            (
                watch_body(TRUSTED_MOSTRO_PUBKEY, "http://10.0.0.1/push"),
                "Invalid token",
            ),
            (
                json!({"mostro_pubkey": TRUSTED_MOSTRO_PUBKEY, "token": TOKEN, "platform": "ios"}),
                "Invalid platform (expected 'android')",
            ),
            (
                json!({"mostro_pubkey": TRUSTED_MOSTRO_PUBKEY, "token": TOKEN, "platform": "web"}),
                "Invalid platform (expected 'android')",
            ),
        ];
        let (c, checker) = components(None);
        let watchers = c.state.watcher_store.clone();
        let app = atest::init_service(build_test_actix_app(c)).await;

        for (request, message) in cases {
            let (status, _, body) = send!(app, "/api/disputes/watch", request);
            assert_eq!(status, StatusCode::BAD_REQUEST, "{message}");
            assert_eq!(
                body,
                json!({"success": false, "message": message}).to_string()
            );
        }
        assert_eq!(checker.calls(), 0);
        assert_eq!(watchers.count().await, 0);
    }

    #[actix_web::test]
    async fn a_token_fcm_does_not_know_is_a_400_and_is_not_stored() {
        for kind in [
            PushErrorKind::Unregistered,
            PushErrorKind::InvalidArgument,
            PushErrorKind::SenderMismatch,
        ] {
            let (c, checker) = components(Some(kind));
            let watchers = c.state.watcher_store.clone();
            let app = atest::init_service(build_test_actix_app(c)).await;

            let (status, _, body) = send!(
                app,
                "/api/disputes/watch",
                watch_body(TRUSTED_MOSTRO_PUBKEY, TOKEN)
            );

            assert_eq!(status, StatusCode::BAD_REQUEST, "{kind:?}");
            assert_eq!(body, r#"{"success":false,"message":"Invalid token"}"#);
            assert_eq!(checker.calls(), 1);
            assert_eq!(watchers.count().await, 0);
        }
    }

    #[actix_web::test]
    async fn a_token_that_could_not_be_checked_is_a_503_and_is_not_stored() {
        for kind in [PushErrorKind::Unavailable, PushErrorKind::Other] {
            let (c, _) = components(Some(kind));
            let watchers = c.state.watcher_store.clone();
            let app = atest::init_service(build_test_actix_app(c)).await;

            let (status, _, body) = send!(
                app,
                "/api/disputes/watch",
                watch_body(TRUSTED_MOSTRO_PUBKEY, TOKEN)
            );

            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{kind:?}");
            assert_eq!(
                body,
                r#"{"success":false,"message":"Token could not be checked"}"#
            );
            assert_eq!(watchers.count().await, 0);
        }
    }

    #[actix_web::test]
    async fn without_fcm_a_new_watch_is_a_503() {
        // No token checker: FCM is disabled or failed to start.
        let c = make_test_components_with_trusted_whitelist();
        let watchers = c.state.watcher_store.clone();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let (status, _, _) = send!(
            app,
            "/api/disputes/watch",
            watch_body(TRUSTED_MOSTRO_PUBKEY, TOKEN)
        );

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(watchers.count().await, 0);
    }

    #[actix_web::test]
    async fn a_full_node_is_a_429_but_still_renews_a_device_on_its_list() {
        let (mut c, checker) = components(None);
        let watchers =
            Arc::new(WatcherStore::new(c.state.notify_log_salt.clone()).with_caps(1, 10));
        c.state.watcher_store = watchers.clone();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let (status, _, _) = send!(
            app,
            "/api/disputes/watch",
            watch_body(TRUSTED_MOSTRO_PUBKEY, TOKEN)
        );
        assert_eq!(status, StatusCode::OK);

        let (status, retry_after, body) = send!(
            app,
            "/api/disputes/watch",
            watch_body(TRUSTED_MOSTRO_PUBKEY, OTHER_TOKEN)
        );
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(retry_after.as_deref(), Some("3600"));
        assert_eq!(body, r#"{"success":false,"message":"rate limited"}"#);
        // A full list costs no request to FCM.
        assert_eq!(checker.calls(), 1);
        assert!(
            !watchers
                .is_watching(TRUSTED_MOSTRO_PUBKEY, OTHER_TOKEN)
                .await
        );

        let (status, _, _) = send!(
            app,
            "/api/disputes/watch",
            watch_body(TRUSTED_MOSTRO_PUBKEY, TOKEN)
        );
        assert_eq!(status, StatusCode::OK);
    }

    #[actix_web::test]
    async fn an_unwatch_removes_the_watch_and_answers_the_same_without_one() {
        let (c, _) = components(None);
        let watchers = c.state.watcher_store.clone();
        let app = atest::init_service(build_test_actix_app(c)).await;
        send!(
            app,
            "/api/disputes/watch",
            watch_body(TRUSTED_MOSTRO_PUBKEY, TOKEN)
        );
        send!(
            app,
            "/api/disputes/watch",
            watch_body(TRUSTED_MOSTRO_PUBKEY, OTHER_TOKEN)
        );

        let unwatch = json!({"mostro_pubkey": TRUSTED_MOSTRO_PUBKEY, "token": TOKEN});
        let (status, _, first) = send!(app, "/api/disputes/unwatch", unwatch.clone());
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first, r#"{"success":true}"#);
        assert!(!watchers.is_watching(TRUSTED_MOSTRO_PUBKEY, TOKEN).await);
        assert!(
            watchers
                .is_watching(TRUSTED_MOSTRO_PUBKEY, OTHER_TOKEN)
                .await
        );

        // Again, and for a node nobody watches: the same answer.
        let (status, _, again) = send!(app, "/api/disputes/unwatch", unwatch);
        assert_eq!((status, again.as_str()), (StatusCode::OK, first.as_str()));
        let (status, _, other) = send!(
            app,
            "/api/disputes/unwatch",
            json!({"mostro_pubkey": UNTRUSTED_MOSTRO_PUBKEY, "token": TOKEN})
        );
        assert_eq!((status, other.as_str()), (StatusCode::OK, first.as_str()));
    }

    #[actix_web::test]
    async fn a_malformed_unwatch_is_a_400() {
        let (c, _) = components(None);
        let app = atest::init_service(build_test_actix_app(c)).await;

        for (request, message) in [
            (
                json!({"mostro_pubkey": "abc", "token": TOKEN}),
                "Invalid mostro_pubkey format (expected 64 hex characters)",
            ),
            (
                json!({"mostro_pubkey": TRUSTED_MOSTRO_PUBKEY, "token": ""}),
                "Token cannot be empty",
            ),
        ] {
            let (status, _, body) = send!(app, "/api/disputes/unwatch", request);
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(
                body,
                json!({"success": false, "message": message}).to_string()
            );
        }
    }

    #[actix_web::test]
    async fn an_unwatch_the_disk_refused_is_a_500_and_the_watch_stays() {
        let path = std::env::temp_dir().join(format!(
            "mostro-push-disputes-test-{}.db",
            uuid::Uuid::new_v4()
        ));
        let key = "01".repeat(32);
        let sqlite = SqliteStore::open(&path, TokenCipher::from_hex(&key).unwrap()).unwrap();
        let (mut c, _) = components(None);
        let (watchers, _) =
            WatcherStore::persistent(c.state.notify_log_salt.clone(), sqlite).unwrap();
        let watchers = Arc::new(watchers);
        c.state.watcher_store = watchers.clone();
        let app = atest::init_service(build_test_actix_app(c)).await;
        send!(
            app,
            "/api/disputes/watch",
            watch_body(TRUSTED_MOSTRO_PUBKEY, TOKEN)
        );
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(
                "CREATE TRIGGER fail_delete BEFORE DELETE ON watchers
                 BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END;",
            )
            .unwrap();

        let (status, _, body) = send!(
            app,
            "/api/disputes/unwatch",
            json!({"mostro_pubkey": TRUSTED_MOSTRO_PUBKEY, "token": TOKEN})
        );

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body, r#"{"success":false,"message":"internal error"}"#);
        assert!(watchers.is_watching(TRUSTED_MOSTRO_PUBKEY, TOKEN).await);

        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
        }
    }

    /// Both endpoints sit behind the per-IP limiter of `/api/register`.
    #[actix_web::test]
    async fn the_register_limiter_covers_both_endpoints() {
        for uri in ["/api/disputes/watch", "/api/disputes/unwatch"] {
            let (c, _) = components(None);
            let app = atest::init_service(build_test_actix_app(c)).await;
            let body = watch_body(TRUSTED_MOSTRO_PUBKEY, TOKEN);

            for _ in 0..REGISTER_IP_BURST {
                let (status, _, _) = send!(app, uri, body.clone());
                assert_eq!(status, StatusCode::OK, "{uri}");
            }
            let (status, retry_after, _) = send!(app, uri, body.clone());
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{uri}");
            assert!(retry_after.is_some());
        }
    }

    #[actix_web::test]
    async fn an_oversized_body_is_a_400() {
        let (c, _) = components(None);
        let app = atest::init_service(build_test_actix_app(c)).await;

        let (status, _, _) = send!(
            app,
            "/api/disputes/watch",
            watch_body(TRUSTED_MOSTRO_PUBKEY, &"t".repeat(16 * 1024))
        );
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
