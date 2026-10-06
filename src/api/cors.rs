//! CORS for the browser-facing endpoints (`/api/register`, `/api/unregister`,
//! `/api/notify`), so a web client can register its FCM Web Push token.
//!
//! Hand-rolled rather than `actix-cors` because new crates need approval
//! (hard constraint 6), and the surface is tiny: one method, one header, no
//! credentials. The headers depend only on the request's `Origin`, never on
//! the body or on registration state, so `/api/notify` stays an oracle-free
//! endpoint (hard constraint 2).

use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::{
        header::{
            HeaderValue, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
            ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE,
            ORIGIN, VARY,
        },
        Method,
    },
    middleware::Next,
    web, Error, HttpResponse,
};
use serde::Deserialize;

/// Default for `CORS_ALLOWED_ORIGINS`: the deployed Mostro web client.
pub const DEFAULT_ALLOWED_ORIGINS: &str = "https://mostro.network";

/// How long a browser may cache a preflight answer.
const PREFLIGHT_MAX_AGE_SECS: &str = "86400";

/// Origins allowed to call the browser-facing endpoints, from
/// `CORS_ALLOWED_ORIGINS`. An empty list disables CORS entirely.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub enum AllowedOrigins {
    /// `*`: any origin. Safe here because the endpoints carry no credentials.
    Any,
    /// Exact origins, compared byte for byte with the `Origin` header.
    List(Vec<String>),
}

impl AllowedOrigins {
    /// Parses a comma-separated list. Blank entries are ignored, so an empty
    /// value disables CORS; a `*` entry anywhere allows every origin.
    pub fn parse(raw: &str) -> Self {
        let origins: Vec<String> = raw
            .split(',')
            .map(str::trim)
            .filter(|origin| !origin.is_empty())
            .map(String::from)
            .collect();
        if origins.iter().any(|origin| origin == "*") {
            Self::Any
        } else {
            Self::List(origins)
        }
    }

    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::List(origins) if origins.is_empty())
    }

    /// The `Access-Control-Allow-Origin` value for a request from `origin`,
    /// or `None` when that origin is not allowed.
    fn allow_origin(&self, origin: &HeaderValue) -> Option<HeaderValue> {
        match self {
            Self::Any => Some(HeaderValue::from_static("*")),
            Self::List(origins) => {
                let origin_str = origin.to_str().ok()?;
                origins
                    .iter()
                    .any(|allowed| allowed == origin_str)
                    .then(|| origin.clone())
            }
        }
    }
}

/// Answers preflights and tags responses for allowed origins.
///
/// Actual responses expose `Retry-After`, which is not CORS-safelisted, so a
/// web client can honour a `429`'s backoff the way the native client does.
///
/// Wrapped outside the rate limiters, so a preflight neither reaches a
/// handler nor spends a rate-limit token. A request with no `Origin`, or
/// from an origin that is not allowed, passes through untouched: it gets no
/// CORS headers and exactly the response it got before this middleware.
/// Without `AllowedOrigins` in app data, every request passes through.
pub async fn cors_mw(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let allow_origin = req
        .app_data::<web::Data<AllowedOrigins>>()
        .zip(req.headers().get(ORIGIN))
        .and_then(|(allowed, origin)| allowed.allow_origin(origin));

    let Some(allow_origin) = allow_origin else {
        return Ok(next.call(req).await?.map_into_boxed_body());
    };

    if req.method() == Method::OPTIONS {
        let preflight = HttpResponse::NoContent()
            .insert_header((ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin))
            .insert_header((ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS"))
            .insert_header((ACCESS_CONTROL_ALLOW_HEADERS, "Content-Type"))
            .insert_header((ACCESS_CONTROL_MAX_AGE, PREFLIGHT_MAX_AGE_SECS))
            .insert_header((VARY, "Origin"))
            .finish();
        return Ok(req.into_response(preflight));
    }

    let mut res = next.call(req).await?;
    let headers = res.headers_mut();
    headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin);
    headers.insert(
        ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("Retry-After"),
    );
    headers.append(VARY, HeaderValue::from_static("Origin"));
    Ok(res.map_into_boxed_body())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_comma_separated_list() {
        assert_eq!(
            AllowedOrigins::parse(" https://mostro.network , http://localhost:5173,,"),
            AllowedOrigins::List(vec![
                "https://mostro.network".to_string(),
                "http://localhost:5173".to_string(),
            ])
        );
    }

    #[test]
    fn a_wildcard_entry_allows_any_origin() {
        assert_eq!(AllowedOrigins::parse("*"), AllowedOrigins::Any);
        assert_eq!(
            AllowedOrigins::parse("https://mostro.network, *"),
            AllowedOrigins::Any
        );
    }

    #[test]
    fn a_blank_value_disables_cors() {
        assert!(AllowedOrigins::parse("").is_disabled());
        assert!(AllowedOrigins::parse(" , ").is_disabled());
        assert!(!AllowedOrigins::parse(DEFAULT_ALLOWED_ORIGINS).is_disabled());
        assert!(!AllowedOrigins::Any.is_disabled());
    }

    #[test]
    fn listed_origins_are_echoed_and_others_refused() {
        let allowed = AllowedOrigins::parse(DEFAULT_ALLOWED_ORIGINS);
        let listed = HeaderValue::from_static("https://mostro.network");

        assert_eq!(allowed.allow_origin(&listed), Some(listed.clone()));
        for other in [
            "https://evil.example",
            "http://mostro.network",
            "https://mostro.network.evil.example",
            "https://mostro.network/",
            "null",
        ] {
            assert_eq!(
                allowed.allow_origin(&HeaderValue::from_static(other)),
                None,
                "{other}"
            );
        }
    }

    #[test]
    fn any_answers_with_a_wildcard() {
        let origin = HeaderValue::from_static("https://fork.example");
        assert_eq!(
            AllowedOrigins::Any.allow_origin(&origin),
            Some(HeaderValue::from_static("*"))
        );
    }
}

/// End-to-end behaviour through the real route table and rate limiters.
#[cfg(test)]
mod http_tests {
    use super::AllowedOrigins;
    use crate::api::rate_limit::{IP_BURST, REGISTER_IP_BURST};
    use crate::api::test_support::{
        build_test_actix_app, build_test_actix_app_with_origins, make_test_components,
        register_test_pubkey, TEST_PUBKEY, TEST_PUBKEY_2,
    };
    use actix_web::http::header::{
        HeaderMap, ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS,
        ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_EXPOSE_HEADERS,
        ACCESS_CONTROL_MAX_AGE, ORIGIN, VARY,
    };
    use actix_web::http::{Method, StatusCode};
    use actix_web::test::{self, TestRequest};

    const ALLOWED: &str = "https://mostro.network";
    const OTHER: &str = "https://evil.example";
    const BROWSER_ENDPOINTS: [&str; 3] = ["/api/register", "/api/unregister", "/api/notify"];

    fn preflight(uri: &str, origin: Option<&str>) -> TestRequest {
        let req = TestRequest::default()
            .method(Method::OPTIONS)
            .uri(uri)
            .insert_header(("Fly-Client-IP", "8.8.8.8"))
            .insert_header(("Access-Control-Request-Method", "POST"))
            .insert_header(("Access-Control-Request-Headers", "content-type"));
        match origin {
            Some(origin) => req.insert_header((ORIGIN, origin)),
            None => req,
        }
    }

    fn post(uri: &str, origin: Option<&str>, body: serde_json::Value) -> TestRequest {
        let req = TestRequest::post()
            .uri(uri)
            .insert_header(("Fly-Client-IP", "8.8.8.8"))
            .set_json(body);
        match origin {
            Some(origin) => req.insert_header((ORIGIN, origin)),
            None => req,
        }
    }

    fn register_body(pubkey: &str) -> serde_json::Value {
        serde_json::json!({ "trade_pubkey": pubkey, "token": "t", "platform": "web" })
    }

    fn pubkey_body(pubkey: &str) -> serde_json::Value {
        serde_json::json!({ "trade_pubkey": pubkey })
    }

    fn assert_no_cors_headers(headers: &HeaderMap, context: &str) {
        for name in [
            ACCESS_CONTROL_ALLOW_ORIGIN,
            ACCESS_CONTROL_ALLOW_METHODS,
            ACCESS_CONTROL_ALLOW_HEADERS,
            ACCESS_CONTROL_MAX_AGE,
            ACCESS_CONTROL_ALLOW_CREDENTIALS,
            ACCESS_CONTROL_EXPOSE_HEADERS,
            VARY,
        ] {
            assert!(!headers.contains_key(&name), "{context}: unexpected {name}");
        }
    }

    fn assert_actual_cors_headers(headers: &HeaderMap, allow_origin: &str, context: &str) {
        assert_eq!(
            headers.get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            allow_origin,
            "{context}"
        );
        assert_eq!(headers.get(VARY).unwrap(), "Origin", "{context}");
        assert!(
            !headers.contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS),
            "{context}"
        );
    }

    /// Every header except the per-request `x-request-id` value, sorted.
    fn comparable_headers(headers: &HeaderMap) -> Vec<(String, String)> {
        let mut pairs: Vec<(String, String)> = headers
            .iter()
            .filter(|(name, _)| name.as_str() != "x-request-id")
            .map(|(name, value)| (name.to_string(), value.to_str().unwrap().to_string()))
            .collect();
        pairs.sort();
        pairs
    }

    #[actix_web::test]
    async fn preflight_from_an_allowed_origin_is_answered_on_every_browser_endpoint() {
        let app = test::init_service(build_test_actix_app(make_test_components())).await;

        for uri in BROWSER_ENDPOINTS {
            let resp = test::call_service(&app, preflight(uri, Some(ALLOWED)).to_request()).await;

            assert_eq!(resp.status(), StatusCode::NO_CONTENT, "{uri}");
            let headers = resp.headers();
            assert_actual_cors_headers(headers, ALLOWED, uri);
            assert_eq!(
                headers.get(ACCESS_CONTROL_ALLOW_METHODS).unwrap(),
                "POST, OPTIONS"
            );
            assert_eq!(
                headers.get(ACCESS_CONTROL_ALLOW_HEADERS).unwrap(),
                "Content-Type"
            );
            assert_eq!(headers.get(ACCESS_CONTROL_MAX_AGE).unwrap(), "86400");
            // An empty body: the handler, which would answer 400 to a
            // bodiless request, was never reached.
            assert!(test::read_body(resp).await.is_empty(), "{uri}");
        }
    }

    /// `request_id_mw` stays outermost on /api/notify, so a preflight gets a
    /// server-generated id like every other response there.
    #[actix_web::test]
    async fn notify_preflight_carries_a_server_generated_request_id() {
        let app = test::init_service(build_test_actix_app(make_test_components())).await;

        let req = preflight("/api/notify", Some(ALLOWED))
            .insert_header(("X-Request-Id", "spoofed-by-client"))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let id = resp
            .headers()
            .get("x-request-id")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(uuid::Uuid::parse_str(id).is_ok());
    }

    #[actix_web::test]
    async fn preflights_spend_no_rate_limit_token() {
        let c = make_test_components();
        let app = test::init_service(build_test_actix_app(c)).await;

        for uri in BROWSER_ENDPOINTS {
            let burst = if uri == "/api/notify" {
                IP_BURST
            } else {
                REGISTER_IP_BURST
            };
            for _ in 0..(burst + 10) {
                let resp =
                    test::call_service(&app, preflight(uri, Some(ALLOWED)).to_request()).await;
                assert_eq!(resp.status(), StatusCode::NO_CONTENT, "{uri}");
            }
        }

        // The buckets are still full: real requests from the same IP pass.
        let resp = test::call_service(
            &app,
            post("/api/register", Some(ALLOWED), register_body(TEST_PUBKEY)).to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = test::call_service(
            &app,
            post("/api/notify", Some(ALLOWED), pubkey_body(TEST_PUBKEY)).to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    /// A preflight from an origin that is not allowed falls through to the
    /// pre-CORS behaviour: the same response a request without `Origin` gets.
    #[actix_web::test]
    async fn preflight_from_another_origin_is_unchanged() {
        for uri in BROWSER_ENDPOINTS {
            let app = test::init_service(build_test_actix_app(make_test_components())).await;
            let baseline = test::call_service(&app, preflight(uri, None).to_request()).await;
            let app = test::init_service(build_test_actix_app(make_test_components())).await;
            let foreign = test::call_service(&app, preflight(uri, Some(OTHER)).to_request()).await;

            assert_eq!(foreign.status(), baseline.status(), "{uri}");
            assert_eq!(foreign.status(), StatusCode::METHOD_NOT_ALLOWED, "{uri}");
            assert_no_cors_headers(foreign.headers(), uri);
            assert_eq!(
                comparable_headers(foreign.headers()),
                comparable_headers(baseline.headers()),
                "{uri}"
            );
            assert_eq!(
                test::read_body(foreign).await,
                test::read_body(baseline).await,
                "{uri}"
            );
        }
    }

    #[actix_web::test]
    async fn actual_responses_from_an_allowed_origin_carry_cors_headers() {
        let app = test::init_service(build_test_actix_app(make_test_components())).await;

        let cases = [
            ("/api/register", register_body(TEST_PUBKEY), StatusCode::OK),
            (
                "/api/register",
                register_body("bad"),
                StatusCode::BAD_REQUEST,
            ),
            ("/api/unregister", pubkey_body(TEST_PUBKEY), StatusCode::OK),
            (
                "/api/notify",
                pubkey_body(TEST_PUBKEY),
                StatusCode::ACCEPTED,
            ),
            ("/api/notify", pubkey_body("bad"), StatusCode::BAD_REQUEST),
        ];
        for (uri, body, expected) in cases {
            let resp = test::call_service(&app, post(uri, Some(ALLOWED), body).to_request()).await;
            assert_eq!(resp.status(), expected, "{uri}");
            assert_actual_cors_headers(resp.headers(), ALLOWED, uri);
        }
    }

    #[actix_web::test]
    async fn rate_limited_and_fail_closed_responses_carry_cors_headers() {
        let app = test::init_service(build_test_actix_app(make_test_components())).await;

        let mut limited = None;
        for _ in 0..(REGISTER_IP_BURST + 5) {
            let req = post("/api/unregister", Some(ALLOWED), pubkey_body(TEST_PUBKEY));
            let resp = test::call_service(&app, req.to_request()).await;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                limited = Some(resp);
                break;
            }
        }
        let limited = limited.expect("the register limiter must answer 429");
        assert_actual_cors_headers(limited.headers(), ALLOWED, "429");
        assert!(limited.headers().contains_key("retry-after"));
        // `Retry-After` is not CORS-safelisted: without this a browser hides
        // it and the web client falls back to its generic backoff.
        assert_eq!(
            limited
                .headers()
                .get(ACCESS_CONTROL_EXPOSE_HEADERS)
                .unwrap(),
            "Retry-After"
        );

        // No proxy header and no peer address: the per-IP key cannot be
        // extracted and the limiter fails closed.
        let req = TestRequest::post()
            .uri("/api/notify")
            .insert_header((ORIGIN, ALLOWED))
            .set_json(pubkey_body(TEST_PUBKEY))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_actual_cors_headers(resp.headers(), ALLOWED, "500");
    }

    /// Requests from another origin, or with no `Origin`, are answered exactly
    /// as before: same status, headers and body, and no CORS headers.
    #[actix_web::test]
    async fn other_origins_get_the_pre_cors_response() {
        let cases = [
            ("/api/register", register_body(TEST_PUBKEY)),
            ("/api/register", register_body("bad")),
            ("/api/unregister", pubkey_body(TEST_PUBKEY)),
            ("/api/notify", pubkey_body(TEST_PUBKEY)),
        ];
        for (uri, body) in cases {
            let app = test::init_service(build_test_actix_app(make_test_components())).await;
            let baseline =
                test::call_service(&app, post(uri, None, body.clone()).to_request()).await;
            let app = test::init_service(build_test_actix_app(make_test_components())).await;
            let foreign = test::call_service(&app, post(uri, Some(OTHER), body).to_request()).await;

            assert_eq!(foreign.status(), baseline.status(), "{uri}");
            assert_no_cors_headers(baseline.headers(), uri);
            assert_no_cors_headers(foreign.headers(), uri);
            assert_eq!(
                comparable_headers(foreign.headers()),
                comparable_headers(baseline.headers()),
                "{uri}"
            );
            assert_eq!(
                test::read_body(foreign).await,
                test::read_body(baseline).await,
                "{uri}"
            );
        }
    }

    #[actix_web::test]
    async fn a_wildcard_allows_any_origin_with_a_wildcard_answer() {
        let app = test::init_service(build_test_actix_app_with_origins(
            make_test_components(),
            AllowedOrigins::Any,
        ))
        .await;

        let resp =
            test::call_service(&app, preflight("/api/notify", Some(OTHER)).to_request()).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_actual_cors_headers(resp.headers(), "*", "preflight");

        let req = post("/api/notify", Some(OTHER), pubkey_body(TEST_PUBKEY));
        let resp = test::call_service(&app, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        assert_actual_cors_headers(resp.headers(), "*", "202");

        // Still nothing without an `Origin`.
        let req = post("/api/notify", None, pubkey_body(TEST_PUBKEY));
        let resp = test::call_service(&app, req.to_request()).await;
        assert_no_cors_headers(resp.headers(), "no origin");
    }

    #[actix_web::test]
    async fn an_empty_allow_list_disables_cors() {
        let app = test::init_service(build_test_actix_app_with_origins(
            make_test_components(),
            AllowedOrigins::parse(""),
        ))
        .await;

        for uri in BROWSER_ENDPOINTS {
            let resp = test::call_service(&app, preflight(uri, Some(ALLOWED)).to_request()).await;
            assert_ne!(resp.status(), StatusCode::NO_CONTENT, "{uri}");
            assert_no_cors_headers(resp.headers(), uri);
        }
        let req = post("/api/register", Some(ALLOWED), register_body(TEST_PUBKEY));
        let resp = test::call_service(&app, req.to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_no_cors_headers(resp.headers(), "register");
    }

    /// Hard constraint 2: with CORS on, a registered and an unregistered
    /// pubkey still get the same status, body and headers from /api/notify.
    #[actix_web::test]
    async fn notify_cors_headers_do_not_reveal_registration() {
        let c = make_test_components();
        register_test_pubkey(&c.state, TEST_PUBKEY).await;
        let app = test::init_service(build_test_actix_app(c)).await;

        let registered = test::call_service(
            &app,
            post("/api/notify", Some(ALLOWED), pubkey_body(TEST_PUBKEY)).to_request(),
        )
        .await;
        let unregistered = test::call_service(
            &app,
            post("/api/notify", Some(ALLOWED), pubkey_body(TEST_PUBKEY_2)).to_request(),
        )
        .await;

        assert_eq!(registered.status(), StatusCode::ACCEPTED);
        assert_eq!(unregistered.status(), registered.status());
        assert_actual_cors_headers(registered.headers(), ALLOWED, "registered");
        assert!(registered.headers().contains_key("x-request-id"));
        assert!(unregistered.headers().contains_key("x-request-id"));
        assert_eq!(
            comparable_headers(unregistered.headers()),
            comparable_headers(registered.headers())
        );
        assert_eq!(
            test::read_body(unregistered).await,
            test::read_body(registered).await
        );
    }
}
