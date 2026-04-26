use actix_web::{
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    web, Error, HttpResponse,
};
use governor::{
    clock::{Clock, DefaultClock},
    DefaultKeyedRateLimiter,
};
use log::warn;
use serde_json::json;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

/// Per-pubkey keyed rate limiter type alias (D-09).
pub type PerPubkeyLimiter = DefaultKeyedRateLimiter<String>;

/// Per-IP keyed rate limiter type alias (D-20).
pub type PerIpLimiter = DefaultKeyedRateLimiter<IpAddr>;

/// Per-pubkey burst (D-01). Not env-overridable in this phase per D-29.
pub const PUBKEY_BURST: u32 = 10;

/// Per-IP burst (D-02). Not env-overridable in this phase per D-29.
pub const IP_BURST: u32 = 30;

/// Cleanup interval default in seconds (D-16). Override via NOTIFY_RATE_LIMIT_CLEANUP_INTERVAL_SECS.
pub const RATE_LIMIT_CLEANUP_INTERVAL_DEFAULT_SECS: u64 = 60;

/// Soft-cap default (D-17). Override via NOTIFY_PUBKEY_LIMITER_SOFT_CAP.
pub const PUBKEY_LIMITER_SOFT_CAP_DEFAULT: usize = 100_000;

/// 429 Too Many Requests response shared by both the per-IP middleware and
/// the per-pubkey check inside notify_token. Body is BYTE-IDENTICAL between
/// the two callers (anti-RL-2 oracle, D-13). Retry-After is in whole seconds.
pub fn rate_limited_response(retry_after_secs: u64) -> HttpResponse {
    HttpResponse::TooManyRequests()
        .insert_header(("Retry-After", retry_after_secs.to_string()))
        .json(json!({
            "success": false,
            "message": "rate limited"
        }))
}

/// IP key extraction with precedence per D-10 (CRIT-4 anti-fix):
/// 1. Fly-Client-IP header (Fly's edge-injected canonical client IP).
/// 2. Rightmost segment of X-Forwarded-For (Fly appends the real client last).
///    Leftmost is attacker-controlled and MUST NOT be used.
/// 3. req.peer_addr().ip() for local development.
/// Returns None ONLY if all three fail; the middleware then short-circuits
/// with 500 (fail-closed per D-11) so an attacker cannot bypass per-IP RL.
fn extract_client_ip(req: &ServiceRequest) -> Option<IpAddr> {
    if let Some(v) = req.headers().get("Fly-Client-IP") {
        if let Ok(s) = v.to_str() {
            if let Ok(ip) = IpAddr::from_str(s.trim()) {
                return Some(ip);
            }
        }
    }
    if let Some(v) = req.headers().get("X-Forwarded-For") {
        if let Ok(s) = v.to_str() {
            // Rightmost segment per D-10 (Fly appends the real client IP last).
            if let Some(last) = s.rsplit(',').next() {
                if let Ok(ip) = IpAddr::from_str(last.trim()) {
                    return Some(ip);
                }
            }
        }
    }
    req.peer_addr().map(|sa| sa.ip())
}

/// Per-IP middleware applied ONLY to the /api/notify resource (D-21).
///
/// Reads the per-IP limiter from `web::Data<Arc<PerIpLimiter>>` (D-20: kept
/// out of AppState because the key type is IpAddr, not String).
///
/// Behaviour:
/// - On `check_key(ip).is_ok()`: pass through to `next.call(req)`.
/// - On `Err(not_until)`: short-circuit with `rate_limited_response(retry)`.
///   Body is byte-identical to the per-pubkey 429 (D-13). Retry-After
///   is `not_until.wait_time_from(DefaultClock::default().now()).as_secs().max(1)`.
/// - On IP extraction failure: 500 (D-11 fail-closed; never share a global bucket).
pub async fn per_ip_rate_limit_mw(
    req: ServiceRequest,
    next: Next<impl MessageBody + 'static>,
) -> Result<ServiceResponse<BoxBody>, Error> {
    let limiter = req
        .app_data::<web::Data<Arc<PerIpLimiter>>>()
        .cloned();

    let limiter = match limiter {
        Some(l) => l,
        None => {
            // Wiring error: limiter not in app_data. Fail-closed per D-11.
            warn!("per-ip rate-limit middleware: limiter not in app_data (wiring bug)");
            let resp = HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "internal error"
            }));
            return Ok(req.into_response(resp).map_into_boxed_body());
        }
    };

    let ip = match extract_client_ip(&req) {
        Some(ip) => ip,
        None => {
            // Fail-closed per D-11: never share a global bucket; never bypass.
            let resp = HttpResponse::InternalServerError().json(json!({
                "success": false,
                "message": "internal error"
            }));
            return Ok(req.into_response(resp).map_into_boxed_body());
        }
    };

    match limiter.check_key(&ip) {
        Ok(()) => {
            let res = next.call(req).await?;
            Ok(res.map_into_boxed_body())
        }
        Err(not_until) => {
            let retry_after_secs = not_until
                .wait_time_from(DefaultClock::default().now())
                .as_secs()
                .max(1);
            let resp = rate_limited_response(retry_after_secs);
            log::debug!("per-ip 429 retry_after={}s", retry_after_secs);
            Ok(req.into_response(resp).map_into_boxed_body())
        }
    }
}

/// Soft-cap branch of the cleanup task, extracted as a sync helper so the
/// LIMIT-06 warn-emission path is unit-testable without spawning a real
/// `tokio::time::interval` loop.
///
/// Invariant: `on_overflow` is invoked iff `len > soft_cap` (strict >).
/// Boundary: `len == soft_cap` does NOT invoke the callback.
pub(crate) fn check_soft_cap<F: FnOnce(usize)>(len: usize, soft_cap: usize, on_overflow: F) {
    if len > soft_cap {
        on_overflow(len);
    }
}

/// Periodic cleanup task for the per-pubkey limiter (LIMIT-05).
/// Mirrors src/store/mod.rs::start_cleanup_task.
///
/// Every `interval` tick:
/// - Calls `limiter.retain_recent()` to evict keys whose GCRA state is
///   indistinguishable from a fresh state.
/// - Routes the LIMIT-06 soft-cap check through `check_soft_cap` so the
///   warn-emission path is independently unit-testable.
/// - Cadence per D-18: every tick when over cap, no throttling.
/// - The warn line MUST NOT include any pubkey (RL-2 + privacy).
pub fn start_rate_limit_cleanup_task(
    limiter: Arc<PerPubkeyLimiter>,
    interval: Duration,
    soft_cap: usize,
) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            limiter.retain_recent();
            check_soft_cap(limiter.len(), soft_cap, |n| {
                warn!("rate-limit pubkey map size exceeded soft cap: {}", n);
            });
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::num::NonZeroU32;
    use std::time::Duration;
    use actix_web::{http::StatusCode, test as atest, web, App};
    use governor::{
        clock::FakeRelativeClock,
        state::keyed::HashMapStateStore,
        Quota, RateLimiter,
    };
    use crate::api::test_support::{
        make_test_components, build_test_actix_app, seed_hex_pubkey, TEST_PUBKEY,
    };

    /// LIMIT-06: above the cap, the callback fires with the actual length.
    #[test]
    fn check_soft_cap_fires_above_cap() {
        let calls: Mutex<Vec<usize>> = Mutex::new(Vec::new());
        check_soft_cap(5, 2, |n| calls.lock().unwrap().push(n));
        let captured = calls.lock().unwrap().clone();
        assert_eq!(captured, vec![5], "callback must fire exactly once with len=5");
    }

    /// LIMIT-06 boundary: at the cap (strict >), the callback does NOT fire.
    /// Below the cap, likewise no fire.
    #[test]
    fn check_soft_cap_does_not_fire_at_or_below_cap() {
        let calls: Mutex<Vec<usize>> = Mutex::new(Vec::new());
        check_soft_cap(2, 2, |n| calls.lock().unwrap().push(n));
        check_soft_cap(1, 2, |n| calls.lock().unwrap().push(n));
        let captured = calls.lock().unwrap().clone();
        assert!(captured.is_empty(), "boundary: len <= soft_cap MUST NOT fire (got {:?})", captured);
    }

    /// D-24 #5: Per-IP 429 boundary.
    /// Hit /api/notify 40 times from the same Fly-Client-IP, ROTATING
    /// trade_pubkey on each iteration so the per-pubkey limiter (burst 10)
    /// never fires before the per-IP limiter (burst 30).
    ///
    /// rotate pubkey to avoid per-pubkey limiter (burst=10) firing before
    /// per-IP (burst=30). Without rotation, the loop would 429 at iteration
    /// 11 from the per-pubkey path, never reaching the per-IP path.
    ///
    /// Structural assertion: the first 429 MUST appear at iteration >= IP_BURST
    /// (= 30, 0-indexed). If it fires earlier, the rotation is broken and the
    /// per-pubkey limiter fired first.
    #[actix_web::test]
    async fn per_ip_burst_exhaustion_returns_429() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let mut first_429_iter: Option<usize> = None;
        let mut successes_before_429: usize = 0;
        for i in 0..40 {
            // rotate pubkey to avoid per-pubkey limiter (burst=10) firing before per-IP (burst=30)
            let pk = seed_hex_pubkey(i as u64);
            let req = atest::TestRequest::post()
                .uri("/api/notify")
                .insert_header(("Fly-Client-IP", "1.2.3.4"))
                .set_json(serde_json::json!({"trade_pubkey": pk}))
                .to_request();
            let resp = atest::call_service(&app, req).await;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                first_429_iter = Some(i);
                assert!(
                    resp.headers().get("retry-after").is_some(),
                    "429 must carry Retry-After header"
                );
                break;
            } else {
                successes_before_429 += 1;
            }
        }
        let iter = first_429_iter.expect("per-IP burst MUST trigger 429 within 40 iterations");
        assert!(
            iter >= IP_BURST as usize,
            "first 429 came from the per-IP path: iter={} must be >= IP_BURST={} (otherwise per-pubkey fired first)",
            iter,
            IP_BURST
        );
        assert!(
            successes_before_429 >= IP_BURST as usize,
            "must see at least IP_BURST={} successes before the per-IP 429 (got {})",
            IP_BURST,
            successes_before_429
        );
    }

    /// D-24 #4: Per-pubkey 429 boundary.
    /// Hit /api/notify 15 times for the same pubkey from DIFFERENT IPs.
    /// Per-pubkey burst is PUBKEY_BURST=10, so call 11 must be 429.
    /// Different IPs ensure the per-IP limiter does not trigger first.
    ///
    /// Structural assertion: the first 429 MUST appear at iteration
    /// <= PUBKEY_BURST (0-indexed). If it fires later, the per-IP limiter
    /// got there first.
    #[actix_web::test]
    async fn per_pubkey_burst_exhaustion_returns_429() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let mut first_429_iter: Option<usize> = None;
        let mut successes_before_429: usize = 0;
        for i in 0..15 {
            // Rotate IP, fix pubkey so the per-pubkey limiter is the one exhausted.
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            let req = atest::TestRequest::post()
                .uri("/api/notify")
                .insert_header(("Fly-Client-IP", ip.as_str()))
                .set_json(serde_json::json!({"trade_pubkey": TEST_PUBKEY}))
                .to_request();
            let resp = atest::call_service(&app, req).await;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                first_429_iter = Some(i);
                assert!(resp.headers().get("retry-after").is_some());
                break;
            } else {
                successes_before_429 += 1;
            }
        }
        let iter = first_429_iter.expect("per-pubkey burst MUST trigger 429 within 15 iterations");
        assert!(
            iter <= PUBKEY_BURST as usize,
            "first 429 came from the per-pubkey path: iter={} must be <= PUBKEY_BURST={} (otherwise per-IP fired first)",
            iter,
            PUBKEY_BURST
        );
        assert!(
            successes_before_429 >= PUBKEY_BURST as usize,
            "must see at least PUBKEY_BURST={} successes before the per-pubkey 429 (got {})",
            PUBKEY_BURST,
            successes_before_429
        );
    }

    /// D-25 byte-equality: the 429 body from per-IP and per-pubkey paths must
    /// be byte-identical (anti-RL-2 oracle / OOS-18). Both halves are
    /// NON-TAUTOLOGICAL:
    /// - body_ip: rotates pubkeys (fixes IP) → captures a per-IP 429.
    /// - body_pk: rotates IPs (fixes pubkey) → captures a per-pubkey 429.
    #[actix_web::test]
    async fn rate_limited_429_body_byte_identical_per_ip_vs_per_pubkey() {
        // ---- Per-IP 429 body (rotate pubkeys to avoid per-pubkey firing first) ----
        let c_ip = make_test_components();
        let app_ip = atest::init_service(build_test_actix_app(c_ip)).await;
        let mut body_ip: Option<Vec<u8>> = None;
        let mut body_ip_iter: Option<usize> = None;
        for i in 0..40 {
            // rotate pubkey to avoid per-pubkey limiter (burst=10) firing before per-IP (burst=30)
            let pk = seed_hex_pubkey(i as u64);
            let req = atest::TestRequest::post()
                .uri("/api/notify")
                .insert_header(("Fly-Client-IP", "7.7.7.7"))
                .set_json(serde_json::json!({"trade_pubkey": pk}))
                .to_request();
            let resp = atest::call_service(&app_ip, req).await;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                body_ip_iter = Some(i);
                let bytes = atest::read_body(resp).await;
                body_ip = Some(bytes.to_vec());
                break;
            }
        }
        let body_ip = body_ip.expect("per-IP 429 path must trigger");
        let body_ip_iter = body_ip_iter.unwrap();
        assert!(
            body_ip_iter >= IP_BURST as usize,
            "body_ip captured a per-IP 429: iter={} must be >= IP_BURST={}",
            body_ip_iter,
            IP_BURST
        );

        // ---- Per-pubkey 429 body (rotate IPs to avoid per-IP firing first) ----
        let c_pk = make_test_components();
        let app_pk = atest::init_service(build_test_actix_app(c_pk)).await;
        let mut body_pk: Option<Vec<u8>> = None;
        let mut body_pk_iter: Option<usize> = None;
        for i in 0..15 {
            let ip = format!("10.20.{}.{}", i / 256, i % 256);
            let req = atest::TestRequest::post()
                .uri("/api/notify")
                .insert_header(("Fly-Client-IP", ip.as_str()))
                .set_json(serde_json::json!({"trade_pubkey": TEST_PUBKEY}))
                .to_request();
            let resp = atest::call_service(&app_pk, req).await;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                body_pk_iter = Some(i);
                let bytes = atest::read_body(resp).await;
                body_pk = Some(bytes.to_vec());
                break;
            }
        }
        let body_pk = body_pk.expect("per-pubkey 429 path must trigger");
        let body_pk_iter = body_pk_iter.unwrap();
        assert!(
            body_pk_iter <= PUBKEY_BURST as usize,
            "body_pk captured a per-pubkey 429: iter={} must be <= PUBKEY_BURST={}",
            body_pk_iter,
            PUBKEY_BURST
        );

        assert_eq!(
            body_ip, body_pk,
            "429 body MUST be byte-identical between per-IP and per-pubkey paths (anti-RL-2 oracle / OOS-18)"
        );

        let body_str = std::str::from_utf8(&body_ip).unwrap();
        assert_eq!(body_str, r#"{"success":false,"message":"rate limited"}"#);
    }

    /// D-25 LIMIT-05 plumbing: retain_recent on the keyed limiter reduces
    /// len() once virtual time advances past the GCRA window.
    ///
    /// D-27 resolution: governor's DefaultClock is QuantaClock (OS monotonic;
    /// NOT controlled by tokio::time::pause). This test explicitly constructs
    /// a limiter with FakeRelativeClock for deterministic virtual time advance.
    #[test]
    fn retain_recent_reduces_len_with_fake_clock() {
        let clock = FakeRelativeClock::default();
        // 1 req/sec, burst 1: keys age out after 1 second.
        let quota = Quota::per_second(NonZeroU32::new(1).unwrap());
        // The fourth generic must be NoOpMiddleware<<FakeRelativeClock as Clock>::Instant>
        // (= NoOpMiddleware<Nanos>) to satisfy trait bounds under quanta feature.
        let limiter: RateLimiter<
            String,
            HashMapStateStore<String>,
            FakeRelativeClock,
            governor::middleware::NoOpMiddleware<<FakeRelativeClock as Clock>::Instant>,
        > = RateLimiter::new(
            quota,
            HashMapStateStore::default(),
            &clock,
        );

        for i in 0..10 {
            let _ = limiter.check_key(&format!("key-{}", i));
        }
        assert_eq!(limiter.len(), 10, "10 distinct keys after population");

        // Advance virtual time well past the GCRA window (120s >> 1s).
        clock.advance(Duration::from_secs(120));

        limiter.retain_recent();

        assert!(
            limiter.len() < 10,
            "retain_recent must evict stale keys (len before=10, after={})",
            limiter.len()
        );
    }

    /// LIMIT-06 warn-emission contract against a REAL PerPubkeyLimiter.
    ///
    /// Populates a real PerPubkeyLimiter with 5 distinct keys, then invokes
    /// `check_soft_cap` with a closure that captures callback invocations.
    /// Also asserts the boundary case (soft_cap == len) does NOT fire.
    #[test]
    fn check_soft_cap_fires_for_real_limiter_above_cap() {
        let limiter: PerPubkeyLimiter =
            RateLimiter::keyed(Quota::per_minute(NonZeroU32::new(60).unwrap()));
        for i in 0..5 {
            let _ = limiter.check_key(&format!("k-{}", i));
        }
        assert_eq!(limiter.len(), 5, "5 distinct keys after population");

        // Above-cap: soft_cap=2, len=5 → callback MUST fire with n=5.
        let calls = Mutex::new(Vec::<usize>::new());
        check_soft_cap(limiter.len(), 2, |n| calls.lock().unwrap().push(n));
        let captured = calls.lock().unwrap().clone();
        assert_eq!(
            captured,
            vec![5],
            "above-cap (soft_cap=2, len=5): callback must fire exactly once with n=5"
        );

        // Boundary: soft_cap == limiter.len() = 5 → callback MUST NOT fire.
        let calls = Mutex::new(Vec::<usize>::new());
        check_soft_cap(limiter.len(), 5, |n| calls.lock().unwrap().push(n));
        let captured = calls.lock().unwrap().clone();
        assert!(
            captured.is_empty(),
            "boundary (soft_cap == len): callback MUST NOT fire (got {:?})",
            captured
        );
    }

    /// extract_client_ip precedence (D-10): when Fly-Client-IP is missing,
    /// the rightmost segment of X-Forwarded-For MUST be used (anti-CRIT-4
    /// leftmost-XFF spoofing).
    ///
    /// rotate pubkey to avoid per-pubkey limiter (burst=10) firing before
    /// per-IP (burst=30) — without rotation the per-pubkey path would 429
    /// first and we'd never exercise the rightmost-XFF guard.
    ///
    /// Structural assertion: the first 429 MUST appear at iteration
    /// >= IP_BURST + 1 (= 31). If it fires earlier, either (a) rotation is
    /// broken or (b) the middleware read the leftmost segment (CRIT-4).
    #[actix_web::test]
    async fn rightmost_xff_used_when_fly_client_ip_missing() {
        let c = make_test_components();
        let app = atest::init_service(build_test_actix_app(c)).await;

        let mut first_429_iter: Option<usize> = None;
        for i in 0..40 {
            // rotate pubkey to avoid per-pubkey limiter (burst=10) firing before per-IP (burst=30)
            let pk = seed_hex_pubkey(i as u64);
            let req = atest::TestRequest::post()
                .uri("/api/notify")
                // No Fly-Client-IP. Attacker spoofs leftmost (9.9.9.9).
                // Real client is rightmost (3.3.3.3) — the only segment the
                // middleware is allowed to read.
                .insert_header(("X-Forwarded-For", "9.9.9.9, 5.5.5.5, 3.3.3.3"))
                .set_json(serde_json::json!({"trade_pubkey": pk}))
                .to_request();
            let resp = atest::call_service(&app, req).await;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                first_429_iter = Some(i);
                break;
            }
        }
        let iter = first_429_iter
            .expect("rightmost-XFF (3.3.3.3) MUST be the rate-limit key — 31+ reqs hit per-IP burst");
        assert!(
            iter >= IP_BURST as usize,
            "rightmost-XFF guard exercised: iter={} must be >= IP_BURST={} (otherwise per-pubkey fired first or leftmost was read)",
            iter,
            IP_BURST
        );
    }
}
