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
    use std::sync::Mutex;

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
}
