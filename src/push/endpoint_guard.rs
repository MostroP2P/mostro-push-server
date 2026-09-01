//! SSRF guard for UnifiedPush endpoint URLs.
//!
//! The UnifiedPush backend treats a registered device token as a URL and POSTs
//! to it, so an unvalidated token is a request-forgery primitive reachable from
//! the unauthenticated `/api/register` + `/api/notify` pair. This module is the
//! single place that decides whether such a URL may be contacted.
//!
//! Two entry points, deliberately different in strength:
//!
//! - [`classify_token`] is pure and never touches the network. It runs at
//!   registration to keep obviously hostile values out of the token store.
//! - [`validate_endpoint`] runs on the dispatch path, immediately before the
//!   outbound POST, and additionally resolves domain hosts so a name pointing
//!   at an internal address is refused. This is the authoritative check.
//!
//! Both passes inspect only the **first hop**. That is only sufficient because
//! the UnifiedPush backend runs on a client that refuses redirects; see
//! `UnifiedPushService::build_client`. Reusing a redirect-following client here
//! would reduce this whole module to decoration.
//!
//! Registration cannot be the only gate: `/api/register` carries no field
//! saying which backend a token belongs to, so an FCM token and a UnifiedPush
//! URL arrive indistinguishable. `classify_token` therefore only inspects
//! values whose scheme is `http` or `https`; anything else is opaque and left
//! for its own backend to interpret.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use reqwest::Url;
use tokio::net::lookup_host;
use tokio::time::timeout;

/// Schemes refused outright at registration. None of them can produce an
/// outbound request through `reqwest`, so this is data hygiene rather than an
/// SSRF control: a token spelled this way is broken whichever backend claims
/// it, and there is no reason to hold it in the store until its TTL expires.
const DANGEROUS_SCHEMES: &[&str] = &["file", "ftp", "gopher", "data", "dict", "ldap"];

/// Upper bound on the pre-flight DNS lookup in [`validate_endpoint`].
///
/// The lookup runs before `reqwest` ever sees the request, so it is outside
/// that client's 5 s total timeout. The endpoint host is attacker-supplied, so
/// its nameserver may simply never answer: the Nostr listener awaits dispatch
/// inline and `/api/notify` holds one of its 50 permits for the lifetime of
/// the spawned task, which makes an unbounded lookup a way to stall event
/// processing and drain the permit pool. Matches the client's connect timeout.
const DNS_TIMEOUT: Duration = Duration::from_secs(2);

/// Why an endpoint URL was refused. Kept coarse on purpose: the HTTP layer
/// collapses every variant into one message so a caller cannot use the
/// response to map the server's internal network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointRejection {
    /// Scheme is `http`. Push endpoints must be TLS-protected.
    InsecureScheme,
    /// URL carries no host (e.g. `https:///path`).
    MissingHost,
    /// Host is, or resolves to, an address outside the public internet.
    NonPublicAddress,
    /// Host is a domain that could not be resolved.
    UnresolvableHost,
}

impl fmt::Display for EndpointRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EndpointRejection::InsecureScheme => "scheme must be https",
            EndpointRejection::MissingHost => "URL has no host",
            EndpointRejection::NonPublicAddress => "host is not a public address",
            EndpointRejection::UnresolvableHost => "host could not be resolved",
        };
        f.write_str(s)
    }
}

/// What a registration `token` turned out to be.
#[derive(Debug, PartialEq, Eq)]
pub enum TokenShape {
    /// Not an `http`/`https` URL, so not something this guard can reason
    /// about: an FCM registration token, or a value no backend will accept.
    /// `reqwest` refuses to issue a request for a non-HTTP scheme, so an
    /// opaque value cannot become an outbound request by itself.
    Opaque,
    /// A syntactically acceptable https endpoint. Domain hosts still face DNS
    /// validation at dispatch time.
    Endpoint,
    /// An http(s) URL that must not be contacted.
    Rejected(EndpointRejection),
}

/// Pure, network-free classification of a registration token.
pub fn classify_token(token: &str) -> TokenShape {
    let url = match Url::parse(token) {
        Ok(url) => url,
        // Not a URL at all. FCM tokens without a `:` land here.
        Err(_) => return TokenShape::Opaque,
    };

    // FCM tokens containing a `:` do parse, with the part before the colon
    // taken as the scheme and no host. Only http(s) can become an outbound
    // request — `reqwest` refuses every other scheme — so only those are this
    // guard's SSRF business.
    //
    // `DANGEROUS_SCHEMES` is a separate, weaker concern: hygiene. Those values
    // are neither a valid FCM token nor a usable push endpoint, so they are
    // refused rather than stored, even though no backend would act on them.
    match url.scheme() {
        "https" => {}
        "http" => return TokenShape::Rejected(EndpointRejection::InsecureScheme),
        scheme if DANGEROUS_SCHEMES.contains(&scheme) => {
            return TokenShape::Rejected(EndpointRejection::InsecureScheme)
        }
        _ => return TokenShape::Opaque,
    }

    let host = match url.host_str() {
        Some(host) if !host.is_empty() => host,
        _ => return TokenShape::Rejected(EndpointRejection::MissingHost),
    };

    // A host that parses as an IP is settled here; anything else is a domain
    // and is resolved at dispatch time. See `validate_endpoint`.
    if let Some(ip) = parse_host_ip(host) {
        if is_non_public(ip) {
            return TokenShape::Rejected(EndpointRejection::NonPublicAddress);
        }
    }

    TokenShape::Endpoint
}

/// Authoritative check, run immediately before the outbound POST.
///
/// Applies [`classify_token`] and, for domain hosts, resolves the name and
/// refuses if **any** resolved address is non-public. A domain that resolves
/// to several addresses is refused if even one of them is internal, so a
/// round-robin record cannot be used to slip through. The lookup is bounded by
/// [`DNS_TIMEOUT`], since the host it resolves is attacker-supplied.
///
/// This narrows but does not eliminate DNS rebinding: `reqwest` performs its
/// own resolution when it connects, so a record with a very short TTL can
/// still change between this check and that connection. Closing that race
/// requires pinning the validated address into the connection itself, tracked
/// in #39.
pub async fn validate_endpoint(token: &str) -> Result<(), EndpointRejection> {
    let url = match classify_token(token) {
        TokenShape::Endpoint => Url::parse(token).map_err(|_| EndpointRejection::MissingHost)?,
        TokenShape::Rejected(reason) => return Err(reason),
        // Reached only if a caller hands a non-HTTP value straight to the
        // dispatch path; refuse rather than let reqwest decide.
        TokenShape::Opaque => return Err(EndpointRejection::InsecureScheme),
    };

    let host = match url.host_str() {
        Some(host) if !host.is_empty() => host.to_string(),
        _ => return Err(EndpointRejection::MissingHost),
    };

    // IP literals were already settled by the static pass.
    if parse_host_ip(&host).is_some() {
        return Ok(());
    }
    let domain = host;

    let port = url.port_or_known_default().unwrap_or(443);
    let resolved = resolve_addresses(&domain, port, DNS_TIMEOUT).await?;

    if resolved.is_empty() {
        return Err(EndpointRejection::UnresolvableHost);
    }
    if resolved.iter().any(|addr| is_non_public(addr.ip())) {
        return Err(EndpointRejection::NonPublicAddress);
    }

    Ok(())
}

/// Resolves a domain host under an explicit time budget.
///
/// A lookup that times out and one that fails are the same answer here: the
/// host was not shown to be safe, so it is not contacted. The budget is a
/// parameter rather than a constant read inline so the bound itself is
/// testable without a stalling nameserver.
async fn resolve_addresses(
    domain: &str,
    port: u16,
    budget: Duration,
) -> Result<Vec<SocketAddr>, EndpointRejection> {
    match timeout(budget, lookup_host((domain, port))).await {
        Ok(Ok(addrs)) => Ok(addrs.collect()),
        Ok(Err(_)) | Err(_) => Err(EndpointRejection::UnresolvableHost),
    }
}

/// Parses a URL host component as an IP address, if it is one.
///
/// `Url::host_str` serialises IPv6 hosts in their bracketed form (`[::1]`),
/// which `IpAddr::from_str` does not accept, so the brackets are stripped
/// first. A domain never parses as an IP, which makes the distinction
/// unambiguous. Alternative literal spellings (`0x7f.1`, octal, decimal) are
/// already normalised by `Url::parse` before reaching this function.
fn parse_host_ip(host: &str) -> Option<IpAddr> {
    let unbracketed = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    IpAddr::from_str(unbracketed).ok()
}

/// Whether an address is anything other than a routable public one.
///
/// Deliberately conservative: everything not clearly on the public internet is
/// refused, because the blast radius of a false negative (reaching a cloud
/// metadata service, a container-local admin port) is far worse than that of a
/// false positive (a self-hosted push server on a private range, which the
/// operator can front with a public name).
fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(addr) => is_non_public_v4(addr),
        IpAddr::V6(addr) => is_non_public_v6(addr),
    }
}

fn is_non_public_v4(addr: Ipv4Addr) -> bool {
    let [a, b, ..] = addr.octets();

    addr.is_loopback()            // 127.0.0.0/8
        || addr.is_private()      // 10/8, 172.16/12, 192.168/16
        || addr.is_link_local()   // 169.254.0.0/16 — cloud metadata lives here
        || addr.is_broadcast()
        || addr.is_documentation()
        || addr.is_multicast()
        || a == 0                 // 0.0.0.0/8 "this network"
        || (a == 100 && (64..=127).contains(&b))  // 100.64.0.0/10 CGNAT
        || (a == 192 && b == 0)   // 192.0.0.0/24 IETF protocol assignments
        || (a == 198 && (18..=19).contains(&b))   // 198.18.0.0/15 benchmarking
        || a >= 240 // 240.0.0.0/4 reserved
}

/// An allowlist, unlike the IPv4 rules above.
///
/// Enumerating non-public IPv6 blocks is a losing game: most of the address
/// space is unassigned, `Ipv6Addr` exposes no stable predicate for the
/// special-purpose ranges, and each pass over this function found another block
/// the list had missed. Only global unicast (`2000::/3`) is reachable on the
/// public internet at all, so everything else is refused by default — loopback,
/// unspecified, unique-local, link-local, site-local, multicast, and every
/// block IANA has not handed out yet. A new special-purpose assignment outside
/// `2000::/3` then needs no change here.
fn is_non_public_v6(addr: Ipv6Addr) -> bool {
    // `https://[::ffff:169.254.169.254]/` parses as an Ipv6 host, so the v4
    // ranges must be applied to the embedded address or every v4 rule above is
    // trivially bypassable. Covers both ::ffff:a.b.c.d and ::a.b.c.d.
    if let Some(v4) = addr.to_ipv4() {
        return is_non_public_v4(v4);
    }

    let seg = addr.segments();

    if (seg[0] & 0xe000) != 0x2000 {
        return true;
    }

    // Blocks carved out of 2000::/3 that are not globally reachable. 6to4 and
    // the IETF assignments matter most: both wrap an arbitrary IPv4 address, so
    // leaving them out would reopen the v4 rules from the other side, the way
    // `::ffff:` does.
    match seg[0] {
        // 2001::/23 IETF protocol assignments (Teredo, benchmarking, ORCHIDv2)
        // and 2001:db8::/32 documentation.
        0x2001 => (seg[1] & 0xfe00) == 0 || seg[1] == 0x0db8,
        // 2002::/16 6to4.
        0x2002 => true,
        // 3fff::/20 documentation.
        0x3fff => (seg[1] & 0xf000) == 0,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Realistic FCM registration tokens. These MUST stay accepted: FCM is the
    /// only backend enabled in production, and `/api/register` cannot tell an
    /// FCM token from a UnifiedPush URL, so an over-eager guard here would
    /// break every real registration.
    const FCM_TOKENS: &[&str] = &[
        "cXY7bF2mRk2vQ1s:APA91bH8xYzKq3vN9pLmT4wRbC7dEfGhIjKlMnOpQrStUvWxYz",
        "fMEP0vJhS9-abcdefghij:APA91bExampleTokenValue1234567890",
        "d1PxYz8QRk-2vQ1sAbCdEf",
        "",
    ];

    #[test]
    fn fcm_tokens_are_opaque() {
        for token in FCM_TOKENS {
            assert_eq!(
                classify_token(token),
                TokenShape::Opaque,
                "FCM token must not be treated as an endpoint: {token}"
            );
        }
    }

    #[test]
    fn public_https_endpoint_is_allowed() {
        for token in [
            "https://up.example.com/UP?token=abc",
            "https://ntfy.sh/abcdef",
            "https://8.8.8.8/push",
            "https://[2606:4700:4700::1111]/push",
        ] {
            assert_eq!(classify_token(token), TokenShape::Endpoint, "{token}");
        }
    }

    #[test]
    fn plain_http_is_refused() {
        assert_eq!(
            classify_token("http://up.example.com/UP"),
            TokenShape::Rejected(EndpointRejection::InsecureScheme)
        );
    }

    #[test]
    fn dangerous_schemes_are_refused() {
        for token in [
            "file:///etc/passwd",
            "ftp://internal.example.com/x",
            "gopher://127.0.0.1:11211/",
        ] {
            assert_eq!(
                classify_token(token),
                TokenShape::Rejected(EndpointRejection::InsecureScheme),
                "{token}"
            );
        }
    }

    #[test]
    fn non_public_ipv4_literals_are_refused() {
        for token in [
            "https://127.0.0.1:8080/",         // loopback
            "https://169.254.169.254/latest/", // cloud metadata
            "https://10.0.0.1/",               // RFC1918
            "https://172.16.0.1/",             // RFC1918
            "https://192.168.1.1/",            // RFC1918
            "https://100.64.0.1/",             // CGNAT
            "https://0.0.0.0/",                // this network
            "https://192.0.0.1/",              // IETF assignments
            "https://198.18.0.1/",             // benchmarking
            "https://240.0.0.1/",              // reserved
        ] {
            assert_eq!(
                classify_token(token),
                TokenShape::Rejected(EndpointRejection::NonPublicAddress),
                "{token}"
            );
        }
    }

    #[test]
    fn non_public_ipv6_literals_are_refused() {
        for token in [
            "https://[::1]:9000/", // loopback
            "https://[fe80::1]/",  // link local
            "https://[fc00::1]/",  // unique local
            "https://[::]/",       // unspecified
        ] {
            assert_eq!(
                classify_token(token),
                TokenShape::Rejected(EndpointRejection::NonPublicAddress),
                "{token}"
            );
        }
    }

    /// Everything outside global unicast is refused by the allowlist, with no
    /// per-block rule. Site-local is the case that motivated the allowlist: it
    /// slipped past an enumeration that already covered ULA and link-local.
    #[test]
    fn ipv6_outside_global_unicast_is_refused() {
        for token in [
            "https://[fec0::1]/",    // site-local, RFC 3879
            "https://[100::1]/",     // discard-only, RFC 6666
            "https://[64:ff9b::1]/", // NAT64 well-known prefix
            "https://[4000::1]/",    // unassigned
            "https://[a000::1]/",    // unassigned
            "https://[c000::1]/",    // unassigned
        ] {
            assert_eq!(
                classify_token(token),
                TokenShape::Rejected(EndpointRejection::NonPublicAddress),
                "{token}"
            );
        }
    }

    /// The blocks inside `2000::/3` that the allowlist alone would let through.
    #[test]
    fn non_routable_blocks_inside_global_unicast_are_refused() {
        for token in [
            "https://[2001:db8::1]/",       // documentation, RFC 3849
            "https://[2001:db8:ffff::1]/",  // documentation, upper end
            "https://[3fff::1]/",           // documentation, RFC 9637
            "https://[3fff:0fff:ffff::1]/", // documentation, upper end
            "https://[2001::1]/",           // Teredo
            "https://[2001:2::1]/",         // benchmarking
            "https://[2001:20::1]/",        // ORCHIDv2
            "https://[2002:a9fe:a9fe::1]/", // 6to4 wrapping 169.254.169.254
        ] {
            assert_eq!(
                classify_token(token),
                TokenShape::Rejected(EndpointRejection::NonPublicAddress),
                "{token}"
            );
        }
    }

    /// Pins the carve-out masks: each of these sits just outside one of the
    /// blocks above, inside global unicast, and must stay reachable. A mask one
    /// bit too wide would silently refuse legitimate endpoints.
    #[test]
    fn addresses_just_outside_the_carve_outs_stay_public() {
        for ip in [
            "2001:db9::1",      // 2001:db8::/32 is 32 bits wide, not 16
            "2001:db7:ffff::1", // just below it
            "2001:200::1",      // just above 2001::/23
            "2003::1",          // just above 2002::/16
            "3fff:1000::1",     // 3fff::/20 stops at 3fff:0fff:...
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(!is_non_public(parsed), "{ip} should be public");
        }
    }

    /// `https://[::ffff:169.254.169.254]/` parses as an IPv6 host. Without
    /// unmapping the embedded address, every IPv4 rule above is one bracket
    /// away from being bypassed.
    #[test]
    fn ipv4_mapped_into_ipv6_is_refused() {
        for token in [
            "https://[::ffff:169.254.169.254]/latest/",
            "https://[::ffff:127.0.0.1]/",
            "https://[::ffff:10.0.0.1]/",
        ] {
            assert_eq!(
                classify_token(token),
                TokenShape::Rejected(EndpointRejection::NonPublicAddress),
                "{token}"
            );
        }
    }

    /// Alternative literal spellings are normalised by `Url::parse` before the
    /// guard sees them, so they cannot be used to smuggle a loopback address.
    #[test]
    fn obfuscated_ipv4_spellings_are_normalised_and_refused() {
        for token in [
            "https://0x7f.1/",
            "https://2130706433/",
            "https://017700000001/",
        ] {
            assert_eq!(
                classify_token(token),
                TokenShape::Rejected(EndpointRejection::NonPublicAddress),
                "{token}"
            );
        }
    }

    #[test]
    fn public_addresses_are_not_flagged() {
        for ip in [
            "8.8.8.8",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "93.184.216.34",
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(!is_non_public(parsed), "{ip} should be public");
        }
    }

    /// The resolved-address branch of `validate_endpoint` and the literal
    /// branch of `classify_token` both decide through `is_non_public`, so this
    /// covers the DNS path for addresses no test can make a resolver return.
    #[test]
    fn resolved_addresses_are_judged_by_the_same_rules() {
        for ip in [
            "fec0::1",           // site-local
            "2002:a9fe:a9fe::1", // 6to4 wrapping cloud metadata
            "fd00::1",           // unique local
            "169.254.169.254",   // cloud metadata
        ] {
            let parsed: IpAddr = ip.parse().unwrap();
            assert!(is_non_public(parsed), "{ip} must not be treated as public");
        }
    }

    /// Exercises the DNS branch offline: `localhost` always resolves to a
    /// loopback address, so a domain pointing at an internal host is refused
    /// even though the name itself carries no hint of that.
    #[tokio::test]
    async fn domain_resolving_to_loopback_is_refused() {
        assert_eq!(
            validate_endpoint("https://localhost/up").await,
            Err(EndpointRejection::NonPublicAddress)
        );
    }

    /// A stalled resolver must be refused rather than awaited: the lookup runs
    /// outside the HTTP client's timeout while a dispatch permit is held.
    ///
    /// `lookup_host` defers to the blocking pool, so capping that pool at one
    /// thread and occupying it makes the lookup unable to start. That stalls
    /// the resolution deterministically, where simply passing a zero budget
    /// races against a `localhost` lookup that often completes on the first
    /// poll.
    #[test]
    fn dns_lookup_is_bounded() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();

        rt.block_on(async {
            let (release, held) = std::sync::mpsc::channel::<()>();
            let blocker = tokio::task::spawn_blocking(move || {
                let _ = held.recv();
            });
            // Let the blocker actually take the one blocking thread.
            tokio::time::sleep(Duration::from_millis(50)).await;

            // Outer bound so that dropping the inner one fails the test rather
            // than deadlocking it: the blocker is only released afterwards.
            let result = timeout(
                Duration::from_secs(5),
                resolve_addresses("localhost", 443, Duration::from_millis(50)),
            )
            .await
            .expect("resolve_addresses must return within its own budget");

            let _ = release.send(());
            let _ = blocker.await;

            assert_eq!(result, Err(EndpointRejection::UnresolvableHost));
        });
    }

    /// The same host under the real budget resolves, so the test above pins the
    /// bound rather than a name that never resolves.
    #[tokio::test]
    async fn dns_lookup_succeeds_within_budget() {
        let resolved = resolve_addresses("localhost", 443, DNS_TIMEOUT)
            .await
            .expect("localhost must resolve");
        assert!(!resolved.is_empty());
    }

    /// `.invalid` is reserved by RFC 2606 and never resolves.
    #[tokio::test]
    async fn unresolvable_domain_is_refused() {
        assert_eq!(
            validate_endpoint("https://this-host-does-not-exist.invalid/up").await,
            Err(EndpointRejection::UnresolvableHost)
        );
    }

    #[tokio::test]
    async fn dispatch_refuses_what_registration_refuses() {
        assert_eq!(
            validate_endpoint("https://169.254.169.254/latest/").await,
            Err(EndpointRejection::NonPublicAddress)
        );
        assert_eq!(
            validate_endpoint("https://[fec0::1]/push").await,
            Err(EndpointRejection::NonPublicAddress)
        );
        assert_eq!(
            validate_endpoint("http://up.example.com/UP").await,
            Err(EndpointRejection::InsecureScheme)
        );
    }

    /// An opaque value must never reach the outbound POST: the dispatch path
    /// refuses it rather than letting reqwest decide what to do with it.
    #[tokio::test]
    async fn dispatch_refuses_opaque_tokens() {
        assert_eq!(
            validate_endpoint(FCM_TOKENS[0]).await,
            Err(EndpointRejection::InsecureScheme)
        );
    }
}
