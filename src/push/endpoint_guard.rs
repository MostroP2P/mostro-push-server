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
//! Registration cannot be the only gate: `/api/register` carries no field
//! saying which backend a token belongs to, so an FCM token and a UnifiedPush
//! URL arrive indistinguishable. `classify_token` therefore only inspects
//! values whose scheme is `http` or `https`; anything else is opaque and left
//! for its own backend to interpret.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use reqwest::Url;
use tokio::net::lookup_host;

/// Schemes refused outright at registration. None of them can produce an
/// outbound request through `reqwest`, so this is data hygiene rather than an
/// SSRF control: a token spelled this way is broken whichever backend claims
/// it, and there is no reason to hold it in the store until its TTL expires.
const DANGEROUS_SCHEMES: &[&str] = &["file", "ftp", "gopher", "data", "dict", "ldap"];

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
/// round-robin record cannot be used to slip through.
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
    let resolved = lookup_host((domain.as_str(), port))
        .await
        .map_err(|_| EndpointRejection::UnresolvableHost)?;

    let mut saw_address = false;
    for addr in resolved {
        saw_address = true;
        if is_non_public(addr.ip()) {
            return Err(EndpointRejection::NonPublicAddress);
        }
    }

    if saw_address {
        Ok(())
    } else {
        Err(EndpointRejection::UnresolvableHost)
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

fn is_non_public_v6(addr: Ipv6Addr) -> bool {
    // `https://[::ffff:169.254.169.254]/` parses as an Ipv6 host, so the v4
    // ranges must be applied to the embedded address or every v4 rule above is
    // trivially bypassable. Covers both ::ffff:a.b.c.d and ::a.b.c.d.
    if let Some(v4) = addr.to_ipv4() {
        return is_non_public_v4(v4);
    }

    let first = addr.segments()[0];

    addr.is_loopback()
        || addr.is_unspecified()
        || addr.is_multicast()
        || (first & 0xfe00) == 0xfc00   // fc00::/7 unique local
        || (first & 0xffc0) == 0xfe80 // fe80::/10 link local
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
