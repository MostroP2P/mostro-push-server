# UnifiedPush

[UnifiedPush](https://unifiedpush.org/) is the push notification path for Android devices without Google Play Services (GrapheneOS, LineageOS, /e/OS, …). Instead of a single carrier (FCM), each client picks a *distributor* app that owns a per-device endpoint URL; the server POSTs to that URL to wake the app.

The server treats UnifiedPush as a peer of FCM behind the same `PushService` trait, so the Nostr listener and `/api/notify` paths are unchanged.

## Lifecycle

1. The mobile client picks a distributor and obtains an endpoint URL from it.
2. The client calls `POST /api/register` with `platform = "android"` and `token` set to that endpoint URL — i.e. for UnifiedPush, the "device token" *is* the URL.
3. On dispatch, `UnifiedPushService::send_to_token` POSTs a small JSON payload to the URL.
4. The distributor delivers a wake-up to the client app, which then fetches the relevant Nostr events itself.

## Wire format

The server posts:

```json
{
  "type": "silent_wake",
  "timestamp": 1736208000
}
```

`Content-Type: application/json`, no auth, no payload data. The client must not rely on the body — UnifiedPush is a wake-up channel, not a message bus. After waking, the client queries Nostr directly.

A `2xx` response is treated as success. Any other response is logged at `error!` level and the dispatcher tries the next backend (in practice, none — UnifiedPush registrations are Android-only and there is no fallback for them).

## Persistence

`UnifiedPushService` keeps an in-memory `HashMap<device_id, UnifiedPushEndpoint>` mirrored to `data/unifiedpush_endpoints.json` on every mutation, written atomically (temp file + rename). Endpoints survive restarts; the token-store map of `trade_pubkey -> token` does not.

The endpoint store is loaded once at startup. Failures to read or parse the file are logged and the service starts with an empty map.

## Platform support

`UnifiedPushService::supports_platform` returns `true` only for `Platform::Android`. iOS clients are FCM-only.

If `UNIFIEDPUSH_ENABLED=false`, the service is not added to the dispatcher slice. Existing entries in `data/unifiedpush_endpoints.json` are ignored at runtime but not deleted.

## Endpoint validation

The registered device token *is* the URL the server POSTs to, which makes it a
request-forgery surface reachable from the unauthenticated `/api/register` and
`/api/notify` pair. `src/push/endpoint_guard.rs` is the single place that
decides whether an endpoint may be contacted.

Two passes:

1. **Registration** — static, no network. Refuses non-`https` schemes and hosts
   that are IP literals outside the public internet.
2. **Dispatch** — runs immediately before the outbound POST, repeats the static
   checks, and resolves domain hosts, refusing if *any* resolved address is
   non-public. This is the authoritative gate; registration is defence in
   depth and fast feedback.

The guard only ever inspects the **first hop**, which is why this backend does
not use the shared HTTP client. `reqwest` follows up to 10 redirects by
default, so a registered endpoint answering `302 Location: http://169.254.169.254/`
would walk the request past the guard entirely. `UnifiedPushService::build_client`
refuses redirects outright: a push endpoint has no legitimate reason to issue
one. A regression test asserts the second hop is never requested.

Known limitation: `reqwest` resolves the host again when it connects, so a DNS
record with a very short TTL can change between validation and connection.
Closing that race requires pinning the validated address into the connection;
tracked in [#39](https://github.com/MostroP2P/mostro-push-server/issues/39).

## Operational notes

- UnifiedPush has no per-payload distinction between silent and visible push. `send_silent_to_token` falls back to `send_to_token`, which is the same code path the Nostr listener uses.
- There is no rate limiting on outbound UnifiedPush calls beyond what the server-wide `reqwest::Client` timeouts provide (2 s connect, 5 s total).
- The endpoint URL is fully attacker-controlled in the sense that the distributor can be any HTTP server. A dedicated `reqwest::Client` (`UnifiedPushService::build_client`) enforces TLS, the timeouts, and a no-redirect policy; the server does not pin certificates.

## Reference

- UnifiedPush specification: https://unifiedpush.org/developers/spec/
- Implementation: [src/push/unifiedpush.rs](../src/push/unifiedpush.rs)
