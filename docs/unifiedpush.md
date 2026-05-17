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

Logs never include raw UnifiedPush `device_id` values or endpoint URL prefixes.
Device IDs are represented by the same salted, truncated BLAKE3 correlator used
for other privacy-sensitive identifiers, with a random in-memory salt per
process.

## Platform support

`UnifiedPushService::supports_platform` returns `true` only for `Platform::Android`. iOS clients are FCM-only.

If `UNIFIEDPUSH_ENABLED=false`, the service is not added to the dispatcher slice. Existing entries in `data/unifiedpush_endpoints.json` are ignored at runtime but not deleted.

## Operational notes

- UnifiedPush has no per-payload distinction between silent and visible push. `send_silent_to_token` falls back to `send_to_token`, which is the same code path the Nostr listener uses.
- There is no rate limiting on outbound UnifiedPush calls beyond what the server-wide `reqwest::Client` timeouts provide (2 s connect, 5 s total).
- The endpoint URL is fully attacker-controlled in the sense that the distributor can be any HTTP server. The shared `reqwest::Client` enforces TLS and the timeouts; the server does not pin certificates or restrict hostnames.

## Reference

- UnifiedPush specification: https://unifiedpush.org/developers/spec/
- Implementation: [src/push/unifiedpush.rs](../src/push/unifiedpush.rs)
