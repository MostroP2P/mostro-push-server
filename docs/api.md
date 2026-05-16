# API Reference

All endpoints are mounted under `/api`. Bodies and responses are JSON unless noted otherwise.

| Method | Path             | Purpose                                                |
|--------|------------------|--------------------------------------------------------|
| GET    | `/api/health`    | Liveness probe                                         |
| GET    | `/api/info`      | Server version and feature flags                       |
| GET    | `/api/status`    | Server status with token counts                        |
| POST   | `/api/register`  | Register a device token for a `trade_pubkey`           |
| POST   | `/api/unregister`| Remove a registered token                              |
| POST   | `/api/notify`    | Trigger a silent push to the device for a `trade_pubkey` |

## GET /api/health

Liveness check. Always `200 OK`.

```bash
curl http://localhost:8080/api/health
```

```json
{"status":"ok"}
```

## GET /api/info

Returns server version and feature flags. Token registration is currently plaintext; `encryption_enabled` is `false`.

```bash
curl http://localhost:8080/api/info
```

```json
{
  "version": "0.2.0",
  "encryption_enabled": false,
  "note": "Token encryption will be enabled in a future phase"
}
```

## GET /api/status

Returns server status and token-store statistics.

```bash
curl http://localhost:8080/api/status
```

```json
{
  "status": "running",
  "version": "0.2.0",
  "tokens": {
    "total": 5,
    "android": 3,
    "ios": 2
  }
}
```

## POST /api/register

Registers a device token for a `trade_pubkey`. The token is stored in plaintext in memory; HTTPS is the only confidentiality layer in transit.

Request:

```json
{
  "trade_pubkey": "<64-char hex>",
  "token": "<fcm-or-unifiedpush-token>",
  "platform": "android",
  "mostro_pubkey": "<64-char hex of the Mostro instance>"
}
```

| Field           | Type   | Description                                                                                                            |
|-----------------|--------|------------------------------------------------------------------------------------------------------------------------|
| `trade_pubkey`  | string | 64 hex characters                                                                                                      |
| `token`         | string | FCM device token, or UnifiedPush endpoint URL                                                                          |
| `platform`      | string | `"android"` or `"ios"`                                                                                                 |
| `mostro_pubkey` | string | 64 hex characters. Optional on the wire; required when the trusted-instance whitelist is non-empty (see below). |

Success — `200 OK`:

```json
{
  "success": true,
  "message": "Token registered successfully",
  "platform": "android"
}
```

Validation failure — `400 Bad Request`:

```json
{
  "success": false,
  "message": "Invalid trade_pubkey format (expected 64 hex characters)"
}
```

Possible validation errors:

- `trade_pubkey` not 64 hex characters
- `token` empty
- `platform` not `"android"` or `"ios"`
- `mostro_pubkey` present but not 64 hex characters

Trusted-instance filter — `403 Forbidden`:

The filter is gated by `TRUSTED_WHITELIST_ENABLED` (default `false`) and
only fires when the runtime flag is `true` AND the embedded whitelist is
non-empty (see [configuration.md](./configuration.md)). When it does
fire, the response body distinguishes two cases so clients can react
without parsing logs:

```json
{
  "success": false,
  "message": "Mostro instance pubkey required"
}
```

Returned when the `mostro_pubkey` field is absent. Typical for clients
that pre-date the feature.

```json
{
  "success": false,
  "message": "Mostro instance not trusted"
}
```

Returned when the field is present, hex-valid, but the value is not on
the whitelist.

The whitelist is compiled into the binary from
`config/trusted_mostro_pubkeys.json`. The filter is honour-system: there
is no cryptographic proof binding the device to the declared instance.

**Mobile client compatibility.** The `mostro_pubkey` field is supported
by mobile client `vX.Y.Z` and later (TODO: pin the released version once
the mobile-side change merges). Clients older than that release will
receive `403 "Mostro instance pubkey required"` whenever
`TRUSTED_WHITELIST_ENABLED=true`. Operators should keep the flag at
`false` during the rollout window and flip it on after the mobile
release is in users' hands.

## POST /api/unregister

Removes a registered token by `trade_pubkey`.

Request:

```json
{ "trade_pubkey": "<64-char hex>" }
```

Always `200 OK` on parse-valid input. The body distinguishes "removed" vs "was not registered":

```json
{ "success": true, "message": "Token unregistered successfully" }
```

```json
{ "success": true, "message": "Token not found (may have already been unregistered)" }
```

## POST /api/notify

Sender-triggered silent push to the device registered for `trade_pubkey`. Used by the mobile client when peer-to-peer chat events are sent without a Mostro-daemon hop, so the recipient app needs an external wake-up signal.

### Privacy contract

- Always `202 Accepted` on parse-valid input. The response body is identical for registered and unregistered pubkeys, so this endpoint cannot be used as an enumeration oracle.
- The dispatch happens in a `tokio::spawn` task detached from the response. The 202 means "accepted for dispatch", not "delivered". FCM `200` further along the pipeline only means Google accepted the request, not that the device woke.
- No authentication, no `sender_pubkey`, no signature, no `Idempotency-Key`. Adding any of these would let the operator correlate sender and recipient.
- Every response (202 / 400 / 429) carries a server-generated UUIDv4 `x-request-id` header. Any inbound `X-Request-Id` from the client is stripped first; a client cannot pin its own correlator into server logs.
- Rate-limit responses are byte-identical between the per-IP and per-pubkey paths so the two cannot be distinguished by callers.

### Request

```json
{ "trade_pubkey": "<64-char hex>" }
```

### Responses

`202 Accepted`:

```json
{ "accepted": true }
```

`400 Bad Request` — malformed JSON or invalid `trade_pubkey`:

```json
{
  "success": false,
  "message": "Invalid trade_pubkey format (expected 64 hex characters)"
}
```

`429 Too Many Requests` — per-IP or per-pubkey limiter hit. The body is identical on both paths; clients must read `Retry-After` (whole seconds, minimum 1) to back off:

```json
{ "success": false, "message": "rate limited" }
```

```
Retry-After: 12
```

### Example

```bash
curl -i -X POST http://localhost:8080/api/notify \
  -H 'content-type: application/json' \
  -d '{"trade_pubkey":"a1b2c3d4e5f67890123456789012345678901234567890123456789012345abc"}'
```

## HTTP status summary

| Status | Used by                                                                       |
|--------|-------------------------------------------------------------------------------|
| 200    | `/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister` |
| 202    | `/api/notify` on parse-valid input                                            |
| 400    | Malformed body, invalid `trade_pubkey`, invalid `platform`, empty `token`     |
| 429    | `/api/register`, `/api/unregister`, `/api/notify` rate limits                 |
| 500    | Rate-limited endpoints fail closed when the per-IP key cannot be extracted   |

## Rate limiting

`/api/register` and `/api/unregister` share a per-IP limit to protect the
in-memory token store from registration churn:

- Per-IP: `120/min`, burst `100`

`/api/notify` has separate per-IP and per-`trade_pubkey` limits; both must allow the request to pass. Defaults:

- Per-pubkey: `30/min`, burst `10` (env `NOTIFY_RATE_PER_PUBKEY_PER_MIN`)
- Per-IP: `120/min`, burst `30` (env `NOTIFY_RATE_PER_IP_PER_MIN`)

`/api/health`, `/api/info`, and `/api/status` are intentionally not
rate-limited at the HTTP layer; capacity at the edge is governed by
`fly.toml` `hard_limit = 25`.

See [configuration.md](./configuration.md) for the full rate-limit knob list and the `NOTIFY_TRUST_PROXY_HEADERS` flag governing trust of `Fly-Client-IP` / `X-Forwarded-For`.
