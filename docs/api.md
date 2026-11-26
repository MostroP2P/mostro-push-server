# API Reference

All endpoints are mounted under `/api`. Bodies and responses are JSON unless noted otherwise. `/api/register`, `/api/unregister`, `/api/notify` and the two `/api/disputes` endpoints can also be called from a browser; see [CORS](#cors-browser-clients).

| Method | Path             | Purpose                                                |
|--------|------------------|--------------------------------------------------------|
| GET    | `/api/health`    | Liveness probe                                         |
| GET    | `/api/info`      | Server version and feature flags                       |
| GET    | `/api/status`    | Server status with token counts                        |
| POST   | `/api/register`  | Register a device token for a `trade_pubkey`           |
| POST   | `/api/unregister`| Remove a registered token                              |
| POST   | `/api/notify`    | Trigger a silent push to the device for a `trade_pubkey` |
| POST   | `/api/disputes/watch` | Watch a Mostro node for new disputes                |
| POST   | `/api/disputes/unwatch` | Stop watching a node                              |

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

A `web` count is appended after `ios` once at least one browser is registered (`"web": 1`). While there are none the field is omitted, so the body is byte-identical to the one served before web clients existed.

## POST /api/register

Registers a device token for a `trade_pubkey`. The token is held in plaintext in memory and, when persistence is enabled, encrypted on disk; HTTPS protects it in transit. Registering an already registered `trade_pubkey` replaces its token and restarts its TTL.

When the store holds `MAX_TOKENS` registrations, a new `trade_pubkey` is answered with the same `429` body as the rate limiter (`{"success":false,"message":"rate limited"}`, `Retry-After: 3600`); refreshing an existing one always succeeds.

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
| `token`         | string | FCM device token, or UnifiedPush endpoint URL. Non-empty, at most 4096 bytes. If it parses as an `http`/`https` URL it must be `https` and point at a public address (see below). |
| `platform`      | string | `"android"`, `"ios"` or `"web"`, case-insensitive. `web` is a browser registered through FCM Web Push; its token is an ordinary FCM registration token and is delivered by FCM only. |
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
- `token` empty, or longer than 4096 bytes
- `token` rejected as a push endpoint (see below)
- `platform` not `"android"`, `"ios"` or `"web"`. The message still reads `Invalid platform '<value>' (expected 'android' or 'ios')`: the `400` bodies are frozen against the pre-1.1 fixtures.
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
The same list also restricts the Nostr listener, which only pushes for
events signed by these nodes whatever the flag says.

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

`200 OK` on parse-valid input. The body distinguishes "removed" vs "was not registered":

```json
{ "success": true, "message": "Token unregistered successfully" }
```

```json
{ "success": true, "message": "Token not found (may have already been unregistered)" }
```

With persistence enabled, the row is deleted from disk before memory. If that deletion fails, nothing is changed and the endpoint answers `500` with `{"success":false,"message":"internal error"}` rather than acknowledging an unregister that the next restart would undo. Retry once the store recovers.

## POST /api/disputes/watch

A device asks to be told when a Mostro node opens a dispute. The watch names a node, never a solver: no key of the caller is sent. The push itself is sent by the Nostr listener and carries no dispute, node or party; see [When a dispute rings](#when-a-dispute-rings).

Request:

```json
{ "mostro_pubkey": "<64-char hex>", "token": "<FCM token>", "platform": "android" }
```

`200 OK`:

```json
{ "success": true }
```

Watching again renews the watch, which lasts 30 days since the day it was last asked for (so between 29 and 30 days: only the day is kept).

- **Only `android`**, and only FCM tokens. A token that is an `http(s)` URL (a UnifiedPush endpoint) is refused.
- **The node must be on the trusted list** (`config/trusted_mostro_pubkeys.json`), whatever `TRUSTED_WHITELIST_ENABLED` says: the listener only rings for those nodes.
- **A new token is checked with FCM before it is stored** (`messages:send` with `validate_only`, which delivers nothing). A watch that is renewed is not checked again.
- **New watches are limited per IP address**: 5 at once, then one more every 12 minutes (`NEW_WATCHES_PER_IP_PER_HOUR`, which is that burst and that refill: 9 fit in a first hour, 5 an hour after that), apart from the per-IP limit shared with `/api/register`. A valid FCM token is cheap to come by, so without this one address could take every place of a node. An IPv6 address is counted with its /64. A renewal does not count. A token FCM refuses does, and so does a check FCM did not answer (the `503` below): the allowance is what bounds how often an address makes the server ask FCM. A `503` because FCM is disabled costs nothing.
- **The platform is not verified.** FCM accepts any token of the project in that check, so an iOS or web token sent as `android` is stored and takes a place, although the `dispute_new` notification is only defined for Android.

| Status | Body `message` | When |
|--------|----------------|------|
| 400 | `Invalid mostro_pubkey format (expected 64 hex characters)` | |
| 400 | `Token cannot be empty` / `Token exceeds maximum length` | Over 4096 bytes |
| 400 | `Invalid platform (expected 'android')` | |
| 400 | `Invalid token` | A URL, or a token FCM does not know for this server's Firebase project |
| 403 | `Mostro instance not trusted` | |
| 429 | `rate limited`, with `Retry-After` | A per-IP limit (requests, or new watches), or the node's watcher list (`MAX_WATCHERS_PER_NODE`) or the store (`MAX_WATCHERS`) is full. A device already on the list is still renewed. For a full list `Retry-After` is `3600`: how often to ask again, not when a place will be free |
| 500 | `internal error` | With persistence enabled, the watch could not be written to disk. Nothing is stored |
| 503 | `Token could not be checked` | FCM is disabled, unreachable, did not answer within 8 seconds, or answered something else. Nothing is stored; try again later, not at once |

Error bodies are `{"success":false,"message":"…"}`.

### When a dispute rings

The listener subscribes to `kind 38386` events with `s` = `initiated` authored by the trusted nodes. Every device watching the node gets one `dispute_new` push when all of this holds:

- The event is signed by a node on the trusted list and has a `d` tag (the dispute id) of at most 64 bytes.
- Its `created_at` is within 10 minutes of the server's clock, either way. An older one is a relay sending the event again.
- That dispute of that node did not ring in the last 30 minutes.
- The node has not spent its allowance: 5 dispute pushes at once, refilled at one every 12 seconds.

What a client can rely on, and what it cannot:

- **It is a hint, not a list.** The push says a dispute was opened and nothing else; the client reads the node's disputes from the relays.
- **A dispute may not ring.** It does not when the server was down or disconnected for more than 10 minutes around it, when the event did not reach the relays the server listens on, when the node spent its allowance, when ten other disputes were being sent and none ended within two minutes, or when FCM did not take the push: nothing is retried. The server reads each event once, even when its connection to a relay drops and comes back, so a dispute it dropped does not come again: count on it not ringing.
- **A dispute may ring twice.** What was seen is kept in memory only, so a dispute opened in the 10 minutes before a restart rings again after it. And a dispute no device was counted as told about is not kept as seen: when the pushes were cut by the 60-second limit, one of them may have arrived all the same, and that device is told again if the dispute comes again, which takes the node signing it again as `initiated` or the server starting its listener over.
- **A dispute the node signs again may be missed.** While a dispute is waiting or being sent, another `initiated` event of the same dispute is ignored as already seen; if the first then reaches no device, the second is not looked at again.
- **A dispute may ring late, even for one already taken.** With ten other disputes being sent, a dispute waits for its turn, up to two minutes, and is then sent without reading the node's events again: a solver may be told of a new dispute another solver took meanwhile. The client reads the node's disputes from the relays, which is where it sees that.
- **On a node with many watchers, some may not ring.** The pushes of one dispute go out 25 at a time and stop after 60 seconds; with hundreds of watchers and a slow FCM, the last ones are not sent.
- **A dead token stops watching.** When FCM answers that it no longer knows a token (`UNREGISTERED`), its watch is removed, provided the same dispute reached at least one other device of the node: with no push delivered, that answer may be this server's doing, and nothing is removed. No other failure removes one, and an answer that did not come within the 60 seconds is not read: that watch stays until another dispute or until it expires. A client that gets a new FCM token watches again with it.

## POST /api/disputes/unwatch

Removes a watch.

```json
{ "mostro_pubkey": "<64-char hex>", "token": "<FCM token>" }
```

`200 OK` with `{"success":true}` whether or not the watch existed. `400` for a malformed pubkey or token, as above. With persistence enabled the row is deleted from disk first; if that fails nothing is changed and the answer is `500` with `{"success":false,"message":"internal error"}`.

## POST /api/notify

Sender-triggered silent push to the device registered for `trade_pubkey`. Used by the mobile client when peer-to-peer chat events are sent without a Mostro-daemon hop, so the recipient app needs an external wake-up signal.

### Privacy contract

- Always `202 Accepted` on parse-valid input. The response body is identical for registered and unregistered pubkeys, so this endpoint cannot be used as an enumeration oracle.
- The dispatch happens in a `tokio::spawn` task detached from the response. The 202 means "accepted for dispatch", not "delivered". FCM `200` further along the pipeline only means Google accepted the request, not that the device woke.
- No authentication, no `sender_pubkey`, no signature, no `Idempotency-Key`. Adding any of these would let the operator correlate sender and recipient.
- Every response (202 / 400 / 429, and CORS preflights) carries a server-generated UUIDv4 `x-request-id` header. Any inbound `X-Request-Id` from the client is stripped first; a client cannot pin its own correlator into server logs.
- Rate-limit responses are byte-identical between the per-IP and per-pubkey paths so the two cannot be distinguished by callers.
- CORS headers depend only on the request's `Origin`, never on the pubkey, so they cannot tell a registered pubkey from an unregistered one either.

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
| 200    | `/api/health`, `/api/info`, `/api/status`, `/api/register`, `/api/unregister`, `/api/disputes/watch`, `/api/disputes/unwatch` |
| 202    | `/api/notify` on parse-valid input                                            |
| 204    | CORS preflight (`OPTIONS`) from an allowed origin on `/api/register`, `/api/unregister`, `/api/notify`, `/api/disputes/watch`, `/api/disputes/unwatch` |
| 400    | Malformed body, body over the size limit, invalid `trade_pubkey` or `mostro_pubkey`, invalid `platform`, empty or oversized `token`, rejected push endpoint, a token FCM does not know (`/api/disputes/watch`) |
| 403    | `/api/register` with the whitelist on, and `/api/disputes/watch` always: node not on the trusted list |
| 429    | `/api/register`, `/api/unregister`, `/api/notify`, `/api/disputes/*` rate limits; `/api/register` when the token store is full; `/api/disputes/watch` when a watcher list is full |
| 500    | Rate-limited endpoints fail closed when the per-IP key cannot be extracted; `/api/unregister` and `/api/disputes/unwatch` when the persisted row cannot be deleted; `/api/disputes/watch` when it cannot be written |
| 503    | `/api/disputes/watch` when the token could not be checked with FCM |

### Push endpoint validation

The `token` field is overloaded: for FCM it is an opaque registration token,
for UnifiedPush it is the URL the server will POST to. The request carries no
field saying which, so the server inspects the value instead.

A token that parses as an `http` or `https` URL is treated as a push endpoint
and must satisfy all of:

- scheme is `https`
- the host is not a private, loopback, link-local, CGNAT, or otherwise
  non-routable IPv4 address, including the IPv4-mapped IPv6 spellings of those
  (`https://[::ffff:169.254.169.254]/`)
- the host, if IPv6, is inside globally routable unicast (`2000::/3`). This is
  an allowlist rather than a list of bad ranges, so site-local, unique-local,
  link-local, discard-only and unassigned space are all refused without a rule
  each. The blocks carved out of `2000::/3` that are not globally reachable —
  documentation, 6to4, and the IETF protocol assignments — are refused as well

A value that parses under one of a short list of clearly unusable schemes
(`file`, `ftp`, `gopher`, `data`, `dict`, `ldap`) is refused outright. That is
hygiene rather than an SSRF control: none of those schemes can produce an
outbound request, so such a token is broken whichever backend claims it.

Every remaining value — including anything that does not parse as a URL at all
— is treated as an opaque backend token and passed through untouched, so FCM
registrations are unaffected.

Rejection — `400 Bad Request`:

```json
{
  "success": false,
  "message": "Invalid push endpoint"
}
```

The message is identical for every rejection reason on purpose. A caller must
not be able to use the response to distinguish "unsupported scheme" from
"internal address" and map the server's network.

Registration performs the checks above without touching the network. The
authoritative check runs again immediately before the outbound POST and
additionally resolves domain hosts, refusing the endpoint if any resolved
address is non-public.

## CORS (browser clients)

A web client, such as the Mostro web app at `https://mostro.network/app/`,
registers its FCM Web Push token with `platform: "web"`. Browsers only send
those cross-origin `POST`s after a successful preflight, so `/api/register`,
`/api/unregister` and `/api/notify` answer CORS for the origins listed in
`CORS_ALLOWED_ORIGINS` (default `https://mostro.network`; see
[configuration.md](./configuration.md#cors)). `/api/health`, `/api/info` and
`/api/status` do not.

The push sent to a web token sets no click target (`webpush.fcm_options.link`):
the web client's service worker must handle `notificationclick` itself, or a
tap on the notification opens nothing. Register that listener before importing
the FCM libraries, as Firebase's documentation asks: the SDK adds its own
`notificationclick` listener, and one registered after it may never run.

That push is sent with `webpush.headers.Urgency: high`, matching the Android and
iOS priority, and sets no `webpush.notification.icon` or `badge`. The FCM SDK
renders it from `notification.title` and `body` alone, so a web client cannot
brand it with its own icon today.

The data-only `chat_wake` push sent through `/api/notify` carries the same
`webpush.headers.Urgency: high` for web tokens, and nothing else in a `webpush`
block: the client's service worker builds that notice itself.

Preflight from an allowed origin — `204 No Content`, empty body:

```
Access-Control-Allow-Origin: https://mostro.network
Access-Control-Allow-Methods: POST, OPTIONS
Access-Control-Allow-Headers: Content-Type
Access-Control-Max-Age: 86400
Vary: Origin
```

The preflight is answered before the rate limiters, so it never spends a
rate-limit token and never reaches a handler.

Every other response to a request from an allowed origin — `200`, `202`,
`400`, `403`, `429`, `500` — carries `Access-Control-Allow-Origin`,
`Access-Control-Expose-Headers: Retry-After` and `Vary: Origin`. The allowed
origin is echoed back; with `CORS_ALLOWED_ORIGINS=*` the value is `*`.
`Retry-After` is not CORS-safelisted, so without the expose header a browser
would hide it from a web client backing off a `429`. `Access-Control-Allow-Credentials` is never sent: none of
these endpoints uses cookies or authentication.

A request with no `Origin`, or from an origin that is not allowed, gets no CORS
headers and exactly the response it got before CORS existed. That includes a
preflight, which then goes through the rate limiter and is answered `405 Method
Not Allowed`, so the browser blocks the call.

## Request size limits

Every endpoint that accepts a body caps it. Actix's own default is 2 MB, which
on unauthenticated endpoints is a free memory-amplification primitive.

| Endpoint          | Max body | Notes                                                        |
|-------------------|----------|--------------------------------------------------------------|
| `/api/register`   | 8 KiB    | Sized to fit a 4096-byte `token` plus the other fields        |
| `/api/unregister` | 1 KiB    | Body carries a single 64-char hex pubkey                      |
| `/api/notify`     | 1 KiB    | Body carries a single 64-char hex pubkey                      |
| `/api/disputes/watch`, `/api/disputes/unwatch` | 8 KiB | As `/api/register`: a pubkey and a `token` of up to 4096 bytes |

The `token` field of a registration is bounded separately at **4096 bytes**. The
body cap stops an enormous request; the field cap stops a merely large one from
being retained in the token store for its whole TTL.

Exceeding either limit is reported as `400 Bad Request`, **not** `413 Payload
Too Large`:

```json
{
  "success": false,
  "message": "Request body too large"
}
```

```json
{
  "success": false,
  "message": "Token exceeds maximum length"
}
```

Compressed request bodies are not accepted on any endpoint. The server is built
without actix-web's `compress-*` features, so a `Content-Encoding` of `gzip`,
`deflate`, `br` or `zstd` is not decoded: the body reaches the JSON parser as
opaque bytes and is refused as malformed. This is what makes the limits above
meaningful — actix decompresses inside the JSON extractor, before the limit is
consulted and into an unbounded buffer, so a few hundred compressed bytes would
otherwise expand to hundreds of megabytes on an unauthenticated endpoint.

Returning `400` rather than `413` is deliberate. The response bodies of
`/api/register` and `/api/unregister` are frozen against pre-1.1 fixtures, and
`/api/notify` is contractually restricted to a single failure status, so the
size cap reuses the shape those endpoints already emit instead of introducing a
new one. Only the payload-overflow case is remapped; every other body-parsing
failure keeps its previous behaviour.

## Rate limiting

`/api/register`, `/api/unregister`, `/api/disputes/watch` and
`/api/disputes/unwatch` share a per-IP limit to protect the stores from
registration churn (`MAX_TOKENS`, `MAX_WATCHERS_PER_NODE` and `MAX_WATCHERS`
bound their size). It also bounds how often one address can make the server
ask FCM about a token:

- Per-IP: `120/min`, burst `100`

`/api/disputes/watch` has a second per-IP limit, on **new** watches only:
a burst of `5`, refilled at `5/hour` (`NEW_WATCHES_PER_IP_PER_HOUR` sets both), keyed by the address for IPv4 and by
its /64 for IPv6. Renewing a watch and `/api/disputes/unwatch` do not count
against it.

`/api/notify` has separate per-IP and per-`trade_pubkey` limits; both must allow the request to pass. Defaults:

- Per-pubkey: `30/min`, burst `10` (env `NOTIFY_RATE_PER_PUBKEY_PER_MIN`)
- Per-IP: `120/min`, burst `30` (env `NOTIFY_RATE_PER_IP_PER_MIN`)

`/api/health`, `/api/info`, and `/api/status` are intentionally not
rate-limited at the HTTP layer; capacity at the edge is governed by
`fly.toml` `hard_limit = 25`.

See [configuration.md](./configuration.md) for the full rate-limit knob list and the `NOTIFY_TRUST_PROXY_HEADERS` flag governing trust of `Fly-Client-IP` / `X-Forwarded-For`.
