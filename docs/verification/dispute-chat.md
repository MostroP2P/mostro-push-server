# Manual verification: dispute-chat path

This runbook describes how an operator end-to-end verifies that
administrative DMs (sent directly user-to-user, NOT routed through the
Mostro daemon) still reach registered devices as silent pushes via the
Nostr listener path.

This procedure is run after every deploy of milestone v1.1 (phases 1,
2, and 3). It is the only end-to-end signal that the Phase 1 refactor
(`PushDispatcher`) and the Phase 2 addition (`POST /api/notify`) have
not introduced a silent regression in the listener path.

## Why this runbook exists

In Mostro, dispute chats between administrators and users are sent as
direct Nostr messages with `kind 1059` (Gift Wrap, NIP-59). The sender
is the administrator (a human user), NOT the Mostro daemon. The Mostro
daemon publishes trade-update events, but NOT administrative DMs.

For this reason, the Nostr listener at `src/nostr/listener.rs` MUST
NOT filter events by `authors`. Filtering by `mostro_pubkey` would
silently drop administrative DMs, breaking dispute chat for every
user.

Additionally, Gift Wrap (NIP-59) uses an ephemeral outer key per
event. The sender's key is never visible in the outer event, so
filtering by `authors` is structurally impossible even if it were
desired.

This constraint is documented as anti-requirement **OOS-19 /
CRIT-1** in `.planning/PROJECT.md` and as a comment block above
`Filter::new()` in `src/nostr/listener.rs` (introduced in Phase 1
decision D-11).

## Prerequisites

- Access to the Fly.io staging environment (`mostro-push-server`).
- `flyctl` installed and authenticated (`flyctl auth whoami` must
  respond).
- A secondary Nostr client able to publish `kind 1059` events
  against a relay configured by the server (for example Damus,
  Amethyst, or a `nostr-tool` script).
- A test `trade_pubkey` (64 hex characters) and a test FCM or
  UnifiedPush token registered for that pubkey.
- A test device (real or emulator) able to receive the silent push
  for the registered token.
- Read-only access to the repo source tree
  (`mostro-push-server`) to run the anti-CRIT-1 grep verification at
  the end of the procedure.

## Procedure

### Step 1: Register the test pubkey

Register the `trade_pubkey` and the device token through the existing
`POST /api/register` endpoint:

```bash
curl -i -X POST https://mostro-push-server.fly.dev/api/register \
  -H 'content-type: application/json' \
  -d '{
    "trade_pubkey": "<64-hex-chars>",
    "token": "<fcm-or-unifiedpush-token>",
    "platform": "android"
  }'
```

Expected response: `200 OK` with body
`{"success":true,"message":"Token registered successfully","platform":"android"}`.

Take note of the exact `trade_pubkey` you registered — you will need
it in the next step.

### Step 2: Publish a kind 1059 event from a secondary Nostr client

From a secondary Nostr client (NOT the Mostro daemon — it is
important to simulate a sender that is a human user, not the
daemon), publish a Gift Wrap (NIP-59, `kind 1059`) addressed to the
registered `trade_pubkey`, against one of the relays configured on
the server (`NOSTR_RELAYS`).

The event must have:

- `kind`: `1059`
- `p` tag: the `trade_pubkey` registered in step 1.
- Outer key: ephemeral (any `Keys::generate()` or equivalent). This
  is the key that signs the outer event; it is NOT the
  administrator's key.

The inner content of the Gift Wrap can be any test message; the push
server does not decrypt or inspect the content.

The Mostro daemon does NOT send administrative DMs. Administrators
contact users directly (user-to-user). Filtering by `mostro_pubkey`
in the listener would silently break this path, which is why Phase 1
D-11 introduced the explicit comment block in
`src/nostr/listener.rs` and Phase 3 OPEN-6 keeps the `MOSTRO_PUBKEY`
field inert without applying it as a filter.

### Step 3: Verify silent push delivery

Immediately after publishing the event, watch the server logs on
Fly.io:

```bash
flyctl logs -a mostro-push-server | grep -E "(Push sent successfully for event|Failed to send push)"
```

You should see a line of the form:

```
Push sent successfully for event <event-id>
```

within ~5-10 seconds of publishing the event.

Additionally, the test device must receive the silent push. Verify
according to the backend:

- **FCM (iOS or Android)**: the mobile client's background handler
  must run (for example, `didReceiveRemoteNotification` on iOS,
  `FirebaseMessagingService.onMessageReceived` on Android).
- **UnifiedPush (Android)**: the client's background receiver must
  fire according to the configured distributor.

If you do NOT see the `Push sent successfully for event ...` line in
the logs:

- Confirm that the event reached the configured relay (some Nostr
  tools fail silently if the relay rejects the event).
- Confirm that the `p` tag matches the registered `trade_pubkey`
  exactly (64 hex characters, no mixed upper/lower case).
- Inspect the full logs for errors in `connect_and_listen` or in
  `dispatcher.dispatch(...)`.

### Step 4: Anti-CRIT-1 verification

After every deploy, run the following command in the repo source
tree to confirm that the forbidden anti-fix
(`.authors(mostro_pubkey)` in the listener filter) has not been
re-introduced:

```bash
grep -n '\.authors(' src/nostr/listener.rs
```

Expected output: exactly ONE match, inside the Phase 1 D-11 comment
block (the line that says `// DO NOT add .authors(...) here.` or
equivalent).

For a bash exit-code verification that fails if an active
`.authors(...)` call (not in a comment) appears:

```bash
if grep -nE '^\s*[^/].*\.authors\(' src/nostr/listener.rs; then
    echo "FAIL: .authors() filter present in the listener — anti-CRIT-1 violated"
    exit 1
else
    echo "PASS: no active .authors() filter"
fi
```

If the command exits with `1`, open a security issue immediately —
someone has re-introduced the forbidden anti-fix and administrative
DMs are being silently dropped.

## Cleanup

After verification, remove the test token via the
`POST /api/unregister` endpoint to avoid polluting production
metrics:

```bash
curl -i -X POST https://mostro-push-server.fly.dev/api/unregister \
  -H 'content-type: application/json' \
  -d '{"trade_pubkey": "<64-hex-chars>"}'
```

Expected response: `200 OK` with body
`{"success":true,"message":"Token unregistered successfully"}`
or `{"success":true,"message":"Token not found (may have already been unregistered)"}`.

## Recommended frequency

- After every deploy of milestone v1.1 (phases 1, 2, and 3).
- After any modification to `src/nostr/listener.rs`,
  `src/push/dispatcher.rs`, or `src/push/mod.rs`.
- As a periodic monthly verification in production.

## References

- `.planning/PROJECT.md` — anti-requirement **OOS-19 / CRIT-1**.
- `.planning/REQUIREMENTS.md` — requirement **VERIFY-03**.
- `.planning/phases/01-pushdispatcher-refactor-no-behaviour-change/01-CONTEXT.md` — decision **D-11** (introduction of the anti-CRIT-1 comment block).
- `src/nostr/listener.rs` — comment block above `Filter::new()`.
- NIP-59 (Gift Wrap, `kind 1059`) — specification of the event
  schema that wraps the DMs.
