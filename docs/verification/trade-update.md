# Manual verification: trade-update path

This runbook verifies end to end that a trade update published by a trusted
Mostro node reaches a registered device through the Nostr listener, and that
an event from any other author does not.

Run it after every deploy and after any change to `src/nostr/listener.rs`,
`src/push/dispatcher.rs`, `src/push/mod.rs` or
`config/trusted_mostro_pubkeys.json`. It is the only end-to-end signal that
the listener path is intact.

## What the listener accepts

- Only `kind 14` (Mostro protocol v2, NIP-44 direct) events authored by a node
  in `config/trusted_mostro_pubkeys.json`. The subscription asks relays for
  those authors only, and each event's author is checked again; nostr-sdk has
  already verified its signature.
- The recipient is the first `p` tag, which must match a registered
  `trade_pubkey`.
- At most 10 pushes per minute per `trade_pubkey`.

Gift Wrap (`kind 1059`, protocol v1) is no longer observed. Chat messages (P2P
and dispute) are addressed to a conversation key, not a `trade_pubkey`, and
are woken through `POST /api/notify` instead; this runbook does not cover
them.

## Prerequisites

- `flyctl` installed and authenticated (`flyctl auth whoami` must respond).
- The Mostro mobile app on a test device, configured on one of the trusted
  nodes, with push notifications enabled.
- A second client able to take an order on that node (another device, or
  `mostro-cli`).
- A Nostr tool able to sign and publish an arbitrary event (for example
  `nak`), for the negative check.

## Procedure

### Step 1: Check the listener started correctly

```bash
flyctl logs -a mostro-push-server | grep -E "trusted Mostro nodes"
```

Expected, after the latest start:

```
Loaded N trusted Mostro nodes (register whitelist enabled: false)
Subscribed to kind 14 events from trusted Mostro nodes on M of K relays
```

`N` must match the entries in `config/trusted_mostro_pubkeys.json`, and `M`
should equal `K`. If `M` is lower, the relays listed in the warnings above that
line refused the subscription.

### Step 2: Positive check, a real trade update

1. On the test device, create a small order and put the app in the background
   (or close it) with the screen off.
2. Take the order from the second client.
3. Watch the server logs:

   ```bash
   flyctl logs -a mostro-push-server | grep -E "Received protocol v2|MATCH|Push sent successfully|Failed to send push"
   ```

   Within a few seconds of the take you should see, for the node's message to
   the maker, `Received protocol v2 (kind 14) event`, then `MATCH!` and
   `Push sent successfully for event <event-id>`.

4. The device must show the notification.

If nothing is logged, the node is probably missing from the trusted list or
publishes to no relay in `NOSTR_RELAYS`. If `Received` appears but no
`MATCH!`, the app did not register (or re-register) the trade.

### Step 3: Negative check, a forged update

Take the maker's `trade_pubkey` from the test device (or from the order's
`p` tag on the relay) and publish a `kind 14` event tagging it, signed with a
throwaway key, to a relay in `NOSTR_RELAYS`. For example with `nak`:

```bash
nak event -k 14 -c "forged" -p <trade_pubkey> --sec <throwaway-secret> wss://<relay>
```

Expected:

- The device receives **no** notification.
- The logs show no `Received protocol v2` line for that event id: the relay
  does not even deliver it to the server's subscription. With
  `RUST_LOG=debug`, a relay that ignores the filter shows
  `Ignoring kind 14 event <id> from an untrusted author` instead.

A push here means the author filter regressed: open a security issue.

## Cleanup

Cancel or finish the test order. No server-side cleanup is needed: the
registration expires with the TTL, and disabling push notifications in the
app unregisters it immediately.

## References

- [docs/architecture.md](../architecture.md) — listener design and privacy
  invariants.
- [docs/configuration.md](../configuration.md) — trusted Mostro nodes.
- `src/nostr/listener.rs` — `subscription_filter` and `EventHandler::handle`.
