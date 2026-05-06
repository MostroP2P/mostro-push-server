# Mostro Push Server Documentation

Operator and integrator documentation for the Mostro Push Server, a privacy-preserving push notification backend for the Mostro P2P trading ecosystem.

## Table of Contents

1. [Architecture Overview](./architecture.md) — components, data flow, concurrency model
2. [API Reference](./api.md) — HTTP endpoints, request and response formats
3. [Configuration](./configuration.md) — environment variables and tuning
4. [Deployment](./deployment.md) — Fly.io deployment, Docker, reverse proxy
5. [UnifiedPush](./unifiedpush.md) — UnifiedPush backend notes
6. [Verification: dispute chat](./verification/dispute-chat.md) — manual end-to-end runbook for the Nostr listener path

## What this server does

- Subscribes to Nostr relays and observes Gift Wrap events (`kind 1059`).
- Maintains an in-memory map of `trade_pubkey -> device_token` populated by mobile clients via `POST /api/register`.
- On a matching event, dispatches a silent push via Firebase Cloud Messaging (FCM) and/or UnifiedPush.
- Exposes `POST /api/notify` for the mobile client to trigger a sender-side wake-up (silent push) when peer-to-peer chat events are sent without going through the Mostro daemon.

## What this server explicitly does NOT do

- It does not authenticate `/api/register`, `/api/unregister`, or `/api/notify` callers. The contract is intentionally unauthenticated: anything that would let the operator correlate a sender to a recipient is rejected.
- It does not filter the Nostr listener by `authors`. Gift Wrap uses an ephemeral outer key per event, and dispute admin DMs are sent user-to-user, never by the Mostro daemon. An author filter would silently drop those.
- It does not persist registered tokens to disk. Tokens are in-memory only, cleared on restart, and TTL-expired in the background. UnifiedPush endpoints are the only state persisted (atomic JSON write to `data/unifiedpush_endpoints.json`).
- It does not log raw `trade_pubkey`s. All pubkeys are rendered through `log_pubkey` (a salted, truncated BLAKE3 keyed hash) so logs cannot be used as a correlation oracle.

## Quick start

```bash
cp .env.example .env
# edit .env: set NOSTR_RELAYS at minimum; FIREBASE_* if FCM is enabled
cargo run --release
```

Health check once it is up:

```bash
curl http://localhost:8080/api/health
```

## License

MIT — see [LICENSE](../LICENSE).
