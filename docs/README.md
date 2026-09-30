# Mostro Push Server Documentation

Operator and integrator documentation for the Mostro Push Server, a privacy-preserving push notification backend for the Mostro P2P trading ecosystem.

## Table of Contents

1. [Architecture Overview](./architecture.md) — components, data flow, concurrency model
2. [API Reference](./api.md) — HTTP endpoints, request and response formats
3. [Configuration](./configuration.md) — environment variables and tuning
4. [Deployment](./deployment.md) — Fly.io deployment, Docker, reverse proxy
5. [UnifiedPush](./unifiedpush.md) — UnifiedPush backend notes
6. [Verification: trade update](./verification/trade-update.md) — manual end-to-end runbook for the Nostr listener path

## What this server does

- Subscribes to Nostr relays and observes the NIP-44 direct messages (`kind 14`, Mostro protocol v2) authored by the trusted Mostro nodes in `config/trusted_mostro_pubkeys.json`.
- Maintains a map of `trade_pubkey -> device_token` populated by mobile clients via `POST /api/register`, kept in memory and optionally persisted (encrypted) to SQLite so it survives restarts.
- On a matching event, dispatches a silent push via Firebase Cloud Messaging (FCM) and/or UnifiedPush.
- Exposes `POST /api/notify` for the mobile client to trigger a sender-side wake-up (silent push) when peer-to-peer chat events are sent without going through the Mostro daemon.

## What this server explicitly does NOT do

- It does not authenticate `/api/register`, `/api/unregister`, or `/api/notify` callers. The contract is intentionally unauthenticated: anything that would let the operator correlate a sender to a recipient is rejected.
- It does not push for events from other authors. Anyone can tag a registered `trade_pubkey`, so only a trusted node's signed kind-14 event wakes a device, at most 10 times per minute per `trade_pubkey`. Gift Wrap (`kind 1059`, protocol v1) is no longer observed.
- It does not keep registrations longer than needed. They expire with the TTL and are deleted on `unregister`, in memory and on disk; device tokens on disk are encrypted and deleted rows are zeroed. See [Deployment: Persistence](./deployment.md#persistence).
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
