# Mostro Push Server

Privacy-preserving push notification backend for the [Mostro](https://mostro.network/) P2P trading ecosystem.

The server observes Nostr Gift Wrap events (`kind 1059`), looks up registered device tokens by `trade_pubkey`, and dispatches silent push notifications via Firebase Cloud Messaging (FCM) and UnifiedPush so Mostro Mobile clients can wake up and process trade events. Inspired by [MIP-05](https://github.com/MostroP2P/MIPs).

## How it works

```
                                                       ┌──────────────────┐
┌─────────────────┐    1. POST /api/register           │                  │
│  Mostro Mobile  │ ──────────────────────────────────▶│  Push Server     │
│                 │       trade_pubkey + device_token  │                  │
│                 │                                    │  Stores:         │
│  Mostro Mobile  │    1b. POST /api/notify            │  trade_pubkey →  │
│  (sender)       │ ──────────────────────────────────▶│  device_token    │
│                 │       trade_pubkey                 │                  │
└─────────────────┘                                    └────────┬─────────┘
                                                                │
┌─────────────────┐    2. Publishes kind 1059          ┌────────▼─────────┐
│  Mostro Daemon  │ ──────────────────────────────────▶│  Nostr Relay     │
│  / dispute      │       p: trade_pubkey              │                  │
│  admin / peer   │                                    └────────┬─────────┘
└─────────────────┘                                             │
                                                       ┌────────▼─────────┐
                                                       │  Push Server     │
                                                       │  observes event  │
                                                       │  looks up token  │
                                                       └────────┬─────────┘
                                                                │
                                                       ┌────────▼─────────┐
                                                       │  FCM / UnifiedPush│
                                                       └────────┬─────────┘
                                                                │
                                                       ┌────────▼─────────┐
                                                       │  Mostro Mobile   │
                                                       │  wakes, fetches  │
                                                       │  events          │
                                                       └──────────────────┘
```

Two ingress paths feed the same dispatcher:

1. **Listener path** — the Nostr listener subscribes to `kind 1059` on configured relays and dispatches when a `p` tag matches a registered `trade_pubkey`.
2. **Sender-triggered path** — `POST /api/notify` lets a sender ask the server to wake the recipient when an event was sent peer-to-peer without going through the Mostro daemon (e.g. dispute admin DMs).

## Privacy properties

- The server stores `trade_pubkey -> device_token` in memory only. No persistence other than UnifiedPush endpoint URLs.
- The server does **not** authenticate `/api/register`, `/api/unregister`, or `/api/notify`. Adding signatures or sender identifiers would let the operator correlate sender and recipient.
- `/api/notify` always returns `202` on parse-valid input. Registered and unregistered pubkeys are indistinguishable in status, body, and headers; rate-limit responses are byte-identical between the per-IP and per-pubkey paths. The endpoint cannot be used as an enumeration oracle.
- Inbound `X-Request-Id` on `/api/notify` is stripped; the server generates its own UUIDv4 per request.
- All `trade_pubkey`s in logs go through a salted truncated BLAKE3 keyed hash (`log_pubkey`), with a per-process random salt that is never persisted.
- The Nostr listener does **not** filter by `authors`. Gift Wrap uses an ephemeral outer key, and admin DMs in disputes are user-to-user — an author filter would silently drop them.

What the server *does* see: an in-memory mapping of `trade_pubkey -> device_token`, and timing of incoming Gift Wrap events. It does not see message content, sender identity, or peer relationships.

## Requirements

- Rust 1.75 or later
- Access to one or more Nostr relays
- Optional: Firebase project with a service-account JSON for FCM

## Quick start

```bash
git clone https://github.com/MostroP2P/mostro-push-server.git
cd mostro-push-server
cp .env.example .env
# edit .env: NOSTR_RELAYS is required; FIREBASE_* if FCM is enabled
cargo run --release
```

Verify it is up:

```bash
curl http://localhost:8080/api/health
```

## API endpoints

| Method | Path             | Purpose                                                   |
|--------|------------------|-----------------------------------------------------------|
| GET    | `/api/health`    | Liveness                                                  |
| GET    | `/api/info`      | Server version and feature flags                          |
| GET    | `/api/status`    | Server status with token counts                           |
| POST   | `/api/register`  | Register a device token for a `trade_pubkey`              |
| POST   | `/api/unregister`| Remove a registered token                                 |
| POST   | `/api/notify`    | Trigger a silent push to the device for a `trade_pubkey`  |

See [docs/api.md](docs/api.md) for full request and response shapes.

## Docker

```bash
docker build -t mostro-push-backend .
docker-compose up -d
docker-compose logs -f
```

## Documentation

- [docs/architecture.md](docs/architecture.md) — components, data flow, concurrency, privacy invariants
- [docs/api.md](docs/api.md) — full HTTP contract
- [docs/configuration.md](docs/configuration.md) — environment variables
- [docs/deployment.md](docs/deployment.md) — Fly.io, Docker, nginx, systemd
- [docs/unifiedpush.md](docs/unifiedpush.md) — UnifiedPush backend notes
- [docs/verification/dispute-chat.md](docs/verification/dispute-chat.md) — end-to-end runbook for the listener path

## Development

```bash
cargo test       # in-process integration tests live alongside source
cargo clippy
cargo fmt
```

A shell-script smoke test for a running instance:

```bash
RUST_LOG=info cargo run
./test_server.sh    # in another terminal
```

## License

[MIT](LICENSE).

## Resources

- [MIP-05: Privacy-Preserving Push Notifications](https://github.com/MostroP2P/MIPs)
- [UnifiedPush specification](https://unifiedpush.org/developers/spec/)
- [Nostr SDK Rust](https://docs.rs/nostr-sdk/)
- [Actix Web](https://actix.rs/docs/)
- [FCM v1 API](https://firebase.google.com/docs/cloud-messaging/migrate-v1)
