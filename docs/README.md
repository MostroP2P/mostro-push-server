# Mostro Push Server Documentation

This directory contains comprehensive documentation for the Mostro Push Server, a privacy-preserving push notification system for the Mostro P2P Bitcoin exchange.

## Table of Contents

1. [Architecture Overview](./architecture.md) - System design and component interactions
2. [API Reference](./api.md) - HTTP endpoints and request/response formats
3. [Configuration](./configuration.md) - Environment variables and setup
4. [Cryptography](./cryptography.md) - Token encryption scheme (MIP-05 inspired)
5. [Deployment](./deployment.md) - Production deployment guide

## Quick Start

```bash
# 1. Clone and build
cargo build --release

# 2. Configure environment
cp .env.example .env
# Edit .env with your settings

# 3. Run
cargo run --release
```

## Key Features

- **Privacy-Preserving**: Device tokens are encrypted client-side, server only sees ciphertext
- **Targeted Notifications**: Push sent only to the specific trade participant, not broadcast
- **Multi-Platform**: Supports FCM (Android/iOS) and UnifiedPush (degoogled Android)
- **Nostr Native**: Listens to kind 1059 events from Mostro daemon
- **Auto-Cleanup**: Expired tokens automatically removed based on TTL

## How It Works

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────┐
│   Mobile    │────▶│  Push Server    │◀────│   Mostro    │
│   Client    │     │                 │     │   Daemon    │
└─────────────┘     └─────────────────┘     └─────────────┘
      │                     │                      │
      │ 1. Register         │                      │
      │    encrypted        │                      │
      │    token            │                      │
      │────────────────────▶│                      │
      │                     │                      │
      │                     │ 2. Listen for        │
      │                     │    kind 1059         │
      │                     │◀─────────────────────│
      │                     │                      │
      │ 3. Receive          │                      │
      │    targeted         │                      │
      │    push             │                      │
      │◀────────────────────│                      │
      │                     │                      │
```

## License

MIT License - See LICENSE file for details.
