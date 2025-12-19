# Architecture Overview

## System Components

```
┌────────────────────────────────────────────────────────────────────────┐
│                         MOSTRO PUSH SERVER                              │
├────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │   HTTP API  │  │   Nostr     │  │   Token     │  │   Push      │   │
│  │   Server    │  │   Listener  │  │   Store     │  │   Services  │   │
│  │  (Actix)    │  │  (nostr-sdk)│  │  (HashMap)  │  │  (FCM/UP)   │   │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘   │
│         │                │                │                │          │
│         └────────────────┴────────────────┴────────────────┘          │
│                                    │                                   │
│                          ┌─────────┴─────────┐                        │
│                          │   Token Crypto    │                        │
│                          │  (ECDH+ChaCha20)  │                        │
│                          └───────────────────┘                        │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

## Module Structure

```
src/
├── main.rs           # Application entry point, wiring
├── config.rs         # Environment configuration
├── api/
│   └── routes.rs     # HTTP endpoints
├── nostr/
│   └── listener.rs   # Nostr relay subscription
├── crypto/
│   └── mod.rs        # Token encryption/decryption
├── store/
│   └── mod.rs        # In-memory token storage
├── push/
│   ├── mod.rs        # PushService trait
│   ├── fcm.rs        # Firebase Cloud Messaging
│   └── unifiedpush.rs# UnifiedPush (degoogled)
└── utils/
    └── batching.rs   # Rate limiting utilities
```

## Data Flow

### 1. Token Registration Flow

```
Mobile Client                    Push Server
     │                               │
     │  1. Get server pubkey         │
     │  GET /api/info                │
     │──────────────────────────────▶│
     │                               │
     │  { server_pubkey: "02..." }   │
     │◀──────────────────────────────│
     │                               │
     │  2. Encrypt FCM token         │
     │  (client-side ECDH)           │
     │                               │
     │  3. Register token            │
     │  POST /api/register           │
     │  { trade_pubkey,              │
     │    encrypted_token }          │
     │──────────────────────────────▶│
     │                               │  4. Decrypt token
     │                               │     (server ECDH)
     │                               │
     │                               │  5. Store mapping:
     │                               │     trade_pubkey → device_token
     │                               │
     │  { success: true }            │
     │◀──────────────────────────────│
```

### 2. Push Notification Flow

```
Mostro Daemon          Nostr Relay           Push Server           Mobile
     │                      │                     │                   │
     │  1. Send kind 1059   │                     │                   │
     │     p: trade_pubkey  │                     │                   │
     │─────────────────────▶│                     │                   │
     │                      │                     │                   │
     │                      │  2. Event received  │                   │
     │                      │─────────────────────▶                   │
     │                      │                     │                   │
     │                      │                     │  3. Extract 'p' tag
     │                      │                     │     Look up token
     │                      │                     │                   │
     │                      │                     │  4. Send FCM      │
     │                      │                     │─────────────────▶│
     │                      │                     │                   │
     │                      │                     │                   │ 5. Wake app
     │                      │                     │                   │    Process
```

## Key Design Decisions

### Privacy-First Architecture

The server **never sees plaintext device tokens**. The encryption flow:

1. Client fetches server's public key (`/api/info`)
2. Client generates ephemeral keypair
3. Client performs ECDH with server pubkey
4. Client encrypts `platform || token_length || token || padding`
5. Server decrypts using its private key

This ensures:
- Server operator cannot correlate device tokens across trades
- Even if server is compromised, historical tokens are protected
- No third party can link trades to devices

### Targeted vs Broadcast

Unlike traditional approaches that broadcast to all subscribers:

| Approach | Privacy | Efficiency |
|----------|---------|------------|
| Topic broadcast | Low - all devices wake | Low - unnecessary processing |
| **Targeted push** | **High - only recipient** | **High - single device** |

### Token Lifecycle

```
Register ──▶ Active ──▶ Expired ──▶ Cleaned
   │           │           │
   │           │           └── TTL exceeded (default 48h)
   │           │
   │           └── Trade in progress
   │
   └── Trade started (newSession)
```

## Concurrency Model

- **HTTP Server**: Actix-web with async handlers
- **Nostr Listener**: Tokio task with reconnection logic
- **Token Store**: `RwLock<HashMap>` for concurrent read/write
- **Cleanup Task**: Background Tokio task runs periodically

## Error Handling

| Component | Strategy |
|-----------|----------|
| Nostr connection | Auto-reconnect with backoff |
| FCM send failure | Log error, continue |
| Decryption failure | Return 400 Bad Request |
| Missing token | Silent skip (debug log) |

## Security Considerations

1. **Server Private Key**: Must be kept secret, stored in environment variable
2. **Service Account**: Firebase credentials stored outside repo
3. **Rate Limiting**: Configurable per-minute limits
4. **Input Validation**: All inputs validated before processing
5. **No Persistence**: Tokens stored in memory only (restart clears)
