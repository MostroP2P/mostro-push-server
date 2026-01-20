# Implementation Phases

This document describes the phased implementation approach for the Mostro Push Server, coordinated with the mobile client.

## Overview

The push notification system is implemented in phases to allow incremental testing and validation of each component before adding complexity.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    IMPLEMENTATION ROADMAP                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Phase 1: Core Infrastructure           ✅ COMPLETE                  │
│  ├── HTTP API server (Actix-web)                                    │
│  ├── Nostr relay listener (kind 1059)                               │
│  └── Basic token storage (in-memory)                                │
│                                                                      │
│  Phase 2: Push Delivery                 ✅ COMPLETE                  │
│  ├── FCM integration                                                │
│  ├── UnifiedPush support                                            │
│  └── Intelligent batching                                           │
│                                                                      │
│  Phase 3: Token Registration (Plain)    ✅ COMPLETE                  │
│  ├── Register/unregister endpoints                                  │
│  ├── Platform identification                                        │
│  └── Token lifecycle management                                     │
│                                                                      │
│  Phase 4: Encrypted Token Registration  🔜 FUTURE                   │
│  ├── ECDH key agreement                                             │
│  ├── ChaCha20-Poly1305 encryption                                   │
│  └── Privacy-preserving token handling                              │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Core Infrastructure ✅ COMPLETE

**Objective:** Establish the foundational server architecture.

### Components Implemented
- **HTTP API Server:** Actix-web based REST API
- **Nostr Listener:** WebSocket connection to Nostr relays, subscribing to kind 1059 events
- **Token Store:** In-memory HashMap with RwLock for concurrent access
- **Configuration:** Environment-based configuration via `.env`

### Endpoints
- `GET /api/health` - Health check
- `GET /api/info` - Server information
- `GET /api/status` - Server status with token statistics

---

## Phase 2: Push Delivery ✅ COMPLETE

**Objective:** Implement push notification delivery to mobile devices.

### Components Implemented
- **FCM Service:** Firebase Cloud Messaging integration with OAuth2 authentication
- **UnifiedPush Service:** Support for degoogled Android (GrapheneOS, LineageOS)
- **Batching System:** Intelligent notification batching (5s delay, 60s cooldown)
- **Automatic Reconnection:** Resilient relay connections with backoff

### Push Flow
```
Nostr Relay → Event Received → Extract 'p' tag → Lookup Token → Send Push
```

---

## Phase 3: Token Registration (Plain) ✅ COMPLETE

**Objective:** Enable mobile clients to register device tokens for push notifications.

### Current Implementation
Tokens are currently registered in **plaintext** (protected by HTTPS in transit). This allows validation of the end-to-end push flow before adding encryption complexity.

### Endpoints
- `POST /api/register` - Register a device token
- `POST /api/unregister` - Unregister a device token

### Request Format (Current)
```json
{
  "trade_pubkey": "64-character-hex-pubkey",
  "token": "fcm-device-token",
  "platform": "android"
}
```

### Privacy Note
⚠️ **Current implementation does NOT provide full MIP-05 privacy guarantees.** The server operator can see plaintext device tokens. This is acceptable for testing but will be addressed in Phase 4.

---

## Phase 4: Encrypted Token Registration 🔜 FUTURE

**Objective:** Implement MIP-05 compliant encrypted token registration for privacy-preserving push notifications.

### Overview

This phase will add end-to-end encryption so that even the push server operator cannot correlate device tokens with user identities.

### Changes Required

#### Server Side (`src/crypto/mod.rs`)
1. Generate and store server keypair (secp256k1)
2. Expose server public key via `/api/info`
3. Implement token decryption:
   - Parse ephemeral public key from encrypted token
   - Perform ECDH key agreement
   - Derive encryption key via HKDF
   - Decrypt with ChaCha20-Poly1305
   - Extract platform and device token from payload

#### API Changes
- `/api/info` response will include `server_pubkey`
- `/api/register` will accept `encrypted_token` instead of plaintext

### Encrypted Request Format (Future)
```json
{
  "trade_pubkey": "64-character-hex-pubkey",
  "encrypted_token": "base64-encoded-281-byte-encrypted-token"
}
```

### Cryptographic Specification

See [cryptography.md](./cryptography.md) for full specification.

#### Summary

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Key Agreement | ECDH | secp256k1 curve |
| Key Derivation | HKDF | SHA-256, salt: `mostro-push-v1`, info: `mostro-token-encryption` |
| Encryption | ChaCha20-Poly1305 | 256-bit key, 96-bit nonce |

#### Encrypted Token Structure (281 bytes)

```
┌─────────────────────┬────────────┬─────────────────────────────────┐
│ Ephemeral Pubkey    │   Nonce    │          Ciphertext             │
│     (33 bytes)      │ (12 bytes) │  (220 + 16 = 236 bytes)         │
└─────────────────────┴────────────┴─────────────────────────────────┘
```

#### Decryption Process (Server)

```rust
// 1. Parse components
let ephemeral_pubkey = &encrypted_token[0..33];
let nonce = &encrypted_token[33..45];
let ciphertext = &encrypted_token[45..281];

// 2. ECDH key agreement
let shared_point = ecdh(server_private_key, ephemeral_pubkey);
let shared_x = shared_point.x_coordinate();

// 3. HKDF key derivation
let encryption_key = hkdf_sha256(
    salt: b"mostro-push-v1",
    ikm: shared_x,
    info: b"mostro-token-encryption",
    length: 32
);

// 4. Decrypt with ChaCha20-Poly1305
let payload = chacha20poly1305_decrypt(
    key: encryption_key,
    nonce: nonce,
    ciphertext: ciphertext
)?;  // 220 bytes

// 5. Parse payload
let platform = Platform::from_byte(payload[0])?;
let token_length = u16::from_be_bytes([payload[1], payload[2]]) as usize;
let device_token = String::from_utf8(payload[3..3+token_length].to_vec())?;
```

### Privacy Properties Achieved

Once implemented, Phase 4 will provide:

- **Unlinkability:** Server cannot correlate tokens across registrations
- **Confidentiality:** Only server can decrypt tokens (holder of private key)
- **Forward Secrecy:** Ephemeral keys mean past tokens are protected
- **Platform Privacy:** Platform type hidden within encrypted payload

### Dependencies Required

```toml
[dependencies]
secp256k1 = "0.28"
chacha20poly1305 = "0.10"
hkdf = "0.12"
sha2 = "0.10"
```

### Testing Requirements

- Unit tests for encryption/decryption round-trip
- Integration tests with mobile client
- Performance testing (decryption overhead)
- Error handling for malformed tokens

### Migration Path

1. Deploy server with encryption support (accepting both formats)
2. Update mobile clients to use encryption
3. Monitor adoption via `/api/status` metrics
4. Deprecate plaintext registration after migration complete

---

## Coordination with Mobile Client

The mobile client implementation is documented in:
- `mobile/docs/FCM_IMPLEMENTATION.md`

### Current Status

| Component | Mobile | Server |
|-----------|--------|--------|
| FCM Integration | ✅ | ✅ |
| Token Registration | ✅ | ✅ |
| User Settings | ✅ | N/A |
| Encryption | 🔜 Phase 5 | 🔜 Phase 4 |

### Implementation Order

1. Server implements encryption support (Phase 4)
2. Server exposes public key via `/api/info`
3. Mobile implements encryption (Phase 5)
4. Both systems tested together
5. Plaintext registration deprecated

---

## References

- [MIP-05: Privacy-Preserving Push Notifications](https://github.com/MostroP2P/MIPs)
- [cryptography.md](./cryptography.md) - Detailed encryption specification
- [api.md](./api.md) - API reference
- [architecture.md](./architecture.md) - System architecture
