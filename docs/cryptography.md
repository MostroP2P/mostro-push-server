# Cryptography Specification

This document describes the token encryption scheme used by Mostro Push Server, inspired by [MIP-05](https://github.com/MostroP2P/MIPs).

## Overview

The goal is **privacy-preserving push notifications**: the server can send targeted notifications without knowing which device belongs to which user.

```
┌─────────────────────────────────────────────────────────────────┐
│                    ENCRYPTION FLOW                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Client                              Server                      │
│    │                                   │                         │
│    │  1. Fetch server pubkey           │                         │
│    │──────────────────────────────────▶│                         │
│    │                                   │                         │
│    │  2. Generate ephemeral keypair    │                         │
│    │                                   │                         │
│    │  3. ECDH(ephemeral_priv,          │                         │
│    │         server_pub) = shared_x    │                         │
│    │                                   │                         │
│    │  4. HKDF(shared_x) = key          │                         │
│    │                                   │                         │
│    │  5. ChaCha20-Poly1305             │                         │
│    │     encrypt(payload)              │                         │
│    │                                   │                         │
│    │  6. Send encrypted token          │                         │
│    │──────────────────────────────────▶│                         │
│    │                                   │  7. ECDH(server_priv,   │
│    │                                   │       ephemeral_pub)    │
│    │                                   │                         │
│    │                                   │  8. HKDF → key          │
│    │                                   │                         │
│    │                                   │  9. Decrypt payload     │
│    │                                   │                         │
└─────────────────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Key Agreement | ECDH | secp256k1 curve |
| Key Derivation | HKDF | SHA-256, salt: `mostro-push-v1`, info: `mostro-token-encryption` |
| Encryption | ChaCha20-Poly1305 | 256-bit key, 96-bit nonce |

## Constants

```rust
const HKDF_SALT: &[u8] = b"mostro-push-v1";
const HKDF_INFO: &[u8] = b"mostro-token-encryption";

const PLATFORM_ANDROID: u8 = 0x02;
const PLATFORM_IOS: u8 = 0x01;

const PADDED_PAYLOAD_SIZE: usize = 220;
const EPHEMERAL_PUBKEY_SIZE: usize = 33;  // Compressed secp256k1
const NONCE_SIZE: usize = 12;
const AUTH_TAG_SIZE: usize = 16;

// Total: 33 + 12 + 220 + 16 = 281 bytes
const ENCRYPTED_TOKEN_SIZE: usize = 281;
```

## Encrypted Token Structure

```
┌───────────────────────────────────────────────────────────────────┐
│                    ENCRYPTED TOKEN (281 bytes)                     │
├─────────────────┬────────────┬────────────────────────────────────┤
│ Ephemeral Pubkey│   Nonce    │           Ciphertext               │
│   (33 bytes)    │ (12 bytes) │          (236 bytes)               │
│   compressed    │   random   │   payload + auth_tag               │
└─────────────────┴────────────┴────────────────────────────────────┘
```

## Plaintext Payload Structure

```
┌───────────────────────────────────────────────────────────────────┐
│                  PLAINTEXT PAYLOAD (220 bytes)                     │
├──────────┬──────────────┬─────────────────┬───────────────────────┤
│ Platform │ Token Length │  Device Token   │    Random Padding     │
│ (1 byte) │  (2 bytes)   │   (variable)    │     (remainder)       │
│  0x01/02 │  big-endian  │   UTF-8 string  │   random bytes        │
└──────────┴──────────────┴─────────────────┴───────────────────────┘
```

### Platform Identifiers

| Byte | Platform |
|------|----------|
| `0x01` | iOS |
| `0x02` | Android |

### Token Length

2-byte big-endian unsigned integer indicating the length of the device token in bytes.

### Device Token

UTF-8 encoded FCM/APNs device token. Maximum length: 217 bytes (220 - 3).

### Random Padding

Random bytes to fill the remaining space, ensuring all encrypted tokens are the same size regardless of actual token length. This prevents length-based analysis.

## Encryption Process (Client)

```dart
// 1. Fetch server public key
final serverPubkey = await fetchServerPubkey();  // 33 bytes compressed

// 2. Generate ephemeral keypair
final ephemeralPrivate = generateRandomBytes(32);
final ephemeralPublic = derivePublicKey(ephemeralPrivate);  // 33 bytes

// 3. ECDH key agreement
final sharedPoint = ecdh(ephemeralPrivate, serverPubkey);
final sharedX = sharedPoint.x;  // 32 bytes (x-coordinate only)

// 4. HKDF key derivation
final encryptionKey = hkdf(
  salt: "mostro-push-v1",
  ikm: sharedX,
  info: "mostro-token-encryption",
  length: 32
);

// 5. Build padded payload
final payload = Uint8List(220);
payload[0] = platformByte;  // 0x01 or 0x02
payload.setRange(1, 3, tokenLength.toBytesBigEndian());
payload.setRange(3, 3 + token.length, token.bytes);
payload.fillRange(3 + token.length, 220, randomBytes());

// 6. Generate random nonce
final nonce = generateRandomBytes(12);

// 7. Encrypt with ChaCha20-Poly1305
final ciphertext = chacha20poly1305.encrypt(
  key: encryptionKey,
  nonce: nonce,
  plaintext: payload
);  // 220 + 16 = 236 bytes

// 8. Combine components
final encryptedToken = ephemeralPublic + nonce + ciphertext;  // 281 bytes

// 9. Base64 encode for transmission
final base64Token = base64.encode(encryptedToken);
```

## Decryption Process (Server)

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

// Padding is discarded
```

## Security Properties

### Forward Secrecy

Each token registration uses a fresh ephemeral keypair. Compromise of the server's private key does not reveal previously encrypted tokens (assuming ephemeral keys were properly discarded).

### Unlinkability

- Different trades use different ephemeral keys
- Encrypted tokens are indistinguishable (same size, random padding)
- Server cannot correlate tokens across trades

### Authenticity

ChaCha20-Poly1305 provides authenticated encryption. Any tampering with the ciphertext will be detected during decryption.

### Confidentiality

Only the server (holder of `SERVER_PRIVATE_KEY`) can decrypt tokens. The encryption is IND-CCA2 secure.

## Implementation Notes

### Client (Dart/Flutter)

```dart
// Using pointycastle library
import 'package:pointycastle/export.dart';

// ECDH
final agreement = ECDHBasicAgreement();
agreement.init(ephemeralPrivateKey);
final sharedSecret = agreement.calculateAgreement(serverPublicKey);

// HKDF
final hkdf = HKDFKeyDerivator(SHA256Digest());
hkdf.init(HkdfParameters(sharedSecret, 32, salt, info));

// ChaCha20-Poly1305
final cipher = ChaCha20Poly1305(ChaCha7539Engine(), Poly1305());
```

### Server (Rust)

```rust
// Using secp256k1, hkdf, chacha20poly1305 crates
use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};
use hkdf::Hkdf;
use chacha20poly1305::{ChaCha20Poly1305, aead::Aead};

// ECDH
let shared = SharedSecret::new(&ephemeral_pubkey, &server_secret);

// HKDF
let hk = Hkdf::<Sha256>::new(Some(SALT), &shared.secret_bytes());
hk.expand(INFO, &mut key)?;

// ChaCha20-Poly1305
let cipher = ChaCha20Poly1305::new_from_slice(&key)?;
let plaintext = cipher.decrypt(nonce, ciphertext)?;
```

## Test Vectors

### Input
```
Server Private Key: 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
Platform: Android (0x02)
Device Token: "test_fcm_token_12345"
```

### Expected Flow
1. Server Public Key (compressed): `02...` (derived from private key)
2. Ephemeral keypair generated randomly
3. Shared secret computed via ECDH
4. Encryption key derived via HKDF
5. Payload padded to 220 bytes
6. Encrypted with random nonce
7. Final token: 281 bytes

Note: Due to random ephemeral key and nonce, encrypted output varies each time.

## References

- [MIP-05: Privacy-Preserving Push Notifications](https://github.com/MostroP2P/MIPs)
- [SEC 1: Elliptic Curve Cryptography](https://www.secg.org/sec1-v2.pdf)
- [RFC 5869: HKDF](https://tools.ietf.org/html/rfc5869)
- [RFC 8439: ChaCha20-Poly1305](https://tools.ietf.org/html/rfc8439)
