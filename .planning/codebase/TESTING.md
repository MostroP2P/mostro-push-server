# Testing Patterns

**Analysis Date:** 2026-04-24

## Test Framework

- **Runner:** Built-in `cargo test` harness. No external runner. No `[lib]` or `[[test]]` declarations in `Cargo.toml`; tests are co-located in source modules using `#[cfg(test)] mod tests`.
- **Async runtime:** All tests are synchronous `#[test]` functions. No `#[tokio::test]` or `#[actix_web::test]` is used. The only currently tested area (cryptography) is purely synchronous.
- **Assertion library:** Standard library macros only (`assert_eq!`, `assert!`).
- **Dev dependencies:** `mockito = "1.2"` is declared in `Cargo.toml` line 56 under `[dev-dependencies]` but is **not currently used** anywhere in the codebase (no `mockito::` references in `src/`).

**Run commands:**
```bash
cargo test                                  # Run all unit tests
cargo test crypto                           # Filter to crypto module tests
cargo test test_decrypt_token -- --nocapture  # Show println! output
cargo test -- --test-threads=1              # Run sequentially
```

## Test File Organization

- **Location:** Co-located with source. Tests live inside a `#[cfg(test)] mod tests { ... }` block at the bottom of each module.
- **Currently the only tests** are in `src/crypto/mod.rs` (lines 453-823).
- **Naming:** `snake_case` starting with `test_`: `test_decrypt_token`, `test_hkdf_isolated_with_known_shared_x`, `test_encryption_roundtrip_client_simulation`, `test_fixed_values_with_debug_output`, `test_shared_secret_behavior`, `test_ios_platform_roundtrip`, `test_debug_decrypt_shows_intermediate_values`.
- **No top-level `tests/` directory** and **no integration test crates** exist.

**Untested production modules:**
- `src/api/routes.rs`
- `src/store/mod.rs`
- `src/push/fcm.rs`
- `src/push/unifiedpush.rs`
- `src/nostr/listener.rs`
- `src/utils/batching.rs`
- `src/config.rs`

## Test Structure

The crypto tests follow the canonical Rust shape:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn create_test_encrypted_token(
        server_pubkey: &PublicKey,
        platform: Platform,
        device_token: &str,
    ) -> Vec<u8> { /* shared helper */ }

    #[test]
    fn test_decrypt_token() {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let server_secret = SecretKey::new(&mut rng);
        let server_pubkey = PublicKey::from_secret_key(&secp, &server_secret);

        let crypto = TokenCrypto::new(&hex::encode(server_secret.secret_bytes())).unwrap();
        let device_token = "test_fcm_token_12345";
        let encrypted = create_test_encrypted_token(&server_pubkey, Platform::Android, device_token);

        let decrypted = crypto.decrypt_token(&encrypted).unwrap();
        assert_eq!(decrypted.platform, Platform::Android);
        assert_eq!(decrypted.device_token, device_token);
    }
}
```

- **Setup:** Each test constructs its own `Secp256k1`, key material, and inputs locally. No shared setup/teardown hooks. Some tests use random keys (`SecretKey::new(&mut rng)`); others use fixed hex constants for deterministic Flutter-client comparison.
- **Helpers:** A single shared helper `create_test_encrypted_token` (`src/crypto/mod.rs` lines 458-505). Two production helpers, `encrypt_token_like_client` (lines 344-386) and `encrypt_token_with_debug` (lines 403-451), are kept public outside `#[cfg(test)]` to enable cross-language debugging and are reused by tests.
- **Assertions:** Direct `assert_eq!` on decrypted fields; `assert!` on `Option::is_some()` for debug fields (`src/crypto/mod.rs` lines 818-820).
- **Diagnostic output:** Tests use `println!` extensively to emit fixed test vectors and intermediate values for cross-platform comparison. Run with `cargo test -- --nocapture` to view them.

## Mocking

**No active mocking framework.** `mockito` is declared but unused.

**What to mock when adding tests:**
- External HTTP endpoints currently hard-coded in code:
  - FCM v1 send: `https://fcm.googleapis.com/v1/projects/{project_id}/messages:send` (`src/push/fcm.rs` lines 224-227, 276-279).
  - Google OAuth2 token exchange: `https://oauth2.googleapis.com/token` (`src/push/fcm.rs` line 132).
  - Arbitrary UnifiedPush distributor URLs (`src/push/unifiedpush.rs` lines 142, 179).
- These are not parameterized today, so making them mockable would require injecting a base URL through `Config` or constructor argument.
- Nostr relays would require either a fake WebSocket server or a refactor of `NostrListener` (`src/nostr/listener.rs`) to accept a client trait.

**What NOT to mock:**
- Crypto primitives (`secp256k1`, `chacha20poly1305`, `hkdf`): tests use the real implementations and rely on roundtrip equivalence.
- The in-memory `TokenStore`: it is a simple `HashMap` and can be exercised directly.

## Fixtures and Factories

**Test data:** Inline, deterministic hex constants serve as the fixtures, intended to match Flutter client values:

```rust
let server_secret_hex = "1111111111111111111111111111111111111111111111111111111111111111";
let ephemeral_secret_hex = "2222222222222222222222222222222222222222222222222222222222222222";
let nonce: [u8; 12] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
let device_token = "fcm_test_token_abc123";
```

(See `src/crypto/mod.rs` lines 571-582, 619-642, 692-703, 744-754, 783-792.)

**Factory:** `create_test_encrypted_token(server_pubkey, platform, device_token)` in `src/crypto/mod.rs` lines 458-505. Used by `test_decrypt_token`.

**Location:** All fixtures inline. No `tests/fixtures/`, no shared JSON vectors, no `mod test_utils`.

## Coverage

- **Requirements:** None enforced. No coverage thresholds, no CI coverage configuration, no `tarpaulin`/`grcov`/`llvm-cov` setup.
- **Current scope:** Tests cover only encryption/decryption roundtrip, ECDH behavior, HKDF determinism, and platform-byte parsing for Android (0x02) and iOS (0x01).

```bash
# Recommended (not currently configured):
cargo install cargo-llvm-cov
cargo llvm-cov --html
```

## Test Types

- **Unit tests:** All current tests are unit tests embedded in `src/crypto/mod.rs`. Scope: cryptographic correctness, ECDH shared-secret behavior, HKDF determinism, ChaCha20-Poly1305 roundtrip, platform variants.
- **Integration tests:** No `tests/` directory; no integration test crate. Manual end-to-end testing uses the shell script `test_server.sh` against a running server on `localhost:8080`.
  - **Important:** `test_server.sh` references an older API contract (`device_id`/`endpoint_url`) that does not match the current `RegisterTokenRequest` schema (`trade_pubkey`/`token`/`platform`) in `src/api/routes.rs` lines 9-14. The script is stale.
- **E2E tests:** Not used.

## Common Patterns

**Cross-language vector generation:** Tests like `test_fixed_values_with_debug_output` (`src/crypto/mod.rs` lines 611-680) and `test_hkdf_isolated_with_known_shared_x` (lines 530-561) print intermediate values (`shared_x`, `encryption_key`, `padded_payload`, `ciphertext`) so the same inputs can be replayed in Flutter and compared byte-for-byte.

**ECDH property test:** `test_shared_secret_behavior` (lines 683-736) verifies `ECDH(A_priv, B_pub) == ECDH(B_priv, A_pub)` and explicitly documents the rust-secp256k1 0.28 contract that `secret_bytes()` returns the raw X coordinate (not SHA256 of the point).

**Error testing:** No negative-path tests exist. The production code defines `CryptoError` variants (`InvalidSecretKey`, `InvalidTokenSize`, `InvalidEphemeralKey`, `HkdfError`, `CipherError`, `DecryptionFailed`, `InvalidPayloadSize`, `InvalidTokenLength`, `InvalidPlatform`, `InvalidTokenEncoding`) but they are not exercised by tests.

**Async testing (when added):**
- Use `#[tokio::test]` for code touching `tokio::sync::RwLock`/`Mutex` (e.g., `TokenStore`, `UnifiedPushService`).
- Use `#[actix_web::test]` with `actix_web::test::TestRequest` for handlers in `src/api/routes.rs`.

---

*Testing analysis: 2026-04-24*
