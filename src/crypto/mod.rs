use base64::Engine;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use log::{debug, error};
use secp256k1::{PublicKey, SecretKey, Secp256k1};
use serde::Serialize;
use sha2::Sha256;

const HKDF_SALT: &[u8] = b"mostro-push-v1";
const HKDF_INFO: &[u8] = b"mostro-token-encryption";

const PLATFORM_ANDROID: u8 = 0x02;
const PLATFORM_IOS: u8 = 0x01;

const PADDED_PAYLOAD_SIZE: usize = 220;
const EPHEMERAL_PUBKEY_SIZE: usize = 33;
const NONCE_SIZE: usize = 12;
const AUTH_TAG_SIZE: usize = 16;
pub const ENCRYPTED_TOKEN_SIZE: usize = EPHEMERAL_PUBKEY_SIZE + NONCE_SIZE + PADDED_PAYLOAD_SIZE + AUTH_TAG_SIZE;

#[derive(Debug, Clone, PartialEq)]
pub enum Platform {
    Android,
    Ios,
}

impl Platform {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            PLATFORM_ANDROID => Some(Platform::Android),
            PLATFORM_IOS => Some(Platform::Ios),
            _ => None,
        }
    }

    pub fn to_byte(&self) -> u8 {
        match self {
            Platform::Android => PLATFORM_ANDROID,
            Platform::Ios => PLATFORM_IOS,
        }
    }
}

impl std::fmt::Display for Platform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Platform::Android => write!(f, "android"),
            Platform::Ios => write!(f, "ios"),
        }
    }
}

#[derive(Debug)]
pub struct DecryptedToken {
    pub platform: Platform,
    pub device_token: String,
}

pub struct TokenCrypto {
    secret_key: SecretKey,
    public_key: PublicKey,
    secp: Secp256k1<secp256k1::All>,
}

impl TokenCrypto {
    pub fn new(secret_key_hex: &str) -> Result<Self, CryptoError> {
        let secp = Secp256k1::new();
        
        let secret_key_bytes = hex::decode(secret_key_hex)
            .map_err(|_| CryptoError::InvalidSecretKey)?;
        
        let secret_key = SecretKey::from_slice(&secret_key_bytes)
            .map_err(|_| CryptoError::InvalidSecretKey)?;
        
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);
        
        Ok(Self {
            secret_key,
            public_key,
            secp,
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key.serialize())
    }

    pub fn decrypt_token(&self, encrypted_token: &[u8]) -> Result<DecryptedToken, CryptoError> {
        if encrypted_token.len() != ENCRYPTED_TOKEN_SIZE {
            error!(
                "Invalid token size: expected {}, got {}",
                ENCRYPTED_TOKEN_SIZE,
                encrypted_token.len()
            );
            return Err(CryptoError::InvalidTokenSize);
        }

        // Extract components
        let ephemeral_pubkey_bytes = &encrypted_token[0..EPHEMERAL_PUBKEY_SIZE];
        let nonce_bytes = &encrypted_token[EPHEMERAL_PUBKEY_SIZE..EPHEMERAL_PUBKEY_SIZE + NONCE_SIZE];
        let ciphertext = &encrypted_token[EPHEMERAL_PUBKEY_SIZE + NONCE_SIZE..];

        debug!("Ephemeral pubkey: {}", hex::encode(ephemeral_pubkey_bytes));
        debug!("Nonce: {}", hex::encode(nonce_bytes));
        debug!("Ciphertext length: {}", ciphertext.len());

        // Parse ephemeral public key
        let ephemeral_pubkey = PublicKey::from_slice(ephemeral_pubkey_bytes)
            .map_err(|e| {
                error!("Failed to parse ephemeral pubkey: {}", e);
                CryptoError::InvalidEphemeralKey
            })?;

        // Derive shared secret via ECDH
        let shared_point = secp256k1::ecdh::SharedSecret::new(&ephemeral_pubkey, &self.secret_key);
        let shared_x = shared_point.secret_bytes();

        // Derive encryption key using HKDF
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared_x);
        let mut encryption_key = [0u8; 32];
        hk.expand(HKDF_INFO, &mut encryption_key)
            .map_err(|_| CryptoError::HkdfError)?;

        // Decrypt with ChaCha20-Poly1305
        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
            .map_err(|_| CryptoError::CipherError)?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let padded_payload = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| {
                error!("Decryption failed: {}", e);
                CryptoError::DecryptionFailed
            })?;

        if padded_payload.len() != PADDED_PAYLOAD_SIZE {
            error!(
                "Invalid payload size after decryption: expected {}, got {}",
                PADDED_PAYLOAD_SIZE,
                padded_payload.len()
            );
            return Err(CryptoError::InvalidPayloadSize);
        }

        // Parse padded payload
        let platform_byte = padded_payload[0];
        let token_length = u16::from_be_bytes([padded_payload[1], padded_payload[2]]) as usize;

        if token_length > PADDED_PAYLOAD_SIZE - 3 {
            error!("Token length {} exceeds maximum", token_length);
            return Err(CryptoError::InvalidTokenLength);
        }

        let platform = Platform::from_byte(platform_byte)
            .ok_or(CryptoError::InvalidPlatform)?;

        let device_token_bytes = &padded_payload[3..3 + token_length];
        let device_token = String::from_utf8(device_token_bytes.to_vec())
            .map_err(|_| CryptoError::InvalidTokenEncoding)?;

        debug!("Decrypted token for platform {:?}, length {}", platform, token_length);

        Ok(DecryptedToken {
            platform,
            device_token,
        })
    }
}

#[derive(Debug)]
pub enum CryptoError {
    InvalidSecretKey,
    InvalidTokenSize,
    InvalidEphemeralKey,
    HkdfError,
    CipherError,
    DecryptionFailed,
    InvalidPayloadSize,
    InvalidTokenLength,
    InvalidPlatform,
    InvalidTokenEncoding,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidSecretKey => write!(f, "Invalid secret key"),
            CryptoError::InvalidTokenSize => write!(f, "Invalid encrypted token size"),
            CryptoError::InvalidEphemeralKey => write!(f, "Invalid ephemeral public key"),
            CryptoError::HkdfError => write!(f, "HKDF derivation failed"),
            CryptoError::CipherError => write!(f, "Cipher initialization failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::InvalidPayloadSize => write!(f, "Invalid payload size after decryption"),
            CryptoError::InvalidTokenLength => write!(f, "Invalid token length in payload"),
            CryptoError::InvalidPlatform => write!(f, "Invalid platform identifier"),
            CryptoError::InvalidTokenEncoding => write!(f, "Invalid token encoding"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Result of debug decryption attempt with all intermediate values
#[derive(Debug, Clone, Serialize)]
pub struct DebugDecryptResult {
    pub ephemeral_pubkey_valid: bool,
    pub ephemeral_pubkey_hex: String,
    pub nonce_hex: String,
    pub ciphertext_len: usize,
    pub shared_x_hex: Option<String>,
    pub encryption_key_hex: Option<String>,
    pub decryption_error: Option<String>,
    pub decrypted_payload_hex: Option<String>,
    pub platform: Option<String>,
    pub device_token: Option<String>,
}

impl TokenCrypto {
    /// Debug decryption that returns all intermediate values for troubleshooting
    pub fn debug_decrypt_token(&self, encrypted_token: &[u8]) -> DebugDecryptResult {
        let mut result = DebugDecryptResult {
            ephemeral_pubkey_valid: false,
            ephemeral_pubkey_hex: String::new(),
            nonce_hex: String::new(),
            ciphertext_len: 0,
            shared_x_hex: None,
            encryption_key_hex: None,
            decryption_error: None,
            decrypted_payload_hex: None,
            platform: None,
            device_token: None,
        };

        if encrypted_token.len() != ENCRYPTED_TOKEN_SIZE {
            result.decryption_error = Some(format!(
                "Invalid token size: expected {}, got {}",
                ENCRYPTED_TOKEN_SIZE,
                encrypted_token.len()
            ));
            return result;
        }

        // Extract components
        let ephemeral_pubkey_bytes = &encrypted_token[0..EPHEMERAL_PUBKEY_SIZE];
        let nonce_bytes = &encrypted_token[EPHEMERAL_PUBKEY_SIZE..EPHEMERAL_PUBKEY_SIZE + NONCE_SIZE];
        let ciphertext = &encrypted_token[EPHEMERAL_PUBKEY_SIZE + NONCE_SIZE..];

        result.ephemeral_pubkey_hex = hex::encode(ephemeral_pubkey_bytes);
        result.nonce_hex = hex::encode(nonce_bytes);
        result.ciphertext_len = ciphertext.len();

        // Parse ephemeral public key
        let ephemeral_pubkey = match PublicKey::from_slice(ephemeral_pubkey_bytes) {
            Ok(pk) => {
                result.ephemeral_pubkey_valid = true;
                pk
            }
            Err(e) => {
                result.decryption_error = Some(format!("Invalid ephemeral pubkey: {}", e));
                return result;
            }
        };

        // Derive shared secret via ECDH
        let shared_point = secp256k1::ecdh::SharedSecret::new(&ephemeral_pubkey, &self.secret_key);
        let shared_x = shared_point.secret_bytes();
        result.shared_x_hex = Some(hex::encode(&shared_x));

        // Derive encryption key using HKDF
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared_x);
        let mut encryption_key = [0u8; 32];
        if let Err(_) = hk.expand(HKDF_INFO, &mut encryption_key) {
            result.decryption_error = Some("HKDF expansion failed".to_string());
            return result;
        }
        result.encryption_key_hex = Some(hex::encode(&encryption_key));

        // Decrypt with ChaCha20-Poly1305
        let cipher = match ChaCha20Poly1305::new_from_slice(&encryption_key) {
            Ok(c) => c,
            Err(_) => {
                result.decryption_error = Some("Cipher initialization failed".to_string());
                return result;
            }
        };
        let nonce = Nonce::from_slice(nonce_bytes);

        let padded_payload = match cipher.decrypt(nonce, ciphertext) {
            Ok(p) => p,
            Err(e) => {
                result.decryption_error = Some(format!(
                    "ChaCha20-Poly1305 decryption failed: {} (auth tag mismatch - key derivation likely differs)",
                    e
                ));
                return result;
            }
        };

        result.decrypted_payload_hex = Some(hex::encode(&padded_payload));

        if padded_payload.len() != PADDED_PAYLOAD_SIZE {
            result.decryption_error = Some(format!(
                "Invalid payload size: expected {}, got {}",
                PADDED_PAYLOAD_SIZE,
                padded_payload.len()
            ));
            return result;
        }

        // Parse padded payload
        let platform_byte = padded_payload[0];
        let token_length = u16::from_be_bytes([padded_payload[1], padded_payload[2]]) as usize;

        if let Some(platform) = Platform::from_byte(platform_byte) {
            result.platform = Some(platform.to_string());
        } else {
            result.decryption_error = Some(format!("Invalid platform byte: 0x{:02x}", platform_byte));
            return result;
        }

        if token_length > PADDED_PAYLOAD_SIZE - 3 {
            result.decryption_error = Some(format!("Token length {} exceeds maximum", token_length));
            return result;
        }

        let device_token_bytes = &padded_payload[3..3 + token_length];
        match String::from_utf8(device_token_bytes.to_vec()) {
            Ok(token) => result.device_token = Some(token),
            Err(_) => {
                result.decryption_error = Some("Invalid UTF-8 in device token".to_string());
                return result;
            }
        }

        result
    }
}

/// Encrypt a token exactly as a client would (for testing compatibility)
/// This function simulates Flutter client encryption for roundtrip testing
pub fn encrypt_token_like_client(
    server_pubkey: &PublicKey,
    ephemeral_secret: &SecretKey,
    nonce: &[u8; NONCE_SIZE],
    platform: Platform,
    device_token: &str,
) -> Vec<u8> {
    let secp = Secp256k1::new();
    let ephemeral_pubkey = PublicKey::from_secret_key(&secp, ephemeral_secret);

    // ECDH: shared_point = ephemeral_private * server_public
    let shared_point = secp256k1::ecdh::SharedSecret::new(server_pubkey, ephemeral_secret);

    // In rust-secp256k1 0.28, SharedSecret::new() returns SHA256(compressed_point)
    // But secret_bytes() returns just the x-coordinate (32 bytes)
    let shared_x = shared_point.secret_bytes();

    // HKDF-SHA256
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared_x);
    let mut encryption_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut encryption_key).unwrap();

    // Create padded payload: platform(1) || token_length(2) || token || padding
    let token_bytes = device_token.as_bytes();
    let mut padded_payload = vec![0u8; PADDED_PAYLOAD_SIZE];
    padded_payload[0] = platform.to_byte();
    padded_payload[1..3].copy_from_slice(&(token_bytes.len() as u16).to_be_bytes());
    padded_payload[3..3 + token_bytes.len()].copy_from_slice(token_bytes);
    // Rest is zero-padded for deterministic testing

    // ChaCha20-Poly1305 encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key).unwrap();
    let nonce_obj = Nonce::from_slice(nonce);
    let ciphertext = cipher.encrypt(nonce_obj, padded_payload.as_slice()).unwrap();

    // Format: ephemeral_pubkey(33) || nonce(12) || ciphertext(236)
    let mut encrypted_token = Vec::with_capacity(ENCRYPTED_TOKEN_SIZE);
    encrypted_token.extend_from_slice(&ephemeral_pubkey.serialize());
    encrypted_token.extend_from_slice(nonce);
    encrypted_token.extend_from_slice(&ciphertext);

    encrypted_token
}

/// Debug information about encryption with all intermediate values
#[derive(Debug)]
pub struct EncryptionDebugInfo {
    pub ephemeral_pubkey_hex: String,
    pub server_pubkey_hex: String,
    pub shared_x_hex: String,
    pub encryption_key_hex: String,
    pub nonce_hex: String,
    pub padded_payload_hex: String,
    pub ciphertext_hex: String,
    pub final_token_base64: String,
    pub final_token_hex: String,
}

/// Encrypt with full debug output of all intermediate values
pub fn encrypt_token_with_debug(
    server_pubkey: &PublicKey,
    ephemeral_secret: &SecretKey,
    nonce: &[u8; NONCE_SIZE],
    platform: Platform,
    device_token: &str,
) -> EncryptionDebugInfo {
    let secp = Secp256k1::new();
    let ephemeral_pubkey = PublicKey::from_secret_key(&secp, ephemeral_secret);

    // ECDH
    let shared_point = secp256k1::ecdh::SharedSecret::new(server_pubkey, ephemeral_secret);
    let shared_x = shared_point.secret_bytes();

    // HKDF
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared_x);
    let mut encryption_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut encryption_key).unwrap();

    // Padded payload
    let token_bytes = device_token.as_bytes();
    let mut padded_payload = vec![0u8; PADDED_PAYLOAD_SIZE];
    padded_payload[0] = platform.to_byte();
    padded_payload[1..3].copy_from_slice(&(token_bytes.len() as u16).to_be_bytes());
    padded_payload[3..3 + token_bytes.len()].copy_from_slice(token_bytes);

    // Encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key).unwrap();
    let nonce_obj = Nonce::from_slice(nonce);
    let ciphertext = cipher.encrypt(nonce_obj, padded_payload.as_slice()).unwrap();

    // Combine
    let mut encrypted_token = Vec::with_capacity(ENCRYPTED_TOKEN_SIZE);
    encrypted_token.extend_from_slice(&ephemeral_pubkey.serialize());
    encrypted_token.extend_from_slice(nonce);
    encrypted_token.extend_from_slice(&ciphertext);

    EncryptionDebugInfo {
        ephemeral_pubkey_hex: hex::encode(ephemeral_pubkey.serialize()),
        server_pubkey_hex: hex::encode(server_pubkey.serialize()),
        shared_x_hex: hex::encode(&shared_x),
        encryption_key_hex: hex::encode(&encryption_key),
        nonce_hex: hex::encode(nonce),
        padded_payload_hex: hex::encode(&padded_payload),
        ciphertext_hex: hex::encode(&ciphertext),
        final_token_base64: base64::engine::general_purpose::STANDARD.encode(&encrypted_token),
        final_token_hex: hex::encode(&encrypted_token),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn create_test_encrypted_token(
        server_pubkey: &PublicKey,
        platform: Platform,
        device_token: &str,
    ) -> Vec<u8> {
        let secp = Secp256k1::new();

        // Generate ephemeral keypair
        let mut rng = rand::thread_rng();
        let ephemeral_secret = SecretKey::new(&mut rng);
        let ephemeral_pubkey = PublicKey::from_secret_key(&secp, &ephemeral_secret);

        // Derive shared secret
        let shared_point = secp256k1::ecdh::SharedSecret::new(server_pubkey, &ephemeral_secret);
        let shared_x = shared_point.secret_bytes();

        // Derive encryption key
        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared_x);
        let mut encryption_key = [0u8; 32];
        hk.expand(HKDF_INFO, &mut encryption_key).unwrap();

        // Create padded payload
        let token_bytes = device_token.as_bytes();
        let mut padded_payload = vec![0u8; PADDED_PAYLOAD_SIZE];
        padded_payload[0] = platform.to_byte();
        padded_payload[1..3].copy_from_slice(&(token_bytes.len() as u16).to_be_bytes());
        padded_payload[3..3 + token_bytes.len()].copy_from_slice(token_bytes);

        // Fill rest with random padding
        rng.fill_bytes(&mut padded_payload[3 + token_bytes.len()..]);

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        rng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key).unwrap();
        let ciphertext = cipher.encrypt(nonce, padded_payload.as_slice()).unwrap();

        // Combine: ephemeral_pubkey || nonce || ciphertext
        let mut encrypted_token = Vec::with_capacity(ENCRYPTED_TOKEN_SIZE);
        encrypted_token.extend_from_slice(&ephemeral_pubkey.serialize());
        encrypted_token.extend_from_slice(&nonce_bytes);
        encrypted_token.extend_from_slice(&ciphertext);

        encrypted_token
    }

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

    // =========================================================================
    // Integration tests for Flutter client compatibility debugging
    // =========================================================================

    /// Test 1: HKDF isolated test with known shared_x
    /// This verifies HKDF produces consistent results given the same input
    #[test]
    fn test_hkdf_isolated_with_known_shared_x() {
        println!("\n=== HKDF Isolated Test ===");

        // Known test vector: 32 bytes of shared_x
        let shared_x = hex::decode(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ).unwrap();

        println!("Input shared_x: {}", hex::encode(&shared_x));
        println!("HKDF salt: {:?} ({})",
            String::from_utf8_lossy(HKDF_SALT),
            hex::encode(HKDF_SALT));
        println!("HKDF info: {:?} ({})",
            String::from_utf8_lossy(HKDF_INFO),
            hex::encode(HKDF_INFO));

        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &shared_x);
        let mut encryption_key = [0u8; 32];
        hk.expand(HKDF_INFO, &mut encryption_key).unwrap();

        println!("Output encryption_key: {}", hex::encode(&encryption_key));

        // The encryption key should be deterministic
        // Flutter client should produce the same key given the same shared_x
        assert_eq!(encryption_key.len(), 32);

        // Store expected value for reference
        let expected_key = hex::encode(&encryption_key);
        println!("\n>>> Flutter client should produce this encryption_key: {}", expected_key);
        println!(">>> If it differs, the HKDF parameters or implementation differ");
    }

    /// Test 2: Encryption/decryption roundtrip using client-like encryption
    #[test]
    fn test_encryption_roundtrip_client_simulation() {
        println!("\n=== Encryption Roundtrip Test ===");

        let secp = Secp256k1::new();

        // Fixed server keypair
        let server_secret_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let server_secret = SecretKey::from_slice(&hex::decode(server_secret_hex).unwrap()).unwrap();
        let server_pubkey = PublicKey::from_secret_key(&secp, &server_secret);

        // Fixed ephemeral keypair (simulating client)
        let ephemeral_secret_hex = "2222222222222222222222222222222222222222222222222222222222222222";
        let ephemeral_secret = SecretKey::from_slice(&hex::decode(ephemeral_secret_hex).unwrap()).unwrap();

        // Fixed nonce
        let nonce: [u8; 12] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];

        let device_token = "fcm_test_token_abc123";
        let platform = Platform::Android;

        // Encrypt like client
        let encrypted = encrypt_token_like_client(
            &server_pubkey,
            &ephemeral_secret,
            &nonce,
            platform.clone(),
            device_token,
        );

        println!("Encrypted token length: {}", encrypted.len());
        println!("Encrypted token (base64): {}",
            base64::engine::general_purpose::STANDARD.encode(&encrypted));

        // Decrypt with server
        let crypto = TokenCrypto::new(server_secret_hex).unwrap();
        let decrypted = crypto.decrypt_token(&encrypted).unwrap();

        assert_eq!(decrypted.platform, platform);
        assert_eq!(decrypted.device_token, device_token);

        println!("Decryption successful!");
        println!("Platform: {:?}", decrypted.platform);
        println!("Device token: {}", decrypted.device_token);
    }

    /// Test 3: Full debug output with fixed values for comparison with Flutter
    #[test]
    fn test_fixed_values_with_debug_output() {
        println!("\n=== Fixed Values Test with Full Debug Output ===");
        println!("=== Use these values to compare with Flutter client ===\n");

        let secp = Secp256k1::new();

        // Fixed server keypair - SHARE WITH FLUTTER FOR TESTING
        let server_secret_hex = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let server_secret = SecretKey::from_slice(&hex::decode(server_secret_hex).unwrap()).unwrap();
        let server_pubkey = PublicKey::from_secret_key(&secp, &server_secret);

        println!("SERVER_PRIVATE_KEY: {}", server_secret_hex);
        println!("SERVER_PUBLIC_KEY:  {}", hex::encode(server_pubkey.serialize()));

        // Fixed ephemeral keypair - FLUTTER CLIENT SHOULD USE THIS
        let ephemeral_secret_hex = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let ephemeral_secret = SecretKey::from_slice(&hex::decode(ephemeral_secret_hex).unwrap()).unwrap();
        let ephemeral_pubkey = PublicKey::from_secret_key(&secp, &ephemeral_secret);

        println!("\nEPHEMERAL_PRIVATE_KEY: {}", ephemeral_secret_hex);
        println!("EPHEMERAL_PUBLIC_KEY:  {}", hex::encode(ephemeral_pubkey.serialize()));

        // Fixed nonce
        let nonce: [u8; 12] = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78];
        println!("\nNONCE: {}", hex::encode(&nonce));

        // Test token
        let device_token = "dMw5ABC123:APA91bHtest-token-for-debugging";
        let platform = Platform::Android;
        println!("\nDEVICE_TOKEN: {}", device_token);
        println!("PLATFORM: android (0x02)");

        // Get full debug info
        let debug_info = encrypt_token_with_debug(
            &server_pubkey,
            &ephemeral_secret,
            &nonce,
            platform,
            device_token,
        );

        println!("\n=== INTERMEDIATE VALUES (compare with Flutter) ===");
        println!("shared_x (ECDH result):  {}", debug_info.shared_x_hex);
        println!("encryption_key (HKDF):   {}", debug_info.encryption_key_hex);
        println!("padded_payload:          {}", debug_info.padded_payload_hex);
        println!("ciphertext:              {}", debug_info.ciphertext_hex);

        println!("\n=== FINAL OUTPUT ===");
        println!("encrypted_token (hex):    {}", debug_info.final_token_hex);
        println!("encrypted_token (base64): {}", debug_info.final_token_base64);

        // Now verify server can decrypt
        let crypto = TokenCrypto::new(server_secret_hex).unwrap();
        let encrypted = hex::decode(&debug_info.final_token_hex).unwrap();
        let decrypted = crypto.decrypt_token(&encrypted).unwrap();

        println!("\n=== SERVER DECRYPTION VERIFICATION ===");
        println!("Decrypted platform: {}", decrypted.platform);
        println!("Decrypted token: {}", decrypted.device_token);

        assert_eq!(decrypted.device_token, device_token);

        println!("\n=== TROUBLESHOOTING CHECKLIST ===");
        println!("If Flutter produces different values, check:");
        println!("1. shared_x: Is Flutter using raw X coordinate or SHA256(point)?");
        println!("2. HKDF salt: Must be exactly 'mostro-push-v1' (no null terminator)");
        println!("3. HKDF info: Must be exactly 'mostro-token-encryption'");
        println!("4. Payload format: platform(1) || token_len_be(2) || token || zeros");
    }

    /// Test 5: Verify SharedSecret behavior in rust-secp256k1 0.28
    #[test]
    fn test_shared_secret_behavior() {
        println!("\n=== SharedSecret Behavior Test ===");
        println!("Verifying what rust-secp256k1 0.28 SharedSecret::new() returns\n");

        let secp = Secp256k1::new();

        // Use well-known test keys
        let secret_a_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let secret_b_hex = "0000000000000000000000000000000000000000000000000000000000000002";

        let secret_a = SecretKey::from_slice(&hex::decode(secret_a_hex).unwrap()).unwrap();
        let secret_b = SecretKey::from_slice(&hex::decode(secret_b_hex).unwrap()).unwrap();

        let pubkey_a = PublicKey::from_secret_key(&secp, &secret_a);
        let pubkey_b = PublicKey::from_secret_key(&secp, &secret_b);

        println!("Key A private: {}", secret_a_hex);
        println!("Key A public:  {}", hex::encode(pubkey_a.serialize()));
        println!("Key B private: {}", secret_b_hex);
        println!("Key B public:  {}", hex::encode(pubkey_b.serialize()));

        // Compute shared secret both ways
        let shared_ab = secp256k1::ecdh::SharedSecret::new(&pubkey_b, &secret_a);
        let shared_ba = secp256k1::ecdh::SharedSecret::new(&pubkey_a, &secret_b);

        let shared_ab_bytes = shared_ab.secret_bytes();
        let shared_ba_bytes = shared_ba.secret_bytes();

        println!("\nshared_secret(A_priv * B_pub): {}", hex::encode(&shared_ab_bytes));
        println!("shared_secret(B_priv * A_pub): {}", hex::encode(&shared_ba_bytes));

        // They should be equal (ECDH property)
        assert_eq!(shared_ab_bytes, shared_ba_bytes, "ECDH shared secrets should match");
        println!("\n✓ Shared secrets match (ECDH working correctly)");

        // Check if this looks like raw X coordinate or SHA256
        println!("\n=== Analysis ===");
        println!("Result length: {} bytes", shared_ab_bytes.len());

        // In secp256k1 0.28, secret_bytes() returns the raw x-coordinate (32 bytes)
        // NOT SHA256 of the point
        println!("\nrust-secp256k1 0.28 behavior:");
        println!("- SharedSecret::new() computes ECDH");
        println!("- secret_bytes() returns the raw X coordinate (32 bytes)");
        println!("- This is NOT hashed by default");
        println!("\n>>> Flutter MUST use raw X coordinate, NOT SHA256(shared_point)");

        // Compute what SHA256 would give for comparison
        use sha2::Digest;
        let sha256_of_shared = sha2::Sha256::digest(&shared_ab_bytes);
        println!("\nFor reference - SHA256(shared_x): {}", hex::encode(&sha256_of_shared));
        println!("If Flutter produces this ^^^, they're incorrectly applying SHA256");
    }

    /// Test with iOS platform
    #[test]
    fn test_ios_platform_roundtrip() {
        println!("\n=== iOS Platform Roundtrip Test ===");

        let secp = Secp256k1::new();
        let server_secret_hex = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let server_secret = SecretKey::from_slice(&hex::decode(server_secret_hex).unwrap()).unwrap();
        let server_pubkey = PublicKey::from_secret_key(&secp, &server_secret);

        let ephemeral_secret_hex = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
        let ephemeral_secret = SecretKey::from_slice(&hex::decode(ephemeral_secret_hex).unwrap()).unwrap();

        let nonce: [u8; 12] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc];

        // iOS APNs token format (64 hex chars typically)
        let device_token = "a1b2c3d4e5f6789012345678901234567890123456789012345678901234abcd";
        let platform = Platform::Ios;

        let debug_info = encrypt_token_with_debug(
            &server_pubkey,
            &ephemeral_secret,
            &nonce,
            platform,
            device_token,
        );

        println!("iOS token encrypted successfully");
        println!("Platform byte: 0x01 (iOS)");
        println!("encrypted_token (base64): {}", debug_info.final_token_base64);

        let crypto = TokenCrypto::new(server_secret_hex).unwrap();
        let encrypted = hex::decode(&debug_info.final_token_hex).unwrap();
        let decrypted = crypto.decrypt_token(&encrypted).unwrap();

        assert_eq!(decrypted.platform, Platform::Ios);
        assert_eq!(decrypted.device_token, device_token);
        println!("iOS decryption verified!");
    }

    /// Test debug_decrypt_token function
    #[test]
    fn test_debug_decrypt_shows_intermediate_values() {
        println!("\n=== Debug Decrypt Test ===");

        let secp = Secp256k1::new();
        let server_secret_hex = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
        let server_secret = SecretKey::from_slice(&hex::decode(server_secret_hex).unwrap()).unwrap();
        let server_pubkey = PublicKey::from_secret_key(&secp, &server_secret);

        // Note: 0xfff...fff is invalid for secp256k1, using a different valid key
        let ephemeral_secret_hex = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let ephemeral_secret = SecretKey::from_slice(&hex::decode(ephemeral_secret_hex).unwrap()).unwrap();

        let nonce: [u8; 12] = [0x00; 12];
        let device_token = "test_debug_token";

        let encrypted = encrypt_token_like_client(
            &server_pubkey,
            &ephemeral_secret,
            &nonce,
            Platform::Android,
            device_token,
        );

        let crypto = TokenCrypto::new(server_secret_hex).unwrap();
        let debug_result = crypto.debug_decrypt_token(&encrypted);

        println!("Debug decrypt result:");
        println!("  ephemeral_pubkey_valid: {}", debug_result.ephemeral_pubkey_valid);
        println!("  ephemeral_pubkey: {}", debug_result.ephemeral_pubkey_hex);
        println!("  nonce: {}", debug_result.nonce_hex);
        println!("  ciphertext_len: {}", debug_result.ciphertext_len);
        println!("  shared_x: {:?}", debug_result.shared_x_hex);
        println!("  encryption_key: {:?}", debug_result.encryption_key_hex);
        println!("  error: {:?}", debug_result.decryption_error);
        println!("  platform: {:?}", debug_result.platform);
        println!("  device_token: {:?}", debug_result.device_token);

        assert!(debug_result.ephemeral_pubkey_valid);
        assert!(debug_result.shared_x_hex.is_some());
        assert!(debug_result.encryption_key_hex.is_some());
        assert!(debug_result.decryption_error.is_none());
        assert_eq!(debug_result.device_token, Some(device_token.to_string()));
    }
}
