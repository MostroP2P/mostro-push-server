//! Encryption at rest for device tokens.
//!
//! The persisted token store keeps `trade_pubkey` in the clear (it is public on
//! the relays) and encrypts the device token, so a leaked database file does
//! not reveal which devices use Mostro nor which trades share a device.
//!
//! - Key: `TOKEN_STORE_KEY` (32 bytes, hex), expanded with HKDF-SHA256.
//! - Cipher: ChaCha20-Poly1305 with a random nonce per row, so the same token
//!   sealed twice yields unrelated ciphertexts.
//! - Associated data: the row's `trade_pubkey`, so a ciphertext copied onto
//!   another row fails to open.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;

pub const NONCE_LEN: usize = 12;
const SECRET_LEN: usize = 32;

const HKDF_SALT: &[u8] = b"mostro-push-token-store-v1";
const HKDF_INFO_ENCRYPTION: &[u8] = b"device-token-encryption";
const HKDF_INFO_FINGERPRINT: &[u8] = b"key-fingerprint";

#[derive(Debug, PartialEq, Eq)]
pub enum CipherError {
    /// The configured secret is not 32 bytes of hex.
    InvalidKey,
    /// The nonce read back from storage has the wrong length.
    InvalidNonce,
    Encrypt,
    /// Wrong key, tampered ciphertext or mismatched `trade_pubkey`.
    Decrypt,
}

impl std::fmt::Display for CipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CipherError::InvalidKey => write!(f, "token store key must be 32 bytes of hex"),
            CipherError::InvalidNonce => write!(f, "stored nonce has an invalid length"),
            CipherError::Encrypt => write!(f, "failed to encrypt device token"),
            CipherError::Decrypt => write!(f, "failed to decrypt device token"),
        }
    }
}

impl std::error::Error for CipherError {}

/// A device token as written to storage.
#[derive(Debug, Clone)]
pub struct SealedToken {
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

pub struct TokenCipher {
    cipher: ChaCha20Poly1305,
    fingerprint: [u8; 32],
}

impl TokenCipher {
    /// Builds the cipher from the hex-encoded `TOKEN_STORE_KEY`.
    pub fn from_hex(secret_hex: &str) -> Result<Self, CipherError> {
        let secret = hex::decode(secret_hex.trim()).map_err(|_| CipherError::InvalidKey)?;
        if secret.len() != SECRET_LEN {
            return Err(CipherError::InvalidKey);
        }

        let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &secret);
        let mut encryption_key = [0u8; 32];
        hk.expand(HKDF_INFO_ENCRYPTION, &mut encryption_key)
            .map_err(|_| CipherError::InvalidKey)?;
        let mut fingerprint = [0u8; 32];
        hk.expand(HKDF_INFO_FINGERPRINT, &mut fingerprint)
            .map_err(|_| CipherError::InvalidKey)?;

        let cipher = ChaCha20Poly1305::new_from_slice(&encryption_key)
            .map_err(|_| CipherError::InvalidKey)?;
        Ok(Self {
            cipher,
            fingerprint,
        })
    }

    /// Identifies the key without revealing it. Stored next to the rows so a
    /// changed key is detected at startup instead of failing row by row.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    pub fn seal(&self, trade_pubkey: &str, device_token: &str) -> Result<SealedToken, CipherError> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: device_token.as_bytes(),
                    aad: trade_pubkey.as_bytes(),
                },
            )
            .map_err(|_| CipherError::Encrypt)?;
        Ok(SealedToken { nonce, ciphertext })
    }

    pub fn open(
        &self,
        trade_pubkey: &str,
        nonce: &[u8],
        ciphertext: &[u8],
    ) -> Result<String, CipherError> {
        let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CipherError::InvalidNonce)?;
        let plaintext = self
            .cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: trade_pubkey.as_bytes(),
                },
            )
            .map_err(|_| CipherError::Decrypt)?;
        String::from_utf8(plaintext).map_err(|_| CipherError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const OTHER_KEY: &str = "0202020202020202020202020202020202020202020202020202020202020202";
    const PUBKEY: &str = "a1b2c3d4e5f67890123456789012345678901234567890123456789012345abc";
    const OTHER_PUBKEY: &str = "b1b2c3d4e5f67890123456789012345678901234567890123456789012345abc";
    const TOKEN: &str = "fcm-device-token:APA91bHexample";

    fn cipher(key: &str) -> TokenCipher {
        TokenCipher::from_hex(key).unwrap()
    }

    #[test]
    fn seal_then_open_round_trips() {
        let c = cipher(KEY);
        let sealed = c.seal(PUBKEY, TOKEN).unwrap();
        assert_eq!(
            c.open(PUBKEY, &sealed.nonce, &sealed.ciphertext).unwrap(),
            TOKEN
        );
    }

    #[test]
    fn ciphertext_does_not_contain_the_token() {
        let sealed = cipher(KEY).seal(PUBKEY, TOKEN).unwrap();
        let needle = TOKEN.as_bytes();
        assert!(!sealed.ciphertext.windows(needle.len()).any(|w| w == needle));
    }

    #[test]
    fn same_token_seals_to_different_ciphertexts() {
        // Rows of one device must not be groupable by comparing ciphertexts.
        let c = cipher(KEY);
        let a = c.seal(PUBKEY, TOKEN).unwrap();
        let b = c.seal(OTHER_PUBKEY, TOKEN).unwrap();
        let again = c.seal(PUBKEY, TOKEN).unwrap();
        assert_ne!(a.ciphertext, b.ciphertext);
        assert_ne!(a.ciphertext, again.ciphertext);
        assert_ne!(a.nonce, again.nonce);
    }

    #[test]
    fn another_key_cannot_open() {
        let sealed = cipher(KEY).seal(PUBKEY, TOKEN).unwrap();
        assert_eq!(
            cipher(OTHER_KEY).open(PUBKEY, &sealed.nonce, &sealed.ciphertext),
            Err(CipherError::Decrypt)
        );
    }

    #[test]
    fn ciphertext_is_bound_to_its_trade_pubkey() {
        let c = cipher(KEY);
        let sealed = c.seal(PUBKEY, TOKEN).unwrap();
        assert_eq!(
            c.open(OTHER_PUBKEY, &sealed.nonce, &sealed.ciphertext),
            Err(CipherError::Decrypt)
        );
    }

    #[test]
    fn tampered_ciphertext_fails_to_open() {
        let c = cipher(KEY);
        let mut sealed = c.seal(PUBKEY, TOKEN).unwrap();
        sealed.ciphertext[0] ^= 0x01;
        assert_eq!(
            c.open(PUBKEY, &sealed.nonce, &sealed.ciphertext),
            Err(CipherError::Decrypt)
        );
    }

    #[test]
    fn short_nonce_is_rejected() {
        let c = cipher(KEY);
        let sealed = c.seal(PUBKEY, TOKEN).unwrap();
        assert_eq!(
            c.open(PUBKEY, &sealed.nonce[..8], &sealed.ciphertext),
            Err(CipherError::InvalidNonce)
        );
    }

    #[test]
    fn key_must_be_32_bytes_of_hex() {
        assert!(TokenCipher::from_hex(KEY).is_ok());
        assert!(TokenCipher::from_hex(&format!("  {KEY}\n")).is_ok());
        assert_eq!(
            TokenCipher::from_hex("0101").err(),
            Some(CipherError::InvalidKey)
        );
        assert_eq!(
            TokenCipher::from_hex(&"zz".repeat(32)).err(),
            Some(CipherError::InvalidKey)
        );
    }

    #[test]
    fn fingerprint_identifies_the_key_without_revealing_it() {
        let a = cipher(KEY).fingerprint();
        assert_eq!(a, cipher(KEY).fingerprint());
        assert_ne!(a, cipher(OTHER_KEY).fingerprint());
        assert_ne!(hex::encode(a), KEY);
    }
}
