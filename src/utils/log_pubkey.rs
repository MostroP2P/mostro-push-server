//! Salted, truncated pubkey hashing for privacy-safe operator logs.
//!
//! Per Phase 2 D-14 (PRIV-01): used ONLY in the /api/notify handler and its
//! spawned dispatch task. Existing pubkey-prefix logs in src/nostr/listener.rs,
//! src/api/routes.rs, and src/store/mod.rs are intentionally NOT migrated to
//! preserve operator grep-ability through the transition.
//!
//! The salt is generated once at process startup (random in-memory only,
//! never persisted, never logged). Comparing log lines across process
//! restarts is intentionally impossible — that is the privacy property,
//! not a bug.

/// Salted truncated BLAKE3 keyed-hash of a pubkey, for log correlation.
///
/// Returns the first 8 lowercase hex chars of `BLAKE3::keyed_hash(salt, pk)`.
/// 8 hex chars = 32 bits; collision-free for the registered pubkey set
/// (in-memory map, single process). Salt is 32 bytes, random per process.
pub fn log_pubkey(salt: &[u8; 32], pk: &str) -> String {
    let hash = blake3::keyed_hash(salt, pk.as_bytes());
    hash.to_hex()[..8].to_string()
}
