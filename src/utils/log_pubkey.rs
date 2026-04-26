//! Salted, truncated pubkey hashing for privacy-safe operator logs.
//!
//! Per Phase 2 PRIV-01 / SC #5: used everywhere a `trade_pubkey` would
//! otherwise appear in operator logs (the /api/notify handler and its
//! spawned dispatch task, the registration/unregistration handlers, the
//! TokenStore lifecycle logs, and the Nostr listener event-recipient and
//! match logs). No module emits raw hex prefixes in production.
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
