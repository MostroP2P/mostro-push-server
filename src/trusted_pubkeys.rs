use std::collections::HashSet;

const TRUSTED_PUBKEYS_JSON: &str = include_str!("../config/trusted_mostro_pubkeys.json");

/// Load the trusted Mostro node pubkeys embedded at compile time from
/// `config/trusted_mostro_pubkeys.json`.
///
/// The Nostr listener only pushes for events these nodes author and refuses
/// to start without any. With `TRUSTED_WHITELIST_ENABLED`, `/api/register`
/// also requires a declared `mostro_pubkey` matching one of the entries.
///
/// Panics at startup if the JSON is malformed or any entry is not 64 hex
/// characters. Failing fast at boot is preferable to silently shipping a
/// degraded whitelist.
pub fn load() -> HashSet<String> {
    let raw: Vec<String> = serde_json::from_str(TRUSTED_PUBKEYS_JSON)
        .expect("config/trusted_mostro_pubkeys.json must be a valid JSON array of strings");
    for pk in &raw {
        assert!(
            pk.len() == 64 && hex::decode(pk).is_ok(),
            "invalid trusted Mostro pubkey (expected 64 hex chars): {}",
            pk
        );
    }
    // Normalize to lowercase so the byte-exact `HashSet::contains` lookup in
    // `register_token` matches both `"82FA..."` and `"82fa..."` once the
    // handler also lowercases the incoming `mostro_pubkey`. `hex::decode`
    // already accepts mixed case at both boundaries, so without this
    // normalization a syntactically valid uppercase key would pass the 400
    // gate and falsely hit 403.
    raw.into_iter().map(|pk| pk.to_ascii_lowercase()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `load()` must succeed and yield only valid 64-hex entries. Emptiness is
    /// checked where it matters, when the listener is built.
    #[test]
    fn embedded_json_parses_with_valid_entries() {
        let set = load();
        for pk in &set {
            assert_eq!(pk.len(), 64);
            assert!(hex::decode(pk).is_ok());
            assert!(
                pk.chars().all(|c| !c.is_ascii_uppercase()),
                "load() must canonicalize entries to lowercase: {}",
                pk
            );
        }
    }
}
