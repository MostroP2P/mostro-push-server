use std::collections::HashSet;

const TRUSTED_PUBKEYS_JSON: &str = include_str!("../config/trusted_mostro_pubkeys.json");

/// Load the trusted Mostro instance pubkeys embedded at compile time from
/// `config/trusted_mostro_pubkeys.json`.
///
/// An empty list disables the whitelist (permissive mode). A non-empty list
/// activates the filter on `/api/register`: clients must declare a
/// `mostro_pubkey` matching one of the entries.
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
    raw.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_json_parses_and_validates() {
        let set = load();
        assert!(
            !set.is_empty(),
            "embedded whitelist must not be empty in this build"
        );
        for pk in &set {
            assert_eq!(pk.len(), 64);
            assert!(hex::decode(pk).is_ok());
        }
    }

    #[test]
    fn default_main_instance_is_present() {
        let set = load();
        assert!(
            set.contains("82fa8cb978b43c79b2156585bac2c011176a21d2aead6d9f7c575c005be88390"),
            "default Mostro main-instance pubkey must be on the trusted list"
        );
    }
}
