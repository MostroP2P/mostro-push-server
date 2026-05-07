// `batching` mirrors the gating used for `crypto` in `main.rs`: the module is
// reserved for the future dispatcher batching/cooldown work and is not yet
// invoked at runtime.
#[allow(dead_code)]
pub mod batching;
pub mod log_pubkey;
