# Codebase Concerns

**Analysis Date:** 2026-04-24
**Repository:** `/home/andrea/Documents/oss/mostrop2p/mostro-push-server`

## Tech Debt

**Phase 4 encryption stubbed but not wired:**
- Issue: Crypto module is fully implemented (ECDH/HKDF/ChaCha20-Poly1305) and tested, but the API still accepts plaintext device tokens. The module is gated behind `#[allow(dead_code)]`.
- Files: `src/crypto/mod.rs`, `src/api/routes.rs:78-137`, `src/main.rs:14-15`
- Impact: Server operator can read device tokens in cleartext and correlate them with `trade_pubkey`, violating MIP-05 privacy goals. `/api/info` returns `"encryption_enabled": false`.
- Fix: Add `encrypted_token` field to `RegisterTokenRequest`, instantiate `TokenCrypto` in `main.rs` from `config.crypto.server_private_key`, decrypt before storing, expose `server_pubkey` via `/api/info`.

**Hardcoded `subscription_id` and `event_kinds` ignored:**
- Issue: `NostrConfig` defines `subscription_id` (`"mostro-push-listener"`) and `event_kinds` (`vec![1059]`) but the listener never reads them. Filter is built with hardcoded `Kind::Custom(1059)`.
- Files: `src/config.rs:14-20,67-72`, `src/nostr/listener.rs:73-83`
- Impact: Configuration appears flexible but is not.
- Fix: Read `self.config.nostr.event_kinds` when building the filter, or remove the unused fields.

**Mostro author filter not actually applied:**
- Issue: Comment in `src/nostr/listener.rs:74-75` claims author filtering is intentionally skipped because Gift Wrap uses ephemeral keys. The `mostro_pubkey` is validated at startup but never used to filter events. Any kind 1059 event addressed to a registered `trade_pubkey` triggers a push regardless of sender.
- Files: `src/nostr/listener.rs:25-39,73-141`, `src/config.rs:60-72`
- Impact: An attacker who learns a registered `trade_pubkey` can send arbitrary Gift Wrap events to that pubkey, causing spurious push notifications (DoS / spam vector). Contradicts commit `1f848fb` ("filter Nostr events by Mostro instance public key").
- Fix: Decrypt the rumor inside the Gift Wrap to verify the inner sender, or document that this filter is impossible from the server side and remove the misleading config field.

**Duplicated `MOSTRO_PUBKEY` lookup with conflicting defaults:**
- Issue: `src/config.rs:60-64` reads `MOSTRO_PUBKEY` into a local with default `82fa8cb9...`; the struct is then built using a second `env::var("MOSTRO_PUBKEY")` call at line 71 with a different default `dbe0b1be7a...`. The first variable is unused.
- Files: `src/config.rs:60-72`, `.env.example:3,7`
- Impact: Dead code; defaults are inconsistent. `.env.example` lists both pubkeys with conflicting values.
- Fix: Remove the orphan local, unify defaults, document which is canonical.

**Duplicated `Platform` enum:**
- Issue: `Platform` is defined twice with different byte representations.
- Files: `src/store/mod.rs:8-21` (no byte mapping), `src/crypto/mod.rs:24-54` (with `to_byte`/`from_byte`)
- Impact: Risk of drift if a third platform is added; Phase 4 will require explicit conversion between the two.
- Fix: Consolidate into a single `Platform` (likely in `store/`) with byte methods; have `crypto` import it.

**Unused `BatchingManager`:**
- Issue: `src/utils/batching.rs` defines `BatchingManager::should_send` but nothing instantiates it. `BATCH_DELAY_MS` and `COOLDOWN_MS` are parsed but never consumed.
- Files: `src/utils/batching.rs`, `src/config.rs:81-86`
- Impact: Phase 2 "intelligent batching" claimed in `docs/IMPLEMENTATION_PHASES.md:60-65` is not implemented. Each event triggers an immediate push.
- Fix: Wire `BatchingManager` into the listener or delete it and remove the related config and doc claims.

**Unused rate-limit configuration:**
- Issue: `RateLimitConfig::max_per_minute` is parsed and `governor` is in `Cargo.toml`, but no rate limiting is applied to the HTTP API or Nostr ingestion.
- Files: `src/config.rs:36-39,95-98`, `Cargo.toml:41`, `src/api/routes.rs`
- Impact: `/api/register` and `/api/unregister` accept unbounded request rates. An attacker can flood the in-memory `TokenStore`.
- Fix: Add `actix-governor` middleware on the API scope keyed by IP, or remove the unused config and dependency.

**`send_silent_push` trait method never invoked:**
- Issue: `PushService::send_silent_push` is defined and implemented for both backends, but never called from production code.
- Files: `src/push/mod.rs:14`, `src/push/fcm.rs:220-266`, `src/push/unifiedpush.rs:127-163`
- Impact: ~80 lines of dead code; confuses readers about which pathway is active.
- Fix: Either wire it into the listener or remove it from the trait.

**UnifiedPush register/unregister API not exposed:**
- Issue: `UnifiedPushService::register_endpoint`/`unregister_endpoint` exist and persist to disk but `/api/register` does not call them. `test_server.sh` line 24 sends a `device_id`/`endpoint_url` payload that the current handler does not accept.
- Files: `src/push/unifiedpush.rs:85-122`, `src/api/routes.rs:41-50`, `test_server.sh`
- Impact: UnifiedPush endpoints persisted in `data/unifiedpush_endpoints.json` cannot be created via the API. Persistence path is dead. `test_server.sh` will fail at step 3.
- Fix: Add a UnifiedPush-specific endpoint, or unify registration so a UnifiedPush URL `device_token` is recognized and persisted.

**`Box<dyn std::error::Error>` everywhere:**
- Issue: All fallible APIs return `Box<dyn std::error::Error>`. Some are not `Send + Sync`, forcing manual `e.to_string().into()` conversions that discard error chains.
- Files: `src/push/mod.rs:14-23`, `src/push/fcm.rs:222,274`, `src/config.rs:53`
- Impact: Loses type information; cannot pattern-match on variants.
- Fix: Introduce `thiserror`-based enums per module or at minimum require `Send + Sync` consistently.

## Known Bugs

**Slice indexing inconsistency in `register_token`:**
- Symptoms: `src/api/routes.rs:128-130` indexes `&req.trade_pubkey[..16]` after the 64-char validation, but elsewhere defensive `[..16.min(...)]` slicing is used.
- Files: `src/api/routes.rs:82-83,128-130,143-144`
- Trigger: Currently safe, but a future refactor reordering the length guard would panic on inputs shorter than 16 chars.
- Fix: Use `16.min(len)` consistently at line 129.

**`load_endpoints` swallows errors asymmetrically:**
- Issue: `src/push/unifiedpush.rs:53-69` returns `Ok(())` on read errors (line 65-68) but propagates `?` on parse errors (line 57). Corrupt JSON aborts startup; missing-permissions read errors are silently tolerated.
- Files: `src/push/unifiedpush.rs:53-69`
- Trigger: Manually corrupt `data/unifiedpush_endpoints.json`.
- Fix: Treat both error types symmetrically.

**`save_endpoints` may leak temp files:**
- Issue: `src/push/unifiedpush.rs:73-83` writes `*.tmp` then renames; the temp file is never cleaned up if the rename fails.
- Impact: Stale `data/unifiedpush_endpoints.tmp` may accumulate.
- Fix: Cleanup on failure or use the `tempfile` crate.

## Security Considerations

**CRITICAL - Hard-coded production private key in version control:**
- Risk: `deploy-fly.sh:30` contains `SERVER_PRIVATE_KEY="2dfb72f7e130b4c6f971c5bac364b9f854f2409de51fb53d4dbd3e17bd69b98e"` as a literal value. Committed in `7fc3fa2`. This is the secp256k1 key intended for token decryption in Phase 4.
- Current mitigation: None. The key is in public git history.
- Recommendations:
  1. Treat the key as compromised and rotate before Phase 4.
  2. Move secret provisioning out of the script - read from an untracked `.fly-secrets.env` or use `flyctl secrets import`.
  3. Force-rewrite git history to purge it (or accept compromise and never reuse).
  4. Add a pre-commit `gitleaks` scan.

**Firebase service account JSON in repo tree:**
- Risk: `secrets/mostro-mobile-firebase-adminsdk-fbsvc-1ff8f6232c.json` exists in the working tree and is referenced by `Dockerfile:11` (`COPY secrets/ /secrets/`).
- Current mitigation: `.gitignore:31` lists `secrets/` and `*.json`, but the file may have been added before that rule.
- Recommendations: Verify with `git log --all -- secrets/` whether ever committed. If so, rotate the service account key. Mount the JSON via `fly secrets` or runtime volume rather than baking into the image.

**Insecure default `SERVER_PRIVATE_KEY`:**
- Risk: `src/config.rs:103-104` defaults to `0000...0001` (smallest valid secp256k1 secret). If `SERVER_PRIVATE_KEY` is unset, the server runs with a publicly known key.
- Current mitigation: Production sets the value via deploy script.
- Recommendations: Make `SERVER_PRIVATE_KEY` mandatory once Phase 4 lands; refuse to start with a default.

**No authentication on `/api/register` / `/api/unregister`:**
- Risk: Any caller can register an FCM token under an arbitrary `trade_pubkey`. An attacker who knows a victim's `trade_pubkey` can overwrite their token (DoS) or harvest notification timing metadata.
- Files: `src/api/routes.rs:78-168`
- Current mitigation: None.
- Recommendations: Require Schnorr-signed registration (signature over the request body with the secret key for `trade_pubkey`), or NIP-98-style request auth.

**Trade pubkey logged at INFO level:**
- Risk: `src/nostr/listener.rs:108` logs the first 16 hex chars of `trade_pubkey` per event. The full pubkey is recoverable via the `'p'` tag in associated logs.
- Files: `src/nostr/listener.rs:108,112-116,137`, `src/store/mod.rs:58-62`, `src/api/routes.rs`
- Recommendations: Log a hash (e.g., 8-byte BLAKE3) instead of the prefix. Drop the listener's full-pubkey INFO log to DEBUG level.

**Deploy script enables `RUST_LOG=debug` in production:**
- Risk: `deploy-fly.sh:45` sets `RUST_LOG="debug"`. With debug logging, `src/crypto/mod.rs:106-108,164` would log raw ephemeral pubkeys, nonces, and decrypted-token metadata; `src/push/unifiedpush.rs:176` and `src/push/fcm.rs:283` log device-token prefixes.
- Recommendations: Set `RUST_LOG="info"` in production.

**No TLS at application layer:**
- Risk: `src/main.rs:107-114` binds plain HTTP. Production relies on Fly's `force_https` (`fly.toml:14`); Docker Compose deployments have no TLS.
- Recommendations: Document required reverse-proxy TLS for non-Fly deployments.

## Performance Bottlenecks

**Single-task event loop blocks on each push:**
- Problem: `src/nostr/listener.rs:90-146` processes events sequentially. A slow FCM call blocks subsequent events.
- Cause: `service.send_to_token().await` is inline; `push_services.lock().await` serializes across events.
- Improvement: Spawn `tokio::task` per event or use an `mpsc::channel` worker pool. Configure explicit `reqwest` timeouts.

**`reqwest::Client::new()` per service:**
- Problem: Each service constructs its own `Client` with no shared pool.
- Files: `src/push/fcm.rs:78`, `src/push/unifiedpush.rs:34`
- Improvement: Build one client in `main.rs` with explicit `connect_timeout`, `timeout`, and `pool_idle_timeout`.

**`Mutex<Vec<Box<dyn PushService>>>` serializes all delivery:**
- Problem: `src/main.rs:79`, `src/nostr/listener.rs:119-135` lock the entire vector while iterating.
- Cause: Mutable mutex used for what is effectively read-only data after init.
- Improvement: Use `Arc<[Arc<dyn PushService>]>` (immutable after init).

**FCM access-token cache double-check race:**
- Problem: `src/push/fcm.rs:95-158` reads under `RwLock`, drops the lock, then re-acquires write lock. Concurrent expirations may both perform the JWT exchange.
- Impact: Minor - extra OAuth2 calls under contention.
- Improvement: Hold the write lock through the JWT exchange or use `OnceCell` per epoch.

## Fragile Areas

**Nostr reconnect loop double-sleeps:**
- Files: `src/nostr/listener.rs:42-55`
- Why fragile: Error path sleeps 10s (line 50) then again 5s (line 53), making real reconnect 15s; the log message claims 10s.
- Safe modification: Move the trailing `sleep` into the `Ok` arm only.
- Test coverage: None.

**Crypto unit tests print but rarely assert intermediates:**
- Files: `src/crypto/mod.rs:453-823`
- Why fragile: Heavy `println!` output (lines 532-735) is debugging documentation rather than assertions; only round-trip is checked. A change in `secp256k1`/`hkdf`/`chacha20poly1305` semantics could go undetected.
- Safe modification: Convert print-only tests into `assert_eq!` against frozen vectors.
- Test coverage: 8 `#[test]` functions in the crate, all in `crypto/`.

**`docker-compose.yml` references missing file:**
- Files: `docker-compose.yml:14`, `Dockerfile:11`
- Why fragile: Compose mounts `./firebase-service-account.json` at project root, but the actual file is `secrets/mostro-mobile-firebase-adminsdk-fbsvc-1ff8f6232c.json`. Compose builds will fail.
- Safe modification: Update Compose `volumes` and align with `FIREBASE_SERVICE_ACCOUNT_PATH`.

**Subscription `since` filter loses events on long disconnects:**
- Files: `src/nostr/listener.rs:76-79`
- Why fragile: `since = now - 60s` means events older than 60s are dropped on each reconnect. A >60s disconnect loses all events delivered during downtime.
- Safe modification: Persist last-seen timestamp to disk and restore on reconnect, or document the loss explicitly.

## Scaling Limits

**In-memory `TokenStore`:**
- Files: `src/store/mod.rs:30-138`
- Capacity: Bounded by the 512 MB Fly VM (`fly.toml:36`). RwLock contention dominates well before the memory ceiling.
- Limit: All FCM token state is lost on every restart (UnifiedPush has JSON persistence; FCM does not).
- Scaling path: Move to Redis or SQLite. Document graceful-restart token-loss behavior.

**Single Fly machine, no horizontal scaling:**
- Files: `fly.toml:18-22`
- Capacity: `min_machines_running = 1`, `auto_stop_machines = 'off'`. One machine serves all traffic.
- Limit: All token state is local; horizontal scaling would create inconsistency.
- Scaling path: Externalize state, then enable auto-scaling.

**Hard connection limit of 25:**
- Files: `fly.toml:31-33`
- Limit: Beyond 25 simultaneous connections, Fly rejects.
- Scaling path: Increase once async push/batching is implemented.

## Dependencies at Risk

**`nostr-sdk = "0.27"` (Cargo.toml:23):**
- Risk: Released early 2024; current upstream is several major versions ahead with breaking API changes (`Filter`, `Client::handle_notifications`, `XOnlyPublicKey`, `Kind::Custom`, `RelayPoolNotification`).
- Impact: Security/bug fixes upstream are not available without a focused rewrite of `src/nostr/listener.rs`.
- Migration plan: Pin a current LTS-ish release and budget a migration phase.

**`reqwest = "0.11"` (Cargo.toml:20):**
- Risk: 0.11 is on maintenance; 0.12 is current. Default features pull `native-tls`, coupling to system libssl.
- Migration plan: Bump to 0.12 with `rustls-tls`.

**`actix-web = "4.4"` and `tokio-tungstenite = "0.21"`:**
- Risk: Both lag minor releases.
- Migration plan: Bump as part of dependency hygiene.

## Missing Critical Features

**No persistence for FCM tokens:**
- Problem: `TokenStore` is in-memory only. Restarts drop all FCM/APNs registrations until clients re-register.
- Blocks: Zero-downtime deployments, multi-instance scaling.

**No graceful shutdown:**
- Problem: `src/main.rs` does not handle `SIGTERM`. The Nostr listener task is not cancelled cleanly.
- Blocks: Clean Fly rolling deploys, in-flight push completion.

**No metrics endpoint:**
- Problem: `/api/status` (`src/api/routes.rs:56-66`) reports token counts only; no counters for push successes/failures, Nostr events processed, decryption errors.
- Blocks: Observability, alerting, SLO tracking.

**No request signing on registration API:**
- Problem: As noted under Security; no NIP-98/NIP-42-style auth.
- Blocks: MIP-05 trust model, anti-abuse.

**iOS/APNs delivery untested:**
- Problem: `Platform::Ios` is recognized but FCM is the only backend. APNs-specific config is bundled into the FCM payload (`src/push/fcm.rs:196-211`), no APNs-direct path exists.
- Blocks: iOS delivery for operators that do not use FCM.

## Test Coverage Gaps

**Zero integration tests:**
- What's not tested: HTTP handlers (`src/api/routes.rs`), Nostr event flow (`src/nostr/listener.rs`), FCM OAuth (`src/push/fcm.rs`), UnifiedPush HTTP delivery (`src/push/unifiedpush.rs`), `TokenStore` TTL (`src/store/mod.rs`).
- Risk: All non-`crypto` modules have zero tests. `test_server.sh` exercises endpoints but is not in CI and references endpoints that no longer exist.
- Priority: High.

**No tests for `BatchingManager`:**
- File: `src/utils/batching.rs:1-35`.
- Priority: Low (currently dead code).

**No tests for `TokenStore` TTL cleanup:**
- File: `src/store/mod.rs:90-106`.
- Risk: Off-by-one in TTL math goes undetected.
- Priority: Medium.

**Crypto tests print but do not assert intermediate values:**
- File: `src/crypto/mod.rs:530-823`.
- Risk: Cross-platform compatibility regression with the Flutter client goes undetected.
- Priority: Medium.

**No CI configuration:**
- Files: No `.github/workflows/`, no `.gitlab-ci.yml` in the repository root.
- Risk: Tests, formatting, lints depend on developer discipline.
- Priority: High.

---

*Concerns analysis: 2026-04-24*
