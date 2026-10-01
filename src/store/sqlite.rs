//! SQLite persistence for the token store.
//!
//! Registrations are read from memory; this file only makes them survive a
//! restart. Each row keeps `trade_pubkey` in the clear and the device token
//! sealed by [`TokenCipher`]. `secure_delete` zeroes deleted rows and every
//! cleanup truncates the WAL, so expired and unregistered entries do not
//! linger in the file.

use chrono::{DateTime, TimeZone, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::cipher::{CipherError, TokenCipher};
use super::{Platform, RegisteredToken};

const SCHEMA_VERSION: i64 = 1;
const FINGERPRINT_KEY: &str = "key_fingerprint";

#[derive(Debug)]
pub enum PersistError {
    Sqlite(rusqlite::Error),
    Cipher(CipherError),
    /// The blocking task running the query panicked or was cancelled.
    Task(String),
    /// The file was written by a newer schema than this binary knows.
    UnsupportedSchema(i64),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PersistError::Sqlite(e) => write!(f, "sqlite error: {}", e),
            PersistError::Cipher(e) => write!(f, "{}", e),
            PersistError::Task(e) => write!(f, "token store task failed: {}", e),
            PersistError::UnsupportedSchema(v) => {
                write!(
                    f,
                    "token store schema version {} is newer than supported",
                    v
                )
            }
        }
    }
}

impl std::error::Error for PersistError {}

impl From<rusqlite::Error> for PersistError {
    fn from(e: rusqlite::Error) -> Self {
        PersistError::Sqlite(e)
    }
}

impl From<CipherError> for PersistError {
    fn from(e: CipherError) -> Self {
        PersistError::Cipher(e)
    }
}

/// What [`SqliteStore::load`] found and cleaned up at startup.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LoadReport {
    pub restored: usize,
    pub expired: usize,
    /// Rows that could not be decrypted or parsed and were deleted.
    pub discarded: usize,
    /// The key changed since the rows were written; they were all deleted.
    pub key_changed: bool,
}

pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
    cipher: Arc<TokenCipher>,
}

impl SqliteStore {
    pub fn open(path: &Path, cipher: TokenCipher) -> Result<Self, PersistError> {
        let conn = Connection::open(path)?;
        // journal_mode returns the resulting mode as a row.
        conn.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))?;
        conn.pragma_update(None, "secure_delete", "ON")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;

        let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(PersistError::UnsupportedSchema(version));
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                 key   TEXT PRIMARY KEY,
                 value BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tokens (
                 trade_pubkey  TEXT PRIMARY KEY,
                 platform      INTEGER NOT NULL,
                 registered_at INTEGER NOT NULL,
                 nonce         BLOB NOT NULL,
                 token_ct      BLOB NOT NULL
             );",
        )?;
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            cipher: Arc::new(cipher),
        })
    }

    /// Returns every registration newer than `cutoff`. Expired rows, rows that
    /// fail to decrypt and, when the key changed, all rows are deleted first.
    pub fn load(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<(Vec<(String, RegisteredToken)>, LoadReport), PersistError> {
        let mut conn = lock(&self.conn);
        let mut report = LoadReport::default();
        let mut entries = Vec::new();

        let tx = conn.transaction()?;

        let fingerprint = self.cipher.fingerprint();
        let stored: Option<Vec<u8>> = tx
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                [FINGERPRINT_KEY],
                |row| row.get(0),
            )
            .optional()?;
        if stored.is_some_and(|stored| stored != fingerprint) {
            // Rows sealed with another key can never be opened again.
            tx.execute("DELETE FROM tokens", [])?;
            report.key_changed = true;
        }
        tx.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![FINGERPRINT_KEY, fingerprint.as_slice()],
        )?;

        report.expired = tx.execute(
            "DELETE FROM tokens WHERE registered_at < ?1",
            [cutoff.timestamp()],
        )?;

        let mut unreadable = Vec::new();
        {
            let mut stmt = tx.prepare(
                "SELECT trade_pubkey, platform, registered_at, nonce, token_ct FROM tokens",
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            })?;
            for row in rows {
                let (trade_pubkey, platform, registered_at, nonce, token_ct) = row?;
                let token = self
                    .cipher
                    .open(&trade_pubkey, &nonce, &token_ct)
                    .ok()
                    .zip(platform_from_db(platform))
                    .zip(Utc.timestamp_opt(registered_at, 0).single());
                match token {
                    Some(((device_token, platform), registered_at)) => entries.push((
                        trade_pubkey,
                        RegisteredToken {
                            device_token,
                            platform,
                            registered_at,
                        },
                    )),
                    None => unreadable.push(trade_pubkey),
                }
            }
        }
        for trade_pubkey in &unreadable {
            tx.execute("DELETE FROM tokens WHERE trade_pubkey = ?1", [trade_pubkey])?;
        }
        report.discarded = unreadable.len();
        report.restored = entries.len();

        tx.commit()?;
        checkpoint(&conn)?;
        Ok((entries, report))
    }

    pub async fn upsert(
        &self,
        trade_pubkey: String,
        token: RegisteredToken,
    ) -> Result<(), PersistError> {
        let sealed = self.cipher.seal(&trade_pubkey, &token.device_token)?;
        self.run(move |conn| {
            conn.execute(
                "INSERT INTO tokens (trade_pubkey, platform, registered_at, nonce, token_ct)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(trade_pubkey) DO UPDATE SET
                     platform = excluded.platform,
                     registered_at = excluded.registered_at,
                     nonce = excluded.nonce,
                     token_ct = excluded.token_ct",
                params![
                    trade_pubkey,
                    platform_to_db(&token.platform),
                    token.registered_at.timestamp(),
                    sealed.nonce.as_slice(),
                    sealed.ciphertext,
                ],
            )
            .map(|_| ())
        })
        .await
    }

    pub async fn delete(&self, trade_pubkey: String) -> Result<(), PersistError> {
        self.run(move |conn| {
            conn.execute("DELETE FROM tokens WHERE trade_pubkey = ?1", [trade_pubkey])
                .map(|_| ())
        })
        .await
    }

    /// Deletes rows older than `cutoff` and truncates the WAL so the deleted
    /// pages do not survive in it.
    pub async fn delete_expired(&self, cutoff: DateTime<Utc>) -> Result<usize, PersistError> {
        self.run(move |conn| {
            let removed = conn.execute(
                "DELETE FROM tokens WHERE registered_at < ?1",
                [cutoff.timestamp()],
            )?;
            checkpoint(conn)?;
            Ok(removed)
        })
        .await
    }

    async fn run<T, F>(&self, f: F) -> Result<T, PersistError>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || f(&lock(&conn)))
            .await
            .map_err(|e| PersistError::Task(e.to_string()))?
            .map_err(PersistError::from)
    }
}

/// A panic while holding the lock leaves SQLite itself consistent (every
/// statement is atomic), so a poisoned mutex is still safe to use.
fn lock(conn: &Mutex<Connection>) -> std::sync::MutexGuard<'_, Connection> {
    conn.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn checkpoint(conn: &Connection) -> rusqlite::Result<()> {
    conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
}

fn platform_to_db(platform: &Platform) -> i64 {
    match platform {
        Platform::Android => 0,
        Platform::Ios => 1,
        Platform::Web => 2,
    }
}

fn platform_from_db(value: i64) -> Option<Platform> {
    match value {
        0 => Some(Platform::Android),
        1 => Some(Platform::Ios),
        2 => Some(Platform::Web),
        _ => None,
    }
}
