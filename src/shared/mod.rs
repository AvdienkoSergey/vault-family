mod entries;
mod error;
mod helpers;
mod keypair;
mod membership;
mod vault;

pub use error::SharedError;

use crate::crypto_operations::CryptoProvider;
use rusqlite::Connection;

// ════════════════════════════════════════════════════════════════════
// SharedDB — отдельная БД для шаринга (shared.db)
// ════════════════════════════════════════════════════════════════════
//
// Не зависит от vault/ или auth/.
// Зависит только от types.rs (VaultPass, branded types) и crypto_operations.

pub struct SharedDB<C: CryptoProvider> {
    conn: Connection,
    crypto: C,
}

/// Derive shared.db path from vault.db path (same directory, sibling file).
///
/// `data/vault.db` → `data/shared.db`
/// `data/vault_test_abc.db` → `data/vault_test_abc_shared.db`
///
/// Uses the stem of vault_db_path to produce a unique sibling name.
/// This ensures test isolation when multiple vault DBs exist in the same directory.
pub fn shared_db_path(vault_db_path: &str) -> String {
    let path = std::path::Path::new(vault_db_path);
    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    if stem == "vault" {
        // Production convention: vault.db → shared.db
        parent.join("shared.db").to_string_lossy().into_owned()
    } else {
        // Test / custom: vault_test_abc.db → vault_test_abc_shared.db
        parent
            .join(format!("{stem}_shared.db"))
            .to_string_lossy()
            .into_owned()
    }
}

pub(crate) const MAX_MEMBERS: usize = 5;

impl<C: CryptoProvider> SharedDB<C> {
    pub fn open(path: &str, crypto: C) -> Result<Self, SharedError> {
        let conn = Connection::open(path)
            .map_err(|e| SharedError::Connection(format!("Failed to open shared.db: {e}")))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS user_keys (
                user_id               TEXT PRIMARY KEY,
                public_key            TEXT NOT NULL,
                encrypted_private_key TEXT NOT NULL,
                private_key_nonce     TEXT NOT NULL,
                created_at            TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS shared_vaults (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                owner_id   TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS shared_vault_members (
                vault_id             TEXT NOT NULL,
                user_id              TEXT NOT NULL,
                encrypted_vault_key  TEXT NOT NULL,
                vault_key_nonce      TEXT NOT NULL,
                ephemeral_public_key TEXT NOT NULL,
                permission           TEXT NOT NULL DEFAULT 'read',
                invited_at           TEXT NOT NULL,
                PRIMARY KEY (vault_id, user_id)
            );
            CREATE TABLE IF NOT EXISTS shared_entries (
                id             TEXT PRIMARY KEY,
                vault_id       TEXT NOT NULL,
                encrypted_data TEXT NOT NULL,
                nonce          TEXT NOT NULL,
                created_by     TEXT NOT NULL,
                created_at     TEXT NOT NULL,
                updated_at     TEXT NOT NULL
            );",
        )
        .map_err(|e| SharedError::Schema(format!("Failed to create shared tables: {e}")))?;

        Ok(SharedDB { conn, crypto })
    }
}

#[cfg(test)]
mod tests;
