use crate::crypto_operations::CryptoProvider;
use crate::types::{EncryptedData, EntryId, Nonce, SharedEncryptedEntry, SharedVaultId, UserId};
use chrono::{DateTime, Utc};
use rusqlite::params;

use super::SharedDB;
use super::error::SharedError;

impl<C: CryptoProvider> SharedDB<C> {
    /// Add a pre-encrypted entry to a shared vault (zero-knowledge).
    /// Server stores the blob as-is, never decrypts.
    pub fn add_shared_entry(
        &self,
        user_id: &UserId,
        vault_id: &SharedVaultId,
        entry_id: &str,
        encrypted_data: &str,
        nonce: &str,
        category: &str,
    ) -> Result<EntryId, SharedError> {
        self.verify_write_access(user_id, vault_id)?;

        let now = Utc::now();

        self.conn
            .execute(
                "INSERT INTO shared_entries (id, vault_id, encrypted_data, nonce, category, created_by, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    entry_id,
                    vault_id.as_str(),
                    encrypted_data,
                    nonce,
                    category,
                    user_id.as_str(),
                    now.to_rfc3339(),
                    now.to_rfc3339(),
                ],
            )
            .map_err(|e| SharedError::Database(format!("Failed to add shared entry: {e}")))?;

        Ok(EntryId::new(entry_id.to_string()))
    }

    /// List entries in a shared vault (any member). Returns raw encrypted blobs.
    /// Supports delta sync via `since` parameter.
    /// When `since` is provided, includes soft-deleted entries (tombstones).
    pub fn list_shared_entries(
        &self,
        user_id: &UserId,
        vault_id: &SharedVaultId,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<SharedEncryptedEntry>, SharedError> {
        self.verify_membership(user_id, vault_id)?;

        let (sql, use_since) = match &since {
            Some(_) => (
                "SELECT id, vault_id, encrypted_data, nonce, category, created_by, created_at, updated_at, deleted
                 FROM shared_entries WHERE vault_id = ?1 AND updated_at > ?2
                 ORDER BY updated_at ASC",
                true,
            ),
            None => (
                "SELECT id, vault_id, encrypted_data, nonce, category, created_by, created_at, updated_at, deleted
                 FROM shared_entries WHERE vault_id = ?1 AND deleted = 0
                 ORDER BY updated_at ASC",
                false,
            ),
        };

        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let rows = if use_since {
            let since_str = since.unwrap().to_rfc3339();
            stmt.query_map(params![vault_id.as_str(), &since_str], map_entry_row)
                .map_err(|e| SharedError::Database(e.to_string()))?
        } else {
            stmt.query_map(params![vault_id.as_str()], map_entry_row)
                .map_err(|e| SharedError::Database(e.to_string()))?
        };

        let mut entries = Vec::new();
        for row in rows {
            let raw = row.map_err(|e| SharedError::Database(e.to_string()))?;
            entries.push(parse_entry_row(raw)?);
        }
        Ok(entries)
    }

    /// Soft-delete an entry. Sets deleted=1 so delta sync can propagate tombstones.
    pub fn delete_shared_entry(
        &self,
        user_id: &UserId,
        vault_id: &SharedVaultId,
        entry_id: &EntryId,
    ) -> Result<bool, SharedError> {
        self.verify_write_access(user_id, vault_id)?;

        let updated = self
            .conn
            .execute(
                "UPDATE shared_entries SET deleted = 1, updated_at = ?1 WHERE id = ?2 AND vault_id = ?3",
                params![Utc::now().to_rfc3339(), entry_id.as_str(), vault_id.as_str()],
            )
            .map_err(|e| SharedError::Database(e.to_string()))?;

        Ok(updated > 0)
    }

    /// Bulk upsert entries (zero-knowledge). Used by sync push.
    pub fn push_entries(
        &self,
        user_id: &UserId,
        vault_id: &SharedVaultId,
        entries: &[(String, String, String, String, String, bool)], // (id, encrypted_data, nonce, category, last_modified, deleted)
    ) -> Result<usize, SharedError> {
        self.verify_write_access(user_id, vault_id)?;

        self.conn
            .execute_batch("BEGIN")
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let result = (|| -> Result<usize, SharedError> {
            let mut count = 0usize;
            for (id, encrypted_data, nonce, category, last_modified, deleted) in entries {
                self.conn
                    .execute(
                        "INSERT INTO shared_entries (id, vault_id, encrypted_data, nonce, category, created_by, created_at, updated_at, deleted)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                         ON CONFLICT(id) DO UPDATE SET
                           encrypted_data = excluded.encrypted_data,
                           nonce = excluded.nonce,
                           category = excluded.category,
                           updated_at = excluded.updated_at,
                           deleted = excluded.deleted",
                        params![
                            id,
                            vault_id.as_str(),
                            encrypted_data,
                            nonce,
                            category,
                            user_id.as_str(),
                            last_modified,
                            last_modified,
                            *deleted as i32,
                        ],
                    )
                    .map_err(|e| SharedError::Database(e.to_string()))?;
                count += 1;
            }
            Ok(count)
        })();

        match result {
            Ok(count) => {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(|e| SharedError::Database(e.to_string()))?;
                Ok(count)
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }
}

type EntryRowRaw = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    i32,
);

fn map_entry_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<EntryRowRaw> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn parse_entry_row(raw: EntryRowRaw) -> Result<SharedEncryptedEntry, SharedError> {
    let (id, vid, enc, nonce, category, created_by, created, updated, deleted) = raw;
    let created_at = DateTime::parse_from_rfc3339(&created)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let updated_at = DateTime::parse_from_rfc3339(&updated)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    Ok(SharedEncryptedEntry {
        id: EntryId::new(id),
        vault_id: SharedVaultId::new(vid),
        encrypted_data: EncryptedData::new(enc),
        nonce: Nonce::new(nonce),
        category,
        created_by: UserId::new(created_by),
        created_at,
        updated_at,
        deleted: deleted != 0,
    })
}
