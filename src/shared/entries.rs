use crate::crypto_operations::CryptoProvider;
use crate::types::{
    EncryptedData, EncryptionKey, EntryId, Nonce, PlainEntry, SharedVaultId, UserId, VaultPass,
};
use chrono::{DateTime, Utc};
use rusqlite::params;

use super::SharedDB;
use super::error::SharedError;

impl<C: CryptoProvider> SharedDB<C> {
    /// Add entry to shared vault. Requires ReadWrite permission.
    pub fn add_shared_entry(
        &self,
        pass: &VaultPass,
        vault_id: &SharedVaultId,
        plain: &PlainEntry,
    ) -> Result<EntryId, SharedError> {
        self.verify_write_access(pass.user_id(), vault_id)?;

        let vault_key = self.decrypt_shared_vault_key(vault_id, pass)?;
        let temp_ek = EncryptionKey::new(vault_key.as_str().to_string());
        let encrypted = self.crypto.encrypt_entry(plain, &temp_ek)?;

        let entry_id = plain.id.as_str().to_string();
        let now = Utc::now();

        self.conn
            .execute(
                "INSERT INTO shared_entries (id, vault_id, encrypted_data, nonce, created_by, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &entry_id,
                    vault_id.as_str(),
                    encrypted.encrypted_data.as_str(),
                    encrypted.nonce.as_str(),
                    pass.user_id().as_str(),
                    now.to_rfc3339(),
                    now.to_rfc3339(),
                ],
            )
            .map_err(|e| SharedError::Database(format!("Failed to add shared entry: {e}")))?;

        Ok(EntryId::new(entry_id))
    }

    /// List entries in a shared vault (any member). Decrypts service_name.
    pub fn list_shared_entries(
        &self,
        pass: &VaultPass,
        vault_id: &SharedVaultId,
    ) -> Result<Vec<PlainEntry>, SharedError> {
        self.verify_membership(pass.user_id(), vault_id)?;

        let vault_key = self.decrypt_shared_vault_key(vault_id, pass)?;
        let temp_ek = EncryptionKey::new(vault_key.as_str().to_string());

        let raw_entries = self.list_shared_entries_raw(vault_id)?;
        let mut result = Vec::new();
        for entry in &raw_entries {
            let ee = crate::types::EncryptedEntry {
                id: EntryId::new(entry.id.as_str().to_string()),
                user_id: UserId::new(entry.created_by.as_str().to_string()),
                encrypted_data: EncryptedData::new(entry.encrypted_data.as_str().to_string()),
                nonce: Nonce::new(entry.nonce.as_str().to_string()),
                created_at: entry.created_at,
                updated_at: entry.updated_at,
            };
            let plain = self.crypto.decrypt_entry(&ee, &temp_ek)?;
            result.push(plain);
        }
        Ok(result)
    }

    /// View a specific shared entry (any member).
    pub fn view_shared_entry(
        &self,
        pass: &VaultPass,
        vault_id: &SharedVaultId,
        entry_id: &EntryId,
    ) -> Result<PlainEntry, SharedError> {
        self.verify_membership(pass.user_id(), vault_id)?;

        let vault_key = self.decrypt_shared_vault_key(vault_id, pass)?;
        let temp_ek = EncryptionKey::new(vault_key.as_str().to_string());

        let entry = self
            .conn
            .query_row(
                "SELECT id, vault_id, encrypted_data, nonce, created_by, created_at, updated_at
                 FROM shared_entries WHERE id = ?1 AND vault_id = ?2",
                params![entry_id.as_str(), vault_id.as_str()],
                |row| {
                    let id: String = row.get(0)?;
                    let _vid: String = row.get(1)?;
                    let enc: String = row.get(2)?;
                    let nonce: String = row.get(3)?;
                    let created_by: String = row.get(4)?;
                    let created: String = row.get(5)?;
                    let updated: String = row.get(6)?;
                    Ok((id, enc, nonce, created_by, created, updated))
                },
            )
            .map_err(|_| SharedError::NotFound("shared entry not found".to_string()))?;

        let (id, enc, nonce, created_by, created, updated) = entry;
        let created_at = DateTime::parse_from_rfc3339(&created)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());
        let updated_at = DateTime::parse_from_rfc3339(&updated)
            .map(|dt| dt.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now());

        let ee = crate::types::EncryptedEntry {
            id: EntryId::new(id),
            user_id: UserId::new(created_by),
            encrypted_data: EncryptedData::new(enc),
            nonce: Nonce::new(nonce),
            created_at,
            updated_at,
        };
        let plain = self.crypto.decrypt_entry(&ee, &temp_ek)?;
        Ok(plain)
    }

    /// Delete entry from shared vault. Requires ReadWrite permission.
    pub fn delete_shared_entry(
        &self,
        pass: &VaultPass,
        vault_id: &SharedVaultId,
        entry_id: &EntryId,
    ) -> Result<bool, SharedError> {
        self.verify_write_access(pass.user_id(), vault_id)?;

        let deleted = self
            .conn
            .execute(
                "DELETE FROM shared_entries WHERE id = ?1 AND vault_id = ?2",
                params![entry_id.as_str(), vault_id.as_str()],
            )
            .map_err(|e| SharedError::Database(e.to_string()))?;

        Ok(deleted > 0)
    }
}
