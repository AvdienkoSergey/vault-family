use crate::crypto_operations::CryptoProvider;
use crate::types::{
    EncryptedData, EntryId, Nonce, SharedEncryptedEntry, SharedVaultId, SharedVaultKey, UserId,
    VaultPass,
};
use chrono::{DateTime, Utc};
use rusqlite::params;

use super::SharedDB;
use super::error::SharedError;

impl<C: CryptoProvider> SharedDB<C> {
    /// Decrypt SharedVaultKey for the calling user.
    pub(crate) fn decrypt_shared_vault_key(
        &self,
        vault_id: &SharedVaultId,
        pass: &VaultPass,
    ) -> Result<SharedVaultKey, SharedError> {
        // 1. Read member row
        let (encrypted_vault_key, vault_key_nonce, ephemeral_public) = self
            .conn
            .query_row(
                "SELECT encrypted_vault_key, vault_key_nonce, ephemeral_public_key
                 FROM shared_vault_members WHERE vault_id = ?1 AND user_id = ?2",
                params![vault_id.as_str(), pass.user_id().as_str()],
                |row| {
                    let evk: String = row.get(0)?;
                    let vkn: String = row.get(1)?;
                    let epk: String = row.get(2)?;
                    Ok((evk, vkn, epk))
                },
            )
            .map_err(|_| SharedError::NotFound("not a member of this vault".to_string()))?;

        // 2. Decrypt user's private key
        let user_private = self.decrypt_user_private_key(pass.user_id(), pass.encryption_key())?;

        // 3. DH(private_key, ephemeral_public) → shared AES key
        let shared_aes = self
            .crypto
            .x25519_derive_shared_key(&user_private, &ephemeral_public)?;

        // 4. Decrypt vault key
        let vault_key_bytes =
            self.crypto
                .decrypt_raw(&encrypted_vault_key, &vault_key_nonce, &shared_aes)?;

        Ok(SharedVaultKey::new(hex::encode(vault_key_bytes)))
    }

    pub(crate) fn verify_ownership(
        &self,
        user_id: &UserId,
        vault_id: &SharedVaultId,
    ) -> Result<(), SharedError> {
        let owner_id: String = self
            .conn
            .query_row(
                "SELECT owner_id FROM shared_vaults WHERE id = ?1",
                params![vault_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| SharedError::NotFound("shared vault not found".to_string()))?;

        if owner_id != user_id.as_str() {
            return Err(SharedError::Forbidden("not the vault owner".to_string()));
        }
        Ok(())
    }

    pub(crate) fn verify_membership(
        &self,
        user_id: &UserId,
        vault_id: &SharedVaultId,
    ) -> Result<(), SharedError> {
        if !self.is_member(vault_id, user_id)? {
            return Err(SharedError::Forbidden("not a member".to_string()));
        }
        Ok(())
    }

    pub(crate) fn verify_write_access(
        &self,
        user_id: &UserId,
        vault_id: &SharedVaultId,
    ) -> Result<(), SharedError> {
        let permission: String = self
            .conn
            .query_row(
                "SELECT permission FROM shared_vault_members WHERE vault_id = ?1 AND user_id = ?2",
                params![vault_id.as_str(), user_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| SharedError::Forbidden("not a member".to_string()))?;

        if permission != "readwrite" {
            return Err(SharedError::Forbidden("read-only access".to_string()));
        }
        Ok(())
    }

    pub(crate) fn is_member(
        &self,
        vault_id: &SharedVaultId,
        user_id: &UserId,
    ) -> Result<bool, SharedError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM shared_vault_members WHERE vault_id = ?1 AND user_id = ?2",
                params![vault_id.as_str(), user_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| SharedError::Database(e.to_string()))?;
        Ok(count > 0)
    }

    pub(crate) fn member_count(&self, vault_id: &SharedVaultId) -> Result<usize, SharedError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM shared_vault_members WHERE vault_id = ?1",
                params![vault_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| SharedError::Database(e.to_string()))?;
        Ok(count as usize)
    }

    pub(crate) fn list_member_user_ids(
        &self,
        vault_id: &SharedVaultId,
    ) -> Result<Vec<UserId>, SharedError> {
        let mut stmt = self
            .conn
            .prepare("SELECT user_id FROM shared_vault_members WHERE vault_id = ?1")
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![vault_id.as_str()], |row| {
                let uid: String = row.get(0)?;
                Ok(uid)
            })
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let mut uids = Vec::new();
        for row in rows {
            let uid = row.map_err(|e| SharedError::Database(e.to_string()))?;
            uids.push(UserId::new(uid));
        }
        Ok(uids)
    }

    pub(crate) fn list_shared_entries_raw(
        &self,
        vault_id: &SharedVaultId,
    ) -> Result<Vec<SharedEncryptedEntry>, SharedError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, vault_id, encrypted_data, nonce, created_by, created_at, updated_at
                 FROM shared_entries WHERE vault_id = ?1",
            )
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![vault_id.as_str()], |row| {
                let id: String = row.get(0)?;
                let vid: String = row.get(1)?;
                let enc: String = row.get(2)?;
                let nonce: String = row.get(3)?;
                let created_by: String = row.get(4)?;
                let created: String = row.get(5)?;
                let updated: String = row.get(6)?;
                Ok((id, vid, enc, nonce, created_by, created, updated))
            })
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let mut entries = Vec::new();
        for row in rows {
            let (id, vid, enc, nonce, created_by, created, updated) =
                row.map_err(|e| SharedError::Database(e.to_string()))?;
            let created_at = DateTime::parse_from_rfc3339(&created)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let updated_at = DateTime::parse_from_rfc3339(&updated)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            entries.push(SharedEncryptedEntry {
                id: EntryId::new(id),
                vault_id: SharedVaultId::new(vid),
                encrypted_data: EncryptedData::new(enc),
                nonce: Nonce::new(nonce),
                created_by: UserId::new(created_by),
                created_at,
                updated_at,
            });
        }
        Ok(entries)
    }
}
