use crate::crypto_operations::CryptoProvider;
use crate::types::{SharedVaultId, UserId};
use rusqlite::params;

use super::SharedDB;
use super::error::SharedError;

impl<C: CryptoProvider> SharedDB<C> {
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

    /// Get all member user_ids for a vault (for WS fan-out, no auth check).
    pub fn get_member_user_ids(
        &self,
        vault_id: &SharedVaultId,
    ) -> Result<Vec<String>, SharedError> {
        let mut stmt = self
            .conn
            .prepare("SELECT user_id FROM shared_vault_members WHERE vault_id = ?1")
            .map_err(|e| SharedError::Database(e.to_string()))?;
        let rows = stmt
            .query_map(params![vault_id.as_str()], |row| row.get::<_, String>(0))
            .map_err(|e| SharedError::Database(e.to_string()))?;
        rows.map(|r| r.map_err(|e| SharedError::Database(e.to_string())))
            .collect()
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
}
