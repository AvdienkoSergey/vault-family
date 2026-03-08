use crate::crypto_operations::CryptoProvider;
use crate::types::{SharedVaultId, SharedVaultMember, UserId, VaultPass, VaultPermission};
use chrono::{DateTime, Utc};
use rusqlite::params;

use super::error::SharedError;
use super::SharedDB;

impl<C: CryptoProvider> SharedDB<C> {
    /// Revoke a member (owner only).
    /// In zero-knowledge model: just delete the member row.
    /// Client is responsible for re-keying via update_member_keys().
    pub fn revoke_member(
        &self,
        pass: &VaultPass,
        vault_id: &SharedVaultId,
        target_user_id: &UserId,
    ) -> Result<(), SharedError> {
        self.verify_ownership(pass.user_id(), vault_id)?;

        // Cannot revoke self (owner)
        if target_user_id.as_str() == pass.user_id().as_str() {
            return Err(SharedError::Forbidden(
                "owner cannot revoke themselves".to_string(),
            ));
        }

        // Verify target is a member
        if !self.is_member(vault_id, target_user_id)? {
            return Err(SharedError::NotFound(format!(
                "user {} is not a member of vault {}",
                target_user_id.as_str(),
                vault_id.as_str()
            )));
        }

        // Transaction: delete member + mark related invites as rejected
        self.conn
            .execute_batch("BEGIN")
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let result = (|| -> Result<(), SharedError> {
            self.conn
                .execute(
                    "DELETE FROM shared_vault_members WHERE vault_id = ?1 AND user_id = ?2",
                    params![vault_id.as_str(), target_user_id.as_str()],
                )
                .map_err(|e| SharedError::Database(e.to_string()))?;

            // Mark completed invites for this user as rejected
            self.conn
                .execute(
                    "UPDATE invites SET status = 'rejected', updated_at = ?1
                     WHERE vault_id = ?2 AND invitee_user_id = ?3 AND status = 'completed'",
                    params![
                        Utc::now().to_rfc3339(),
                        vault_id.as_str(),
                        target_user_id.as_str(),
                    ],
                )
                .map_err(|e| SharedError::Database(e.to_string()))?;

            Ok(())
        })();

        match result {
            Ok(()) => {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(|e| SharedError::Database(e.to_string()))?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Update a member's permission (owner only).
    pub fn update_member_permission(
        &self,
        pass: &VaultPass,
        vault_id: &SharedVaultId,
        target_user_id: &UserId,
        permission: VaultPermission,
    ) -> Result<(), SharedError> {
        self.verify_ownership(pass.user_id(), vault_id)?;

        let updated = self
            .conn
            .execute(
                "UPDATE shared_vault_members SET permission = ?1 WHERE vault_id = ?2 AND user_id = ?3",
                params![permission.as_str(), vault_id.as_str(), target_user_id.as_str()],
            )
            .map_err(|e| SharedError::Database(e.to_string()))?;

        if updated == 0 {
            return Err(SharedError::NotFound("member not found".to_string()));
        }
        Ok(())
    }

    /// Client-driven re-keying: bulk update encrypted vault keys for all members.
    /// Owner only. Called after revoke to distribute new vault key.
    pub fn update_member_keys(
        &self,
        owner_id: &UserId,
        vault_id: &SharedVaultId,
        member_keys: &[(String, String, String)], // (user_id, encrypted_vault_key, nonce)
    ) -> Result<(), SharedError> {
        self.verify_ownership(owner_id, vault_id)?;

        self.conn
            .execute_batch("BEGIN")
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let result = (|| -> Result<(), SharedError> {
            for (user_id, encrypted_key, nonce) in member_keys {
                let updated = self
                    .conn
                    .execute(
                        "UPDATE shared_vault_members SET encrypted_vault_key = ?1, vault_key_nonce = ?2
                         WHERE vault_id = ?3 AND user_id = ?4",
                        params![encrypted_key, nonce, vault_id.as_str(), user_id],
                    )
                    .map_err(|e| SharedError::Database(e.to_string()))?;

                if updated == 0 {
                    return Err(SharedError::NotFound(format!(
                        "member {user_id} not found in vault {}",
                        vault_id.as_str()
                    )));
                }
            }
            Ok(())
        })();

        match result {
            Ok(()) => {
                self.conn
                    .execute_batch("COMMIT")
                    .map_err(|e| SharedError::Database(e.to_string()))?;
                Ok(())
            }
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// List members of a shared vault (any member can see).
    /// Returns expanded data including email (from vault.db lookup done at handler level),
    /// public_key, and role.
    pub fn list_members(
        &self,
        user_id: &UserId,
        vault_id: &SharedVaultId,
    ) -> Result<Vec<SharedVaultMember>, SharedError> {
        // Verify caller is a member
        if !self.is_member(vault_id, user_id)? {
            return Err(SharedError::Forbidden("not a member".to_string()));
        }

        let mut stmt = self
            .conn
            .prepare(
                "SELECT vault_id, user_id, permission, invited_at
                 FROM shared_vault_members WHERE vault_id = ?1",
            )
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![vault_id.as_str()], |row| {
                let vid: String = row.get(0)?;
                let uid: String = row.get(1)?;
                let perm: String = row.get(2)?;
                let invited: String = row.get(3)?;
                Ok((vid, uid, perm, invited))
            })
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let mut members = Vec::new();
        for row in rows {
            let (vid, uid, perm, invited) =
                row.map_err(|e| SharedError::Database(e.to_string()))?;
            let invited_at = DateTime::parse_from_rfc3339(&invited)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            members.push(SharedVaultMember {
                vault_id: SharedVaultId::new(vid),
                user_id: UserId::new(uid),
                permission: VaultPermission::from_str_permission(&perm)
                    .unwrap_or(VaultPermission::Read),
                invited_at,
            });
        }
        Ok(members)
    }
}
