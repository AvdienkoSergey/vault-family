use crate::crypto_operations::{CryptoError, CryptoProvider};
use crate::types::{
    EncryptedData, EncryptionKey, EntryId, Nonce, SharedVaultId, SharedVaultMember, UserId,
    VaultPass, VaultPermission,
};
use chrono::{DateTime, Utc};
use rusqlite::params;

use super::error::SharedError;
use super::{MAX_MEMBERS, SharedDB};

impl<C: CryptoProvider> SharedDB<C> {
    /// Invite a user to a shared vault (owner only).
    pub fn invite_member(
        &self,
        pass: &VaultPass,
        vault_id: &SharedVaultId,
        target_user_id: &UserId,
        permission: VaultPermission,
    ) -> Result<(), SharedError> {
        self.verify_ownership(pass.user_id(), vault_id)?;

        // Check member limit
        let count = self.member_count(vault_id)?;
        if count >= MAX_MEMBERS {
            return Err(SharedError::MemberLimit(format!(
                "shared vault already has {count} members (max {MAX_MEMBERS})"
            )));
        }

        // Check target has keypair
        if !self.has_user_keypair(target_user_id)? {
            return Err(SharedError::NoKeypair(format!(
                "user {} has no keypair",
                target_user_id.as_str()
            )));
        }

        // Decrypt SharedVaultKey
        let vault_key = self.decrypt_shared_vault_key(vault_id, pass)?;
        let vault_key_bytes = hex::decode(vault_key.as_str())
            .map_err(|e| SharedError::Crypto(CryptoError::InvalidKey(e.to_string())))?;

        // Get target's public key
        let target_public = self.get_user_public_key(target_user_id)?;

        // Generate ephemeral keypair for target
        let (ephemeral_pub, ephemeral_priv) = self.crypto.generate_x25519_keypair();

        // DH(ephemeral_private, target_public) → AES key
        let shared_aes = self
            .crypto
            .x25519_derive_shared_key(&ephemeral_priv, target_public.as_str())?;

        // Encrypt vault key for target
        let (encrypted_vault_key, vault_key_nonce) =
            self.crypto.encrypt_raw(&vault_key_bytes, &shared_aes)?;

        // Insert member
        self.conn
            .execute(
                "INSERT INTO shared_vault_members (vault_id, user_id, encrypted_vault_key, vault_key_nonce, ephemeral_public_key, permission, invited_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    vault_id.as_str(),
                    target_user_id.as_str(),
                    &encrypted_vault_key,
                    &vault_key_nonce,
                    &ephemeral_pub,
                    permission.as_str(),
                    Utc::now().to_rfc3339(),
                ],
            )
            .map_err(|e| SharedError::Database(format!("Failed to invite member: {e}")))?;

        Ok(())
    }

    /// Revoke a member (owner only). Triggers re-keying.
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

        // Decrypt OLD SharedVaultKey
        let old_vault_key = self.decrypt_shared_vault_key(vault_id, pass)?;
        let old_ek = EncryptionKey::new(old_vault_key.as_str().to_string());

        // Generate NEW SharedVaultKey
        let new_key_bytes: [u8; 32] = rand::random();
        let new_key_hex = hex::encode(new_key_bytes);
        let new_ek = EncryptionKey::new(new_key_hex.clone());

        // BEGIN TRANSACTION
        self.conn
            .execute_batch("BEGIN")
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let result = (|| -> Result<(), SharedError> {
            // Re-encrypt all entries
            let entries = self.list_shared_entries_raw(vault_id)?;
            for entry in &entries {
                let ee = crate::types::EncryptedEntry {
                    id: EntryId::new(entry.id.as_str().to_string()),
                    user_id: UserId::new(entry.created_by.as_str().to_string()),
                    encrypted_data: EncryptedData::new(entry.encrypted_data.as_str().to_string()),
                    nonce: Nonce::new(entry.nonce.as_str().to_string()),
                    created_at: entry.created_at,
                    updated_at: entry.updated_at,
                };
                let plain = self.crypto.decrypt_entry(&ee, &old_ek)?;
                let re_encrypted = self.crypto.encrypt_entry(&plain, &new_ek)?;

                self.conn
                    .execute(
                        "UPDATE shared_entries SET encrypted_data = ?1, nonce = ?2, updated_at = ?3 WHERE id = ?4",
                        params![
                            re_encrypted.encrypted_data.as_str(),
                            re_encrypted.nonce.as_str(),
                            Utc::now().to_rfc3339(),
                            entry.id.as_str(),
                        ],
                    )
                    .map_err(|e| SharedError::Database(e.to_string()))?;
            }

            // Delete revoked member
            self.conn
                .execute(
                    "DELETE FROM shared_vault_members WHERE vault_id = ?1 AND user_id = ?2",
                    params![vault_id.as_str(), target_user_id.as_str()],
                )
                .map_err(|e| SharedError::Database(e.to_string()))?;

            // Re-wrap key for remaining members
            let remaining = self.list_member_user_ids(vault_id)?;
            for member_uid in &remaining {
                let member_public = self.get_user_public_key(member_uid)?;
                let (eph_pub, eph_priv) = self.crypto.generate_x25519_keypair();
                let shared_aes = self
                    .crypto
                    .x25519_derive_shared_key(&eph_priv, member_public.as_str())?;
                let (enc_vault_key, vk_nonce) =
                    self.crypto.encrypt_raw(&new_key_bytes, &shared_aes)?;

                self.conn
                    .execute(
                        "UPDATE shared_vault_members SET encrypted_vault_key = ?1, vault_key_nonce = ?2, ephemeral_public_key = ?3 WHERE vault_id = ?4 AND user_id = ?5",
                        params![
                            &enc_vault_key,
                            &vk_nonce,
                            &eph_pub,
                            vault_id.as_str(),
                            member_uid.as_str(),
                        ],
                    )
                    .map_err(|e| SharedError::Database(e.to_string()))?;
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

    /// List members of a shared vault (any member can see).
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
