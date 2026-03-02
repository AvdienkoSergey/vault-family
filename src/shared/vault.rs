use crate::crypto_operations::CryptoProvider;
use crate::types::{
    SharedVault, SharedVaultId, SharedVaultName, UserId, VaultPass, VaultPermission,
};
use chrono::{DateTime, Utc};
use rusqlite::params;

use super::SharedDB;
use super::error::SharedError;

impl<C: CryptoProvider> SharedDB<C> {
    /// Create a new shared vault. Caller becomes owner + member(ReadWrite).
    pub fn create_shared_vault(
        &self,
        pass: &VaultPass,
        name: SharedVaultName,
    ) -> Result<SharedVault, SharedError> {
        // 1. Generate SharedVaultKey
        let vault_key_bytes: [u8; 32] = rand::random();

        // 2. Decrypt owner's private key (validates keypair is accessible)
        let _owner_private =
            self.decrypt_user_private_key(pass.user_id(), pass.encryption_key())?;

        // 3. Get owner's public key
        let owner_public = self.get_user_public_key(pass.user_id())?;

        // 4. Generate ephemeral keypair for wrapping
        let (ephemeral_pub, ephemeral_priv) = self.crypto.generate_x25519_keypair();
        // 5. DH(ephemeral_private, owner_public) → AES key
        let shared_aes = self
            .crypto
            .x25519_derive_shared_key(&ephemeral_priv, owner_public.as_str())?;

        // 6. Encrypt vault key for owner
        let (encrypted_vault_key, vault_key_nonce) =
            self.crypto.encrypt_raw(&vault_key_bytes, &shared_aes)?;

        // 7. Insert vault + owner as member
        let vault_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        self.conn
            .execute(
                "INSERT INTO shared_vaults (id, name, owner_id, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![&vault_id, name.as_str(), pass.user_id().as_str(), now.to_rfc3339()],
            )
            .map_err(|e| SharedError::Database(format!("Failed to create shared vault: {e}")))?;

        self.conn
            .execute(
                "INSERT INTO shared_vault_members (vault_id, user_id, encrypted_vault_key, vault_key_nonce, ephemeral_public_key, permission, invited_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    &vault_id,
                    pass.user_id().as_str(),
                    &encrypted_vault_key,
                    &vault_key_nonce,
                    &ephemeral_pub,
                    VaultPermission::ReadWrite.as_str(),
                    now.to_rfc3339(),
                ],
            )
            .map_err(|e| SharedError::Database(format!("Failed to add owner as member: {e}")))?;

        Ok(SharedVault {
            id: SharedVaultId::new(vault_id),
            name,
            owner_id: UserId::new(pass.user_id().as_str().to_string()),
            created_at: now,
        })
    }

    /// List shared vaults where user is owner or member.
    pub fn list_shared_vaults(&self, user_id: &UserId) -> Result<Vec<SharedVault>, SharedError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sv.id, sv.name, sv.owner_id, sv.created_at
                 FROM shared_vaults sv
                 JOIN shared_vault_members svm ON sv.id = svm.vault_id
                 WHERE svm.user_id = ?1",
            )
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![user_id.as_str()], |row| {
                let id: String = row.get(0)?;
                let name: String = row.get(1)?;
                let owner: String = row.get(2)?;
                let created: String = row.get(3)?;
                Ok((id, name, owner, created))
            })
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let mut vaults = Vec::new();
        for row in rows {
            let (id, name, owner, created) =
                row.map_err(|e| SharedError::Database(e.to_string()))?;
            let created_at = DateTime::parse_from_rfc3339(&created)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            vaults.push(SharedVault {
                id: SharedVaultId::new(id),
                name: SharedVaultName::new(name),
                owner_id: UserId::new(owner),
                created_at,
            });
        }
        Ok(vaults)
    }

    /// Delete a shared vault (owner only). Deletes members and entries too.
    pub fn delete_shared_vault(
        &self,
        pass: &VaultPass,
        vault_id: &SharedVaultId,
    ) -> Result<(), SharedError> {
        self.verify_ownership(pass.user_id(), vault_id)?;

        self.conn
            .execute_batch("BEGIN")
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let result = (|| {
            self.conn.execute(
                "DELETE FROM shared_entries WHERE vault_id = ?1",
                params![vault_id.as_str()],
            )?;
            self.conn.execute(
                "DELETE FROM shared_vault_members WHERE vault_id = ?1",
                params![vault_id.as_str()],
            )?;
            self.conn.execute(
                "DELETE FROM shared_vaults WHERE id = ?1",
                params![vault_id.as_str()],
            )?;
            Ok::<(), rusqlite::Error>(())
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
                Err(SharedError::Database(e.to_string()))
            }
        }
    }
}
