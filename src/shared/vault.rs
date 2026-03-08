use crate::crypto_operations::CryptoProvider;
use crate::types::{SharedVault, SharedVaultId, SharedVaultName, UserId, VaultPass};
use chrono::{DateTime, Utc};
use rusqlite::params;

use super::SharedDB;
use super::error::SharedError;

/// Extended vault info with member/entry counts for API response.
#[derive(Debug)]
pub struct SharedVaultWithCounts {
    pub id: SharedVaultId,
    pub name: SharedVaultName,
    pub owner_id: UserId,
    pub member_count: usize,
    pub entry_count: usize,
    pub created_at: DateTime<Utc>,
}

impl<C: CryptoProvider> SharedDB<C> {
    /// Create a new shared vault (zero-knowledge).
    /// Server creates vault row + owner as member.
    /// Vault key is managed client-side; server stores empty key fields initially.
    pub fn create_shared_vault(
        &self,
        pass: &VaultPass,
        name: SharedVaultName,
    ) -> Result<SharedVault, SharedError> {
        let vault_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        self.conn
            .execute(
                "INSERT INTO shared_vaults (id, name, owner_id, created_at) VALUES (?1, ?2, ?3, ?4)",
                params![&vault_id, name.as_str(), pass.user_id().as_str(), now.to_rfc3339()],
            )
            .map_err(|e| SharedError::Database(format!("Failed to create shared vault: {e}")))?;

        // Add owner as member with readwrite permission
        self.conn
            .execute(
                "INSERT INTO shared_vault_members (vault_id, user_id, role, permission, invited_at)
                 VALUES (?1, ?2, 'owner', 'readwrite', ?3)",
                params![&vault_id, pass.user_id().as_str(), now.to_rfc3339()],
            )
            .map_err(|e| SharedError::Database(format!("Failed to add owner as member: {e}")))?;

        Ok(SharedVault {
            id: SharedVaultId::new(vault_id),
            name,
            owner_id: UserId::new(pass.user_id().as_str().to_string()),
            created_at: now,
        })
    }

    /// List shared vaults where user is a member. Includes member_count and entry_count.
    pub fn list_shared_vaults_with_counts(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<SharedVaultWithCounts>, SharedError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT sv.id, sv.name, sv.owner_id, sv.created_at,
                        (SELECT COUNT(*) FROM shared_vault_members WHERE vault_id = sv.id) AS member_count,
                        (SELECT COUNT(*) FROM shared_entries WHERE vault_id = sv.id AND deleted = 0) AS entry_count
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
                let member_count: i64 = row.get(4)?;
                let entry_count: i64 = row.get(5)?;
                Ok((id, name, owner, created, member_count, entry_count))
            })
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let mut vaults = Vec::new();
        for row in rows {
            let (id, name, owner, created, mc, ec) =
                row.map_err(|e| SharedError::Database(e.to_string()))?;
            let created_at = DateTime::parse_from_rfc3339(&created)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            vaults.push(SharedVaultWithCounts {
                id: SharedVaultId::new(id),
                name: SharedVaultName::new(name),
                owner_id: UserId::new(owner),
                member_count: mc as usize,
                entry_count: ec as usize,
                created_at,
            });
        }
        Ok(vaults)
    }

    /// List shared vaults (backward compatible — without counts).
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

    /// Delete a shared vault (owner only). Deletes members, entries, and invites.
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
                "DELETE FROM invites WHERE vault_id = ?1",
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
