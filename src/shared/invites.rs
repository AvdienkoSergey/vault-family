use crate::crypto_operations::CryptoProvider;
use crate::types::{
    AcceptedInvite, Invite, InviteId, InviteStatus, Role, SharedVaultId, UserId, VaultPermission,
};
use chrono::{DateTime, Utc};
use rusqlite::params;
use sha2::{Digest, Sha256};

use super::error::SharedError;
use super::{MAX_MEMBERS, SharedDB};

impl<C: CryptoProvider> SharedDB<C> {
    /// Step 1: Owner creates an invite. Returns (invite_id, plaintext_code).
    ///
    /// The plaintext code is returned ONCE and must be delivered out-of-band.
    /// Only SHA-256(code) is stored in the DB.
    pub fn create_invite(
        &self,
        inviter_id: &UserId,
        vault_id: &SharedVaultId,
        invitee_email: &str,
        role: Role,
        permission: VaultPermission,
    ) -> Result<(InviteId, String), SharedError> {
        // Verify caller is the owner
        self.verify_ownership(inviter_id, vault_id)?;

        // Check member limit
        let count = self.member_count(vault_id)?;
        if count >= MAX_MEMBERS {
            return Err(SharedError::MemberLimit(format!(
                "shared vault already has {count} members (max {MAX_MEMBERS})"
            )));
        }

        // Check for duplicate pending invite
        let existing: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM invites WHERE vault_id = ?1 AND invitee_email = ?2 AND status = 'pending'",
                params![vault_id.as_str(), invitee_email],
                |row| row.get(0),
            )
            .map_err(|e| SharedError::Database(e.to_string()))?;

        if existing > 0 {
            return Err(SharedError::Conflict(format!(
                "pending invite already exists for {invitee_email}"
            )));
        }

        // Generate 6-digit code
        let code = generate_invite_code();
        let code_hash = hex::encode(Sha256::digest(code.as_bytes()));

        let invite_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.conn
            .execute(
                "INSERT INTO invites (id, vault_id, inviter_id, invitee_email, role, permission, code_hash, status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9)",
                params![
                    &invite_id,
                    vault_id.as_str(),
                    inviter_id.as_str(),
                    invitee_email,
                    role.as_str(),
                    permission.as_str(),
                    &code_hash,
                    &now,
                    &now,
                ],
            )
            .map_err(|e| SharedError::Database(format!("Failed to create invite: {e}")))?;

        Ok((InviteId::new(invite_id), code))
    }

    /// List invites where user is inviter (by user_id) OR invitee (by email).
    pub fn list_user_invites(
        &self,
        user_id: &UserId,
        user_email: &str,
    ) -> Result<Vec<Invite>, SharedError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT i.id, i.vault_id, i.inviter_id, i.invitee_email, i.role, i.permission,
                        i.status, i.created_at, i.updated_at, sv.name
                 FROM invites i
                 LEFT JOIN shared_vaults sv ON sv.id = i.vault_id
                 WHERE i.inviter_id = ?1 OR i.invitee_email = ?2
                 ORDER BY i.created_at DESC",
            )
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![user_id.as_str(), user_email], |row| {
                let id: String = row.get(0)?;
                let vault_id: String = row.get(1)?;
                let inviter_id: String = row.get(2)?;
                let invitee_email: String = row.get(3)?;
                let role: String = row.get(4)?;
                let permission: String = row.get(5)?;
                let status: String = row.get(6)?;
                let created: String = row.get(7)?;
                let updated: String = row.get(8)?;
                let vault_name: Option<String> = row.get(9)?;
                Ok((
                    id,
                    vault_id,
                    inviter_id,
                    invitee_email,
                    role,
                    permission,
                    status,
                    created,
                    updated,
                    vault_name,
                ))
            })
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let mut invites = Vec::new();
        for row in rows {
            let (
                id,
                vault_id,
                inviter_id,
                invitee_email,
                role,
                permission,
                status,
                created,
                updated,
                vault_name,
            ) = row.map_err(|e| SharedError::Database(e.to_string()))?;

            let created_at = DateTime::parse_from_rfc3339(&created)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());
            let updated_at = DateTime::parse_from_rfc3339(&updated)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            invites.push(Invite {
                id: InviteId::new(id),
                vault_id: SharedVaultId::new(vault_id),
                inviter_id: UserId::new(inviter_id),
                invitee_email,
                role: Role::from_str_role(&role).unwrap_or(Role::Viewer),
                permission: VaultPermission::from_str_permission(&permission)
                    .unwrap_or(VaultPermission::Read),
                status: InviteStatus::from_str_status(&status).unwrap_or(InviteStatus::Pending),
                vault_name,
                created_at,
                updated_at,
            });
        }
        Ok(invites)
    }

    /// Step 2: Invitee accepts an invite, sending their public key + confirmation key.
    pub fn accept_invite(
        &self,
        invite_id: &InviteId,
        user_id: &UserId,
        public_key_hex: &str,
        confirmation_key_hex: &str,
    ) -> Result<(), SharedError> {
        // Verify invite exists and is pending
        let status: String = self
            .conn
            .query_row(
                "SELECT status FROM invites WHERE id = ?1",
                params![invite_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| {
                SharedError::InviteNotFound(format!("invite {} not found", invite_id.as_str()))
            })?;

        if status != "pending" {
            return Err(SharedError::InvalidInviteState(format!(
                "invite is '{status}', expected 'pending'"
            )));
        }

        let now = Utc::now().to_rfc3339();

        self.conn
            .execute(
                "UPDATE invites SET status = 'accepted', invitee_user_id = ?1, invitee_public_key = ?2, confirmation_key = ?3, updated_at = ?4 WHERE id = ?5",
                params![
                    user_id.as_str(),
                    public_key_hex,
                    confirmation_key_hex,
                    &now,
                    invite_id.as_str(),
                ],
            )
            .map_err(|e| SharedError::Database(format!("Failed to accept invite: {e}")))?;

        Ok(())
    }

    /// Step 3: Owner retrieves accepted invites for a vault (to process key exchange).
    pub fn get_accepted_invites(
        &self,
        vault_id: &SharedVaultId,
        owner_id: &UserId,
    ) -> Result<Vec<AcceptedInvite>, SharedError> {
        self.verify_ownership(owner_id, vault_id)?;

        let mut stmt = self
            .conn
            .prepare(
                "SELECT i.id, i.invitee_user_id, i.invitee_email, i.invitee_public_key, i.confirmation_key
                 FROM invites i
                 WHERE i.vault_id = ?1 AND i.status = 'accepted'
                   AND i.invitee_user_id IS NOT NULL
                   AND i.invitee_public_key IS NOT NULL
                   AND i.confirmation_key IS NOT NULL",
            )
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let rows = stmt
            .query_map(params![vault_id.as_str()], |row| {
                let id: String = row.get(0)?;
                let user_id: String = row.get(1)?;
                let email: String = row.get(2)?;
                let public_key: String = row.get(3)?;
                let confirmation_key: String = row.get(4)?;
                Ok((id, user_id, email, public_key, confirmation_key))
            })
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let mut result = Vec::new();
        for row in rows {
            let (id, user_id, email, public_key, confirmation_key) =
                row.map_err(|e| SharedError::Database(e.to_string()))?;
            result.push(AcceptedInvite {
                invite_id: InviteId::new(id),
                user_id: UserId::new(user_id),
                email,
                public_key_hex: public_key,
                confirmation_key_hex: confirmation_key,
            });
        }
        Ok(result)
    }

    /// Step 4: Owner completes the key exchange by sending encrypted vault key.
    /// This also inserts the new member into shared_vault_members.
    pub fn complete_invite(
        &self,
        invite_id: &InviteId,
        inviter_id: &UserId,
        encrypted_vault_key: &str,
        nonce: &str,
    ) -> Result<(), SharedError> {
        // Verify invite exists, is accepted, and caller is the inviter
        let row = self
            .conn
            .query_row(
                "SELECT vault_id, inviter_id, invitee_user_id, role, permission, status
                 FROM invites WHERE id = ?1",
                params![invite_id.as_str()],
                |row| {
                    let vault_id: String = row.get(0)?;
                    let inv_id: String = row.get(1)?;
                    let invitee_uid: Option<String> = row.get(2)?;
                    let role: String = row.get(3)?;
                    let perm: String = row.get(4)?;
                    let status: String = row.get(5)?;
                    Ok((vault_id, inv_id, invitee_uid, role, perm, status))
                },
            )
            .map_err(|_| {
                SharedError::InviteNotFound(format!("invite {} not found", invite_id.as_str()))
            })?;

        let (vault_id, actual_inviter_id, invitee_user_id, role, permission, status) = row;

        if status != "accepted" {
            return Err(SharedError::InvalidInviteState(format!(
                "invite is '{status}', expected 'accepted'"
            )));
        }

        if actual_inviter_id != inviter_id.as_str() {
            return Err(SharedError::Forbidden(
                "only the inviter can complete the key exchange".to_string(),
            ));
        }

        let invitee_uid = invitee_user_id.ok_or_else(|| {
            SharedError::InvalidInviteState("invitee_user_id is missing".to_string())
        })?;

        let now = Utc::now().to_rfc3339();

        // Transaction: update invite + insert member
        self.conn
            .execute_batch("BEGIN")
            .map_err(|e| SharedError::Database(e.to_string()))?;

        let result = (|| -> Result<(), SharedError> {
            // Update invite status
            self.conn
                .execute(
                    "UPDATE invites SET status = 'completed', encrypted_vault_key = ?1, vault_key_nonce = ?2, updated_at = ?3 WHERE id = ?4",
                    params![encrypted_vault_key, nonce, &now, invite_id.as_str()],
                )
                .map_err(|e| SharedError::Database(e.to_string()))?;

            // Insert member into shared_vault_members
            self.conn
                .execute(
                    "INSERT OR IGNORE INTO shared_vault_members (vault_id, user_id, encrypted_vault_key, vault_key_nonce, role, permission, invited_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        &vault_id,
                        &invitee_uid,
                        encrypted_vault_key,
                        nonce,
                        &role,
                        &permission,
                        &now,
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
}

/// Generate a random 6-digit invite code (e.g. "847291").
fn generate_invite_code() -> String {
    let n: u32 = rand::random::<u32>() % 1_000_000;
    format!("{n:06}")
}
