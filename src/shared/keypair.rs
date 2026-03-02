use crate::crypto_operations::{CryptoError, CryptoProvider};
use crate::types::{EncryptionKey, UserId, UserPublicKey};
use chrono::Utc;
use rusqlite::params;

use super::SharedDB;
use super::error::SharedError;

impl<C: CryptoProvider> SharedDB<C> {
    /// Generate and store X25519 keypair, encrypted with user's EncryptionKey.
    pub fn save_user_keypair(
        &self,
        user_id: &UserId,
        encryption_key: &EncryptionKey,
    ) -> Result<UserPublicKey, SharedError> {
        let (public_hex, private_hex) = self.crypto.generate_x25519_keypair();
        let private_bytes = hex::decode(&private_hex)
            .map_err(|e| SharedError::Crypto(CryptoError::InvalidKey(e.to_string())))?;
        let (encrypted_private, nonce) = self
            .crypto
            .encrypt_raw(&private_bytes, encryption_key.as_str())?;

        self.conn
            .execute(
                "INSERT INTO user_keys (user_id, public_key, encrypted_private_key, private_key_nonce, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    user_id.as_str(),
                    &public_hex,
                    &encrypted_private,
                    &nonce,
                    Utc::now().to_rfc3339(),
                ],
            )
            .map_err(|e| SharedError::Database(format!("Failed to save user keypair: {e}")))?;

        Ok(UserPublicKey::new(public_hex))
    }

    /// Check if user has a keypair.
    pub fn has_user_keypair(&self, user_id: &UserId) -> Result<bool, SharedError> {
        let count: i64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM user_keys WHERE user_id = ?1",
                params![user_id.as_str()],
                |row| row.get(0),
            )
            .map_err(|e| SharedError::Database(format!("Failed to check user keypair: {e}")))?;
        Ok(count > 0)
    }

    /// Get user's public key.
    pub fn get_user_public_key(&self, user_id: &UserId) -> Result<UserPublicKey, SharedError> {
        self.conn
            .query_row(
                "SELECT public_key FROM user_keys WHERE user_id = ?1",
                params![user_id.as_str()],
                |row| {
                    let pk: String = row.get(0)?;
                    Ok(UserPublicKey::new(pk))
                },
            )
            .map_err(|e| SharedError::NotFound(format!("User keypair not found: {e}")))
    }

    /// Decrypt user's X25519 private key using their EncryptionKey.
    pub(crate) fn decrypt_user_private_key(
        &self,
        user_id: &UserId,
        encryption_key: &EncryptionKey,
    ) -> Result<String, SharedError> {
        let (encrypted, nonce) = self
            .conn
            .query_row(
                "SELECT encrypted_private_key, private_key_nonce FROM user_keys WHERE user_id = ?1",
                params![user_id.as_str()],
                |row| {
                    let enc: String = row.get(0)?;
                    let n: String = row.get(1)?;
                    Ok((enc, n))
                },
            )
            .map_err(|e| SharedError::NotFound(format!("User keypair not found: {e}")))?;

        let private_bytes = self
            .crypto
            .decrypt_raw(&encrypted, &nonce, encryption_key.as_str())?;
        Ok(hex::encode(private_bytes))
    }
}
