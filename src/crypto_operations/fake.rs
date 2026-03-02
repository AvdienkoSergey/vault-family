use super::{CryptoError, CryptoProvider};
use crate::types::{
    AuthSalt, EncryptedData, EncryptedEntry, EncryptionKey, EncryptionSalt, EntryId, EntryPassword,
    Login, MasterPassword, MasterPasswordHash, Nonce, PlainEntry, ServiceName, ServiceUrl, UserId,
};

#[derive(Clone)]
pub struct FakeCrypto; // заглушка для тестов

impl CryptoProvider for FakeCrypto {
    fn encrypt_entry(
        &self,
        entry: &PlainEntry,
        key: &EncryptionKey,
    ) -> Result<EncryptedEntry, CryptoError> {
        assert!(!key.as_str().is_empty(), "Encryption key must not be empty");
        let json = serde_json::json!({
            "service_name": entry.service_name.as_str(),
            "service_url": entry.service_url.as_str(),
            "login": entry.login.as_str(),
            "password": entry.password.as_str(),
            "notes": entry.notes,
        })
        .to_string();

        Ok(EncryptedEntry {
            id: EntryId::new(entry.id.as_str().to_string()),
            user_id: UserId::new(entry.user_id.as_str().to_string()),
            encrypted_data: EncryptedData::new(json),
            nonce: Nonce::new("fake_nonce".to_string()),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        })
    }
    fn decrypt_entry(
        &self,
        entry: &EncryptedEntry,
        key: &EncryptionKey,
    ) -> Result<PlainEntry, CryptoError> {
        assert!(!key.as_str().is_empty(), "Encryption key must not be empty");
        let json: serde_json::Value = serde_json::from_str(entry.encrypted_data.as_str())
            .map_err(|e| CryptoError::InvalidData(e.to_string()))?;

        Ok(PlainEntry {
            id: EntryId::new(entry.id.as_str().to_string()),
            user_id: UserId::new(entry.user_id.as_str().to_string()),
            service_name: ServiceName::new(
                json["service_name"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            ),
            service_url: ServiceUrl::new(
                json["service_url"].as_str().unwrap_or_default().to_string(),
            ),
            login: Login::new(json["login"].as_str().unwrap_or_default().to_string()),
            password: EntryPassword::new(json["password"].as_str().unwrap_or_default().to_string()),
            notes: json["notes"].as_str().unwrap_or("").to_string(),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        })
    }
    fn hash_master_password(
        &self,
        password: &MasterPassword,
    ) -> Result<(MasterPasswordHash, AuthSalt), CryptoError> {
        let fake_hash = password.as_str().chars().rev().collect::<String>();
        let fake_salt = "fake_salt_16bytes".to_string();
        Ok((MasterPasswordHash::new(fake_hash), AuthSalt::new(fake_salt)))
    }
    fn verify_master_password(
        &self,
        password: &MasterPassword,
        hash: &MasterPasswordHash,
        _salt: &AuthSalt,
    ) -> Result<bool, CryptoError> {
        let expected: String = password.as_str().chars().rev().collect();
        Ok(expected == hash.as_str())
    }
    fn derive_encryption_key(
        &self,
        password: &MasterPassword,
        salt: &EncryptionSalt,
    ) -> EncryptionKey {
        EncryptionKey::new(format!("key_{}_{}", password.as_str(), salt.as_str()))
    }
    fn generate_salt(&self) -> EncryptionSalt {
        EncryptionSalt::new("fake_enc_salt_16".to_string())
    }

    // ── X25519 + raw AES-GCM fakes (для shared vault тестов) ──

    fn generate_x25519_keypair(&self) -> (String, String) {
        // Deterministic fake: 32-byte hex keys
        (
            "aa".repeat(32), // public key: 64 hex chars
            "bb".repeat(32), // private key: 64 hex chars
        )
    }

    fn encrypt_raw(
        &self,
        plaintext: &[u8],
        key_hex: &str,
    ) -> Result<(String, String), CryptoError> {
        assert!(!key_hex.is_empty(), "Key must not be empty");
        // Fake: just hex-encode the plaintext (no actual encryption)
        Ok((hex::encode(plaintext), "fake_raw_nonce".to_string()))
    }

    fn decrypt_raw(
        &self,
        ciphertext_hex: &str,
        _nonce_hex: &str,
        key_hex: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        assert!(!key_hex.is_empty(), "Key must not be empty");
        // Fake: just hex-decode back
        hex::decode(ciphertext_hex).map_err(|e| CryptoError::InvalidData(e.to_string()))
    }

    fn x25519_derive_shared_key(
        &self,
        private_key_hex: &str,
        public_key_hex: &str,
    ) -> Result<String, CryptoError> {
        // Deterministic fake: SHA-256(private || public) → 64-char hex
        use sha2::{Digest, Sha256};
        let combined = format!("{}{}", private_key_hex, public_key_hex);
        Ok(hex::encode(Sha256::digest(combined.as_bytes())))
    }
}
