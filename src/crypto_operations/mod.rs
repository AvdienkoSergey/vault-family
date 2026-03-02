use crate::types;
use crate::types::{
    AuthSalt, EncryptedData, EncryptionSalt, EntryId, EntryPassword, Login, MasterPassword,
    MasterPasswordHash, Nonce, ServiceName, ServiceUrl, UserId,
};
use aes_gcm::aead::Aead;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use pbkdf2::{
    Pbkdf2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use sha2::Sha256;
use std::fmt;
use types::{EncryptedEntry, EncryptionKey, PlainEntry};

#[cfg(test)]
mod fake;
#[cfg(test)]
pub use fake::FakeCrypto;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum CryptoError {
    EncryptionFailed(String),
    DecryptionFailed(String),
    HashingFailed(String),
    VerificationFailed(String),
    InvalidKey(String),
    InvalidData(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::EncryptionFailed(msg) => write!(f, "encryption failed: {msg}"),
            CryptoError::DecryptionFailed(msg) => write!(f, "decryption failed: {msg}"),
            CryptoError::HashingFailed(msg) => write!(f, "hashing failed: {msg}"),
            CryptoError::VerificationFailed(msg) => write!(f, "verification failed: {msg}"),
            CryptoError::InvalidKey(msg) => write!(f, "invalid key: {msg}"),
            CryptoError::InvalidData(msg) => write!(f, "invalid data: {msg}"),
        }
    }
}

pub trait CryptoProvider {
    fn encrypt_entry(
        &self,
        entry: &PlainEntry,
        key: &EncryptionKey,
    ) -> Result<EncryptedEntry, CryptoError>;
    fn decrypt_entry(
        &self,
        entry: &EncryptedEntry,
        key: &EncryptionKey,
    ) -> Result<PlainEntry, CryptoError>;
    fn hash_master_password(
        &self,
        password: &MasterPassword,
    ) -> Result<(MasterPasswordHash, AuthSalt), CryptoError>;
    fn verify_master_password(
        &self,
        password: &MasterPassword,
        hash: &MasterPasswordHash,
        salt: &AuthSalt,
    ) -> Result<bool, CryptoError>;
    fn derive_encryption_key(
        &self,
        password: &MasterPassword,
        salt: &EncryptionSalt,
    ) -> EncryptionKey;
    fn generate_salt(&self) -> EncryptionSalt;
}

#[derive(Clone)]
pub struct RealCrypto; // PBKDF2 + AES-256-GCM

impl CryptoProvider for RealCrypto {
    /// PlainEntry + EncryptionKey → EncryptedEntry
    /// Единственный способ создать EncryptedEntry
    fn encrypt_entry(
        &self,
        entry: &PlainEntry,
        key: &EncryptionKey,
    ) -> Result<EncryptedEntry, CryptoError> {
        let json = serde_json::json!({
            "service_name": entry.service_name.as_str(),
            "service_url": entry.service_url.as_str(),
            "login": entry.login.as_str(),
            "password": entry.password.as_str(),
            "notes": entry.notes,
        })
        .to_string();

        let key_bytes =
            hex::decode(key.as_str()).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;

        let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, json.as_bytes())
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

        Ok(EncryptedEntry {
            id: EntryId::new(entry.id.as_str().to_string()),
            user_id: UserId::new(entry.user_id.as_str().to_string()),
            encrypted_data: EncryptedData::new(hex::encode(&ciphertext)),
            nonce: Nonce::new(hex::encode(nonce)),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        })
    }

    /// EncryptedEntry + EncryptionKey → PlainEntry
    /// Единственный способ получить PlainEntry
    fn decrypt_entry(
        &self,
        entry: &EncryptedEntry,
        key: &EncryptionKey,
    ) -> Result<PlainEntry, CryptoError> {
        let key_bytes =
            hex::decode(key.as_str()).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let nonce_bytes = hex::decode(entry.nonce.as_str())
            .map_err(|e| CryptoError::InvalidData(format!("invalid nonce hex: {e}")))?;
        let ciphertext = hex::decode(entry.encrypted_data.as_str())
            .map_err(|e| CryptoError::InvalidData(format!("invalid ciphertext hex: {e}")))?;

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

        let json: serde_json::Value = serde_json::from_slice(&plaintext)
            .map_err(|e| CryptoError::InvalidData(format!("invalid JSON: {e}")))?;

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

    /// Регистрация: хэшируем мастер-пароль для хранения в БД.
    /// Возвращает хеш + соль (оба сохраняются в таблице users)
    fn hash_master_password(
        &self,
        password: &MasterPassword,
    ) -> Result<(MasterPasswordHash, AuthSalt), CryptoError> {
        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Pbkdf2
            .hash_password(password.as_str().as_bytes(), &salt)
            .map_err(|e| CryptoError::HashingFailed(e.to_string()))?
            .to_string();
        Ok((
            MasterPasswordHash::new(password_hash),
            AuthSalt::new(salt.to_string()),
        ))
    }

    /// Логин: проверяем мастер-пароль против хеша из БД
    fn verify_master_password(
        &self,
        password: &MasterPassword,
        hash: &MasterPasswordHash,
        _salt: &AuthSalt,
    ) -> Result<bool, CryptoError> {
        let parsed_hash = PasswordHash::new(hash.as_str())
            .map_err(|e| CryptoError::VerificationFailed(e.to_string()))?;
        Ok(Pbkdf2
            .verify_password(password.as_str().as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// После успешного логина: деривируем ключ шифрования.
    /// Использует отдельную соль (encryption_salt, не auth_salt)
    fn derive_encryption_key(
        &self,
        password: &MasterPassword,
        salt: &EncryptionSalt,
    ) -> EncryptionKey {
        let iterations = 600_000;
        let mut bytes = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(
            password.as_str().as_bytes(),
            salt.as_str().as_bytes(),
            iterations,
            &mut bytes,
        );
        EncryptionKey::new(hex::encode(bytes))
    }

    /// Генерация случайной соли (16 байт) для деривации ключа шифрования.
    /// Вызывается один раз при регистрации, сохраняется в таблицу users
    fn generate_salt(&self) -> EncryptionSalt {
        let bytes: [u8; 16] = rand::random();
        EncryptionSalt::new(hex::encode(bytes))
    }
}
