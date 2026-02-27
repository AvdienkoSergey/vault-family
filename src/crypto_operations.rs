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

pub struct RealCrypto; // PBKDF2 + AES-256-GCM
#[cfg(test)]
pub struct FakeCrypto; // заглушка для тестов

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

#[cfg(test)]
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_test_key() -> EncryptionKey {
        let crypto = RealCrypto;
        let password = MasterPassword::new("TestPassword123!".to_string());
        let salt = crypto.generate_salt();
        crypto.derive_encryption_key(&password, &salt)
    }

    fn make_test_entry(user_id: &str) -> PlainEntry {
        PlainEntry {
            id: EntryId::new("entry-1".to_string()),
            user_id: UserId::new(user_id.to_string()),
            service_name: ServiceName::new("GitHub".to_string()),
            service_url: ServiceUrl::new("https://github.com".to_string()),
            login: Login::new("alex-gh".to_string()),
            password: EntryPassword::new("gh-secret-123".to_string()),
            notes: "work account".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // ── generate_salt ──

    #[test]
    fn test_generate_salt_is_hex_32_chars() {
        let crypto = RealCrypto;
        let salt = crypto.generate_salt();
        // 16 байт = 32 hex символа
        assert_eq!(salt.as_str().len(), 32);
        assert!(salt.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_salt_unique() {
        let crypto = RealCrypto;
        let salt1 = crypto.generate_salt();
        let salt2 = crypto.generate_salt();
        assert_ne!(salt1.as_str(), salt2.as_str());
    }

    // ── hash_master_password ──

    #[test]
    fn test_hash_master_password_returns_valid_phc() {
        let crypto = RealCrypto;
        let password = MasterPassword::new("SuperSecret123!".to_string());
        let (hash, salt) = crypto.hash_master_password(&password).unwrap();
        // PHC format starts with $pbkdf2-sha256$
        assert!(hash.as_str().starts_with("$pbkdf2-sha256$"));
        assert!(!salt.as_str().is_empty());
    }

    #[test]
    fn test_hash_master_password_unique_per_call() {
        let crypto = RealCrypto;
        let password = MasterPassword::new("SamePassword!".to_string());
        let (hash1, _) = crypto.hash_master_password(&password).unwrap();
        let (hash2, _) = crypto.hash_master_password(&password).unwrap();
        // Разные соли → разные хеши
        assert_ne!(hash1.as_str(), hash2.as_str());
    }

    // ── verify_master_password ──

    #[test]
    fn test_verify_correct_password() {
        let crypto = RealCrypto;
        let password = MasterPassword::new("CorrectPassword!".to_string());
        let (hash, salt) = crypto.hash_master_password(&password).unwrap();

        let result = crypto
            .verify_master_password(&password, &hash, &salt)
            .unwrap();
        assert!(result);
    }

    #[test]
    fn test_verify_wrong_password() {
        let crypto = RealCrypto;
        let password = MasterPassword::new("CorrectPassword!".to_string());
        let (hash, salt) = crypto.hash_master_password(&password).unwrap();

        let wrong = MasterPassword::new("WrongPassword!".to_string());
        let result = crypto.verify_master_password(&wrong, &hash, &salt).unwrap();
        assert!(!result);
    }

    // ── derive_encryption_key ──

    #[test]
    fn test_derive_key_is_hex_64_chars() {
        let crypto = RealCrypto;
        let password = MasterPassword::new("MyPassword".to_string());
        let salt = EncryptionSalt::new("abcdef0123456789".to_string());
        let key = crypto.derive_encryption_key(&password, &salt);
        // 32 байта = 64 hex символа
        assert_eq!(key.as_str().len(), 64);
        assert!(key.as_str().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_derive_key_deterministic() {
        let crypto = RealCrypto;
        let password = MasterPassword::new("MyPassword".to_string());
        let salt = EncryptionSalt::new("fixed_salt_value".to_string());
        let key1 = crypto.derive_encryption_key(&password, &salt);
        let key2 = crypto.derive_encryption_key(&password, &salt);
        assert_eq!(key1.as_str(), key2.as_str());
    }

    #[test]
    fn test_derive_key_different_salt_different_key() {
        let crypto = RealCrypto;
        let password = MasterPassword::new("MyPassword".to_string());
        let salt1 = EncryptionSalt::new("salt_aaa".to_string());
        let salt2 = EncryptionSalt::new("salt_bbb".to_string());
        let key1 = crypto.derive_encryption_key(&password, &salt1);
        let key2 = crypto.derive_encryption_key(&password, &salt2);
        assert_ne!(key1.as_str(), key2.as_str());
    }

    #[test]
    fn test_derive_key_different_password_different_key() {
        let crypto = RealCrypto;
        let salt = EncryptionSalt::new("same_salt".to_string());
        let key1 =
            crypto.derive_encryption_key(&MasterPassword::new("Password1".to_string()), &salt);
        let key2 =
            crypto.derive_encryption_key(&MasterPassword::new("Password2".to_string()), &salt);
        assert_ne!(key1.as_str(), key2.as_str());
    }

    // ── encrypt_entry + decrypt_entry (roundtrip) ──

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let crypto = RealCrypto;
        let key = make_test_key();
        let plain = make_test_entry("user-1");

        let encrypted = crypto.encrypt_entry(&plain, &key).unwrap();
        let decrypted = crypto.decrypt_entry(&encrypted, &key).unwrap();

        assert_eq!(decrypted.service_name.as_str(), "GitHub");
        assert_eq!(decrypted.service_url.as_str(), "https://github.com");
        assert_eq!(decrypted.login.as_str(), "alex-gh");
        assert_eq!(decrypted.password.as_str(), "gh-secret-123");
        assert_eq!(decrypted.notes, "work account");
        assert_eq!(decrypted.id.as_str(), "entry-1");
        assert_eq!(decrypted.user_id.as_str(), "user-1");
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let crypto = RealCrypto;
        let key = make_test_key();
        let plain = make_test_entry("user-1");

        let enc1 = crypto.encrypt_entry(&plain, &key).unwrap();
        let enc2 = crypto.encrypt_entry(&plain, &key).unwrap();

        // Разные nonce → разный ciphertext
        assert_ne!(enc1.encrypted_data.as_str(), enc2.encrypted_data.as_str());
        assert_ne!(enc1.nonce.as_str(), enc2.nonce.as_str());
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let crypto = RealCrypto;
        let key = make_test_key();
        let wrong_key = make_test_key(); // другой ключ (другая соль)
        let plain = make_test_entry("user-1");

        let encrypted = crypto.encrypt_entry(&plain, &key).unwrap();
        let result = crypto.decrypt_entry(&encrypted, &wrong_key);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_with_invalid_key_fails() {
        let crypto = RealCrypto;
        let bad_key = EncryptionKey::new("not_valid_hex".to_string());
        let plain = make_test_entry("user-1");

        let result = crypto.encrypt_entry(&plain, &bad_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_with_short_key_fails() {
        let crypto = RealCrypto;
        // 16 байт вместо 32 — слишком короткий для AES-256
        let short_key = EncryptionKey::new("aa".repeat(16));
        let plain = make_test_entry("user-1");

        let result = crypto.encrypt_entry(&plain, &short_key);
        assert!(result.is_err());
    }
}
