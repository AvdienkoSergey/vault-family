use crate::types;
use types::{ PlainEntry, EncryptionKey, EncryptedEntry };
use crate::types::{
    MasterPassword,
    MasterPasswordHash,
    AuthSalt,
    EncryptionSalt,
    EntryId,
    UserId,
    EncryptedData,
    Nonce,
    ServiceName,
    ServiceUrl,
    Email,
    EntryPassword
};

pub trait CryptoProvider {
    fn encrypt_entry(&self, entry: &PlainEntry, key: &EncryptionKey) -> EncryptedEntry;
    fn decrypt_entry(&self, entry: &EncryptedEntry, key: &EncryptionKey) -> PlainEntry;
    fn hash_master_password(&self, password: &MasterPassword) -> (MasterPasswordHash, AuthSalt);
    fn verify_master_password(&self, password: &MasterPassword, hash: &MasterPasswordHash, salt: &AuthSalt) -> bool;
    fn derive_encryption_key(&self, password: &MasterPassword, salt: &EncryptionSalt) -> EncryptionKey;
    fn generate_salt(&self) -> EncryptionSalt;
}

pub struct RealCrypto;       // настоящий PBKDF2 + AES
pub struct FakeCrypto;       // заглушка для тестов

impl CryptoProvider for RealCrypto {
    /// PlainEntry + EncryptionKey → EncryptedEntry
    /// Единственный способ создать EncryptedEntry
    fn encrypt_entry(&self, entry: &PlainEntry, key: &EncryptionKey) -> EncryptedEntry {
        todo!()
    }
    /// EncryptedEntry + EncryptionKey → PlainEntry
    /// Единственный способ получить PlainEntry
    fn decrypt_entry(&self, entry: &EncryptedEntry, key: &EncryptionKey) -> PlainEntry {
        todo!()
    }
    /// Регистрация: хэшируем мастер-пароль для хранения в БД.
    /// Возвращает хеш + соль (оба сохраняются в таблице users)
    fn hash_master_password(&self, password: &MasterPassword) -> (MasterPasswordHash, AuthSalt) {
        todo!()
    }
    /// Логин: проверяем мастер-пароль против хеша из БД
    fn verify_master_password(&self, password: &MasterPassword, hash: &MasterPasswordHash, salt: &AuthSalt) -> bool {
        todo!()
    }
    /// После успешного логина: деривируем ключ шифрования.
    /// Использует отдельную соль (encryption_salt, не auth_salt)
    fn derive_encryption_key(&self, password: &MasterPassword, salt: &EncryptionSalt) -> EncryptionKey {
        todo!()
    }
    /// Генерация случайной соли (16 байт) для деривации ключа шифрования.
    /// Вызывается один раз при регистрации, сохраняется в таблицу users
    fn generate_salt(&self) -> EncryptionSalt {
        todo!()
    }
}

impl CryptoProvider for FakeCrypto {
    fn encrypt_entry(&self, entry: &PlainEntry, key: &EncryptionKey) -> EncryptedEntry {
        let json = serde_json::json!({
        "service_name": entry.service_name.as_str(),
        "service_url": entry.service_url.as_str(),
        "email": entry.email.as_str(),
        "password": entry.password.as_str(),
        "notes": entry.notes,
    }).to_string();

        EncryptedEntry {
            id: EntryId::new(entry.id.as_str().to_string()),
            user_id: UserId::new(entry.user_id.as_str().to_string()),
            encrypted_data: EncryptedData::new(json),  // "шифрование" = просто JSON
            nonce: Nonce::new("fake_nonce".to_string()),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        }
    }
    fn decrypt_entry(&self, entry: &EncryptedEntry, key: &EncryptionKey) -> PlainEntry {
        let json: serde_json::Value = serde_json::from_str(
            entry.encrypted_data.as_str()
        ).expect("Invalid JSON");

        PlainEntry {
            id: EntryId::new(entry.id.as_str().to_string()),
            user_id: UserId::new(entry.user_id.as_str().to_string()),
            service_name: ServiceName::new(json["service_name"].as_str().unwrap().to_string()),
            service_url: ServiceUrl::new(json["service_url"].as_str().unwrap().to_string()),
            email: Email::new(json["email"].as_str().unwrap().to_string()),
            password: EntryPassword::new(json["password"].as_str().unwrap().to_string()),
            notes: json["notes"].as_str().unwrap_or("").to_string(),
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        }
    }
    fn hash_master_password(&self, password: &MasterPassword) -> (MasterPasswordHash, AuthSalt) {
        // Заглушка: "хеш" = сам пароль задом наперёд
        let fake_hash = password.as_str().chars().rev().collect::<String>();
        let fake_salt = "fake_salt_16bytes".to_string();
        (
            MasterPasswordHash::new(fake_hash),
            AuthSalt::new(fake_salt),
        )
    }
    fn verify_master_password(
        &self,
        password: &MasterPassword,
        hash: &MasterPasswordHash,
        salt: &AuthSalt,
    ) -> bool {
        let expected: String = password.as_str().chars().rev().collect();
        expected == hash.as_str()
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
