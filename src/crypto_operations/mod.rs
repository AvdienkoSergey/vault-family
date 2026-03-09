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
use std::sync::LazyLock;
use types::{EncryptedEntry, EncryptionKey, PlainEntry};

/// PBKDF2 iteration count, configurable via `PBKDF2_ITERATIONS` env var.
/// Default: 600 000 (release) / 100 000 (debug).
static PBKDF2_ITERATIONS: LazyLock<u32> = LazyLock::new(|| {
    if let Ok(val) = std::env::var("PBKDF2_ITERATIONS")
        && let Ok(n) = val.parse::<u32>()
    {
        tracing::info!(iterations = n, "PBKDF2 iterations (from env)");
        return n;
    }
    let default = if cfg!(debug_assertions) {
        100_000
    } else {
        600_000
    };
    tracing::info!(iterations = default, "PBKDF2 iterations (default)");
    default
});

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

    // ── X25519 + raw AES-GCM (для shared vaults) ──

    /// Generate X25519 keypair. Returns (public_key_hex, private_key_hex).
    fn generate_x25519_keypair(&self) -> (String, String);

    /// Encrypt raw bytes with AES-256-GCM. Returns (ciphertext_hex, nonce_hex).
    fn encrypt_raw(&self, plaintext: &[u8], key_hex: &str)
    -> Result<(String, String), CryptoError>;

    /// Decrypt raw bytes with AES-256-GCM.
    fn decrypt_raw(
        &self,
        ciphertext_hex: &str,
        nonce_hex: &str,
        key_hex: &str,
    ) -> Result<Vec<u8>, CryptoError>;

    /// X25519 Diffie-Hellman → SHA-256 → AES-256 key (hex).
    fn x25519_derive_shared_key(
        &self,
        private_key_hex: &str,
        public_key_hex: &str,
    ) -> Result<String, CryptoError>;
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
        let rounds = *PBKDF2_ITERATIONS;
        let salt = SaltString::generate(&mut OsRng);
        let params = pbkdf2::Params {
            rounds,
            output_length: 32,
        };
        let password_hash = Pbkdf2
            .hash_password_customized(password.as_str().as_bytes(), None, None, params, &salt)
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
        let iterations = *PBKDF2_ITERATIONS;
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

    // ── X25519 + raw AES-GCM (для shared vaults) ──

    fn generate_x25519_keypair(&self) -> (String, String) {
        let secret_bytes: [u8; 32] = rand::random();
        let secret = x25519_dalek::StaticSecret::from(secret_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        (
            hex::encode(public.as_bytes()),
            hex::encode(secret.to_bytes()),
        )
    }

    fn encrypt_raw(
        &self,
        plaintext: &[u8],
        key_hex: &str,
    ) -> Result<(String, String), CryptoError> {
        let key_bytes = hex::decode(key_hex).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
        Ok((hex::encode(ciphertext), hex::encode(nonce)))
    }

    fn decrypt_raw(
        &self,
        ciphertext_hex: &str,
        nonce_hex: &str,
        key_hex: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        let key_bytes = hex::decode(key_hex).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let nonce_bytes = hex::decode(nonce_hex)
            .map_err(|e| CryptoError::InvalidData(format!("invalid nonce hex: {e}")))?;
        let ciphertext = hex::decode(ciphertext_hex)
            .map_err(|e| CryptoError::InvalidData(format!("invalid ciphertext hex: {e}")))?;
        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
    }

    fn x25519_derive_shared_key(
        &self,
        private_key_hex: &str,
        public_key_hex: &str,
    ) -> Result<String, CryptoError> {
        use sha2::Digest;
        let priv_bytes: [u8; 32] = hex::decode(private_key_hex)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("private key must be 32 bytes".to_string()))?;
        let pub_bytes: [u8; 32] = hex::decode(public_key_hex)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?
            .try_into()
            .map_err(|_| CryptoError::InvalidKey("public key must be 32 bytes".to_string()))?;

        let secret = x25519_dalek::StaticSecret::from(priv_bytes);
        let public = x25519_dalek::PublicKey::from(pub_bytes);
        let shared = secret.diffie_hellman(&public);

        let aes_key = Sha256::digest(shared.as_bytes());
        Ok(hex::encode(aes_key))
    }
}
