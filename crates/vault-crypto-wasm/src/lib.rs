//! Vault Family — WASM Crypto Module
//!
//! Client-side E2E encryption for React Native.
//! Uses the same algorithms and parameters as the Rust server:
//! - PBKDF2-HMAC-SHA256 (600 000 iterations) for key derivation
//! - AES-256-GCM for authenticated encryption
//! - X25519 Diffie-Hellman for shared vault key exchange
//!
//! All hex encoding matches the server convention.

use aes_gcm::aead::Aead;
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use pbkdf2::password_hash::{
    PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    rand_core::OsRng,
};
use pbkdf2::Pbkdf2;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

// ════════════════════════════════════════════════════════════════════
// Return types (serialized to JS via serde-wasm-bindgen)
// ════════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize)]
pub struct HashResult {
    pub hash: String,
    pub salt: String,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptResult {
    pub encrypted_data: String,
    pub nonce: String,
}

#[derive(Serialize, Deserialize)]
pub struct KeypairResult {
    pub public_key: String,
    pub private_key: String,
}

// ════════════════════════════════════════════════════════════════════
// Init
// ════════════════════════════════════════════════════════════════════

#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

// ════════════════════════════════════════════════════════════════════
// Master Password — PBKDF2-SHA256
// ════════════════════════════════════════════════════════════════════

/// Хэширование мастер-пароля для регистрации/аутентификации.
/// Возвращает { hash: PHC-строка, salt: строка }
///
/// Совместимо с серверным `RealCrypto::hash_master_password`.
#[wasm_bindgen(js_name = "hashMasterPassword")]
pub fn hash_master_password(password: &str) -> Result<JsValue, JsError> {
    let salt = SaltString::generate(&mut OsRng);
    let password_hash = Pbkdf2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| JsError::new(&format!("hashing failed: {e}")))?
        .to_string();

    let result = HashResult {
        hash: password_hash,
        salt: salt.to_string(),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Проверка мастер-пароля против хеша из БД.
/// hash — PHC-строка (содержит соль внутри).
///
/// Совместимо с серверным `RealCrypto::verify_master_password`.
#[wasm_bindgen(js_name = "verifyMasterPassword")]
pub fn verify_master_password(password: &str, hash: &str) -> Result<bool, JsError> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| JsError::new(&format!("invalid hash format: {e}")))?;
    Ok(Pbkdf2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok())
}

/// Деривация ключа шифрования из мастер-пароля + encryption_salt.
/// Возвращает hex-encoded 32-байтный ключ.
/// PBKDF2-HMAC-SHA256, 600 000 итераций.
///
/// Совместимо с серверным `RealCrypto::derive_encryption_key`.
#[wasm_bindgen(js_name = "deriveEncryptionKey")]
pub fn derive_encryption_key(password: &str, salt: &str) -> String {
    let mut key_bytes = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt.as_bytes(),
        600_000,
        &mut key_bytes,
    );
    let result = hex::encode(key_bytes);
    key_bytes.zeroize();
    result
}

// ════════════════════════════════════════════════════════════════════
// Salt Generation
// ════════════════════════════════════════════════════════════════════

/// Генерация случайной 16-байтной соли (hex).
/// Совместимо с серверным `RealCrypto::generate_salt`.
#[wasm_bindgen(js_name = "generateEncryptionSalt")]
pub fn generate_encryption_salt() -> Result<String, JsError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| JsError::new(&format!("RNG failed: {e}")))?;
    Ok(hex::encode(bytes))
}

// ════════════════════════════════════════════════════════════════════
// Entry Encryption — AES-256-GCM
// ════════════════════════════════════════════════════════════════════

/// Шифрование записи (JSON → AES-256-GCM).
/// entry_json: JSON-строка { service_name, service_url, login, password, notes }
/// key_hex: 32-байтный ключ шифрования (hex)
/// Возвращает { encrypted_data: hex, nonce: hex }
///
/// Совместимо с серверным `RealCrypto::encrypt_entry`.
#[wasm_bindgen(js_name = "encryptEntry")]
pub fn encrypt_entry(entry_json: &str, key_hex: &str) -> Result<JsValue, JsError> {
    let key_bytes =
        hex::decode(key_hex).map_err(|e| JsError::new(&format!("invalid key hex: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| JsError::new(&format!("invalid key: {e}")))?;

    let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, entry_json.as_bytes())
        .map_err(|e| JsError::new(&format!("encryption failed: {e}")))?;

    let result = EncryptResult {
        encrypted_data: hex::encode(&ciphertext),
        nonce: hex::encode(nonce),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Расшифровка записи (AES-256-GCM → JSON).
/// Возвращает JSON-строку { service_name, service_url, login, password, notes }
///
/// Промежуточные буферы зануляются (zeroize).
/// Совместимо с серверным `RealCrypto::decrypt_entry`.
#[wasm_bindgen(js_name = "decryptEntry")]
pub fn decrypt_entry(
    encrypted_data_hex: &str,
    nonce_hex: &str,
    key_hex: &str,
) -> Result<String, JsError> {
    let key_bytes =
        hex::decode(key_hex).map_err(|e| JsError::new(&format!("invalid key hex: {e}")))?;
    let nonce_bytes =
        hex::decode(nonce_hex).map_err(|e| JsError::new(&format!("invalid nonce hex: {e}")))?;
    let ciphertext = hex::decode(encrypted_data_hex)
        .map_err(|e| JsError::new(&format!("invalid ciphertext hex: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| JsError::new(&format!("invalid key: {e}")))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| JsError::new(&format!("decryption failed: {e}")))?;

    let result = match std::str::from_utf8(&plaintext) {
        Ok(s) => {
            let owned = s.to_string();
            plaintext.zeroize();
            Ok(owned)
        }
        Err(e) => {
            plaintext.zeroize();
            Err(JsError::new(&format!("invalid UTF-8: {e}")))
        }
    };

    result
}

// ════════════════════════════════════════════════════════════════════
// Raw AES-256-GCM (для shared vault keys, private keys и т.д.)
// ════════════════════════════════════════════════════════════════════

/// Шифрование сырых данных (hex → AES-256-GCM).
/// plaintext_hex: данные для шифрования (hex)
/// key_hex: 32-байтный ключ (hex)
/// Возвращает { encrypted_data: hex, nonce: hex }
///
/// Совместимо с серверным `RealCrypto::encrypt_raw`.
#[wasm_bindgen(js_name = "encryptRaw")]
pub fn encrypt_raw(plaintext_hex: &str, key_hex: &str) -> Result<JsValue, JsError> {
    let plaintext = hex::decode(plaintext_hex)
        .map_err(|e| JsError::new(&format!("invalid plaintext hex: {e}")))?;
    let key_bytes =
        hex::decode(key_hex).map_err(|e| JsError::new(&format!("invalid key hex: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| JsError::new(&format!("invalid key: {e}")))?;
    let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|e| JsError::new(&format!("encryption failed: {e}")))?;

    let result = EncryptResult {
        encrypted_data: hex::encode(ciphertext),
        nonce: hex::encode(nonce),
    };

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// Расшифровка сырых данных (AES-256-GCM → hex).
/// Возвращает plaintext как hex.
///
/// Совместимо с серверным `RealCrypto::decrypt_raw`.
#[wasm_bindgen(js_name = "decryptRaw")]
pub fn decrypt_raw(
    ciphertext_hex: &str,
    nonce_hex: &str,
    key_hex: &str,
) -> Result<String, JsError> {
    let key_bytes =
        hex::decode(key_hex).map_err(|e| JsError::new(&format!("invalid key hex: {e}")))?;
    let nonce_bytes =
        hex::decode(nonce_hex).map_err(|e| JsError::new(&format!("invalid nonce hex: {e}")))?;
    let ciphertext = hex::decode(ciphertext_hex)
        .map_err(|e| JsError::new(&format!("invalid ciphertext hex: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| JsError::new(&format!("invalid key: {e}")))?;
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);

    let mut plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| JsError::new(&format!("decryption failed: {e}")))?;

    let result = hex::encode(&plaintext);
    plaintext.zeroize();

    Ok(result)
}

// ════════════════════════════════════════════════════════════════════
// X25519 Diffie-Hellman (для shared vault key exchange)
// ════════════════════════════════════════════════════════════════════

/// Генерация X25519 keypair.
/// Возвращает { public_key: hex, private_key: hex }
///
/// Совместимо с серверным `RealCrypto::generate_x25519_keypair`.
#[wasm_bindgen(js_name = "generateX25519Keypair")]
pub fn generate_x25519_keypair() -> Result<JsValue, JsError> {
    let mut secret_bytes = [0u8; 32];
    getrandom::getrandom(&mut secret_bytes)
        .map_err(|e| JsError::new(&format!("RNG failed: {e}")))?;

    let secret = x25519_dalek::StaticSecret::from(secret_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);

    let result = KeypairResult {
        public_key: hex::encode(public.as_bytes()),
        private_key: hex::encode(secret.to_bytes()),
    };

    secret_bytes.zeroize();

    serde_wasm_bindgen::to_value(&result).map_err(|e| JsError::new(&e.to_string()))
}

/// X25519 Diffie-Hellman → SHA-256 → AES-256 key (hex).
/// Используется для обмена ключами shared vault.
///
/// Совместимо с серверным `RealCrypto::x25519_derive_shared_key`.
#[wasm_bindgen(js_name = "x25519DeriveSharedKey")]
pub fn x25519_derive_shared_key(
    private_key_hex: &str,
    public_key_hex: &str,
) -> Result<String, JsError> {
    use sha2::Digest;

    let priv_bytes: [u8; 32] = hex::decode(private_key_hex)
        .map_err(|e| JsError::new(&format!("invalid private key hex: {e}")))?
        .try_into()
        .map_err(|_| JsError::new("private key must be 32 bytes"))?;

    let pub_bytes: [u8; 32] = hex::decode(public_key_hex)
        .map_err(|e| JsError::new(&format!("invalid public key hex: {e}")))?
        .try_into()
        .map_err(|_| JsError::new("public key must be 32 bytes"))?;

    let secret = x25519_dalek::StaticSecret::from(priv_bytes);
    let public = x25519_dalek::PublicKey::from(pub_bytes);
    let shared = secret.diffie_hellman(&public);

    let aes_key = Sha256::digest(shared.as_bytes());
    Ok(hex::encode(aes_key))
}

// ════════════════════════════════════════════════════════════════════
// Shared Vault Key Generation
// ════════════════════════════════════════════════════════════════════

/// Генерация случайного 32-байтного ключа shared vault (hex).
#[wasm_bindgen(js_name = "generateSharedVaultKey")]
pub fn generate_shared_vault_key() -> Result<String, JsError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| JsError::new(&format!("RNG failed: {e}")))?;
    let result = hex::encode(bytes);
    bytes.zeroize();
    Ok(result)
}

// ════════════════════════════════════════════════════════════════════
// Password Generator
// ════════════════════════════════════════════════════════════════════

/// Генерация случайного пароля.
/// Совместимо с серверным `PasswordGenerator`.
#[wasm_bindgen(js_name = "generatePassword")]
pub fn generate_password(
    length: usize,
    lowercase: bool,
    uppercase: bool,
    digits: bool,
    symbols: bool,
) -> Result<String, JsError> {
    if !lowercase && !uppercase && !digits && !symbols {
        return Err(JsError::new("at least one character set must be enabled"));
    }
    if length < 8 {
        return Err(JsError::new("minimum password length is 8"));
    }

    let mut pool = Vec::new();
    if lowercase {
        pool.extend('a'..='z');
    }
    if uppercase {
        pool.extend('A'..='Z');
    }
    if digits {
        pool.extend('0'..='9');
    }
    if symbols {
        pool.extend("!@#$%^&*".chars());
    }

    let pool_len = pool.len();
    let mut result = String::with_capacity(length);

    // 4 random bytes per character (rejection-free modular selection)
    let mut buf = vec![0u8; length * 4];
    getrandom::getrandom(&mut buf)
        .map_err(|e| JsError::new(&format!("RNG failed: {e}")))?;

    for i in 0..length {
        let offset = i * 4;
        let val = u32::from_le_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]]);
        result.push(pool[val as usize % pool_len]);
    }

    buf.zeroize();
    Ok(result)
}
