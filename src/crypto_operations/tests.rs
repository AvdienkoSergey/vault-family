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
    let key1 = crypto.derive_encryption_key(&MasterPassword::new("Password1".to_string()), &salt);
    let key2 = crypto.derive_encryption_key(&MasterPassword::new("Password2".to_string()), &salt);
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
