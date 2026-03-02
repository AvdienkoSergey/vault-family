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

// ── generate_x25519_keypair ──

#[test]
fn test_generate_x25519_keypair_valid_hex() {
    let crypto = RealCrypto;
    let (public_hex, private_hex) = crypto.generate_x25519_keypair();
    // 32 bytes = 64 hex chars
    assert_eq!(public_hex.len(), 64);
    assert_eq!(private_hex.len(), 64);
    assert!(public_hex.chars().all(|c| c.is_ascii_hexdigit()));
    assert!(private_hex.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_generate_x25519_keypair_unique() {
    let crypto = RealCrypto;
    let (pub1, priv1) = crypto.generate_x25519_keypair();
    let (pub2, priv2) = crypto.generate_x25519_keypair();
    assert_ne!(pub1, pub2);
    assert_ne!(priv1, priv2);
}

// ── encrypt_raw + decrypt_raw ──

#[test]
fn test_encrypt_decrypt_raw_roundtrip() {
    let crypto = RealCrypto;
    let key = make_test_key();
    let plaintext = b"hello, shared vault!";

    let (ciphertext, nonce) = crypto.encrypt_raw(plaintext, key.as_str()).unwrap();
    let decrypted = crypto
        .decrypt_raw(&ciphertext, &nonce, key.as_str())
        .unwrap();

    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_raw_wrong_key_fails() {
    let crypto = RealCrypto;
    let key1 = make_test_key();
    let key2 = make_test_key(); // different key (different salt)
    let plaintext = b"secret data";

    let (ciphertext, nonce) = crypto.encrypt_raw(plaintext, key1.as_str()).unwrap();
    let result = crypto.decrypt_raw(&ciphertext, &nonce, key2.as_str());

    assert!(result.is_err());
}

#[test]
fn test_encrypt_raw_produces_different_ciphertext() {
    let crypto = RealCrypto;
    let key = make_test_key();
    let plaintext = b"same data";

    let (ct1, n1) = crypto.encrypt_raw(plaintext, key.as_str()).unwrap();
    let (ct2, n2) = crypto.encrypt_raw(plaintext, key.as_str()).unwrap();

    // Different nonce → different ciphertext
    assert_ne!(ct1, ct2);
    assert_ne!(n1, n2);
}

// ── x25519_derive_shared_key ──

#[test]
fn test_x25519_derive_shared_key_deterministic() {
    let crypto = RealCrypto;
    let (pub_a, priv_a) = crypto.generate_x25519_keypair();

    let key1 = crypto.x25519_derive_shared_key(&priv_a, &pub_a).unwrap();
    let key2 = crypto.x25519_derive_shared_key(&priv_a, &pub_a).unwrap();

    assert_eq!(key1, key2);
    assert_eq!(key1.len(), 64); // SHA-256 = 32 bytes = 64 hex
}

#[test]
fn test_x25519_dh_commutative() {
    // Critical: DH(a_priv, b_pub) == DH(b_priv, a_pub)
    let crypto = RealCrypto;
    let (pub_a, priv_a) = crypto.generate_x25519_keypair();
    let (pub_b, priv_b) = crypto.generate_x25519_keypair();

    let key_ab = crypto.x25519_derive_shared_key(&priv_a, &pub_b).unwrap();
    let key_ba = crypto.x25519_derive_shared_key(&priv_b, &pub_a).unwrap();

    assert_eq!(key_ab, key_ba);
}

#[test]
fn test_x25519_different_pairs_different_keys() {
    let crypto = RealCrypto;
    let (_pub_a, priv_a) = crypto.generate_x25519_keypair();
    let (pub_b, _priv_b) = crypto.generate_x25519_keypair();
    let (pub_c, _priv_c) = crypto.generate_x25519_keypair();

    let key_ab = crypto.x25519_derive_shared_key(&priv_a, &pub_b).unwrap();
    let key_ac = crypto.x25519_derive_shared_key(&priv_a, &pub_c).unwrap();

    assert_ne!(key_ab, key_ac);
}

// ── Full X25519 + AES-GCM roundtrip (simulates shared vault key wrapping) ──

#[test]
fn test_x25519_key_wrapping_roundtrip() {
    let crypto = RealCrypto;

    // 1. Alice and Bob generate keypairs
    let (_pub_alice, priv_alice) = crypto.generate_x25519_keypair();
    let (pub_bob, priv_bob) = crypto.generate_x25519_keypair();

    // 2. Shared vault key (random 32 bytes)
    let vault_key: [u8; 32] = rand::random();

    // 3. Alice wraps vault key for Bob using ephemeral keypair
    let (ephemeral_pub, ephemeral_priv) = crypto.generate_x25519_keypair();
    let shared_aes = crypto
        .x25519_derive_shared_key(&ephemeral_priv, &pub_bob)
        .unwrap();
    let (encrypted_vault_key, nonce) = crypto.encrypt_raw(&vault_key, &shared_aes).unwrap();

    // 4. Bob unwraps using his private key + ephemeral public
    let bob_shared_aes = crypto
        .x25519_derive_shared_key(&priv_bob, &ephemeral_pub)
        .unwrap();
    let decrypted = crypto
        .decrypt_raw(&encrypted_vault_key, &nonce, &bob_shared_aes)
        .unwrap();

    assert_eq!(decrypted, vault_key);

    // 5. Alice cannot be impersonated: wrong private key fails
    let wrong_shared = crypto
        .x25519_derive_shared_key(&priv_alice, &ephemeral_pub)
        .unwrap();
    let result = crypto.decrypt_raw(&encrypted_vault_key, &nonce, &wrong_shared);
    assert!(result.is_err());
}
