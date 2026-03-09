//! Модуль Хранилище — работа с пользователями и зашифрованными записями.
//!
//! Typestate-машина БД:
//!   DB<Closed> → open() → DB<Open> → enter(VaultPass) → DB<Authenticated>
//!
//! **Не знает про JWT, refresh-токены, HTTP.**
//! Единственный вход в Authenticated — через `VaultPass` (Пропуск).

use crate::crypto_operations::{CryptoError, CryptoProvider};
use crate::types;
use crate::types::{AuthSalt, EncryptedData, EncryptionSalt, MasterPasswordHash, Nonce};
use chrono::Utc;
use rusqlite::Connection;
use std::marker::PhantomData;
use types::{
    AuthSession, Email, EncryptedEntry, EntryId, MasterPassword, PlainEntry, User, UserId,
    VaultPass,
};
use uuid::Uuid;

// ════════════════════════════════════════════════════════════════════
// Typestate: Closed → Open → Authenticated
// ════════════════════════════════════════════════════════════════════

mod sealed {
    pub trait Sealed {}
}

pub struct Closed;
pub struct Open;
pub struct Authenticated;

pub trait ConnectionState: sealed::Sealed {
    type Conn;
    type Session;
}

impl sealed::Sealed for Closed {}
impl sealed::Sealed for Open {}
impl sealed::Sealed for Authenticated {}

impl ConnectionState for Closed {
    type Conn = ();
    type Session = ();
}

impl ConnectionState for Open {
    type Conn = Connection;
    type Session = ();
}

impl ConnectionState for Authenticated {
    type Conn = Connection;
    type Session = AuthSession;
}

pub struct DB<State: ConnectionState, C: CryptoProvider> {
    conn: State::Conn,
    session: State::Session,
    crypto: C,
    _state: PhantomData<State>,
}

// ════════════════════════════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum VaultError {
    Connection(String),
    Schema(String),
    Database(String),
    Auth(String),
    Crypto(CryptoError),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Connection(msg) => write!(f, "connection error: {msg}"),
            VaultError::Schema(msg) => write!(f, "schema error: {msg}"),
            VaultError::Database(msg) => write!(f, "database error: {msg}"),
            VaultError::Auth(msg) => write!(f, "auth error: {msg}"),
            VaultError::Crypto(err) => write!(f, "crypto error: {err}"),
        }
    }
}

impl From<CryptoError> for VaultError {
    fn from(err: CryptoError) -> Self {
        VaultError::Crypto(err)
    }
}

impl std::error::Error for VaultError {}

// ════════════════════════════════════════════════════════════════════
// Closed: создать и открыть
// ════════════════════════════════════════════════════════════════════

impl<C: CryptoProvider> DB<Closed, C> {
    pub fn new(crypto: C) -> Self {
        Self {
            conn: (),
            session: (),
            crypto,
            _state: PhantomData,
        }
    }

    /// Closed → Open (потребляет self!)
    ///
    /// Схема: только users + entries. Никаких refresh_tokens —
    /// это забота модуля auth/.
    pub fn open(self, path: &str) -> Result<DB<Open, C>, VaultError> {
        let crypto = self.crypto;
        let conn = Connection::open(path)
            .map_err(|e| VaultError::Connection(format!("Unable to open database: {}", e)))?;

        conn.execute_batch(
            "BEGIN;
            CREATE TABLE IF NOT EXISTS users (
                id              TEXT PRIMARY KEY,
                email           TEXT UNIQUE NOT NULL,
                master_hash     TEXT NOT NULL,
                auth_salt       TEXT NOT NULL,
                encryption_salt TEXT NOT NULL,
                created_at      TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS entries (
                id              TEXT PRIMARY KEY,
                user_id         TEXT NOT NULL,
                encrypted_data  TEXT NOT NULL,
                nonce           TEXT NOT NULL,
                created_at      TEXT NOT NULL,
                updated_at      TEXT NOT NULL
            );
            COMMIT;",
        )
        .map_err(|e| VaultError::Schema(format!("Failed to create tables: {}", e)))?;

        Ok(DB {
            conn,
            session: (),
            crypto,
            _state: PhantomData,
        })
    }
}

// ════════════════════════════════════════════════════════════════════
// Open: регистрация, выдача пропуска, вход
// ════════════════════════════════════════════════════════════════════

impl<C: CryptoProvider> DB<Open, C> {
    /// Создать пользователя (регистрация, не требует логина).
    pub fn create_user(
        &self,
        email: Email,
        master_password: MasterPassword,
    ) -> Result<User, VaultError> {
        let crypto = &self.crypto;
        let id = UserId::new(Uuid::new_v4().to_string());
        let (master_hash, auth_salt) = crypto.hash_master_password(&master_password)?;
        let encryption_salt = crypto.generate_salt();
        let created_at = Utc::now();

        let user = User {
            id,
            email,
            master_hash,
            auth_salt,
            encryption_salt,
            created_at,
        };

        self.conn
            .execute(
                "INSERT INTO users (id, email, master_hash, auth_salt, encryption_salt, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6);",
                (
                    user.id.as_str(),
                    user.email.as_str(),
                    user.master_hash.as_str(),
                    user.auth_salt.as_str(),
                    user.encryption_salt.as_str(),
                    user.created_at.to_string(),
                ),
            )
            .map_err(|e| VaultError::Database(format!("Failed to add User: {}", e)))?;

        Ok(user)
    }

    /// Проверить пароль и выдать Пропуск (VaultPass).
    ///
    /// **Заимствует `&self`** — не потребляет DB.
    /// После получения пропуска вызывайте `enter()`.
    ///
    /// ```ignore
    /// let pass = db.create_pass(email, password)?;
    /// let db = db.enter(pass)?;
    /// ```
    pub fn create_pass(
        &self,
        email: Email,
        master_password: MasterPassword,
    ) -> Result<VaultPass, VaultError> {
        let crypto = &self.crypto;

        let user = {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT id, email, master_hash, auth_salt, encryption_salt, created_at
                     FROM users WHERE email = ?1",
                )
                .map_err(|e| VaultError::Database(format!("Failed to prepare statement: {}", e)))?;

            stmt.query_row(rusqlite::params![email.as_str()], |row| {
                Ok(User {
                    id: UserId::new(row.get(0)?),
                    email: Email::new(row.get(1)?),
                    master_hash: MasterPasswordHash::new(row.get(2)?),
                    auth_salt: AuthSalt::new(row.get(3)?),
                    encryption_salt: EncryptionSalt::new(row.get(4)?),
                    created_at: row
                        .get::<_, String>(5)?
                        .parse::<chrono::DateTime<Utc>>()
                        .unwrap_or_else(|_| Utc::now()),
                })
            })
            .map_err(|e| VaultError::Database(format!("User not found: {}", e)))?
        };

        let is_verify =
            crypto.verify_master_password(&master_password, &user.master_hash, &user.auth_salt)?;
        if !is_verify {
            return Err(VaultError::Auth("Invalid master password".to_string()));
        }

        let key = crypto.derive_encryption_key(&master_password, &user.encryption_salt);

        Ok(VaultPass::new(user.id, user.email, key))
    }

    /// Update master password hash for an existing user.
    ///
    /// Called after password change from a trusted device.
    /// Only updates `master_hash` and `auth_salt` — `encryption_salt` stays the same
    /// so the derived encryption key doesn't change (vault_key is re-wrapped on client).
    pub fn update_password(
        &self,
        email: &Email,
        new_password: MasterPassword,
    ) -> Result<(), VaultError> {
        let crypto = &self.crypto;
        let (new_hash, new_salt) = crypto.hash_master_password(&new_password)?;

        let rows = self
            .conn
            .execute(
                "UPDATE users SET master_hash = ?1, auth_salt = ?2 WHERE email = ?3",
                (new_hash.as_str(), new_salt.as_str(), email.as_str()),
            )
            .map_err(|e| VaultError::Database(format!("Failed to update password: {e}")))?;

        if rows == 0 {
            return Err(VaultError::Database("User not found".to_string()));
        }
        Ok(())
    }

    /// Look up user by email → UserId (needed for invite by email in shared vaults).
    /// Read-only query, does not require authentication.
    pub fn find_user_id_by_email(&self, email: &Email) -> Result<UserId, VaultError> {
        self.conn
            .query_row(
                "SELECT id FROM users WHERE email = ?1",
                rusqlite::params![email.as_str()],
                |row| {
                    let id: String = row.get(0)?;
                    Ok(UserId::new(id))
                },
            )
            .map_err(|e| VaultError::Database(format!("User not found: {e}")))
    }

    /// Войти в Хранилище с Пропуском.
    ///
    /// **Потребляет self** — DB переходит в Authenticated.
    /// Проверяет что пользователь существует в vault.db.
    ///
    /// Не знает КАК был получен пропуск — это дело Вахтера.
    pub fn enter(self, pass: VaultPass) -> Result<DB<Authenticated, C>, VaultError> {
        let conn = self.conn;
        let (user_id, _pass_email, encryption_key) = pass.into_parts();

        // Проверяем что user существует и берём актуальные данные из БД
        let user = {
            let mut stmt = conn
                .prepare("SELECT id, email FROM users WHERE id = ?1")
                .map_err(|e| VaultError::Database(format!("Failed to prepare statement: {e}")))?;
            stmt.query_row(rusqlite::params![user_id.as_str()], |row| {
                Ok(types::SessionUser {
                    id: UserId::new(row.get(0)?),
                    email: Email::new(row.get(1)?),
                })
            })
            .map_err(|e| VaultError::Database(format!("User not found: {e}")))?
        };

        Ok(DB {
            conn,
            session: AuthSession {
                user,
                key: encryption_key,
            },
            crypto: self.crypto,
            _state: PhantomData,
        })
    }
}

// ════════════════════════════════════════════════════════════════════
// Authenticated: работа с записями
// ════════════════════════════════════════════════════════════════════

impl<C: CryptoProvider> DB<Authenticated, C> {
    /// Принимает ТОЛЬКО EncryptedEntry.
    /// PlainEntry передать невозможно — ошибка компиляции.
    pub fn save_entry(&self, entry: &EncryptedEntry) -> Result<(), VaultError> {
        self.conn
            .execute(
                "INSERT INTO entries (id, user_id, encrypted_data, nonce, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)
                 ON CONFLICT(id) DO UPDATE SET
                 encrypted_data = ?3, nonce = ?4, updated_at = ?6",
                rusqlite::params![
                    entry.id.as_str(),
                    self.session.user.id.as_str(),
                    entry.encrypted_data.as_str(),
                    entry.nonce.as_str(),
                    entry.created_at.to_rfc3339(),
                    entry.updated_at.to_rfc3339(),
                ],
            )
            .map_err(|e| VaultError::Database(format!("Failed to save entry: {}", e)))?;

        Ok(())
    }

    /// Возвращает зашифрованные записи пользователя.
    pub fn list_entries(&self, user_id: &UserId) -> Result<Vec<EncryptedEntry>, VaultError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, user_id, encrypted_data, nonce, created_at, updated_at
                 FROM entries WHERE user_id = ?1",
            )
            .map_err(|e| VaultError::Database(format!("Failed to prepare statement: {}", e)))?;

        let rows_iter = stmt
            .query_map(rusqlite::params![user_id.as_str()], |row| {
                Ok(EncryptedEntry {
                    id: EntryId::new(row.get(0)?),
                    user_id: UserId::new(row.get(1)?),
                    encrypted_data: EncryptedData::new(row.get(2)?),
                    nonce: Nonce::new(row.get(3)?),
                    created_at: row
                        .get::<_, String>(4)?
                        .parse::<chrono::DateTime<Utc>>()
                        .unwrap_or_else(|_| Utc::now()),
                    updated_at: row
                        .get::<_, String>(5)?
                        .parse::<chrono::DateTime<Utc>>()
                        .unwrap_or_else(|_| Utc::now()),
                })
            })
            .map_err(|e| VaultError::Database(format!("Failed to query entries: {}", e)))?;

        let mut entries = Vec::new();
        for row in rows_iter {
            let entry =
                row.map_err(|e| VaultError::Database(format!("Failed to read entry: {}", e)))?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Удалить запись — нужны оба ID чтобы не удалить чужую.
    pub fn delete_entry(&self, entry_id: &EntryId) -> Result<bool, VaultError> {
        let affected = self
            .conn
            .execute(
                "DELETE FROM entries WHERE id = ?1 AND user_id = ?2",
                rusqlite::params![entry_id.as_str(), self.session.user.id.as_str()],
            )
            .map_err(|e| VaultError::Database(format!("Failed to delete entry: {}", e)))?;

        Ok(affected > 0)
    }

    /// Зашифровать запись для сохранения в БД.
    /// PlainEntry → EncryptedEntry (готова к save_entry).
    pub fn encrypt(&self, entry: &PlainEntry) -> Result<EncryptedEntry, VaultError> {
        self.crypto
            .encrypt_entry(entry, &self.session.key)
            .map_err(VaultError::Crypto)
    }

    /// Расшифровать запись из БД для показа пользователю.
    /// EncryptedEntry → PlainEntry.
    pub fn decrypt(&self, entry: &EncryptedEntry) -> Result<PlainEntry, VaultError> {
        self.crypto
            .decrypt_entry(entry, &self.session.key)
            .map_err(VaultError::Crypto)
    }

    /// Accessor: user_id текущей сессии.
    pub fn user_id(&self) -> &UserId {
        &self.session.user.id
    }

    /// Accessor: email текущей сессии.
    pub fn user_email(&self) -> &Email {
        &self.session.user.email
    }

    /// Accessor: encryption key текущей сессии.
    pub fn encryption_key(&self) -> &types::EncryptionKey {
        &self.session.key
    }
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_operations::FakeCrypto;
    use crate::types::{EncryptionKey, EntryPassword, Login, ServiceName, ServiceUrl};

    fn open_test_db() -> DB<Open, FakeCrypto> {
        DB::<Closed, FakeCrypto>::new(FakeCrypto)
            .open(":memory:")
            .expect("Failed to open test database")
    }

    fn authenticated_test_db() -> DB<Authenticated, FakeCrypto> {
        let db = open_test_db();

        db.create_user(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("SuperSecret123!".to_string()),
        )
        .expect("Failed to create user");

        let pass = db
            .create_pass(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("SuperSecret123!".to_string()),
            )
            .expect("Failed to create pass");

        db.enter(pass).expect("Failed to enter vault")
    }

    // ════════════════════════════════════════════
    // create_user
    // ════════════════════════════════════════════

    #[test]
    fn test_open_database() {
        let db = open_test_db();
        let user = db
            .create_user(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("SuperSecret123!".to_string()),
            )
            .expect("Failed to create user");

        assert_eq!(user.email.as_str(), "alex@icloud.com");
    }

    // ════════════════════════════════════════════
    // create_pass
    // ════════════════════════════════════════════

    #[test]
    fn create_pass_returns_vault_pass() {
        let db = open_test_db();
        db.create_user(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("SuperSecret123!".to_string()),
        )
        .unwrap();

        let pass = db
            .create_pass(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("SuperSecret123!".to_string()),
            )
            .unwrap();

        assert_eq!(pass.email().as_str(), "alex@icloud.com");
        assert!(!pass.user_id().as_str().is_empty());
        assert!(!pass.encryption_key().as_str().is_empty());
    }

    #[test]
    fn create_pass_wrong_password_fails() {
        let db = open_test_db();
        db.create_user(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("CorrectPassword!".to_string()),
        )
        .unwrap();

        let result = db.create_pass(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("WrongPassword!".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn create_pass_nonexistent_user_fails() {
        let db = open_test_db();

        let result = db.create_pass(
            Email::new("nobody@example.com".to_string()),
            MasterPassword::new("anything".to_string()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn create_pass_does_not_consume_db() {
        let db = open_test_db();
        db.create_user(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("SuperSecret123!".to_string()),
        )
        .unwrap();

        // create_pass заимствует &self — db жив после вызова
        let _pass = db
            .create_pass(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("SuperSecret123!".to_string()),
            )
            .unwrap();

        // db всё ещё доступен для enter()
        let pass2 = db
            .create_pass(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("SuperSecret123!".to_string()),
            )
            .unwrap();

        let _db = db.enter(pass2).unwrap();
    }

    // ════════════════════════════════════════════
    // enter
    // ════════════════════════════════════════════

    #[test]
    fn enter_with_pass_from_create_pass() {
        let db = open_test_db();
        db.create_user(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("SuperSecret123!".to_string()),
        )
        .unwrap();

        let pass = db
            .create_pass(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("SuperSecret123!".to_string()),
            )
            .unwrap();

        let db = db.enter(pass).unwrap();
        assert_eq!(db.user_email().as_str(), "alex@icloud.com");
    }

    #[test]
    fn enter_with_external_pass() {
        // Симулируем VaultPass, пришедший от Вахтера (JWT decode)
        let db = open_test_db();
        let user = db
            .create_user(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("SuperSecret123!".to_string()),
            )
            .unwrap();

        let external_pass = VaultPass::new(
            UserId::new(user.id.as_str().to_string()),
            Email::new("alex@icloud.com".to_string()),
            EncryptionKey::new("external-key-from-jwt".to_string()),
        );

        let db = db.enter(external_pass).unwrap();
        assert_eq!(db.user_email().as_str(), "alex@icloud.com");
        assert_eq!(db.encryption_key().as_str(), "external-key-from-jwt");
    }

    #[test]
    fn enter_nonexistent_user_fails() {
        let db = open_test_db();
        let fake_pass = VaultPass::new(
            UserId::new("nonexistent-user-id".to_string()),
            Email::new("nobody@example.com".to_string()),
            EncryptionKey::new("0".repeat(64)),
        );

        assert!(db.enter(fake_pass).is_err());
    }

    #[test]
    fn enter_uses_db_email_not_pass_email() {
        // enter() берёт email из БД (авторитетный источник),
        // а не из VaultPass (который мог прийти из JWT claims)
        let db = open_test_db();
        let user = db
            .create_user(
                Email::new("real@icloud.com".to_string()),
                MasterPassword::new("SuperSecret123!".to_string()),
            )
            .unwrap();

        let pass_with_stale_email = VaultPass::new(
            UserId::new(user.id.as_str().to_string()),
            Email::new("stale@old-email.com".to_string()),
            EncryptionKey::new("some-key".to_string()),
        );

        let db = db.enter(pass_with_stale_email).unwrap();
        // Должен быть email из БД, а не из pass
        assert_eq!(db.user_email().as_str(), "real@icloud.com");
    }

    // ════════════════════════════════════════════
    // CRUD entries
    // ════════════════════════════════════════════

    #[test]
    fn test_save_and_read_entry() {
        let db = authenticated_test_db();
        let plain = PlainEntry {
            id: EntryId::new(Uuid::new_v4().to_string()),
            user_id: UserId::new(db.user_id().as_str().to_string()),
            service_name: ServiceName::new("Hetzner Cloud".to_string()),
            service_url: ServiceUrl::new("https://console.hetzner.com".to_string()),
            login: Login::new("alex@icloud.com".to_string()),
            password: EntryPassword::new("Kx7$mR#2pL9&".to_string()),
            notes: "VPS CX23 Helsinki".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let encrypted = db.encrypt(&plain).expect("Failed to encrypt");
        db.save_entry(&encrypted).expect("Failed to save entry");

        let user_id = UserId::new(db.user_id().as_str().to_string());
        let entries = db.list_entries(&user_id).expect("Failed to list entries");
        assert_eq!(entries.len(), 1);

        let decrypted = db.decrypt(&entries[0]).expect("Failed to decrypt");
        assert_eq!(decrypted.service_name.as_str(), "Hetzner Cloud");
        assert_eq!(
            decrypted.service_url.as_str(),
            "https://console.hetzner.com"
        );
        assert_eq!(decrypted.login.as_str(), "alex@icloud.com");
        assert_eq!(decrypted.password.as_str(), "Kx7$mR#2pL9&");
        assert_eq!(decrypted.notes, "VPS CX23 Helsinki");
    }

    #[test]
    fn test_delete_entry() {
        let db = authenticated_test_db();
        let plain = PlainEntry {
            id: EntryId::new(Uuid::new_v4().to_string()),
            user_id: UserId::new(db.user_id().as_str().to_string()),
            service_name: ServiceName::new("Instagram".to_string()),
            service_url: ServiceUrl::new("https://instagram.com".to_string()),
            login: Login::new("nastya_gram".to_string()),
            password: EntryPassword::new("InstaPass456!".to_string()),
            notes: "".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let encrypted = db.encrypt(&plain).expect("Failed to encrypt");
        db.save_entry(&encrypted).expect("Failed to save");

        let deleted = db.delete_entry(&encrypted.id).expect("Failed to delete");
        assert!(deleted);

        let user_id = UserId::new(db.user_id().as_str().to_string());
        let entries = db.list_entries(&user_id).expect("Failed to list");
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_user_isolation() {
        let db = open_test_db();
        db.create_user(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("AlexPass123!".to_string()),
        )
        .expect("Failed to create alex");
        db.create_user(
            Email::new("nastya@mail.com".to_string()),
            MasterPassword::new("NastyaPass456!".to_string()),
        )
        .expect("Failed to create nastya");

        let pass = db
            .create_pass(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("AlexPass123!".to_string()),
            )
            .expect("Failed to create pass");

        let db = db.enter(pass).expect("Failed to enter");

        let plain = PlainEntry {
            id: EntryId::new(Uuid::new_v4().to_string()),
            user_id: UserId::new(db.user_id().as_str().to_string()),
            service_name: ServiceName::new("Hetzner".to_string()),
            service_url: ServiceUrl::new("https://hetzner.com".to_string()),
            login: Login::new("alex_hetzner".to_string()),
            password: EntryPassword::new("secret123".to_string()),
            notes: "".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let encrypted = db.encrypt(&plain).expect("Failed to encrypt");
        db.save_entry(&encrypted).expect("Failed to save");

        let alex_id = UserId::new(db.user_id().as_str().to_string());
        let alex_entries = db.list_entries(&alex_id).expect("Failed to list");
        assert_eq!(alex_entries.len(), 1);

        let nastya_fake_id = UserId::new("nastya-fake-id".to_string());
        let nastya_entries = db.list_entries(&nastya_fake_id).expect("Failed to list");
        assert_eq!(nastya_entries.len(), 0);
    }

    // ════════════════════════════════════════════
    // find_user_id_by_email
    // ════════════════════════════════════════════

    #[test]
    fn find_user_id_by_email_existing() {
        let db = open_test_db();
        let user = db
            .create_user(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("SuperSecret123!".to_string()),
            )
            .unwrap();

        let found = db
            .find_user_id_by_email(&Email::new("alex@icloud.com".to_string()))
            .unwrap();
        assert_eq!(found.as_str(), user.id.as_str());
    }

    #[test]
    fn find_user_id_by_email_not_found() {
        let db = open_test_db();
        let result = db.find_user_id_by_email(&Email::new("nobody@example.com".to_string()));
        assert!(result.is_err());
    }

    // ════════════════════════════════════════════
    // Full flow: create_pass → enter (File-based DB)
    // ════════════════════════════════════════════

    #[test]
    fn full_flow_create_pass_then_enter() {
        let tmp = std::env::temp_dir().join("vault_test_full_flow.db");
        let _ = std::fs::remove_file(&tmp);

        // 1. Регистрируем и получаем pass
        let db = DB::<Closed, FakeCrypto>::new(FakeCrypto)
            .open(tmp.to_str().unwrap())
            .unwrap();
        db.create_user(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("SuperSecret123!".to_string()),
        )
        .unwrap();

        let pass = db
            .create_pass(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("SuperSecret123!".to_string()),
            )
            .unwrap();

        let user_id = UserId::new(pass.user_id().as_str().to_string());
        let ek_str = pass.encryption_key().as_str().to_string();
        let db = db.enter(pass).unwrap();
        assert_eq!(db.user_email().as_str(), "alex@icloud.com");
        drop(db);

        // 2. Новое подключение — enter с внешним VaultPass (как от JWT)
        let db = DB::<Closed, FakeCrypto>::new(FakeCrypto)
            .open(tmp.to_str().unwrap())
            .unwrap();
        let external_pass = VaultPass::new(
            user_id,
            Email::new("alex@icloud.com".to_string()),
            EncryptionKey::new(ek_str),
        );
        let db = db.enter(external_pass).unwrap();
        assert_eq!(db.user_email().as_str(), "alex@icloud.com");

        let _ = std::fs::remove_file(&tmp);
    }
}
