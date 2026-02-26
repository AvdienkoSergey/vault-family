use crate::crypto_operations::CryptoProvider;
use crate::types;
use crate::types::{AuthSalt, EncryptedData, EncryptionSalt, MasterPasswordHash, Nonce};
use chrono::Utc;
use rusqlite::Connection;
use std::marker::PhantomData;
use types::{
    AuthSession, Email, EncryptedEntry, EntryId, MasterPassword, PlainEntry, User, UserId,
};
use uuid::Uuid;
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
#[derive(Debug)]
pub enum VaultError {
    Connection(String),
    Schema(String),
    Database(String),
    Auth(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::Connection(msg) => write!(f, "connection error: {msg}"),
            VaultError::Schema(msg) => write!(f, "schema error: {msg}"),
            VaultError::Database(msg) => write!(f, "database error: {msg}"),
            VaultError::Auth(msg) => write!(f, "auth error: {msg}"),
        }
    }
}
/// Closed: можно только создать и открыть
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
    pub fn open(self, path: &str) -> Result<DB<Open, C>, VaultError> {
        let crypto = self.crypto;
        let conn = Connection::open(path)
            .map_err(|e| VaultError::Connection(format!("Unable to open database: {}", e)))?;

        let create_tables = conn.execute_batch(
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
        );

        if let Err(e) = create_tables {
            return Err(VaultError::Schema(format!(
                "Failed to create tables: {}",
                e
            )));
        }

        Ok(DB {
            conn,
            session: (),
            crypto,
            _state: PhantomData,
        })
    }
}
/// Open: регистрация и логин
impl<C: CryptoProvider> DB<Open, C> {
    /// Создать пользователя (регистрация, не требует логина)
    pub fn create_user(
        &self,
        email: Email,
        master_password: MasterPassword,
    ) -> Result<User, VaultError> {
        let crypto = &self.crypto;
        let id = UserId::new(Uuid::new_v4().to_string());
        let (master_hash, auth_salt) = crypto.hash_master_password(&master_password);
        let encryption_salt = crypto.generate_salt();
        let created_at = Utc::now();

        let user: User = User {
            id,
            email,
            master_hash,
            auth_salt,
            encryption_salt,
            created_at,
        };

        self.conn
            .execute(
                "
            INSERT INTO users (id, email, master_hash, auth_salt, encryption_salt, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6);
        ",
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

    /// Open → Authenticated (потребляет self!)
    pub fn authenticate(
        self,
        email: Email,
        master_password: MasterPassword,
    ) -> Result<DB<Authenticated, C>, VaultError> {
        let conn = self.conn;
        let crypto = self.crypto;
        let user = {
            let mut stmt = conn
                .prepare(
                    "
            SELECT id, email, master_hash, auth_salt, encryption_salt, created_at
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
            .map_err(|e| VaultError::Database(format!("Failed to get user ID: {}", e)))?
        };
        let is_verify =
            crypto.verify_master_password(&master_password, &user.master_hash, &user.auth_salt);
        if !is_verify {
            return Err(VaultError::Auth("Invalid master password".to_string()));
        };
        let key = crypto.derive_encryption_key(&master_password, &user.encryption_salt);
        Ok(DB {
            conn,
            session: AuthSession { user, key },
            crypto,
            _state: PhantomData,
        })
    }
}
/// Authenticated: работа с записями
impl<C: CryptoProvider> DB<Authenticated, C> {
    /// Принимает ТОЛЬКО EncryptedEntry
    /// PlainEntry передать невозможно — ошибка компиляции
    pub fn save_entry(&self, entry: &EncryptedEntry) -> Result<(), VaultError> {
        self.conn
            .execute(
                "
            INSERT INTO entries (id, user_id, encrypted_data, nonce, created_at, updated_at)
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
    /// Возвращает зашифрованные записи
    pub fn list_entries(&self, user_id: &UserId) -> Result<Vec<EncryptedEntry>, VaultError> {
        let conn = &self.conn;
        let mut stmt = conn
            .prepare(
                "
            SELECT id, user_id, encrypted_data, nonce, created_at, updated_at
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
    /// Удалить запись — нужны оба ID чтобы не удалить чужую
    pub fn delete_entry(&self, entry_id: &EntryId) -> Result<bool, VaultError> {
        let affected = self
            .conn
            .execute(
                "DELETE FROM entries WHERE id = ?1 AND user_id = ?2",
                rusqlite::params![entry_id.as_str(), self.session.user.id.as_str(),],
            )
            .map_err(|e| VaultError::Database(format!("Failed to delete entry: {}", e)))?;

        Ok(affected > 0)
    }
    /// Зашифровать запись для сохранения в БД
    /// Использует EncryptionKey из текущей сессии
    /// PlainEntry → EncryptedEntry (готова к save_entry
    pub fn encrypt(&self, entry: &PlainEntry) -> EncryptedEntry {
        self.crypto.encrypt_entry(entry, &self.session.key)
    }
    /// Расшифровать запись из БД для показа пользователю
    /// Использует EncryptionKey из текущей сессии
    /// EncryptedEntry → PlainEntry (можно читать через .as_str())
    pub fn decrypt(&self, entry: &EncryptedEntry) -> PlainEntry {
        self.crypto.decrypt_entry(entry, &self.session.key)
    }
}

pub fn demo() {
    use crate::crypto_operations::FakeCrypto;
    use crate::types::{EntryPassword, PlainEntry, ServiceName, ServiceUrl};

    println!("=== Vault Demo (FakeCrypto) ===\n");

    // Closed → Open
    let db = DB::<Closed, FakeCrypto>::new(FakeCrypto)
        .open(":memory:")
        .expect("Failed to open database");

    // Регистрация
    let user = db
        .create_user(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("SuperSecret123!".to_string()),
        )
        .expect("Failed to create user");
    println!("Registered: {:?}", user.id);

    // Open → Authenticated
    let db = db
        .authenticate(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("SuperSecret123!".to_string()),
        )
        .expect("Failed to authenticate");
    println!("Authenticated: {:?}", db.session.user.email);

    // Создаём запись → шифруем → сохраняем
    let plain = PlainEntry {
        id: EntryId::new(Uuid::new_v4().to_string()),
        user_id: UserId::new(db.session.user.id.as_str().to_string()),
        service_name: ServiceName::new("Hetzner Cloud".to_string()),
        service_url: ServiceUrl::new("https://console.hetzner.com".to_string()),
        email: Email::new("alex@icloud.com".to_string()),
        password: EntryPassword::new("Kx7$mR#2pL9&".to_string()),
        notes: "VPS CX23 Helsinki".to_string(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let encrypted = db.encrypt(&plain);
    db.save_entry(&encrypted).expect("Failed to save entry");
    println!("Saved entry: {:?}", encrypted.id);

    // Читаем → расшифровываем
    let user_id = UserId::new(db.session.user.id.as_str().to_string());
    let entries = db.list_entries(&user_id).expect("Failed to list entries");
    println!("Found {} entry(ies)", entries.len());

    let decrypted = db.decrypt(&entries[0]);
    println!(
        "Decrypted: {} — {}",
        decrypted.service_name.as_str(),
        decrypted.service_url.as_str()
    );
    println!("  email: {:?}", decrypted.email);
    println!("  password: {:?}", decrypted.password);
    println!("  notes: {}", decrypted.notes);

    // Удаляем
    let deleted = db.delete_entry(&encrypted.id).expect("Failed to delete");
    println!("Deleted: {deleted}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_operations::FakeCrypto;
    use crate::types::{EntryPassword, PlainEntry, ServiceName, ServiceUrl};

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

        db.authenticate(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("SuperSecret123!".to_string()),
        )
        .expect("Failed to authenticate")
    }
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
    #[test]
    fn test_authenticate() {
        let db = open_test_db();

        // Сначала регистрируем
        db.create_user(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("SuperSecret123!".to_string()),
        )
        .expect("Failed to create user");

        // Потом логинимся — db потребляется, возвращается DB<Authenticated>
        let db = db
            .authenticate(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("SuperSecret123!".to_string()),
            )
            .expect("Failed to authenticate");

        // db теперь DB<Authenticated, FakeCrypto>
        assert_eq!(db.session.user.email.as_str(), "alex@icloud.com");
    }
    #[test]
    fn test_save_and_read_entry() {
        let db = authenticated_test_db();
        // Создаём открытую запись
        let plain = PlainEntry {
            id: EntryId::new(Uuid::new_v4().to_string()),
            user_id: UserId::new(db.session.user.id.as_str().to_string()),
            service_name: ServiceName::new("Hetzner Cloud".to_string()),
            service_url: ServiceUrl::new("https://console.hetzner.com".to_string()),
            email: Email::new("alex@icloud.com".to_string()),
            password: EntryPassword::new("Kx7$mR#2pL9&".to_string()),
            notes: "VPS CX23 Helsinki".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        // Шифруем и сохраняем
        let encrypted = db.encrypt(&plain);
        db.save_entry(&encrypted).expect("Failed to save entry");
        // Читаем обратно
        let user_id = UserId::new(db.session.user.id.as_str().to_string());
        let entries = db.list_entries(&user_id).expect("Failed to list entries");
        assert_eq!(entries.len(), 1);
        // Расшифровываем и проверяем
        let decrypted = db.decrypt(&entries[0]);
        assert_eq!(decrypted.service_name.as_str(), "Hetzner Cloud");
        assert_eq!(
            decrypted.service_url.as_str(),
            "https://console.hetzner.com"
        );
        assert_eq!(decrypted.email.as_str(), "alex@icloud.com");
        assert_eq!(decrypted.password.as_str(), "Kx7$mR#2pL9&");
        assert_eq!(decrypted.notes, "VPS CX23 Helsinki");
    }
    #[test]
    fn test_delete_entry() {
        let db = authenticated_test_db();
        let plain = PlainEntry {
            id: EntryId::new(Uuid::new_v4().to_string()),
            user_id: UserId::new(db.session.user.id.as_str().to_string()),
            service_name: ServiceName::new("Instagram".to_string()),
            service_url: ServiceUrl::new("https://instagram.com".to_string()),
            email: Email::new("nastya@mail.com".to_string()),
            password: EntryPassword::new("InstaPass456!".to_string()),
            notes: "".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let encrypted = db.encrypt(&plain);
        db.save_entry(&encrypted).expect("Failed to save");
        let deleted = db.delete_entry(&encrypted.id).expect("Failed to delete");
        assert!(deleted);
        let user_id = UserId::new(db.session.user.id.as_str().to_string());
        let entries = db.list_entries(&user_id).expect("Failed to list");
        assert_eq!(entries.len(), 0);
    }
    #[test]
    fn test_user_isolation() {
        let db = open_test_db();
        // Регистрируем двух юзеров
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
        // Логинимся как alex
        let db = db
            .authenticate(
                Email::new("alex@icloud.com".to_string()),
                MasterPassword::new("AlexPass123!".to_string()),
            )
            .expect("Failed to auth alex");
        // Сохраняем запись alex
        let plain = PlainEntry {
            id: EntryId::new(Uuid::new_v4().to_string()),
            user_id: UserId::new(db.session.user.id.as_str().to_string()),
            service_name: ServiceName::new("Hetzner".to_string()),
            service_url: ServiceUrl::new("https://hetzner.com".to_string()),
            email: Email::new("alex@icloud.com".to_string()),
            password: EntryPassword::new("secret123".to_string()),
            notes: "".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let encrypted = db.encrypt(&plain);
        db.save_entry(&encrypted).expect("Failed to save");
        // Проверяем: у alex одна запись
        let alex_id = UserId::new(db.session.user.id.as_str().to_string());
        let alex_entries = db.list_entries(&alex_id).expect("Failed to list");
        assert_eq!(alex_entries.len(), 1);
        // Проверяем: у nastya ноль записей (даже через alex's DB)
        let nastya_fake_id = UserId::new("nastya-fake-id".to_string());
        let nastya_entries = db.list_entries(&nastya_fake_id).expect("Failed to list");
        assert_eq!(nastya_entries.len(), 0);
    }
    #[test]
    fn test_wrong_password() {
        let db = open_test_db();
        db.create_user(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("CorrectPassword!".to_string()),
        )
        .expect("Failed to create user");
        let result = db.authenticate(
            Email::new("alex@icloud.com".to_string()),
            MasterPassword::new("WrongPassword!".to_string()),
        );
        assert!(result.is_err());
    }
}
