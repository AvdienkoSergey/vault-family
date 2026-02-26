use std::marker::PhantomData;
use chrono::Utc;
use rusqlite::{Connection};
use uuid::Uuid;
use crate::types;
use types::{
    Email,
    MasterPassword,
    User,
    UserId,
    AuthSession,
    EncryptedEntry,
    EntryId,
    ServiceName,
    ServiceUrl,
    EntryPassword,
    PlainEntry,
};
use crate::crypto_operations::{ CryptoProvider, FakeCrypto };
use crate::types::{AuthSalt, EncryptedData, EncryptionSalt, MasterPasswordHash, Nonce};
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
    ConnectionError(String),
    SchemaError(String),
    DatabaseError(String),
    CryptoError(String),
    AuthError(String),
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
        let conn = Connection::open(path).map_err(|e| VaultError::ConnectionError(
            format!("Unable to open database: {}", e)
        ))?;

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
            return Err(VaultError::SchemaError(
                format!("Failed to create tables: {}", e)
            ));
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
    pub fn create_user(&self, email: Email, master_password: MasterPassword) -> Result<User, VaultError> {
        let crypto = &self.crypto;
        let id = UserId::new(Uuid::new_v4().to_string());
        let (
            master_hash,
            auth_salt
        ) = crypto.hash_master_password(
            &master_password
        );
        let encryption_salt = crypto.generate_salt();
        let created_at = Utc::now();

        let user: User = User { id, email, master_hash, auth_salt, encryption_salt, created_at };

        self.conn.execute("
            INSERT INTO users (id, email, master_hash, auth_salt, encryption_salt, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6);
        ", (
            user.id.as_str(),
            user.email.as_str(),
            user.master_hash.as_str(),
            user.auth_salt.as_str(),
            user.encryption_salt.as_str(),
            user.created_at.to_string())
        ).map_err(|e| VaultError::DatabaseError(
            format!("Failed to add User: {}", e)
        ))?;

        Ok(user)
    }

    /// Open → Authenticated (потребляет self!)
    pub fn authenticate(self, email: Email, master_password: MasterPassword) -> Result<DB<Authenticated, C>, VaultError> {
        let conn = self.conn;
        let crypto = self.crypto;
        let user = {
            let mut stmt = conn.prepare("
            SELECT id, email, master_hash, auth_salt, encryption_salt, created_at
            FROM users WHERE email = ?1"
            ).map_err(|e| VaultError::DatabaseError(
                format!("Failed to prepare statement: {}", e)

            ))?;
            stmt.query_row(
                rusqlite::params![email.as_str()],
                |row| {
                    Ok(User {
                        id: UserId::new(row.get(0)?),
                        email: Email::new(row.get(1)?),
                        master_hash: MasterPasswordHash::new(row.get(2)?),
                        auth_salt: AuthSalt::new(row.get(3)?),
                        encryption_salt: EncryptionSalt::new(row.get(4)?),
                        created_at: row.get::<_, String>(5)?
                            .parse::<chrono::DateTime<Utc>>()
                            .unwrap_or_else(|_| Utc::now()),
                    })
                },
            ).map_err(|e| VaultError::DatabaseError(
                format!("Failed to get user ID: {}", e)
            ))?
        };
        let is_verify = crypto.verify_master_password(&master_password, &user.master_hash, &user.auth_salt);
        if !is_verify {
            return Err(VaultError::AuthError("Invalid master password".to_string()));
        };
        let key = crypto.derive_encryption_key(&master_password, &user.encryption_salt);
        Ok(DB {
            conn,
            session: AuthSession {
                user,
                key,
            },
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
        self.conn.execute("
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
        ).map_err(|e| VaultError::DatabaseError(
            format!("Failed to save entry: {}", e)
        ))?;

        Ok(())
    }
    /// Возвращает зашифрованные записи
    pub fn list_entries(&self, user_id: &UserId) -> Result<Vec<EncryptedEntry>, VaultError> {
        let conn = &self.conn;
        let mut stmt = conn.prepare("
            SELECT id, user_id, encrypted_data, nonce, created_at, updated_at
            FROM entries WHERE user_id = ?1"
        ).map_err(|e| VaultError::DatabaseError(
            format!("Failed to prepare statement: {}", e)
        ))?;
        let rows_iter = stmt.query_map(
            rusqlite::params![user_id.as_str()],
            |row| {
                Ok(EncryptedEntry {
                    id: EntryId::new(row.get(0)?),
                    user_id: UserId::new(row.get(1)?),
                    encrypted_data: EncryptedData::new(row.get(2)?),
                    nonce: Nonce::new(row.get(3)?),
                    created_at: row.get::<_, String>(4)?
                        .parse::<chrono::DateTime<Utc>>()
                        .unwrap_or_else(|_| Utc::now()),
                    updated_at: row.get::<_, String>(5)?
                        .parse::<chrono::DateTime<Utc>>()
                        .unwrap_or_else(|_| Utc::now()),
                })
            },
        ).map_err(|e| VaultError::DatabaseError(
            format!("Failed to query entries: {}", e)
        ))?;
        let mut entries = Vec::new();
        for row in rows_iter {
            let entry = row.map_err(|e| VaultError::DatabaseError(
                format!("Failed to read entry: {}", e)
            ))?;
            entries.push(entry);
        }
        Ok(entries)
    }
    /// Удалить запись — нужны оба ID чтобы не удалить чужую
    pub fn delete_entry(&self, entry_id: &EntryId) -> Result<bool, VaultError> {
        let affected = self.conn.execute(
            "DELETE FROM entries WHERE id = ?1 AND user_id = ?2",
            rusqlite::params![
            entry_id.as_str(),
            self.session.user.id.as_str(),
        ],
        ).map_err(|e| VaultError::DatabaseError(
            format!("Failed to delete entry: {}", e)
        ))?;

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
