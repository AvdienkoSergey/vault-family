//! Хранилище refresh-токенов — отдельная auth.db.
//!
//! AuthStore владеет СВОИМ подключением к auth.db,
//! не зависит от vault.db и не знает про записи/пароли.
//!
//! Таблица refresh_tokens:
//!   token_hash  TEXT PRIMARY KEY  — SHA-256 хэш (branded RefreshTokenHash)
//!   user_id     TEXT NOT NULL     — владелец токена
//!   expires_at  TEXT NOT NULL     — ISO 8601 datetime

use super::RefreshTokenHash;
use crate::types::UserId;
use chrono::Utc;
use rusqlite::Connection;

// ════════════════════════════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum StoreError {
    Connection(String),
    Schema(String),
    Database(String),
    TokenNotFound,
    TokenExpired,
}

impl std::error::Error for StoreError {}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Connection(msg) => write!(f, "auth store connection error: {msg}"),
            StoreError::Schema(msg) => write!(f, "auth store schema error: {msg}"),
            StoreError::Database(msg) => write!(f, "auth store database error: {msg}"),
            StoreError::TokenNotFound => write!(f, "refresh token not found"),
            StoreError::TokenExpired => write!(f, "refresh token expired"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// AuthStore
// ════════════════════════════════════════════════════════════════════

/// Хранилище refresh-токенов с отдельным подключением к auth.db.
pub struct AuthStore {
    conn: Connection,
}

impl AuthStore {
    /// Открыть (или создать) auth.db и гарантировать схему.
    pub fn open(auth_db_path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(auth_db_path)
            .map_err(|e| StoreError::Connection(format!("Unable to open auth.db: {e}")))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash  TEXT PRIMARY KEY,
                user_id     TEXT NOT NULL,
                expires_at  TEXT NOT NULL
            );",
        )
        .map_err(|e| StoreError::Schema(format!("Failed to create refresh_tokens table: {e}")))?;

        Ok(Self { conn })
    }

    /// Сохранить хэш refresh-токена.
    pub fn save_refresh_token(
        &self,
        token_hash: &RefreshTokenHash,
        user_id: &UserId,
        expires_at: chrono::DateTime<Utc>,
    ) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    token_hash.as_str(),
                    user_id.as_str(),
                    expires_at.to_rfc3339(),
                ],
            )
            .map_err(|e| StoreError::Database(format!("Failed to save refresh token: {e}")))?;
        Ok(())
    }

    /// Проверить refresh-токен и удалить его (rotation).
    ///
    /// Возвращает user_id владельца токена.
    /// После вызова старый токен больше не существует —
    /// повторное использование невозможно.
    pub fn verify_and_delete_refresh_token(
        &self,
        token_hash: &RefreshTokenHash,
    ) -> Result<UserId, StoreError> {
        let (user_id, expires_at): (String, String) = self
            .conn
            .query_row(
                "SELECT user_id, expires_at FROM refresh_tokens WHERE token_hash = ?1",
                rusqlite::params![token_hash.as_str()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| StoreError::TokenNotFound)?;

        let expires = expires_at
            .parse::<chrono::DateTime<Utc>>()
            .map_err(|e| StoreError::Database(format!("Invalid expires_at: {e}")))?;

        if expires < Utc::now() {
            // Удаляем протухший токен
            let _ = self.conn.execute(
                "DELETE FROM refresh_tokens WHERE token_hash = ?1",
                rusqlite::params![token_hash.as_str()],
            );
            return Err(StoreError::TokenExpired);
        }

        // Rotation: удаляем использованный токен
        self.conn
            .execute(
                "DELETE FROM refresh_tokens WHERE token_hash = ?1",
                rusqlite::params![token_hash.as_str()],
            )
            .map_err(|e| StoreError::Database(format!("Failed to delete refresh token: {e}")))?;

        Ok(UserId::new(user_id))
    }
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn open_test_store() -> AuthStore {
        AuthStore::open(":memory:").expect("Failed to open in-memory auth store")
    }

    #[test]
    fn save_and_verify_refresh_token() {
        let store = open_test_store();
        let hash = RefreshTokenHash::new("abc123hash".to_string());
        let user_id = UserId::new("user-1".to_string());
        let expires_at = Utc::now() + chrono::Duration::hours(1);

        store
            .save_refresh_token(&hash, &user_id, expires_at)
            .unwrap();

        let returned_id = store.verify_and_delete_refresh_token(&hash).unwrap();
        assert_eq!(returned_id.as_str(), "user-1");
    }

    #[test]
    fn verify_deletes_token_rotation() {
        let store = open_test_store();
        let hash = RefreshTokenHash::new("abc123hash".to_string());
        let user_id = UserId::new("user-1".to_string());
        let expires_at = Utc::now() + chrono::Duration::hours(1);

        store
            .save_refresh_token(&hash, &user_id, expires_at)
            .unwrap();
        store.verify_and_delete_refresh_token(&hash).unwrap();

        // Повторный вызов — токен уже удалён (rotation)
        let result = store.verify_and_delete_refresh_token(&hash);
        assert!(matches!(result, Err(StoreError::TokenNotFound)));
    }

    #[test]
    fn verify_expired_token_fails() {
        let store = open_test_store();
        let hash = RefreshTokenHash::new("expired-hash".to_string());
        let user_id = UserId::new("user-1".to_string());
        let expires_at = Utc::now() - chrono::Duration::hours(1); // в прошлом

        store
            .save_refresh_token(&hash, &user_id, expires_at)
            .unwrap();

        let result = store.verify_and_delete_refresh_token(&hash);
        assert!(matches!(result, Err(StoreError::TokenExpired)));
    }

    #[test]
    fn verify_nonexistent_token_fails() {
        let store = open_test_store();
        let hash = RefreshTokenHash::new("does-not-exist".to_string());

        let result = store.verify_and_delete_refresh_token(&hash);
        assert!(matches!(result, Err(StoreError::TokenNotFound)));
    }
}
