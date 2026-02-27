use chrono::{DateTime, Utc};
use std::fmt;
use std::str::FromStr;

// ════════════════════════════════════════════════════════════════════
// Макросы: фабрики branded types
// ════════════════════════════════════════════════════════════════════
/// Открытые данные — можно показывать в логах
#[macro_export]
macro_rules! branded_no_secret {
    ($name:ident) => {
        #[derive(Debug, Clone, Hash, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
        pub struct $name(String);

        impl $name {
            pub fn new(id: String) -> Self {
                Self(id)
            }
            pub fn as_str(&self) -> &str {
                &self.0.as_str()
            }
        }
    };
}

/// Секретные данные — прячем в Debug, нет Serialize (нельзя случайно отправить)
#[macro_export]
macro_rules! branded_secret {
    ($name:ident) => {
        #[derive(
            Hash, PartialEq, Eq, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop,
        )]
        pub struct $name(String);

        impl $name {
            pub fn new(id: String) -> Self {
                Self(id)
            }
            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}: {}", stringify!($name), "Secret(***)")
            }
        }
    };
}

// ════════════════════════════════════════════════════════════════════
// Branded types - привязаны к генератору паролей (password_generator)
// ════════════════════════════════════════════════════════════════════
branded_secret!(Password);

// ════════════════════════════════════════════════════════════════════
// Branded types - привязаны к таблицам SQLite (sqlite)
// ════════════════════════════════════════════════════════════════════
// --- TABLE users ---
branded_no_secret!(UserId); // users.id
branded_secret!(Email); // users.email (персональные данные)

// ════════════════════════════════════════════════════════════════════
// Email валидация (RFC 5321/5322 через email_address crate)
// ════════════════════════════════════════════════════════════════════
#[derive(Debug, PartialEq)]
pub struct EmailError(String);

impl fmt::Display for EmailError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid email: {}", self.0)
    }
}

impl std::error::Error for EmailError {}

impl Email {
    /// Валидирующий конструктор для пользовательского ввода.
    /// Проверяет формат по RFC 5321/5322
    pub fn parse(input: String) -> Result<Self, EmailError> {
        let trimmed = input.trim().to_string();
        if trimmed.is_empty() {
            return Err(EmailError("email cannot be empty".to_string()));
        }
        email_address::EmailAddress::from_str(&trimmed).map_err(|e| EmailError(e.to_string()))?;
        Ok(Self::new(trimmed))
    }
}

branded_secret!(MasterPasswordHash); // users.master_password_hash
branded_secret!(AuthSalt); // users.auth_salt
branded_secret!(EncryptionSalt); // users.encryption_salt
// --- TABLE entries ---
branded_no_secret!(EntryId); // entries.id
branded_no_secret!(EncryptedData); // entries.encrypted_data (уже зашифровано, не секрет)
branded_no_secret!(Nonce); // entries.nonce (не секрет, бесполезен без ключа)
// --- Вне БД: живут только в памяти ---
branded_secret!(MasterPassword); // ввод пользователя, никогда не хранится
branded_secret!(EncryptionKey); // деривируется из мастер-пароля, никогда не хранится
branded_secret!(EntryPassword); // расшифрованный пароль записи
// --- Для полей расшифрованной записи ---
branded_no_secret!(ServiceName); // "Hetzner Cloud"
branded_no_secret!(ServiceUrl); // "https://console.hetzner.com"
branded_secret!(Login); // логин на сервисе (email, username, телефон и т.д.)

// ════════════════════════════════════════════════════════════════════
//  Доменные структуры
//════════════════════════════════════════════════════════════════════
/// Пользователь — соответствует строке в TABLE users
/// Возвращается после create_user и authenticate
#[derive(Debug)]
pub struct User {
    pub id: UserId,
    pub email: Email,
    pub master_hash: MasterPasswordHash,
    pub auth_salt: AuthSalt,
    pub encryption_salt: EncryptionSalt,
    pub created_at: DateTime<Utc>,
}

/// Расшифрованная запись — живёт ТОЛЬКО в памяти
/// В базу данных попасть НЕ МОЖЕТ (нет EncryptedData)
#[derive(Debug)]
pub struct PlainEntry {
    pub id: EntryId,
    pub user_id: UserId,
    pub service_name: ServiceName,
    pub service_url: ServiceUrl,
    pub login: Login,
    pub password: EntryPassword,
    pub notes: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Зашифрованная запись — соответствует строке в TABLE entries
/// Только эта структура может быть сохранена в БД
#[derive(Debug, Clone)]
pub struct EncryptedEntry {
    pub id: EntryId,
    pub user_id: UserId,
    pub encrypted_data: EncryptedData, // PlainEntry → AES-GCM → base64
    pub nonce: Nonce,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ════════════════════════════════════════════
    // Email::parse() — наша логика
    // RFC-валидацию тестирует email_address crate
    // ════════════════════════════════════════════

    #[test]
    fn parse_valid_email() {
        let email = Email::parse("user@example.com".to_string()).unwrap();
        assert_eq!(email.as_str(), "user@example.com");
    }

    #[test]
    fn parse_trims_whitespace() {
        let email = Email::parse("  user@example.com  ".to_string()).unwrap();
        assert_eq!(email.as_str(), "user@example.com");
    }

    #[test]
    fn parse_empty_fails() {
        assert!(Email::parse("".to_string()).is_err());
    }

    #[test]
    fn parse_whitespace_only_fails() {
        assert!(Email::parse("   ".to_string()).is_err());
    }

    #[test]
    fn parse_invalid_rejected() {
        assert!(Email::parse("not-an-email".to_string()).is_err());
    }
}

/// Результат аутентификации — User + ключ для шифрования
/// EncryptionKey не хранится в User, потому что он существует
/// только пока сессия активна
#[derive(Debug)]
pub struct AuthSession {
    pub user: User,
    pub key: EncryptionKey,
}
