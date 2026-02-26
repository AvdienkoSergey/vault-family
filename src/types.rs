use chrono::{DateTime, Utc};
use std::fmt;

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
    pub email: Email,
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

/// Результат аутентификации — User + ключ для шифрования
/// EncryptionKey не хранится в User, потому что он существует
/// только пока сессия активна
#[derive(Debug)]
pub struct AuthSession {
    pub user: User,
    pub key: EncryptionKey,
}
