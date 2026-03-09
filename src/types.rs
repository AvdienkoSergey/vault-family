use chrono::{DateTime, Utc};
use std::fmt;
use std::str::FromStr;
use std::string::String;

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

    // ════════════════════════════════════════════
    // VaultPass — Пропуск
    // ════════════════════════════════════════════

    #[test]
    fn vault_pass_accessors() {
        let pass = VaultPass::new(
            UserId::new("user-1".to_string()),
            Email::new("alex@icloud.com".to_string()),
            EncryptionKey::new("0".repeat(64)),
        );

        assert_eq!(pass.user_id().as_str(), "user-1");
        assert_eq!(pass.email().as_str(), "alex@icloud.com");
        assert_eq!(pass.encryption_key().as_str(), "0".repeat(64));
    }

    #[test]
    fn vault_pass_into_parts() {
        let pass = VaultPass::new(
            UserId::new("user-1".to_string()),
            Email::new("alex@icloud.com".to_string()),
            EncryptionKey::new("abc123".to_string()),
        );

        let (uid, email, ek) = pass.into_parts();
        assert_eq!(uid.as_str(), "user-1");
        assert_eq!(email.as_str(), "alex@icloud.com");
        assert_eq!(ek.as_str(), "abc123");
    }

    #[test]
    fn vault_pass_debug_hides_secrets() {
        let pass = VaultPass::new(
            UserId::new("user-1".to_string()),
            Email::new("alex@icloud.com".to_string()),
            EncryptionKey::new("super-secret-key".to_string()),
        );

        let debug = format!("{:?}", pass);
        assert!(debug.contains("user-1")); // user_id — не секрет
        assert!(!debug.contains("alex@icloud.com")); // email скрыт
        assert!(!debug.contains("super-secret-key")); // ek скрыт
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
// Branded types — привязаны к shared.db (модуль shared/)
// ════════════════════════════════════════════════════════════════════
// --- TABLE user_keys (shared.db) ---
branded_no_secret!(UserPublicKey); // user_keys.public_key (X25519 public, hex)
branded_no_secret!(UserPrivateKeyNonce); // user_keys.private_key_nonce
// --- TABLE shared_vaults ---
branded_no_secret!(SharedVaultId); // shared_vaults.id
branded_no_secret!(SharedVaultName); // shared_vaults.name
// --- TABLE shared_vault_members ---
branded_no_secret!(SharedVaultKeyEncrypted); // encrypted SharedVaultKey per-member
branded_no_secret!(SharedVaultKeyNonce); // nonce для расшифровки vault key
branded_no_secret!(EphemeralPublicKey); // ephemeral X25519 public для DH
// --- Вне БД: живут только в памяти (shared vault crypto) ---
branded_secret!(SharedVaultKey); // расшифрованный 32-byte ключ shared vault
branded_secret!(UserPrivateKey); // расшифрованный X25519 private key
// --- TABLE invites (shared.db) ---
branded_no_secret!(InviteId); // invites.id
branded_no_secret!(InviteCodeHash); // SHA-256(6-digit code), хранится в БД
branded_no_secret!(ConfirmationKey); // HKDF-derived, отправляется invitee

// ════════════════════════════════════════════════════════════════════
// Branded types — transfer module (in-memory relay)
// ════════════════════════════════════════════════════════════════════

/// Одноразовый код трансфера в формате NNN-NNN (000-000 .. 999-999).
///
/// Пространство кодов = 1 000 000 комбинаций.
/// Не Serialize/Deserialize — код извлекается из Path, возвращается как String в DTO.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct TransferCode(String);

impl TransferCode {
    /// Сгенерировать случайный код NNN-NNN.
    pub fn generate() -> Self {
        use rand::RngExt;
        let mut rng = rand::rng();
        let a: u16 = rng.random_range(0..1000);
        let b: u16 = rng.random_range(0..1000);
        Self(format!("{a:03}-{b:03}"))
    }

    /// Распарсить и валидировать пользовательский ввод.
    /// Принимает только формат NNN-NNN (ровно 7 символов, цифры и дефис).
    pub fn parse(input: &str) -> Option<Self> {
        let s = input.trim();
        if s.len() != 7 {
            return None;
        }
        let (left, right) = s.split_once('-')?;
        if left.len() != 3 || right.len() != 3 {
            return None;
        }
        if !left.bytes().all(|b| b.is_ascii_digit()) || !right.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Some(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Права доступа участника в shared vault
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VaultPermission {
    Read,
    ReadWrite,
}

impl VaultPermission {
    pub fn as_str(&self) -> &str {
        match self {
            VaultPermission::Read => "read",
            VaultPermission::ReadWrite => "readwrite",
        }
    }

    pub fn from_str_permission(s: &str) -> Result<Self, String> {
        match s {
            "read" => Ok(VaultPermission::Read),
            "readwrite" => Ok(VaultPermission::ReadWrite),
            other => Err(format!("unknown permission: {other}")),
        }
    }
}

/// Роль участника в shared vault (owner/editor/viewer)
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Role {
    Owner,
    Editor,
    Viewer,
}

impl Role {
    pub fn as_str(&self) -> &str {
        match self {
            Role::Owner => "owner",
            Role::Editor => "editor",
            Role::Viewer => "viewer",
        }
    }

    pub fn from_str_role(s: &str) -> Result<Self, String> {
        match s {
            "owner" => Ok(Role::Owner),
            "editor" => Ok(Role::Editor),
            "viewer" => Ok(Role::Viewer),
            other => Err(format!("unknown role: {other}")),
        }
    }
}

/// Статус приглашения в shared vault
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InviteStatus {
    Pending,
    Accepted,
    Completed,
    Rejected,
    Expired,
}

impl InviteStatus {
    pub fn as_str(&self) -> &str {
        match self {
            InviteStatus::Pending => "pending",
            InviteStatus::Accepted => "accepted",
            InviteStatus::Completed => "completed",
            InviteStatus::Rejected => "rejected",
            InviteStatus::Expired => "expired",
        }
    }

    pub fn from_str_status(s: &str) -> Result<Self, String> {
        match s {
            "pending" => Ok(InviteStatus::Pending),
            "accepted" => Ok(InviteStatus::Accepted),
            "completed" => Ok(InviteStatus::Completed),
            "rejected" => Ok(InviteStatus::Rejected),
            "expired" => Ok(InviteStatus::Expired),
            other => Err(format!("unknown invite status: {other}")),
        }
    }
}
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
/// Минимальные данные пользователя для активной сессии.
/// Не содержит master_hash, auth_salt, encryption_salt —
/// они нужны только в момент authenticate().
#[derive(Debug)]
pub struct SessionUser {
    pub id: UserId,
    pub email: Email,
}
/// Результат аутентификации — SessionUser + ключ для шифрования
/// EncryptionKey не хранится в User, потому что он существует
/// только пока сессия активна
#[derive(Debug)]
pub struct AuthSession {
    pub user: SessionUser,
    pub key: EncryptionKey,
}
// ════════════════════════════════════════════════════════════════════
// Доменные структуры — shared.db (модуль shared/)
// ════════════════════════════════════════════════════════════════════
/// Keypair пользователя — строка из TABLE user_keys (shared.db)
#[derive(Debug)]
pub struct UserKeyPair {
    pub user_id: UserId,
    pub public_key: UserPublicKey,
    pub created_at: DateTime<Utc>,
}

/// Shared vault — строка из TABLE shared_vaults
#[derive(Debug)]
pub struct SharedVault {
    pub id: SharedVaultId,
    pub name: SharedVaultName,
    pub owner_id: UserId,
    pub created_at: DateTime<Utc>,
}

/// Участник shared vault — строка из TABLE shared_vault_members
#[derive(Debug)]
pub struct SharedVaultMember {
    pub vault_id: SharedVaultId,
    pub user_id: UserId,
    pub permission: VaultPermission,
    pub invited_at: DateTime<Utc>,
}

/// Зашифрованная запись в shared vault — строка из TABLE shared_entries
#[derive(Debug, Clone)]
pub struct SharedEncryptedEntry {
    pub id: EntryId,
    pub vault_id: SharedVaultId,
    pub encrypted_data: EncryptedData,
    pub nonce: Nonce,
    pub category: String,
    pub created_by: UserId,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted: bool,
}

/// Приглашение в shared vault — строка из TABLE invites
#[derive(Debug, Clone)]
pub struct Invite {
    pub id: InviteId,
    pub vault_id: SharedVaultId,
    pub inviter_id: UserId,
    pub invitee_email: String,
    pub role: Role,
    pub permission: VaultPermission,
    pub status: InviteStatus,
    pub vault_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Принятое приглашение (ожидает complete от inviter)
#[derive(Debug, Clone)]
pub struct AcceptedInvite {
    pub invite_id: InviteId,
    pub user_id: UserId,
    pub email: String,
    pub public_key_hex: String,
    pub confirmation_key_hex: String,
}
// ════════════════════════════════════════════════════════════════════
// VaultPass — Пропуск между Вахтером (auth) и Хранилищем (vault)
// ════════════════════════════════════════════════════════════════════
/// Пропуск — результат любой успешной аутентификации.
///
/// Вахтер (auth/) **создаёт** VaultPass после проверки личности:
/// JWT, Basic Auth, OAuth — неважно как.
///
/// Хранилище (vault/) **принимает** VaultPass через `enter()`:
/// не зная и не спрашивая, как именно пользователь прошёл проверку.
///
/// Не Clone, не Serialize — пропуск нельзя скопировать или случайно
/// отправить по сети. EncryptionKey зануляется при drop (ZeroizeOnDrop).
pub struct VaultPass {
    user_id: UserId,
    email: Email,
    encryption_key: EncryptionKey,
}

impl VaultPass {
    pub fn new(user_id: UserId, email: Email, encryption_key: EncryptionKey) -> Self {
        Self {
            user_id,
            email,
            encryption_key,
        }
    }
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }
    pub fn email(&self) -> &Email {
        &self.email
    }
    pub fn encryption_key(&self) -> &EncryptionKey {
        &self.encryption_key
    }
    /// Деструктурирует пропуск, отдавая владение полями.
    /// Нужен для vault.enter(), который забирает EncryptionKey в сессию.
    pub fn into_parts(self) -> (UserId, Email, EncryptionKey) {
        (self.user_id, self.email, self.encryption_key)
    }
}

impl fmt::Debug for VaultPass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultPass")
            .field("user_id", &self.user_id)
            .field("email", &"***")
            .field("encryption_key", &"***")
            .finish()
    }
}
