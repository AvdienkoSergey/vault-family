//! Модуль Вахтер — аутентификация и управление сессиями.
//!
//! Отвечает за проверку личности (JWT-only).
//! Результат работы — `VaultPass` (Пропуск), который передаётся в Хранилище.
//!
//! **Не зависит от vault/** — не знает про записи, шифрование, entries.
//! Единственный мост между auth и vault — `VaultPass` из `types.rs`.

pub mod device_trust;
pub mod failed_login_tracker;
pub mod jwt_provider;
pub mod jwt_secret;
pub mod jwt_store;
mod jwt_types;
pub mod security_lock;
pub mod session_store;

use crate::types::{UserId, VaultPass};
use axum::http::StatusCode;

// Re-exports для удобства
pub use device_trust::DeviceTrustStore;
pub use failed_login_tracker::FailedLoginTracker;
pub use jwt_provider::{Claims, JwtError, REFRESH_TOKEN_TTL_DAYS};
pub use jwt_store::{AuthStore, StoreError};
pub use jwt_types::{JwtSecret, RefreshTokenHash};
pub use security_lock::SecurityLockStore;
pub use session_store::SessionStore;

// ════════════════════════════════════════════════════════════════════
// AuthError
// ════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum AuthError {
    /// Нет Bearer заголовка
    MissingAuth,
    /// Токен невалиден (подпись, формат, expiration)
    InvalidToken(String),
    /// Неверные credentials (пароль, email)
    InvalidCredentials(String),
    /// EncryptionKey не найден в SessionStore (сервер перезапустился или сессия истекла)
    SessionExpired,
    /// Слишком много неудачных попыток входа (brute-force защита)
    AccountLocked,
    /// Ошибка хранилища refresh-токенов
    Store(StoreError),
}

impl std::error::Error for AuthError {}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::MissingAuth => write!(f, "no authentication provided"),
            AuthError::InvalidToken(msg) => write!(f, "invalid token: {msg}"),
            AuthError::InvalidCredentials(msg) => write!(f, "invalid credentials: {msg}"),
            AuthError::SessionExpired => write!(f, "session expired, please re-login"),
            AuthError::AccountLocked => {
                write!(f, "account temporarily locked, too many failed attempts")
            }
            AuthError::Store(e) => write!(f, "auth store error: {e}"),
        }
    }
}

impl From<JwtError> for AuthError {
    fn from(e: JwtError) -> Self {
        AuthError::InvalidToken(e.to_string())
    }
}

impl From<StoreError> for AuthError {
    fn from(e: StoreError) -> Self {
        AuthError::Store(e)
    }
}

/// Конвертация AuthError → HTTP StatusCode для http_api слоя.
impl From<AuthError> for StatusCode {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::MissingAuth => StatusCode::UNAUTHORIZED,
            AuthError::InvalidToken(_) => StatusCode::UNAUTHORIZED,
            AuthError::InvalidCredentials(_) => StatusCode::UNAUTHORIZED,
            AuthError::SessionExpired => StatusCode::UNAUTHORIZED,
            AuthError::AccountLocked => StatusCode::FORBIDDEN,
            AuthError::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// guard() — единая точка входа
// ════════════════════════════════════════════════════════════════════

/// Извлечь Bearer-токен из заголовка Authorization.
fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;

    header.strip_prefix("Bearer ").map(|t| t.to_string())
}

/// Единая точка аутентификации — Вахтер (JWT-only).
///
/// Извлекает Bearer JWT из заголовка Authorization,
/// проверяет подпись и expiration, достаёт EncryptionKey из SessionStore.
///
/// Пароль не участвует → нет brute-force вектора на этом уровне.
/// Brute-force защита — в `login_handler` (POST /login).
///
/// # Примеры
///
/// ```ignore
/// let pass = auth::guard(&headers, &jwt_secret, &session_store)?;
/// ```
pub fn guard(
    headers: &axum::http::HeaderMap,
    jwt_secret: &JwtSecret,
    session_store: &SessionStore,
) -> Result<VaultPass, AuthError> {
    let token = extract_bearer_token(headers).ok_or(AuthError::MissingAuth)?;

    let claims = jwt_provider::decode_access_token(&token, jwt_secret)?;

    let ek = session_store
        .get(&claims.sub)
        .ok_or(AuthError::SessionExpired)?;

    Ok(VaultPass::new(
        UserId::new(claims.sub),
        crate::types::Email::new(claims.email),
        ek,
    ))
}

// ════════════════════════════════════════════════════════════════════
// Утилита: вычислить путь к auth.db рядом с vault.db
// ════════════════════════════════════════════════════════════════════

/// Определить путь к auth.db на основе пути к vault.db.
///
/// `vault.db` → `auth.db` (в той же директории).
/// Derive auth.db path from vault.db path (same directory, sibling file).
///
/// `data/vault.db` → `data/auth.db`
/// `data/vault_test_abc.db` → `data/vault_test_abc_auth.db`
///
/// Uses the stem of vault_db_path to produce a unique sibling name.
/// This ensures test isolation when multiple vault DBs exist in the same directory.
pub fn auth_db_path(vault_db_path: &str) -> String {
    let path = std::path::Path::new(vault_db_path);
    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    if stem == "vault" {
        // Production convention: vault.db → auth.db
        parent.join("auth.db").to_string_lossy().into_owned()
    } else {
        // Test / custom: vault_test_abc.db → vault_test_abc_auth.db
        parent
            .join(format!("{stem}_auth.db"))
            .to_string_lossy()
            .into_owned()
    }
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::JwtSecret;
    use super::*;
    use crate::types::{Email, EncryptionKey, UserId};
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};

    fn test_secret() -> JwtSecret {
        JwtSecret::new("test-guard-secret".to_string())
    }

    fn make_bearer_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    // ════════════════════════════════════════════
    // guard() — JWT path
    // ════════════════════════════════════════════

    #[test]
    fn guard_jwt_valid_token() {
        let secret = test_secret();
        let store = SessionStore::new();

        // Вставляем ek в session store ДО вызова guard
        store.insert("user-1", &EncryptionKey::new("deadbeef".to_string()));

        let token = jwt_provider::create_access_token(
            &UserId::new("user-1".to_string()),
            &Email::new("alex@icloud.com".to_string()),
            &secret,
        )
        .unwrap();

        let headers = make_bearer_headers(&token);
        let pass = guard(&headers, &secret, &store).unwrap();

        assert_eq!(pass.user_id().as_str(), "user-1");
        assert_eq!(pass.email().as_str(), "alex@icloud.com");
        assert_eq!(pass.encryption_key().as_str(), "deadbeef");
    }

    #[test]
    fn guard_jwt_without_session_returns_session_expired() {
        let secret = test_secret();
        let store = SessionStore::new(); // пустой — нет записи

        let token = jwt_provider::create_access_token(
            &UserId::new("user-1".to_string()),
            &Email::new("alex@icloud.com".to_string()),
            &secret,
        )
        .unwrap();

        let headers = make_bearer_headers(&token);
        let result = guard(&headers, &secret, &store);
        assert!(matches!(result, Err(AuthError::SessionExpired)));
    }

    #[test]
    fn guard_jwt_invalid_token() {
        let secret = test_secret();
        let store = SessionStore::new();
        let headers = make_bearer_headers("not-a-valid-jwt");

        let result = guard(&headers, &secret, &store);
        assert!(result.is_err());
    }

    // ════════════════════════════════════════════
    // guard() — no auth header
    // ════════════════════════════════════════════

    #[test]
    fn guard_no_auth_header() {
        let secret = test_secret();
        let store = SessionStore::new();
        let headers = HeaderMap::new();

        let result = guard(&headers, &secret, &store);
        assert!(matches!(result, Err(AuthError::MissingAuth)));
    }

    #[test]
    fn guard_basic_auth_header_treated_as_missing() {
        use base64::Engine;
        let secret = test_secret();
        let store = SessionStore::new();

        let encoded =
            base64::engine::general_purpose::STANDARD.encode("alice@example.com:password");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );

        // Basic Auth больше не поддерживается — воспринимается как MissingAuth
        let result = guard(&headers, &secret, &store);
        assert!(matches!(result, Err(AuthError::MissingAuth)));
    }

    // ════════════════════════════════════════════
    // auth_db_path()
    // ════════════════════════════════════════════

    #[test]
    fn auth_db_path_from_vault_path() {
        let path = auth_db_path("/data/vault-family/vault.db");
        assert!(path.contains("auth.db"));
        assert!(path.contains("vault-family"));
    }

    #[test]
    fn auth_db_path_unique_for_test_dbs() {
        let path = auth_db_path("/tmp/vault_handler_test_abc123.db");
        assert!(path.contains("vault_handler_test_abc123_auth.db"));
        assert!(!path.ends_with("auth.db") || path.contains("abc123"));
    }
}
