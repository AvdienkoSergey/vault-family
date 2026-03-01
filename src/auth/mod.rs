//! Модуль Вахтер — аутентификация и управление сессиями.
//!
//! Отвечает за проверку личности (JWT, Basic Auth, будущий OAuth).
//! Результат работы — `VaultPass` (Пропуск), который передаётся в Хранилище.
//!
//! **Не зависит от vault/** — не знает про записи, шифрование, entries.
//! Единственный мост между auth и vault — `VaultPass` из `types.rs`.

pub mod basic_provider;
pub mod jwt_provider;
pub mod jwt_secret;
pub mod jwt_store;
mod jwt_types;

use crate::types::{EncryptionKey, MasterPassword, UserId, VaultPass};
use axum::http::StatusCode;

// Re-exports для удобства
pub use basic_provider::Credentials;
pub use jwt_provider::{Claims, JwtError, REFRESH_TOKEN_TTL_DAYS};
pub use jwt_store::{AuthStore, StoreError};
pub use jwt_types::{JwtSecret, RefreshTokenHash};

// ════════════════════════════════════════════════════════════════════
// AuthError
// ════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum AuthError {
    /// Нет ни Bearer, ни Basic заголовка
    MissingAuth,
    /// Токен невалиден (подпись, формат, expiration)
    InvalidToken(String),
    /// Неверные credentials (пароль, email)
    InvalidCredentials(String),
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

/// Единая точка аутентификации — Вахтер.
///
/// Пробует Bearer JWT (быстрый путь, без БД),
/// при неудаче — извлекает Basic Auth credentials
/// и вызывает `verify` callback для проверки пароля.
///
/// `verify` — замыкание, которое обычно вызывает `vault.create_pass()`.
/// Это позволяет auth/ не зависеть от vault/ напрямую.
///
/// # Примеры
///
/// ```ignore
/// // В HTTP handler:
/// let pass = auth::guard(&headers, &jwt_secret, |email, password| {
///     let db = vault_db.open(&db_path)?;
///     db.create_pass(email, password)
///         .map_err(|e| AuthError::InvalidCredentials(e.to_string()))
/// })?;
///
/// // JWT-only (без fallback):
/// let pass = auth::guard(&headers, &jwt_secret, |_, _| {
///     Err(AuthError::MissingAuth)
/// })?;
/// ```
pub fn guard<F>(
    headers: &axum::http::HeaderMap,
    jwt_secret: &JwtSecret,
    verify: F,
) -> Result<VaultPass, AuthError>
where
    F: FnOnce(String, MasterPassword) -> Result<VaultPass, AuthError>,
{
    // 1. Bearer JWT — быстрый путь, без обращения к БД
    if let Some(token) = extract_bearer_token(headers) {
        let claims = jwt_provider::decode_access_token(&token, jwt_secret)?;

        return Ok(VaultPass::new(
            UserId::new(claims.sub),
            crate::types::Email::new(claims.email),
            EncryptionKey::new(claims.ek),
        ));
    }

    // 2. Basic Auth — fallback, делегируем проверку пароля вызывающему
    let creds = basic_provider::extract_basic_auth(headers).map_err(|_| AuthError::MissingAuth)?;

    verify(creds.email, creds.master_password)
}

// ════════════════════════════════════════════════════════════════════
// Утилита: вычислить путь к auth.db рядом с vault.db
// ════════════════════════════════════════════════════════════════════

/// Определить путь к auth.db на основе пути к vault.db.
///
/// `vault.db` → `auth.db` (в той же директории).
pub fn auth_db_path(vault_db_path: &str) -> String {
    let path = std::path::Path::new(vault_db_path);
    let parent = path.parent().unwrap_or(std::path::Path::new("."));
    parent.join("auth.db").to_string_lossy().into_owned()
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::JwtSecret;
    use super::*;
    use crate::types::{Email, EncryptionKey, UserId, VaultPass};
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

    fn make_basic_headers(email: &str, password: &str) -> HeaderMap {
        use base64::Engine;
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{email}:{password}"));
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
        );
        headers
    }

    // ════════════════════════════════════════════
    // guard() — JWT path
    // ════════════════════════════════════════════

    #[test]
    fn guard_jwt_valid_token() {
        let secret = test_secret();
        let token = jwt_provider::create_access_token(
            &UserId::new("user-1".to_string()),
            &Email::new("alex@icloud.com".to_string()),
            &EncryptionKey::new("deadbeef".to_string()),
            &secret,
        )
        .unwrap();

        let headers = make_bearer_headers(&token);
        let unreachable_verify = |_: String, _: MasterPassword| -> Result<VaultPass, AuthError> {
            panic!("verify should not be called for JWT path");
        };

        let pass = guard(&headers, &secret, unreachable_verify).unwrap();

        assert_eq!(pass.user_id().as_str(), "user-1");
        assert_eq!(pass.email().as_str(), "alex@icloud.com");
        assert_eq!(pass.encryption_key().as_str(), "deadbeef");
    }

    #[test]
    fn guard_jwt_invalid_token() {
        let secret = test_secret();
        let headers = make_bearer_headers("not-a-valid-jwt");
        let unreachable_verify = |_: String, _: MasterPassword| -> Result<VaultPass, AuthError> {
            panic!("verify should not be called for invalid JWT");
        };

        let result = guard(&headers, &secret, unreachable_verify);
        assert!(result.is_err());
    }

    // ════════════════════════════════════════════
    // guard() — Basic Auth path
    // ════════════════════════════════════════════

    #[test]
    fn guard_basic_auth_calls_verify() {
        let secret = test_secret();
        let headers = make_basic_headers("alex@icloud.com", "SuperSecret123!");

        let verify = |email: String, password: MasterPassword| -> Result<VaultPass, AuthError> {
            assert_eq!(email, "alex@icloud.com");
            assert_eq!(password.as_str(), "SuperSecret123!");
            Ok(VaultPass::new(
                UserId::new("user-42".to_string()),
                Email::new(email),
                EncryptionKey::new("derived-key".to_string()),
            ))
        };

        let pass = guard(&headers, &secret, verify).unwrap();

        assert_eq!(pass.user_id().as_str(), "user-42");
    }

    #[test]
    fn guard_basic_auth_verify_fails() {
        let secret = test_secret();
        let headers = make_basic_headers("alex@icloud.com", "WrongPassword!");

        let verify = |_: String, _: MasterPassword| -> Result<VaultPass, AuthError> {
            Err(AuthError::InvalidCredentials("wrong password".to_string()))
        };

        let result = guard(&headers, &secret, verify);
        assert!(matches!(result, Err(AuthError::InvalidCredentials(_))));
    }

    // ════════════════════════════════════════════
    // guard() — no auth header
    // ════════════════════════════════════════════

    #[test]
    fn guard_no_auth_header() {
        let secret = test_secret();
        let headers = HeaderMap::new();
        let unreachable_verify = |_: String, _: MasterPassword| -> Result<VaultPass, AuthError> {
            panic!("verify should not be called with no headers");
        };

        let result = guard(&headers, &secret, unreachable_verify);
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
}
