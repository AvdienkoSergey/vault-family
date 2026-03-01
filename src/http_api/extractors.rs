use crate::crypto_operations::CryptoProvider;
use crate::http_api::jwt;
use crate::sqlite::{Closed, DB};
use crate::types::{EncryptionKey, JwtSecret, MasterPassword, UserId};
use axum::http::StatusCode;

pub struct Credentials {
    pub email: String,
    pub master_password: MasterPassword,
}

/// Единый результат аутентификации (Bearer JWT или Basic)
pub struct AuthResult {
    pub user_id: UserId,
    pub encryption_key: EncryptionKey,
}

/// Извлечь Bearer токен из заголовка Authorization
pub fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Result<String, StatusCode> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(token.to_string())
}

pub fn extract_basic_auth(headers: &axum::http::HeaderMap) -> Result<Credentials, StatusCode> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let encoded = header
        .strip_prefix("Basic ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let decoded = String::from_utf8(
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|_| StatusCode::UNAUTHORIZED)?,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let (email, password) = decoded.split_once(':').ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(Credentials {
        email: email.to_string(),
        master_password: MasterPassword::new(password.to_string()),
    })
}

/// Попробовать Bearer JWT, потом Basic Auth (fallback для CLI)
pub fn authenticate<C: CryptoProvider + Clone>(
    headers: &axum::http::HeaderMap,
    jwt_secret: &JwtSecret,
    db_path: &str,
    crypto: C,
) -> Result<AuthResult, StatusCode> {
    // 1. Bearer JWT — быстрый путь, без обращения к БД
    if let Ok(token) = extract_bearer_token(headers) {
        let claims =
            jwt::decode_access_token(&token, jwt_secret).map_err(|_| StatusCode::UNAUTHORIZED)?;

        return Ok(AuthResult {
            user_id: UserId::new(claims.sub),
            encryption_key: EncryptionKey::new(claims.ek),
        });
    }

    // 2. Basic Auth — fallback, открывает БД и деривирует ключ
    let creds = extract_basic_auth(headers)?;
    let email = crate::types::Email::parse(creds.email).map_err(|_| StatusCode::BAD_REQUEST)?;

    let db = DB::<Closed, C>::new(crypto)
        .open(db_path)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let db = db
        .authenticate(email, creds.master_password)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(AuthResult {
        user_id: UserId::new(db.user_id().as_str().to_string()),
        encryption_key: EncryptionKey::new(db.encryption_key().as_str().to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use base64::Engine;

    // ════════════════════════════════════════════
    // extract_bearer_token
    // ════════════════════════════════════════════

    #[test]
    fn extract_bearer_valid() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer my-jwt-token"),
        );

        let token = extract_bearer_token(&headers).unwrap();
        assert_eq!(token, "my-jwt-token");
    }

    #[test]
    fn extract_bearer_missing_header() {
        let headers = HeaderMap::new();
        let result = extract_bearer_token(&headers);
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn extract_bearer_basic_header_fails() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc123"));

        let result = extract_bearer_token(&headers);
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    // ════════════════════════════════════════════
    // extract_basic_auth
    // ════════════════════════════════════════════

    #[test]
    fn extract_basic_valid() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("user@example.com:secret");
        let value = format!("Basic {encoded}");

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&value).unwrap());

        let creds = extract_basic_auth(&headers).unwrap();
        assert_eq!(creds.email, "user@example.com");
        assert_eq!(creds.master_password.as_str(), "secret");
    }

    #[test]
    fn extract_basic_no_colon_fails() {
        let encoded = base64::engine::general_purpose::STANDARD.encode("no-colon-here");
        let value = format!("Basic {encoded}");

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&value).unwrap());

        assert!(extract_basic_auth(&headers).is_err());
    }
}
