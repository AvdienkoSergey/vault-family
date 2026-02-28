use crate::crypto_operations::RealCrypto;
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
pub fn authenticate(
    headers: &axum::http::HeaderMap,
    jwt_secret: &JwtSecret,
    db_path: &str,
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

    let db = DB::<Closed, RealCrypto>::new(RealCrypto)
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
