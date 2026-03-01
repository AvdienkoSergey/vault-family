//! JWT-провайдер — создание и декодирование access-токенов.
//!
//! Знает только про Claims и JwtSecret.
//! Не знает про vault, БД, HTTP — чистая JWT-логика.
//!
//! **EncryptionKey НЕ попадает в JWT.**
//! Токен содержит только идентификацию (sub + email).
//! Ключ шифрования хранится в `SessionStore` (серверная память).

use super::JwtSecret;
use crate::types::{Email, UserId, VaultPass};
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

pub const ACCESS_TOKEN_TTL_MINUTES: i64 = 15;
pub const REFRESH_TOKEN_TTL_DAYS: i64 = 7;

// ════════════════════════════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum JwtError {
    Create(String),
    Decode(String),
}

impl std::error::Error for JwtError {}

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Create(msg) => write!(f, "jwt create error: {msg}"),
            JwtError::Decode(msg) => write!(f, "jwt decode error: {msg}"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// Claims — только идентификация, без секретов
// ════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,   // user_id (subject — стандартное поле JWT)
    pub email: String, // для удобства
    pub exp: usize,    // expiration — Unix timestamp
}

// ════════════════════════════════════════════════════════════════════
// Encode / Decode
// ════════════════════════════════════════════════════════════════════

/// Создать access_token из данных VaultPass.
/// Удобная обёртка: принимает пропуск целиком.
pub fn create_access_token_from_pass(
    pass: &VaultPass,
    secret: &JwtSecret,
) -> Result<String, JwtError> {
    create_access_token(pass.user_id(), pass.email(), secret)
}

/// Создать access_token из отдельных полей.
pub fn create_access_token(
    user_id: &UserId,
    email: &Email,
    secret: &JwtSecret,
) -> Result<String, JwtError> {
    let claims = Claims {
        sub: user_id.as_str().to_string(),
        email: email.as_str().to_string(),
        exp: (Utc::now() + chrono::Duration::minutes(ACCESS_TOKEN_TTL_MINUTES)).timestamp()
            as usize,
    };
    encode(
        &Header::default(), // HS256
        &claims,
        &EncodingKey::from_secret(secret.as_str().as_bytes()),
    )
    .map_err(|e| JwtError::Create(format!("JWT creation error: {:?}", e)))
}

/// Декодировать access_token с проверкой подписи и expiration.
pub fn decode_access_token(token: &str, secret: &JwtSecret) -> Result<Claims, JwtError> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_str().as_bytes()),
        &Validation::default(), // проверяет exp, alg
    )
    .map_err(|e| JwtError::Decode(format!("JWT decode error: {:?}", e)))?;
    Ok(token_data.claims)
}

/// Декодировать JWT без проверки exp — для /refresh,
/// где access_token истёк, но подпись должна быть валидной.
pub fn decode_access_token_allow_expired(
    token: &str,
    secret: &JwtSecret,
) -> Result<Claims, JwtError> {
    let mut validation = Validation::default();
    validation.validate_exp = false;
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_str().as_bytes()),
        &validation,
    )
    .map_err(|e| JwtError::Decode(format!("JWT decode error: {:?}", e)))?;
    Ok(token_data.claims)
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> JwtSecret {
        JwtSecret::new("test-secret-key-for-unit-tests".to_string())
    }

    fn test_user_id() -> UserId {
        UserId::new("user-123".to_string())
    }

    fn test_email() -> Email {
        Email::new("test@example.com".to_string())
    }

    fn test_pass() -> VaultPass {
        use crate::types::EncryptionKey;
        VaultPass::new(
            test_user_id(),
            test_email(),
            EncryptionKey::new("abcdef0123456789".to_string()),
        )
    }

    /// Создаёт токен с произвольным exp (для тестов expiration)
    fn create_token_with_exp(exp: usize, secret: &JwtSecret) -> String {
        let claims = Claims {
            sub: "user-123".to_string(),
            email: "test@example.com".to_string(),
            exp,
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_str().as_bytes()),
        )
        .unwrap()
    }

    #[test]
    fn create_and_decode_roundtrip() {
        let secret = test_secret();
        let token = create_access_token(&test_user_id(), &test_email(), &secret).unwrap();

        let claims = decode_access_token(&token, &secret).unwrap();

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.email, "test@example.com");
    }

    #[test]
    fn create_from_pass_roundtrip() {
        let secret = test_secret();
        let token = create_access_token_from_pass(&test_pass(), &secret).unwrap();

        let claims = decode_access_token(&token, &secret).unwrap();

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.email, "test@example.com");
    }

    #[test]
    fn decode_rejects_wrong_secret() {
        let secret = test_secret();
        let wrong_secret = JwtSecret::new("wrong-secret".to_string());

        let token = create_access_token(&test_user_id(), &test_email(), &secret).unwrap();

        assert!(decode_access_token(&token, &wrong_secret).is_err());
    }

    #[test]
    fn decode_rejects_expired_token() {
        let secret = test_secret();
        let token = create_token_with_exp(0, &secret);

        assert!(decode_access_token(&token, &secret).is_err());
    }

    #[test]
    fn decode_allow_expired_accepts_expired() {
        let secret = test_secret();
        let token = create_token_with_exp(0, &secret);

        let claims = decode_access_token_allow_expired(&token, &secret).unwrap();

        assert_eq!(claims.sub, "user-123");
    }

    #[test]
    fn decode_allow_expired_rejects_wrong_secret() {
        let secret = test_secret();
        let wrong_secret = JwtSecret::new("wrong-secret".to_string());
        let token = create_token_with_exp(0, &secret);

        assert!(decode_access_token_allow_expired(&token, &wrong_secret).is_err());
    }
}
