use crate::types::{Email, EncryptionKey, JwtSecret, UserId};
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

const ACCESS_TOKEN_TTL_MINUTES: i64 = 15;
pub(crate) const REFRESH_TOKEN_TTL_DAYS: i64 = 7;
#[derive(Debug)]
pub enum JwtError {
    Create(String),
    Decode(String),
}
impl std::error::Error for JwtError {}
impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwtError::Create(msg) => write!(f, "create error: {msg}"),
            JwtError::Decode(msg) => write!(f, "decode error: {msg}"),
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,   // user_id (subject = стандартное поле JWT)
    pub email: String, // для удобства
    pub ek: String,    // encryption_key в hex
    pub exp: usize,    // expiration — Unix timestamp
}
pub fn create_access_token(
    user_id: &UserId,               // branded_no_secret — sub в claims
    email: &Email,                  // branded_secret — но нам нужен .as_str()
    encryption_key: &EncryptionKey, // branded_secret — ek в claims
    secret: &JwtSecret,             // branded_secret — HMAC ключ
) -> Result<String, JwtError> {
    let claims = Claims {
        sub: user_id.as_str().to_string(),
        email: email.as_str().to_string(),
        ek: encryption_key.as_str().to_string(),
        exp: (Utc::now() + chrono::Duration::minutes(ACCESS_TOKEN_TTL_MINUTES)).timestamp()
            as usize,
    };
    let token = encode(
        &Header::default(), // HS256
        &claims,
        &EncodingKey::from_secret(secret.as_str().as_bytes()),
    );
    token.map_err(|e| JwtError::Create(format!("JWT creation error: {:?}", e)))
}

pub fn decode_access_token(token: &str, secret: &JwtSecret) -> Result<Claims, JwtError> {
    let token_data = decode::<Claims>(
        &token,
        &DecodingKey::from_secret(secret.as_str().as_bytes()),
        &Validation::default(), // проверяет exp, alg
    )
    .map_err(|e| JwtError::Decode(format!("JWT decode error: {:?}", e)))?;
    let claims = token_data.claims;
    Ok(claims)
}

/// Декодирует JWT без проверки exp — для /refresh,
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

    fn test_encryption_key() -> EncryptionKey {
        EncryptionKey::new("abcdef0123456789".to_string())
    }

    /// Создаёт токен с произвольным exp (для тестов expiration)
    fn create_token_with_exp(exp: usize, secret: &JwtSecret) -> String {
        let claims = Claims {
            sub: "user-123".to_string(),
            email: "test@example.com".to_string(),
            ek: "abcdef0123456789".to_string(),
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
        let token = create_access_token(
            &test_user_id(),
            &test_email(),
            &test_encryption_key(),
            &secret,
        )
        .unwrap();

        let claims = decode_access_token(&token, &secret).unwrap();

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.email, "test@example.com");
        assert_eq!(claims.ek, "abcdef0123456789");
    }

    #[test]
    fn decode_rejects_wrong_secret() {
        let secret = test_secret();
        let wrong_secret = JwtSecret::new("wrong-secret".to_string());

        let token = create_access_token(
            &test_user_id(),
            &test_email(),
            &test_encryption_key(),
            &secret,
        )
        .unwrap();

        assert!(decode_access_token(&token, &wrong_secret).is_err());
    }

    #[test]
    fn decode_rejects_expired_token() {
        let secret = test_secret();
        // exp = 0 → 1970-01-01, давно истёк
        let token = create_token_with_exp(0, &secret);

        assert!(decode_access_token(&token, &secret).is_err());
    }

    #[test]
    fn decode_allow_expired_accepts_expired() {
        let secret = test_secret();
        let token = create_token_with_exp(0, &secret);

        let claims = decode_access_token_allow_expired(&token, &secret).unwrap();

        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.ek, "abcdef0123456789");
    }

    #[test]
    fn decode_allow_expired_rejects_wrong_secret() {
        let secret = test_secret();
        let wrong_secret = JwtSecret::new("wrong-secret".to_string());
        let token = create_token_with_exp(0, &secret);

        assert!(decode_access_token_allow_expired(&token, &wrong_secret).is_err());
    }
}
