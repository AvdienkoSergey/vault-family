use crate::types::{Email, EncryptionKey, JwtSecret, UserId};
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

pub enum JwtError {
    Create(String),
    Decode(String),
}
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
        exp: (Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
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
