//! Basic Auth провайдер — извлечение credentials из заголовка.
//!
//! Не зависит от vault, JWT или БД.
//! Только парсит `Authorization: Basic {base64(email:password)}`.

use crate::types::MasterPassword;
use axum::http::StatusCode;

/// Извлечённые credentials из Basic Auth заголовка.
pub struct Credentials {
    pub email: String,
    pub master_password: MasterPassword,
}

/// Извлечь Basic Auth credentials из заголовка Authorization.
///
/// Формат: `Authorization: Basic {base64(email:password)}`
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

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
    use base64::Engine;

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

    #[test]
    fn extract_basic_missing_header_fails() {
        let headers = HeaderMap::new();
        assert!(extract_basic_auth(&headers).is_err());
    }

    #[test]
    fn extract_basic_bearer_header_fails() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer some-jwt-token"),
        );

        assert!(extract_basic_auth(&headers).is_err());
    }
}
