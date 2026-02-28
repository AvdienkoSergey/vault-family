use axum::http::StatusCode;

pub struct Credentials {
    pub email: String,
    pub master_password: String,
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
        master_password: password.to_string(),
    })
}
