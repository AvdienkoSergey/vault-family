use super::dto::{GenerateParams, GenerateResponse};
use crate::password_generator::{Empty, PasswordGenerator};
use axum::Json;
use axum::extract::Query;
use axum::http::StatusCode;

#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/health",
    tag = "System",
    responses(
        (status = 200, description = "Service is healthy", body = String)
    )
))]
pub async fn health_handler() -> &'static str {
    "ok"
}

/// GET /generate
#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/generate",
    tag = "System",
    params(GenerateParams),
    responses(
        (status = 200, description = "Generated password", body = GenerateResponse),
        (status = 400, description = "Invalid parameters")
    )
))]
pub async fn generate_handler(
    Query(params): Query<GenerateParams>,
) -> Result<Json<GenerateResponse>, StatusCode> {
    let length = params.length;
    if !(8..=128).contains(&length) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !params.lowercase && !params.uppercase && !params.digits && !params.symbols {
        return Err(StatusCode::BAD_REQUEST);
    }

    let pg = PasswordGenerator::<Empty, 8>::from_flags(
        length,
        params.lowercase,
        params.uppercase,
        params.digits,
        params.symbols,
    );
    let password = pg.generate();

    Ok(Json(GenerateResponse {
        password: password.as_str().to_string(),
    }))
}
