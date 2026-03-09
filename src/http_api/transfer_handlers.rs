use axum::Json;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::StatusCode;
use std::net::SocketAddr;

use super::AppState;
use super::dto::{TransferDownloadResponse, TransferUploadRequest, TransferUploadResponse};
use crate::crypto_operations::CryptoProvider;
use crate::transfer::{MAX_COPIES, TransferError};
use crate::types::TransferCode;

fn transfer_error_to_status(err: &TransferError) -> StatusCode {
    match err {
        TransferError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        TransferError::StoreFull => StatusCode::SERVICE_UNAVAILABLE,
        TransferError::CodeCollision => StatusCode::SERVICE_UNAVAILABLE,
        TransferError::NotFound => StatusCode::NOT_FOUND,
        TransferError::Expired => StatusCode::GONE,
        TransferError::RateLimited => StatusCode::TOO_MANY_REQUESTS,
        TransferError::InvalidCode => StatusCode::BAD_REQUEST,
    }
}

/// POST /transfer — загрузить зашифрованный архив.
///
/// Анонимный (без JWT). Защита:
/// - Лимит размера payload (MAX_PAYLOAD_BYTES)
/// - Лимит слотов (MAX_CONCURRENT_SLOTS)
/// - TTL clamp (MAX_TTL_MINUTES)
#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/transfer",
    tag = "Transfer",
    request_body = TransferUploadRequest,
    responses(
        (status = 200, description = "Архив загружен, код для скачивания", body = TransferUploadResponse),
        (status = 413, description = "Payload слишком большой"),
        (status = 503, description = "Хранилище заполнено"),
    )
))]
pub async fn transfer_upload_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    Json(body): Json<TransferUploadRequest>,
) -> Result<Json<TransferUploadResponse>, StatusCode> {
    let transfer_store = state.transfer_store.clone();

    tokio::task::spawn_blocking(move || {
        let clamped_copies = body.copies.clamp(1, MAX_COPIES);

        let (code, expires_at) = transfer_store
            .insert(body.payload, body.ttl_minutes, body.copies)
            .map_err(|e| transfer_error_to_status(&e))?;

        Ok(Json(TransferUploadResponse {
            code: code.as_str().to_string(),
            expires_at: expires_at.to_rfc3339(),
            copies: clamped_copies,
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /transfer/{code} — скачать зашифрованный архив.
///
/// Анонимный (без JWT). Защита:
/// - Per-IP rate limiting (RATE_LIMIT_MAX_ATTEMPTS за RATE_LIMIT_WINDOW_SECS)
/// - Rate limit проверяется ДО поиска кода (предотвращает timing-атаки)
/// - Попытка фиксируется всегда (даже невалидные коды считаются)
/// - TTL + copies_remaining на слоте
#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/transfer/{code}",
    tag = "Transfer",
    params(("code" = String, Path, description = "Код трансфера в формате NNN-NNN")),
    responses(
        (status = 200, description = "Архив получен", body = TransferDownloadResponse),
        (status = 400, description = "Невалидный формат кода"),
        (status = 404, description = "Код не найден"),
        (status = 410, description = "Код истёк"),
        (status = 429, description = "Слишком много попыток"),
    )
))]
pub async fn transfer_download_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Path(code_str): Path<String>,
) -> Result<Json<TransferDownloadResponse>, StatusCode> {
    let transfer_store = state.transfer_store.clone();
    let rate_limiter = state.transfer_rate_limiter.clone();

    tokio::task::spawn_blocking(move || {
        let ip = addr.ip().to_string();

        // Rate limit ДО любой проверки кода — предотвращает timing-атаки
        if rate_limiter.is_limited(&ip) {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        // Фиксируем попытку ВСЕГДА (даже невалидные коды)
        rate_limiter.record_attempt(&ip);

        // Валидация формата кода
        let code = TransferCode::parse(&code_str).ok_or(StatusCode::BAD_REQUEST)?;

        // Claim: payload + декремент copies
        let payload = transfer_store
            .claim(&code)
            .map_err(|e| transfer_error_to_status(&e))?;

        Ok(Json(TransferDownloadResponse { payload }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}
