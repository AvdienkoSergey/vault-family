use super::AppState;
use super::dto::{AddRequest, AddResponse, DeleteResponse, ListEntry, ViewResponse};
use crate::auth;
use crate::crypto_operations::CryptoProvider;
use crate::types::{EntryId, EntryPassword, Login, PlainEntry, ServiceName, ServiceUrl, UserId};
use crate::vault::{Closed, DB};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use uuid::Uuid;

/// POST /add
///
/// Вахтер (guard) → Пропуск (VaultPass) → Хранилище (vault CRUD)
pub async fn add_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<AddRequest>,
) -> Result<Json<AddResponse>, StatusCode> {
    let db_path = state.db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        // Вахтер: JWT-only
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        // Хранилище: входим с пропуском
        let db = DB::<Closed, C>::new(crypto)
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let db = db
            .enter(pass)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // CRUD: добавляем запись
        let now = Utc::now();
        let entry_id = Uuid::new_v4().to_string();

        let plain = PlainEntry {
            id: EntryId::new(entry_id.clone()),
            user_id: UserId::new(db.user_id().as_str().to_string()),
            service_name: ServiceName::new(body.service_name),
            service_url: ServiceUrl::new(body.service_url),
            login: Login::new(body.login),
            password: EntryPassword::new(body.password),
            notes: body.notes,
            created_at: now,
            updated_at: now,
        };

        let encrypted = db
            .encrypt(&plain)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        db.save_entry(&encrypted)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(AddResponse {
            entry_id,
            message: "Entry added successfully".to_string(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /list
///
/// Вахтер (guard) → Пропуск → Хранилище (list_entries)
pub async fn list_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<ListEntry>>, StatusCode> {
    let db_path = state.db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        // Вахтер: JWT-only
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        // Хранилище
        let db = DB::<Closed, C>::new(crypto)
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let db = db
            .enter(pass)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let user_id = UserId::new(db.user_id().as_str().to_string());
        let entries = db
            .list_entries(&user_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let mut result = Vec::new();
        for entry in &entries {
            let plain = db
                .decrypt(entry)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            result.push(ListEntry {
                entry_id: entry.id.as_str().to_string(),
                service_name: plain.service_name.as_str().to_string(),
                created_at: entry.created_at.to_rfc3339(),
            });
        }

        Ok(Json(result))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /view/{id}
///
/// Вахтер (guard) → Пропуск → Хранилище (decrypt entry)
pub async fn view_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(entry_id): Path<String>,
) -> Result<Json<ViewResponse>, StatusCode> {
    let db_path = state.db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        // Вахтер: JWT-only
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        // Хранилище
        let db = DB::<Closed, C>::new(crypto)
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let db = db
            .enter(pass)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let user_id = UserId::new(db.user_id().as_str().to_string());
        let entries = db
            .list_entries(&user_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let entry = entries
            .iter()
            .find(|e| e.id.as_str() == entry_id)
            .ok_or(StatusCode::NOT_FOUND)?;

        let plain = db
            .decrypt(entry)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(ViewResponse {
            entry_id: entry.id.as_str().to_string(),
            service_name: plain.service_name.as_str().to_string(),
            service_url: plain.service_url.as_str().to_string(),
            login: plain.login.as_str().to_string(),
            password: plain.password.as_str().to_string(),
            notes: plain.notes,
            created_at: entry.created_at.to_rfc3339(),
            updated_at: entry.updated_at.to_rfc3339(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// DELETE /delete/{id}
///
/// Вахтер (guard) → Пропуск → Хранилище (delete_entry)
pub async fn delete_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(entry_id): Path<String>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    let db_path = state.db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        // Вахтер: JWT-only
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        // Хранилище
        let db = DB::<Closed, C>::new(crypto)
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let db = db
            .enter(pass)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let deleted = db
            .delete_entry(&EntryId::new(entry_id))
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        if deleted {
            Ok(Json(DeleteResponse {
                message: "Entry deleted successfully".to_string(),
            }))
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}
