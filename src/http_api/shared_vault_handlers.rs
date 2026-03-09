use super::AppState;
use super::dto::{
    ApiEncryptedEntryItem, ApiMemberItem, ApiMyKeyResponse, ApiSharedVaultItem,
    CreateSharedVaultRequest, CreateSharedVaultResponse, DeleteResponse, MemberListItem,
    PullEntriesQuery, PushEntriesRequest, SharedVaultListItem, UpdateMemberKeysRequest,
    UpdatePermissionRequest,
};
use crate::auth;
use crate::crypto_operations::CryptoProvider;
use crate::shared::{SharedDB, SharedError};
use crate::types::{SharedVaultId, SharedVaultName, UserId, VaultPermission};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::{DateTime, Utc};

fn shared_error_to_status(err: &SharedError) -> StatusCode {
    match err {
        SharedError::NotFound(_) => StatusCode::NOT_FOUND,
        SharedError::Forbidden(_) => StatusCode::FORBIDDEN,
        SharedError::MemberLimit(_) => StatusCode::BAD_REQUEST,
        SharedError::NoKeypair(_) => StatusCode::BAD_REQUEST,
        SharedError::InviteNotFound(_) => StatusCode::NOT_FOUND,
        SharedError::InvalidInviteState(_) => StatusCode::CONFLICT,
        SharedError::Conflict(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// ════════════════════════════════════════════════════════════════════
// New /api/vaults/* handlers (zero-knowledge)
// ════════════════════════════════════════════════════════════════════

/// POST /api/vaults — create shared vault (zero-knowledge)
pub async fn api_create_vault_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateSharedVaultRequest>,
) -> Result<(StatusCode, Json<CreateSharedVaultResponse>), StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let vault = shared_db
            .create_shared_vault(&pass, SharedVaultName::new(body.name))
            .map_err(|e| shared_error_to_status(&e))?;

        Ok((
            StatusCode::CREATED,
            Json(CreateSharedVaultResponse {
                vault_id: vault.id.as_str().to_string(),
                message: "Shared vault created".to_string(),
            }),
        ))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /api/vaults — list shared vaults with counts
pub async fn api_list_vaults_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<ApiSharedVaultItem>>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let vaults = shared_db
            .list_shared_vaults_with_counts(pass.user_id())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let items = vaults
            .into_iter()
            .map(|v| ApiSharedVaultItem {
                id: v.id.as_str().to_string(),
                name: v.name.as_str().to_string(),
                created_by: v.owner_id.as_str().to_string(),
                member_count: v.member_count,
                entry_count: v.entry_count,
            })
            .collect();

        Ok(Json(items))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// DELETE /api/vaults/{vault_id}
pub async fn api_delete_vault_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        shared_db
            .delete_shared_vault(&pass, &SharedVaultId::new(vault_id))
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(StatusCode::NO_CONTENT)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /api/vaults/{vault_id}/members — expanded member list
pub async fn api_list_members_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
) -> Result<Json<Vec<ApiMemberItem>>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let members = shared_db
            .list_members(pass.user_id(), &SharedVaultId::new(vault_id))
            .map_err(|e| shared_error_to_status(&e))?;

        // Build expanded member items with public key info
        let items: Vec<ApiMemberItem> = members
            .into_iter()
            .map(|m| {
                let public_key = shared_db
                    .get_user_public_key(&m.user_id)
                    .map(|k| k.as_str().to_string())
                    .unwrap_or_default();

                ApiMemberItem {
                    user_id: m.user_id.as_str().to_string(),
                    email: String::new(), // Email lookup requires vault.db — enriched if needed
                    role: m.permission.as_str().to_string(), // TODO: separate role column
                    permission: m.permission.as_str().to_string(),
                    public_key_hex: public_key,
                    crypto_status: "synced".to_string(),
                }
            })
            .collect();

        Ok(Json(items))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// DELETE /api/vaults/{vault_id}/members/{user_id} — revoke (zero-knowledge)
pub async fn api_revoke_member_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path((vault_id, user_id)): Path<(String, String)>,
) -> Result<StatusCode, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        shared_db
            .revoke_member(&pass, &SharedVaultId::new(vault_id), &UserId::new(user_id))
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(StatusCode::NO_CONTENT)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// PUT /api/vaults/{vault_id}/keys — client-driven re-keying
pub async fn api_update_keys_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
    Json(body): Json<UpdateMemberKeysRequest>,
) -> Result<StatusCode, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let keys: Vec<(String, String, String)> = body
            .members
            .into_iter()
            .map(|m| (m.user_id, m.encrypted_vault_key, m.nonce))
            .collect();

        shared_db
            .update_member_keys(pass.user_id(), &SharedVaultId::new(vault_id), &keys)
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(StatusCode::NO_CONTENT)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /api/vaults/{vault_id}/my-key — get own encrypted vault key
pub async fn api_get_my_key_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
) -> Result<Json<ApiMyKeyResponse>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let vid = SharedVaultId::new(vault_id);

        let (encrypted_key, nonce, sender_pub_key) = shared_db
            .get_member_encrypted_key(pass.user_id(), &vid)
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(Json(ApiMyKeyResponse {
            encrypted_vault_key: encrypted_key,
            nonce,
            owner_public_key_hex: sender_pub_key,
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// POST /api/vaults/{vault_id}/entries — push entries (zero-knowledge)
pub async fn api_push_entries_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
    Json(body): Json<PushEntriesRequest>,
) -> Result<StatusCode, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let entries: Vec<(String, String, String, String, String, bool)> = body
            .entries
            .into_iter()
            .map(|e| {
                (
                    e.id,
                    e.encrypted_data,
                    e.nonce,
                    e.category,
                    e.last_modified,
                    e.deleted.unwrap_or(false),
                )
            })
            .collect();

        shared_db
            .push_entries(pass.user_id(), &SharedVaultId::new(vault_id), &entries)
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(StatusCode::NO_CONTENT)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /api/vaults/{vault_id}/entries — pull entries (zero-knowledge, delta sync)
pub async fn api_pull_entries_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
    Query(query): Query<PullEntriesQuery>,
) -> Result<Json<Vec<ApiEncryptedEntryItem>>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let since = query.since.and_then(|s| {
            DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
        });

        let entries = shared_db
            .list_shared_entries(pass.user_id(), &SharedVaultId::new(vault_id), since)
            .map_err(|e| shared_error_to_status(&e))?;

        let items: Vec<ApiEncryptedEntryItem> = entries
            .into_iter()
            .map(|e| ApiEncryptedEntryItem {
                id: e.id.as_str().to_string(),
                category: e.category,
                encrypted_data: e.encrypted_data.as_str().to_string(),
                nonce: e.nonce.as_str().to_string(),
                last_modified: e.updated_at.to_rfc3339(),
                deleted: Some(e.deleted),
            })
            .collect();

        Ok(Json(items))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

// ════════════════════════════════════════════════════════════════════
// Legacy /shared-vaults/* handlers (backward compatibility)
// ════════════════════════════════════════════════════════════════════

/// POST /shared-vaults
pub async fn create_shared_vault_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<CreateSharedVaultRequest>,
) -> Result<Json<CreateSharedVaultResponse>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let vault = shared_db
            .create_shared_vault(&pass, SharedVaultName::new(body.name))
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(Json(CreateSharedVaultResponse {
            vault_id: vault.id.as_str().to_string(),
            message: "Shared vault created".to_string(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /shared-vaults
pub async fn list_shared_vaults_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<SharedVaultListItem>>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let vaults = shared_db
            .list_shared_vaults(pass.user_id())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let items = vaults
            .into_iter()
            .map(|v| SharedVaultListItem {
                vault_id: v.id.as_str().to_string(),
                name: v.name.as_str().to_string(),
                owner_id: v.owner_id.as_str().to_string(),
                created_at: v.created_at.to_rfc3339(),
            })
            .collect();

        Ok(Json(items))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// DELETE /shared-vaults/{vault_id}
pub async fn delete_shared_vault_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        shared_db
            .delete_shared_vault(&pass, &SharedVaultId::new(vault_id))
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(Json(DeleteResponse {
            message: "Shared vault deleted".to_string(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// DELETE /shared-vaults/{vault_id}/members/{user_id}
pub async fn revoke_member_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path((vault_id, user_id)): Path<(String, String)>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        shared_db
            .revoke_member(&pass, &SharedVaultId::new(vault_id), &UserId::new(user_id))
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(Json(DeleteResponse {
            message: "Member revoked".to_string(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// PATCH /shared-vaults/{vault_id}/members/{user_id}
pub async fn update_permission_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path((vault_id, user_id)): Path<(String, String)>,
    Json(body): Json<UpdatePermissionRequest>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let permission = VaultPermission::from_str_permission(&body.permission)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        shared_db
            .update_member_permission(
                &pass,
                &SharedVaultId::new(vault_id),
                &UserId::new(user_id),
                permission,
            )
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(Json(DeleteResponse {
            message: "Permission updated".to_string(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /shared-vaults/{vault_id}/members
pub async fn list_members_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
) -> Result<Json<Vec<MemberListItem>>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let members = shared_db
            .list_members(pass.user_id(), &SharedVaultId::new(vault_id))
            .map_err(|e| shared_error_to_status(&e))?;

        let items = members
            .into_iter()
            .map(|m| MemberListItem {
                user_id: m.user_id.as_str().to_string(),
                permission: m.permission.as_str().to_string(),
                invited_at: m.invited_at.to_rfc3339(),
            })
            .collect();

        Ok(Json(items))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}
