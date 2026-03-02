use super::AppState;
use super::dto::{
    AddRequest, AddResponse, CreateSharedVaultRequest, CreateSharedVaultResponse, DeleteResponse,
    InviteMemberRequest, InviteMemberResponse, MemberListItem, SharedEntryListItem,
    SharedVaultListItem, UpdatePermissionRequest, ViewResponse,
};
use crate::auth;
use crate::crypto_operations::CryptoProvider;
use crate::shared::{SharedDB, SharedError};
use crate::types::{
    Email, EntryId, EntryPassword, Login, PlainEntry, ServiceName, ServiceUrl, SharedVaultId,
    SharedVaultName, UserId, VaultPermission,
};
use crate::vault::{Closed, DB};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use chrono::Utc;
use uuid::Uuid;

fn shared_error_to_status(err: &SharedError) -> StatusCode {
    match err {
        SharedError::NotFound(_) => StatusCode::NOT_FOUND,
        SharedError::Forbidden(_) => StatusCode::FORBIDDEN,
        SharedError::MemberLimit(_) => StatusCode::BAD_REQUEST,
        SharedError::NoKeypair(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

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

/// POST /shared-vaults/{vault_id}/invite
pub async fn invite_member_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
    Json(body): Json<InviteMemberRequest>,
) -> Result<Json<InviteMemberResponse>, StatusCode> {
    let db_path = state.db_path.clone();
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let permission = VaultPermission::from_str_permission(&body.permission)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        let email = Email::parse(body.email).map_err(|_| StatusCode::BAD_REQUEST)?;

        // Look up target user in vault.db
        let vault_db = DB::<Closed, C>::new(crypto.clone())
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let target_user_id = vault_db
            .find_user_id_by_email(&email)
            .map_err(|_| StatusCode::NOT_FOUND)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        shared_db
            .invite_member(
                &pass,
                &SharedVaultId::new(vault_id),
                &target_user_id,
                permission,
            )
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(Json(InviteMemberResponse {
            message: "Member invited".to_string(),
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
) -> Result<Json<InviteMemberResponse>, StatusCode> {
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

        Ok(Json(InviteMemberResponse {
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

/// POST /shared-vaults/{vault_id}/entries
pub async fn add_shared_entry_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
    Json(body): Json<AddRequest>,
) -> Result<Json<AddResponse>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let now = Utc::now();
        let entry_id = Uuid::new_v4().to_string();

        let plain = PlainEntry {
            id: EntryId::new(entry_id.clone()),
            user_id: UserId::new(pass.user_id().as_str().to_string()),
            service_name: ServiceName::new(body.service_name),
            service_url: ServiceUrl::new(body.service_url),
            login: Login::new(body.login),
            password: EntryPassword::new(body.password),
            notes: body.notes,
            created_at: now,
            updated_at: now,
        };

        let id = shared_db
            .add_shared_entry(&pass, &SharedVaultId::new(vault_id), &plain)
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(Json(AddResponse {
            entry_id: id.as_str().to_string(),
            message: "Shared entry added".to_string(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /shared-vaults/{vault_id}/entries
pub async fn list_shared_entries_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
) -> Result<Json<Vec<SharedEntryListItem>>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let entries = shared_db
            .list_shared_entries(&pass, &SharedVaultId::new(vault_id))
            .map_err(|e| shared_error_to_status(&e))?;

        let items = entries
            .into_iter()
            .map(|e| SharedEntryListItem {
                entry_id: e.id.as_str().to_string(),
                service_name: e.service_name.as_str().to_string(),
                created_at: e.created_at.to_rfc3339(),
            })
            .collect();

        Ok(Json(items))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /shared-vaults/{vault_id}/entries/{entry_id}
pub async fn view_shared_entry_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path((vault_id, entry_id)): Path<(String, String)>,
) -> Result<Json<ViewResponse>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let plain = shared_db
            .view_shared_entry(
                &pass,
                &SharedVaultId::new(vault_id),
                &EntryId::new(entry_id.clone()),
            )
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(Json(ViewResponse {
            entry_id,
            service_name: plain.service_name.as_str().to_string(),
            service_url: plain.service_url.as_str().to_string(),
            login: plain.login.as_str().to_string(),
            password: plain.password.as_str().to_string(),
            notes: plain.notes,
            created_at: plain.created_at.to_rfc3339(),
            updated_at: plain.updated_at.to_rfc3339(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// DELETE /shared-vaults/{vault_id}/entries/{entry_id}
pub async fn delete_shared_entry_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path((vault_id, entry_id)): Path<(String, String)>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let deleted = shared_db
            .delete_shared_entry(
                &pass,
                &SharedVaultId::new(vault_id),
                &EntryId::new(entry_id),
            )
            .map_err(|e| shared_error_to_status(&e))?;

        if deleted {
            Ok(Json(DeleteResponse {
                message: "Shared entry deleted".to_string(),
            }))
        } else {
            Err(StatusCode::NOT_FOUND)
        }
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}
