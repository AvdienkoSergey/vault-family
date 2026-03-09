use super::AppState;
use super::dto::{
    AcceptInviteRequest, ApiAcceptedInviteItem, ApiInviteItem, CompleteInviteRequest,
    SendInviteRequest, SendInviteResponse,
};
use crate::auth;
use crate::crypto_operations::CryptoProvider;
use crate::shared::{SharedDB, SharedError};
use crate::types::{InviteStatus, Role, SharedVaultId, VaultPermission};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

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

/// POST /api/vaults/{vault_id}/invites
#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/api/vaults/{vault_id}/invites",
    tag = "Invites",
    security(("bearer_jwt" = [])),
    params(("vault_id" = String, Path, description = "Shared vault ID")),
    request_body = SendInviteRequest,
    responses(
        (status = 200, description = "Invite sent", body = SendInviteResponse),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not vault owner"),
    )
))]
pub async fn send_invite_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
    Json(body): Json<SendInviteRequest>,
) -> Result<Json<SendInviteResponse>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let role = Role::from_str_role(&body.role).map_err(|_| StatusCode::BAD_REQUEST)?;
        let permission = VaultPermission::from_str_permission(&body.permission)
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let (invite_id, code) = shared_db
            .create_invite(
                pass.user_id(),
                &SharedVaultId::new(vault_id),
                &body.email,
                role,
                permission,
            )
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(Json(SendInviteResponse {
            invite_id: invite_id.as_str().to_string(),
            code,
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /api/invites
#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/api/invites",
    tag = "Invites",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Pending invites for current user", body = Vec<ApiInviteItem>),
        (status = 401, description = "Not authenticated"),
    )
))]
pub async fn list_my_invites_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<ApiInviteItem>>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let email_str = pass.email().as_str().to_string();
        let invites = shared_db
            .list_user_invites(pass.user_id(), &email_str)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let items: Vec<ApiInviteItem> = invites
            .into_iter()
            .filter(|i| i.status == InviteStatus::Pending || i.status == InviteStatus::Accepted)
            .map(|i| ApiInviteItem {
                id: i.id.as_str().to_string(),
                vault_id: i.vault_id.as_str().to_string(),
                vault_name: i.vault_name.unwrap_or_default(),
                inviter_email: String::new(), // Will be enriched at handler level if needed
                role: i.role.as_str().to_string(),
                permission: i.permission.as_str().to_string(),
                code: String::new(), // Code is only returned at creation time
            })
            .collect();

        Ok(Json(items))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// POST /api/invites/{invite_id}/accept
#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/api/invites/{invite_id}/accept",
    tag = "Invites",
    security(("bearer_jwt" = [])),
    params(("invite_id" = String, Path, description = "Invite ID")),
    request_body = AcceptInviteRequest,
    responses(
        (status = 200, description = "Invite accepted"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Invite not found"),
        (status = 409, description = "Invalid invite state"),
    )
))]
pub async fn accept_invite_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(invite_id): Path<String>,
    Json(body): Json<AcceptInviteRequest>,
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
            .accept_invite(
                &crate::types::InviteId::new(invite_id),
                pass.user_id(),
                &body.public_key,
                &body.confirmation_key,
            )
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(StatusCode::OK)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// GET /api/vaults/{vault_id}/invites/accepted
#[cfg_attr(feature = "swagger", utoipa::path(
    get,
    path = "/api/vaults/{vault_id}/invites/accepted",
    tag = "Invites",
    security(("bearer_jwt" = [])),
    params(("vault_id" = String, Path, description = "Shared vault ID")),
    responses(
        (status = 200, description = "Accepted invites awaiting key distribution", body = Vec<ApiAcceptedInviteItem>),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Not vault owner"),
    )
))]
pub async fn get_accepted_invites_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(vault_id): Path<String>,
) -> Result<Json<Vec<ApiAcceptedInviteItem>>, StatusCode> {
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        let shared_db = SharedDB::open(&shared_db_path, crypto)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let accepted = shared_db
            .get_accepted_invites(&SharedVaultId::new(vault_id), pass.user_id())
            .map_err(|e| shared_error_to_status(&e))?;

        let items: Vec<ApiAcceptedInviteItem> = accepted
            .into_iter()
            .map(|a| ApiAcceptedInviteItem {
                invite_id: a.invite_id.as_str().to_string(),
                user_id: a.user_id.as_str().to_string(),
                email: a.email,
                public_key_hex: a.public_key_hex,
                confirmation_key_hex: a.confirmation_key_hex,
            })
            .collect();

        Ok(Json(items))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// POST /api/invites/{invite_id}/complete
#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/api/invites/{invite_id}/complete",
    tag = "Invites",
    security(("bearer_jwt" = [])),
    params(("invite_id" = String, Path, description = "Invite ID")),
    request_body = CompleteInviteRequest,
    responses(
        (status = 204, description = "Invite completed, member added"),
        (status = 401, description = "Not authenticated"),
        (status = 404, description = "Invite not found"),
        (status = 409, description = "Invalid invite state"),
    )
))]
pub async fn complete_invite_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Path(invite_id): Path<String>,
    Json(body): Json<CompleteInviteRequest>,
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
            .complete_invite(
                &crate::types::InviteId::new(invite_id),
                pass.user_id(),
                &body.encrypted_vault_key,
                &body.nonce,
                &body.sender_public_key,
            )
            .map_err(|e| shared_error_to_status(&e))?;

        Ok(StatusCode::NO_CONTENT)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}
