use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════
// Auth
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct RegisterRequest {
    pub email: String,
    pub master_password: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct RegisterResponse {
    pub user_id: String,
    pub message: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct LoginRequest {
    pub email: String,
    pub master_password: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct RefreshRequest {
    pub refresh_token: String,
    pub access_token: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct LogoutResponse {
    pub message: String,
}

// ════════════════════════════════════════════════════════════════════
// Vault
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct AddRequest {
    pub service_name: String,
    pub service_url: String,
    pub login: String,
    pub password: String,
    pub notes: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct AddResponse {
    pub entry_id: String,
    pub message: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ListEntry {
    pub entry_id: String,
    pub service_name: String,
    pub created_at: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ViewResponse {
    pub entry_id: String,
    pub service_name: String,
    pub service_url: String,
    pub login: String,
    pub password: String,
    pub notes: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct DeleteResponse {
    pub message: String,
}

// ════════════════════════════════════════════════════════════════════
// Shared Vaults
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct CreateSharedVaultRequest {
    pub name: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct CreateSharedVaultResponse {
    pub vault_id: String,
    pub message: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct SharedVaultListItem {
    pub vault_id: String,
    pub name: String,
    pub owner_id: String,
    pub created_at: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct UpdatePermissionRequest {
    pub permission: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct MemberListItem {
    pub user_id: String,
    pub permission: String,
    pub invited_at: String,
}

// ════════════════════════════════════════════════════════════════════
// API — Auth (mobile)
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ApiRegisterRequest {
    pub email: String,
    pub master_password: String,
    #[allow(dead_code)]
    pub public_key: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ApiRegisterResponse {
    pub user_id: String,
    pub token: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ApiLoginResponse {
    pub user_id: String,
    pub token: String,
}

// ════════════════════════════════════════════════════════════════════
// API — Shared Vaults (zero-knowledge)
// ════════════════════════════════════════════════════════════════════

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ApiSharedVaultItem {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub member_count: usize,
    pub entry_count: usize,
}

// ════════════════════════════════════════════════════════════════════
// API — Invites
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct SendInviteRequest {
    pub email: String,
    pub role: String,
    pub permission: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct SendInviteResponse {
    pub invite_id: String,
    pub code: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct AcceptInviteRequest {
    pub public_key: String,
    pub confirmation_key: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct CompleteInviteRequest {
    pub encrypted_vault_key: String,
    pub nonce: String,
    #[serde(default)]
    pub sender_public_key: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ApiInviteItem {
    pub id: String,
    pub vault_id: String,
    pub vault_name: String,
    pub inviter_email: String,
    pub role: String,
    pub permission: String,
    pub code: String,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ApiAcceptedInviteItem {
    pub invite_id: String,
    pub user_id: String,
    pub email: String,
    pub public_key_hex: String,
    pub confirmation_key_hex: String,
}

// ════════════════════════════════════════════════════════════════════
// API — Members (expanded)
// ════════════════════════════════════════════════════════════════════

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ApiMemberItem {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub permission: String,
    pub public_key_hex: String,
    pub crypto_status: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct MemberKeyUpdateItem {
    pub user_id: String,
    pub encrypted_vault_key: String,
    pub nonce: String,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct UpdateMemberKeysRequest {
    pub members: Vec<MemberKeyUpdateItem>,
}

// ════════════════════════════════════════════════════════════════════
// API — Member vault key
// ════════════════════════════════════════════════════════════════════

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ApiMyKeyResponse {
    pub encrypted_vault_key: String,
    pub nonce: String,
    pub owner_public_key_hex: String,
}

// ════════════════════════════════════════════════════════════════════
// API — Entries (zero-knowledge)
// ════════════════════════════════════════════════════════════════════

#[derive(Serialize, Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct ApiEncryptedEntryItem {
    pub id: String,
    pub category: String,
    pub encrypted_data: String,
    pub nonce: String,
    pub last_modified: String,
    #[serde(default)]
    pub deleted: Option<bool>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct PushEntriesRequest {
    pub entries: Vec<ApiEncryptedEntryItem>,
}

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct PullEntriesQuery {
    pub since: Option<String>,
}

// ════════════════════════════════════════════════════════════════════
// Generate
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema, utoipa::IntoParams))]
pub struct GenerateParams {
    #[serde(default = "default_length")]
    pub length: usize,
    #[serde(default = "default_true")]
    pub lowercase: bool,
    #[serde(default = "default_true")]
    pub uppercase: bool,
    #[serde(default = "default_true")]
    pub digits: bool,
    #[serde(default = "default_true")]
    pub symbols: bool,
}

fn default_length() -> usize {
    20
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct GenerateResponse {
    pub password: String,
}

// ════════════════════════════════════════════════════════════════════
// Transfer (анонимный in-memory relay)
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct TransferUploadRequest {
    pub payload: String,
    pub ttl_minutes: u64,
    pub copies: u32,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct TransferUploadResponse {
    pub code: String,
    pub expires_at: String,
    pub copies: u32,
}

#[derive(Serialize)]
#[cfg_attr(feature = "swagger", derive(utoipa::ToSchema))]
pub struct TransferDownloadResponse {
    pub payload: String,
}
