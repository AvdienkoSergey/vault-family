use serde::{Deserialize, Serialize};

// ════════════════════════════════════════════════════════════════════
// Auth
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub master_password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub user_id: String,
    pub message: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub master_password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
    pub access_token: String,
}

#[derive(Serialize)]
pub struct LogoutResponse {
    pub message: String,
}

// ════════════════════════════════════════════════════════════════════
// Vault
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct AddRequest {
    pub service_name: String,
    pub service_url: String,
    pub login: String,
    pub password: String,
    pub notes: String,
}

#[derive(Serialize)]
pub struct AddResponse {
    pub entry_id: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct ListEntry {
    pub entry_id: String,
    pub service_name: String,
    pub created_at: String,
}

#[derive(Serialize)]
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
pub struct DeleteResponse {
    pub message: String,
}

// ════════════════════════════════════════════════════════════════════
// Shared Vaults
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct CreateSharedVaultRequest {
    pub name: String,
}

#[derive(Serialize)]
pub struct CreateSharedVaultResponse {
    pub vault_id: String,
    pub message: String,
}

#[derive(Serialize)]
pub struct SharedVaultListItem {
    pub vault_id: String,
    pub name: String,
    pub owner_id: String,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct InviteMemberRequest {
    pub email: String,
    pub permission: String,
}

#[derive(Serialize)]
pub struct InviteMemberResponse {
    pub message: String,
}

#[derive(Deserialize)]
pub struct UpdatePermissionRequest {
    pub permission: String,
}

#[derive(Serialize)]
pub struct SharedEntryListItem {
    pub entry_id: String,
    pub service_name: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct MemberListItem {
    pub user_id: String,
    pub permission: String,
    pub invited_at: String,
}

// ════════════════════════════════════════════════════════════════════
// Generate
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
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
pub struct GenerateResponse {
    pub password: String,
}
