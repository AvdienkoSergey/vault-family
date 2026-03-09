use super::AppState;
use super::dto::{
    ApiLoginResponse, ApiRegisterRequest, ApiRegisterResponse, ChangePasswordRequest, LoginRequest,
    LoginResponse, LogoutResponse, RefreshRequest, RegisterRequest, RegisterResponse,
};
use crate::auth;
use crate::auth::{AuthStore, RefreshTokenHash, jwt_provider};
use crate::crypto_operations::CryptoProvider;
use crate::shared::SharedDB;
use crate::types::{Email, EncryptionKey, MasterPassword};
use crate::vault::{Closed, DB};
use crate::ws::VaultEvent;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// POST /login
///
/// Vault: create_pass(email, password) → VaultPass
/// SessionStore: сохраняем ek в памяти сервера
/// Auth:  JWT access_token (без ek!) + refresh_token → auth.db
#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/login",
    tag = "Auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 400, description = "Invalid email format"),
        (status = 401, description = "Invalid credentials"),
        (status = 403, description = "Account temporarily locked")
    )
))]
pub async fn login_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let db_path = state.db_path.clone();
    let auth_db_path = state.auth_db_path.clone();
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let failed_login_tracker = state.failed_login_tracker.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let email_str = body.email.clone();
        let email = Email::parse(body.email).map_err(|e| {
            tracing::warn!(%e, "login: invalid email format");
            StatusCode::BAD_REQUEST
        })?;

        // Brute-force lock: early return WITHOUT password verification
        if failed_login_tracker.is_locked(&email_str) {
            tracing::warn!(email = %email_str, "login: account temporarily locked (brute-force)");
            return Err(StatusCode::FORBIDDEN);
        }

        // 1. Vault: проверяем пароль → VaultPass
        let db = DB::<Closed, C>::new(crypto.clone())
            .open(&db_path)
            .map_err(|e| {
                tracing::error!(%e, "login: failed to open vault.db");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let pass = db
            .create_pass(email, MasterPassword::new(body.master_password))
            .map_err(|e| {
                tracing::warn!(%e, email = %email_str, "login: create_pass failed");
                failed_login_tracker.record_failed_attempt(&email_str);
                StatusCode::UNAUTHORIZED
            })?;

        // Correct password → clear brute-force counter
        failed_login_tracker.clear_attempts(&email_str);

        // 2. SessionStore: сохраняем ek в памяти сервера
        session_store.insert(
            pass.user_id().as_str(),
            &EncryptionKey::new(pass.encryption_key().as_str().to_string()),
        );

        // 2.5 Lazy keypair generation: ensure user has X25519 keypair for shared vaults
        if let Ok(shared_db) = SharedDB::open(&shared_db_path, crypto) {
            let has_kp = shared_db.has_user_keypair(pass.user_id()).unwrap_or(false);
            if !has_kp {
                let _ = shared_db.save_user_keypair(pass.user_id(), pass.encryption_key());
            }
        }

        // 3. JWT: access token из VaultPass (без ek в payload!)
        let access_token = jwt_provider::create_access_token_from_pass(&pass, &jwt_secret)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // 4. Auth store: refresh token → auth.db
        let refresh_token = Uuid::new_v4().to_string();
        let hash = hex::encode(Sha256::digest(refresh_token.as_bytes()));
        let token_hash = RefreshTokenHash::new(hash);
        let expires_at = Utc::now() + chrono::Duration::days(auth::REFRESH_TOKEN_TTL_DAYS);

        let store =
            AuthStore::open(&auth_db_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        store
            .save_refresh_token(&token_hash, pass.user_id(), expires_at)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(LoginResponse {
            access_token,
            refresh_token,
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// POST /refresh
///
/// Только auth: JWT decode + SessionStore + auth.db (без vault.db).
/// Refresh-токен не требует открытия Хранилища.
#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/refresh",
    tag = "Auth",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Tokens refreshed", body = LoginResponse),
        (status = 401, description = "Invalid or expired tokens")
    )
))]
pub async fn refresh_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let auth_db_path = state.auth_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();

    tokio::task::spawn_blocking(move || {
        // 1. Декодируем истёкший access_token (подпись ✓, exp — ✗)
        let claims =
            jwt_provider::decode_access_token_allow_expired(&body.access_token, &jwt_secret)
                .map_err(|_| StatusCode::UNAUTHORIZED)?;

        // 2. Проверяем refresh_token в auth.db (rotation: verify + delete)
        let hash = hex::encode(Sha256::digest(body.refresh_token.as_bytes()));
        let token_hash = RefreshTokenHash::new(hash);

        let store =
            AuthStore::open(&auth_db_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let token_user_id = store
            .verify_and_delete_refresh_token(&token_hash)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        // 3. user_id в refresh-токене должен совпадать с access-токеном
        if token_user_id.as_str() != claims.sub {
            return Err(StatusCode::UNAUTHORIZED);
        }

        // 4. Достаём ek из SessionStore (не из JWT!)
        let ek = session_store
            .get(&claims.sub)
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // 5. Обновляем TTL записи в SessionStore
        session_store.insert(&claims.sub, &ek);

        // 6. Новый access_token (без ek в payload)
        let access_token = jwt_provider::create_access_token(
            &token_user_id,
            &Email::new(claims.email),
            &jwt_secret,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // 7. Новый refresh_token (rotation)
        let new_refresh_token = Uuid::new_v4().to_string();
        let new_hash = hex::encode(Sha256::digest(new_refresh_token.as_bytes()));
        let new_token_hash = RefreshTokenHash::new(new_hash);
        let expires_at = Utc::now() + chrono::Duration::days(auth::REFRESH_TOKEN_TTL_DAYS);

        store
            .save_refresh_token(&new_token_hash, &token_user_id, expires_at)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(LoginResponse {
            access_token,
            refresh_token: new_refresh_token,
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// POST /logout
///
/// Мгновенная revocation: убиваем сессию в SessionStore + все refresh-токены.
/// После logout:
/// - Все Bearer JWT → 401 SessionExpired (мгновенно, не через 15 мин)
/// - Все refresh_token → 401 TokenNotFound (нечем обновить)
#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/logout",
    tag = "Auth",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Logged out", body = LogoutResponse),
        (status = 401, description = "Not authenticated")
    )
))]
pub async fn logout_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<LogoutResponse>, StatusCode> {
    let auth_db_path = state.auth_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();

    tokio::task::spawn_blocking(move || {
        // Вахтер: JWT-only
        let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

        // 1. SessionStore: убиваем сессию → все JWT мгновенно невалидны
        session_store.remove(pass.user_id().as_str());

        // 2. AuthStore: удаляем все refresh-токены → нечем обновить access_token
        let store =
            AuthStore::open(&auth_db_path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        store
            .delete_all_user_tokens(pass.user_id().as_str())
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(LogoutResponse {
            message: "logged out".to_string(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

/// POST /register
///
/// X25519 keypair is NOT generated here — MasterPassword is consumed by create_user().
/// Keypair is generated lazily at first login (see login_handler).
#[cfg_attr(feature = "swagger", utoipa::path(
    post,
    path = "/register",
    tag = "Auth",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "User registered", body = RegisterResponse),
        (status = 400, description = "Invalid email or user already exists")
    )
))]
pub async fn register_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let db_path = state.db_path.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let email_str = body.email.clone();
        let email = Email::parse(body.email).map_err(|e| {
            tracing::warn!(%e, "legacy register: invalid email format");
            StatusCode::BAD_REQUEST
        })?;

        let db = DB::<Closed, C>::new(crypto).open(&db_path).map_err(|e| {
            tracing::error!(%e, "legacy register: failed to open vault.db");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let user = db
            .create_user(email, MasterPassword::new(body.master_password))
            .map_err(|e| {
                tracing::warn!(%e, email = %email_str, "legacy register: create_user failed");
                StatusCode::BAD_REQUEST
            })?;

        Ok(Json(RegisterResponse {
            user_id: user.id.as_str().to_string(),
            message: "User registered successfully".to_string(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}

// ════════════════════════════════════════════════════════════════════
// API auth handlers (mobile frontend — simplified responses)
// ════════════════════════════════════════════════════════════════════

/// POST /api/auth/register
///
/// Registers user + creates keypair + auto-login. Returns {user_id, token}.
/// Trusts the device (`X-Device-ID`) on successful registration.
pub async fn api_register_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ApiRegisterRequest>,
) -> Result<Json<ApiRegisterResponse>, StatusCode> {
    let db_path = state.db_path.clone();
    let auth_db_path = state.auth_db_path.clone();
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let device_trust = state.device_trust.clone();
    let crypto = state.crypto.clone();

    let device_id = headers
        .get("X-Device-ID")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    tokio::task::spawn_blocking(move || {
        let email_str = body.email.clone();

        // 1. Create user
        let email_for_register =
            Email::parse(email_str.clone()).map_err(|e| {
                tracing::warn!(%e, "register: invalid email format");
                StatusCode::BAD_REQUEST
            })?;
        let db = DB::<Closed, C>::new(crypto.clone())
            .open(&db_path)
            .map_err(|e| {
                tracing::error!(%e, "register: failed to open vault.db");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        let user = db
            .create_user(
                email_for_register,
                MasterPassword::new(body.master_password.clone()),
            )
            .map_err(|e| {
                tracing::warn!(%e, email = %email_str, "register: create_user failed");
                StatusCode::BAD_REQUEST
            })?;

        // 2. Auto-login: create VaultPass for JWT
        let email_for_login = Email::parse(email_str.clone()).map_err(|_| StatusCode::BAD_REQUEST)?;
        let pass = db
            .create_pass(email_for_login, MasterPassword::new(body.master_password))
            .map_err(|e| {
                tracing::error!(%e, email = %email_str, "register: auto-login (create_pass) failed");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // 3. SessionStore: save encryption key
        session_store.insert(
            pass.user_id().as_str(),
            &EncryptionKey::new(pass.encryption_key().as_str().to_string()),
        );

        // 4. Generate keypair (lazy — same as login)
        if let Ok(shared_db) = SharedDB::open(&shared_db_path, crypto) {
            let _ = shared_db.save_user_keypair(pass.user_id(), pass.encryption_key());
        }

        // 5. JWT access token
        let access_token = jwt_provider::create_access_token_from_pass(&pass, &jwt_secret)
            .map_err(|e| {
                tracing::error!(%e, "register: JWT creation failed");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // 6. Refresh token → auth.db
        let refresh_token = Uuid::new_v4().to_string();
        let hash = hex::encode(Sha256::digest(refresh_token.as_bytes()));
        let token_hash = RefreshTokenHash::new(hash);
        let expires_at = Utc::now() + chrono::Duration::days(auth::REFRESH_TOKEN_TTL_DAYS);

        let store =
            AuthStore::open(&auth_db_path).map_err(|e| {
                tracing::error!(%e, "register: failed to open auth.db");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
        store
            .save_refresh_token(&token_hash, pass.user_id(), expires_at)
            .map_err(|e| {
                tracing::error!(%e, "register: failed to save refresh token");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Trust this device
        if !device_id.is_empty() {
            device_trust.trust(&email_str, &device_id);
            tracing::info!(email = %email_str, device_id = %device_id, "register: device trusted");
        }

        tracing::info!(user_id = %user.id.as_str(), "register: success");
        Ok(Json(ApiRegisterResponse {
            user_id: user.id.as_str().to_string(),
            token: access_token,
        }))
    })
    .await
    .map_err(|e| {
        tracing::error!(%e, "register: spawn_blocking panicked");
        StatusCode::INTERNAL_SERVER_ERROR
    })?
}

/// POST /api/auth/login
///
/// Same as login_handler but returns simplified {user_id, token}.
/// Returns 423 Locked if the account has a security lock (attacker device → wipe).
///
/// Trusted devices (previously logged in successfully with `X-Device-ID`)
/// are exempt from brute-force (403) and security lock (423) blocks.
pub async fn api_login_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginRequest>,
) -> Result<Json<ApiLoginResponse>, StatusCode> {
    let db_path = state.db_path.clone();
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let failed_login_tracker = state.failed_login_tracker.clone();
    let security_lock = state.security_lock.clone();
    let device_trust = state.device_trust.clone();
    let ws_registry = state.ws_registry.clone();
    let crypto = state.crypto.clone();

    let device_id = headers
        .get("X-Device-ID")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Result carries either success or (StatusCode, Option<user_id for WS notification>)
    let result = tokio::task::spawn_blocking(move || {
        let email_str = body.email.clone();
        let email = Email::parse(body.email).map_err(|e| {
            tracing::warn!(%e, "api_login: invalid email format");
            (StatusCode::BAD_REQUEST, None)
        })?;

        let is_trusted = device_trust.is_trusted(&email_str, &device_id);

        // Open DB early — we need user_id for WS alerts on 403/423 too
        let db = DB::<Closed, C>::new(crypto.clone())
            .open(&db_path)
            .map_err(|e| {
                tracing::error!(%e, "api_login: failed to open vault.db");
                (StatusCode::INTERNAL_SERVER_ERROR, None)
            })?;

        // Helper: resolve user_id for WS notification (cheap SELECT, no PBKDF2)
        let ws_info = || -> Option<(String, String)> {
            Email::parse(email_str.clone())
                .ok()
                .and_then(|e| db.find_user_id_by_email(&e).ok())
                .map(|uid| (uid.as_str().to_string(), email_str.clone()))
        };

        // Brute-force lock: early return WITHOUT password verification.
        // Trusted devices skip this — they already proved they know the password.
        // No WS alert on 403 — only 401 (actual wrong password) sends SecurityAlert.
        if !is_trusted && failed_login_tracker.is_locked(&email_str) {
            tracing::warn!(email = %email_str, device_id = %device_id, "api_login: account temporarily locked (brute-force), untrusted device blocked");
            return Err((StatusCode::FORBIDDEN, None));
        }

        let pass = db
            .create_pass(email, MasterPassword::new(body.master_password))
            .map_err(|e| {
                tracing::warn!(%e, email = %email_str, "api_login: create_pass failed");
                failed_login_tracker.record_failed_attempt(&email_str);

                // Wrong password + security lock active + untrusted device → 423 (wipe)
                // No WS alert on 423 — only 401 sends SecurityAlert.
                if !is_trusted && security_lock.is_locked(&email_str) {
                    return (
                        StatusCode::from_u16(423).unwrap_or(StatusCode::FORBIDDEN),
                        None,
                    );
                }

                // Wrong password, no lock → 401 + notify legitimate user via WS
                (StatusCode::UNAUTHORIZED, ws_info())
            })?;

        // Correct password — do NOT clear brute-force or security lock.
        // They expire naturally (5 min window). This prevents an attacker
        // who guesses the password from clearing the lock for other devices.

        // Trust this device for future logins
        if !device_id.is_empty() {
            device_trust.trust(&email_str, &device_id);
            tracing::info!(email = %email_str, device_id = %device_id, "api_login: device trusted");
        }

        session_store.insert(
            pass.user_id().as_str(),
            &EncryptionKey::new(pass.encryption_key().as_str().to_string()),
        );

        // Lazy keypair generation
        if let Ok(shared_db) = SharedDB::open(&shared_db_path, crypto) {
            let has_kp = shared_db.has_user_keypair(pass.user_id()).unwrap_or(false);
            if !has_kp {
                let _ = shared_db.save_user_keypair(pass.user_id(), pass.encryption_key());
            }
        }

        let access_token = jwt_provider::create_access_token_from_pass(&pass, &jwt_secret)
            .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, None))?;

        Ok(Json(ApiLoginResponse {
            user_id: pass.user_id().as_str().to_string(),
            token: access_token,
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match result {
        Ok(response) => Ok(response),
        Err((status, Some((user_id, email)))) => {
            // Send WS notification to legitimate user about unauthorized attempt
            let event = VaultEvent::UnauthorizedLoginAttempt {
                email,
                timestamp: Utc::now().to_rfc3339(),
            };
            if let Ok(json) = serde_json::to_string(&event) {
                ws_registry.send_to_user(&user_id, &json);
            }
            Err(status)
        }
        Err((status, None)) => Err(status),
    }
}

/// POST /api/auth/security-lock
///
/// Activate security lock for the caller's email. Requires JWT auth.
/// After activation, failed login attempts for this email return 423 (Locked),
/// signaling the attacker's device to wipe its local data.
pub async fn api_security_lock_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
) -> Result<StatusCode, StatusCode> {
    let pass =
        auth::guard(&headers, &state.jwt_secret, &state.session_store).map_err(StatusCode::from)?;

    state.security_lock.activate(pass.email().as_str());
    tracing::warn!("Security lock activated for {}", pass.email().as_str());

    Ok(StatusCode::NO_CONTENT)
}

/// POST /api/auth/change-password
///
/// Dual-purpose endpoint — NOT blocked by brute-force (403) or security lock (423).
///
/// **Case 1: Trusted device + valid JWT** → verifies old password, updates hash
/// on server to new password, returns token.
///
/// **Case 2: Untrusted device / no JWT** → verifies old password only.
/// If correct → trusts device + returns token (login bypass for 403/423).
/// Password is NOT changed on server in this case.
///
/// This gives legitimate users an escape hatch when their device lost trust
/// (e.g. server restart cleared in-memory DeviceTrustStore).
pub async fn api_change_password_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<ChangePasswordRequest>,
) -> Result<Json<ApiLoginResponse>, StatusCode> {
    let db_path = state.db_path.clone();
    let shared_db_path = state.shared_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let failed_login_tracker = state.failed_login_tracker.clone();
    let device_trust = state.device_trust.clone();
    let crypto = state.crypto.clone();

    let device_id = headers
        .get("X-Device-ID")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Check if caller has a valid JWT (trusted session)
    let has_valid_jwt = auth::guard(&headers, &state.jwt_secret, &state.session_store).is_ok();
    let is_trusted = !device_id.is_empty() && device_trust.is_trusted(&body.email, &device_id);

    let can_change = has_valid_jwt && is_trusted;

    tokio::task::spawn_blocking(move || {
        let email_str = body.email.clone();
        let email = Email::parse(body.email).map_err(|e| {
            tracing::warn!(%e, "change_password: invalid email format");
            StatusCode::BAD_REQUEST
        })?;

        let db = DB::<Closed, C>::new(crypto.clone())
            .open(&db_path)
            .map_err(|e| {
                tracing::error!(%e, "change_password: failed to open vault.db");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

        // Try old_password first
        let old_pass_result = db.create_pass(email, MasterPassword::new(body.old_password));

        let pass = match old_pass_result {
            Ok(pass) => {
                // Case 1: old_password correct
                // Trust this device
                if !device_id.is_empty() {
                    device_trust.trust(&email_str, &device_id);
                    tracing::info!(email = %email_str, device_id = %device_id, "change_password: device trusted");
                }

                // Only update password on server if caller has JWT + trusted device
                if can_change {
                    let email_for_update = Email::parse(email_str.clone())
                        .map_err(|_| StatusCode::BAD_REQUEST)?;
                    db.update_password(&email_for_update, MasterPassword::new(body.new_password))
                        .map_err(|e| {
                            tracing::error!(%e, email = %email_str, "change_password: update failed");
                            StatusCode::INTERNAL_SERVER_ERROR
                        })?;
                    tracing::info!(email = %email_str, "change_password: password updated on server");
                } else {
                    tracing::info!(email = %email_str, "change_password: old password verified, device trusted (no server update)");
                }

                pass
            }
            Err(_) => {
                // old_password wrong → try new_password against server hash
                tracing::info!(email = %email_str, "change_password: old password incorrect, trying new_password");

                let email_retry = Email::parse(email_str.clone())
                    .map_err(|_| StatusCode::BAD_REQUEST)?;
                let new_pass_result = db.create_pass(email_retry, MasterPassword::new(body.new_password));

                match new_pass_result {
                    Ok(pass) => {
                        // Case 2: new_password matches server hash
                        // Trust device + return token, do NOT change password
                        if !device_id.is_empty() {
                            device_trust.trust(&email_str, &device_id);
                            tracing::info!(email = %email_str, device_id = %device_id, "change_password: new_password matches server, device trusted (bypass)");
                        }
                        pass
                    }
                    Err(_) => {
                        // Case 3: both passwords wrong → 401
                        tracing::warn!(email = %email_str, "change_password: both passwords incorrect");
                        failed_login_tracker.record_failed_attempt(&email_str);
                        return Err(StatusCode::UNAUTHORIZED);
                    }
                }
            }
        };

        // Store session + issue token
        session_store.insert(
            pass.user_id().as_str(),
            &EncryptionKey::new(pass.encryption_key().as_str().to_string()),
        );

        // Lazy keypair
        if let Ok(shared_db) = SharedDB::open(&shared_db_path, crypto) {
            let has_kp = shared_db.has_user_keypair(pass.user_id()).unwrap_or(false);
            if !has_kp {
                let _ = shared_db.save_user_keypair(pass.user_id(), pass.encryption_key());
            }
        }

        let access_token = jwt_provider::create_access_token_from_pass(&pass, &jwt_secret)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        Ok(Json(ApiLoginResponse {
            user_id: pass.user_id().as_str().to_string(),
            token: access_token,
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}
