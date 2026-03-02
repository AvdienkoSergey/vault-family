use super::AppState;
use super::dto::{
    LoginRequest, LoginResponse, LogoutResponse, RefreshRequest, RegisterRequest, RegisterResponse,
};
use crate::auth;
use crate::auth::{AuthStore, RefreshTokenHash, jwt_provider};
use crate::crypto_operations::CryptoProvider;
use crate::types::{Email, EncryptionKey, MasterPassword};
use crate::vault::{Closed, DB};
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
pub async fn login_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    let db_path = state.db_path.clone();
    let auth_db_path = state.auth_db_path.clone();
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();
    let failed_login_tracker = state.failed_login_tracker.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let email_str = body.email.clone();
        let email = Email::parse(body.email).map_err(|_| StatusCode::BAD_REQUEST)?;

        // 0. Brute-force: проверяем блокировку ДО проверки пароля
        if failed_login_tracker.is_locked(&email_str) {
            return Err(StatusCode::FORBIDDEN);
        }

        // 1. Vault: проверяем пароль → VaultPass
        let db = DB::<Closed, C>::new(crypto)
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let pass = db
            .create_pass(email, MasterPassword::new(body.master_password))
            .map_err(|_| {
                // Фиксируем неудачную попытку
                failed_login_tracker.record_failed_attempt(&email_str);
                StatusCode::UNAUTHORIZED
            })?;

        // 2. SessionStore: сохраняем ek в памяти сервера
        session_store.insert(
            pass.user_id().as_str(),
            &EncryptionKey::new(pass.encryption_key().as_str().to_string()),
        );

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
pub async fn register_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let db_path = state.db_path.clone();
    let crypto = state.crypto.clone();

    tokio::task::spawn_blocking(move || {
        let email = Email::parse(body.email).map_err(|_| StatusCode::BAD_REQUEST)?;

        let db = DB::<Closed, C>::new(crypto)
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let user = db
            .create_user(email, MasterPassword::new(body.master_password))
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        Ok(Json(RegisterResponse {
            user_id: user.id.as_str().to_string(),
            message: "User registered successfully".to_string(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
}
