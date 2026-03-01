use super::AppState;
use crate::auth;
use crate::auth::{AuthStore, RefreshTokenHash, jwt_provider};
use crate::crypto_operations::CryptoProvider;
use crate::password_generator::{Empty, PasswordGenerator};
use crate::types::{
    Email, EncryptionKey, EntryId, EntryPassword, Login, MasterPassword, PlainEntry, ServiceName,
    ServiceUrl, UserId,
};
use crate::vault::{Closed, DB};
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ════════════════════════════════════════════════════════════════════
// Request / Response structs
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct RegisterRequest {
    email: String,
    master_password: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    user_id: String,
    message: String,
}

#[derive(Deserialize)]
pub struct AddRequest {
    service_name: String,
    service_url: String,
    login: String,
    password: String,
    notes: String,
}

#[derive(Serialize)]
pub struct AddResponse {
    entry_id: String,
    message: String,
}

#[derive(Serialize)]
pub struct ListEntry {
    entry_id: String,
    service_name: String,
    created_at: String,
}

#[derive(Serialize)]
pub struct ViewResponse {
    entry_id: String,
    service_name: String,
    service_url: String,
    login: String,
    password: String,
    notes: String,
    created_at: String,
    updated_at: String,
}

#[derive(Serialize)]
pub struct DeleteResponse {
    message: String,
}

#[derive(Deserialize)]
pub struct GenerateParams {
    #[serde(default = "default_length")]
    length: usize,
    #[serde(default = "default_true")]
    lowercase: bool,
    #[serde(default = "default_true")]
    uppercase: bool,
    #[serde(default = "default_true")]
    digits: bool,
    #[serde(default = "default_true")]
    symbols: bool,
}

fn default_length() -> usize {
    20
}

fn default_true() -> bool {
    true
}

#[derive(Serialize)]
pub struct GenerateResponse {
    password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    email: String,
    master_password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    access_token: String,
    refresh_token: String,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    refresh_token: String,
    access_token: String,
}

#[derive(Serialize)]
pub struct LogoutResponse {
    message: String,
}

// ════════════════════════════════════════════════════════════════════
// Handlers
// ════════════════════════════════════════════════════════════════════

pub async fn health_handler() -> &'static str {
    "ok"
}

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

/// GET /generate
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

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{FailedLoginTracker, JwtSecret, SessionStore};
    use crate::crypto_operations::FakeCrypto;
    use crate::http_api::AppState;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{delete as delete_method, get, post};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    // ════════════════════════════════════════════
    // Test infrastructure
    // ════════════════════════════════════════════

    struct TestApp {
        router: Router,
        db_path: String,
        auth_db_path: String,
    }

    impl TestApp {
        fn new() -> Self {
            let db_path = std::env::temp_dir()
                .join(format!("vault_handler_test_{}.db", Uuid::new_v4()))
                .to_str()
                .unwrap()
                .to_string();

            let auth_db_path = auth::auth_db_path(&db_path);

            let state = AppState {
                db_path: db_path.clone(),
                auth_db_path: auth_db_path.clone(),
                jwt_secret: Arc::new(JwtSecret::new("test-jwt-secret-for-handlers".to_string())),
                session_store: SessionStore::new(),
                failed_login_tracker: FailedLoginTracker::new(),
                crypto: FakeCrypto,
            };

            let router = Router::new()
                .route("/health", get(health_handler))
                .route("/login", post(login_handler::<FakeCrypto>))
                .route("/logout", post(logout_handler::<FakeCrypto>))
                .route("/refresh", post(refresh_handler::<FakeCrypto>))
                .route("/register", post(register_handler::<FakeCrypto>))
                .route("/add", post(add_handler::<FakeCrypto>))
                .route("/list", get(list_handler::<FakeCrypto>))
                .route("/view/{id}", get(view_handler::<FakeCrypto>))
                .route("/delete/{id}", delete_method(delete_handler::<FakeCrypto>))
                .route("/generate", get(generate_handler))
                .with_state(state);

            Self {
                router,
                db_path,
                auth_db_path,
            }
        }

        async fn request(&self, req: Request<Body>) -> axum::http::Response<Body> {
            self.router.clone().oneshot(req).await.unwrap()
        }
    }

    impl Drop for TestApp {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.db_path);
            let _ = std::fs::remove_file(&self.auth_db_path);
        }
    }

    async fn body_json(resp: axum::http::Response<Body>) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// Регистрирует пользователя и логинится, возвращает (access_token, refresh_token)
    async fn register_and_login(app: &TestApp) -> (String, String) {
        let req = Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"test@example.com","master_password":"Secret123!"}"#,
            ))
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let req = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"test@example.com","master_password":"Secret123!"}"#,
            ))
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp).await;
        (
            json["access_token"].as_str().unwrap().to_string(),
            json["refresh_token"].as_str().unwrap().to_string(),
        )
    }

    /// Добавляет запись и возвращает entry_id
    async fn add_entry(app: &TestApp, token: &str) -> String {
        let req = Request::builder()
            .method("POST")
            .uri("/add")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(
                r#"{"service_name":"GitHub","service_url":"https://github.com","login":"alex","password":"gh-pass","notes":"work account"}"#,
            ))
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp).await;
        json["entry_id"].as_str().unwrap().to_string()
    }

    // ════════════════════════════════════════════
    // Health & Generate (stateless)
    // ════════════════════════════════════════════

    #[tokio::test]
    async fn health_returns_ok() {
        let app = TestApp::new();
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], b"ok");
    }

    #[tokio::test]
    async fn generate_returns_password_of_requested_length() {
        let app = TestApp::new();
        let req = Request::builder()
            .uri("/generate?length=16")
            .body(Body::empty())
            .unwrap();

        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp).await;
        assert_eq!(json["password"].as_str().unwrap().len(), 16);
    }

    // ════════════════════════════════════════════
    // Register
    // ════════════════════════════════════════════

    #[tokio::test]
    async fn register_creates_user() {
        let app = TestApp::new();
        let req = Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"test@example.com","master_password":"Secret123!"}"#,
            ))
            .unwrap();

        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp).await;
        assert!(!json["user_id"].as_str().unwrap().is_empty());
        assert_eq!(json["message"], "User registered successfully");
    }

    #[tokio::test]
    async fn register_invalid_email_returns_400() {
        let app = TestApp::new();
        let req = Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"not-an-email","master_password":"Secret123!"}"#,
            ))
            .unwrap();

        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ════════════════════════════════════════════
    // Login
    // ════════════════════════════════════════════

    #[tokio::test]
    async fn login_returns_tokens() {
        let app = TestApp::new();
        let (access_token, refresh_token) = register_and_login(&app).await;

        assert!(!access_token.is_empty());
        assert!(!refresh_token.is_empty());
    }

    #[tokio::test]
    async fn login_wrong_password_returns_401() {
        let app = TestApp::new();

        // Register
        let req = Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"test@example.com","master_password":"Secret123!"}"#,
            ))
            .unwrap();
        app.request(req).await;

        // Login with wrong password
        let req = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"test@example.com","master_password":"WrongPass!"}"#,
            ))
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn login_nonexistent_user_returns_401() {
        let app = TestApp::new();
        let req = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"nobody@example.com","master_password":"Secret123!"}"#,
            ))
            .unwrap();

        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ════════════════════════════════════════════
    // CRUD с Bearer token
    // ════════════════════════════════════════════

    #[tokio::test]
    async fn add_with_bearer_token() {
        let app = TestApp::new();
        let (token, _) = register_and_login(&app).await;
        let entry_id = add_entry(&app, &token).await;

        assert!(!entry_id.is_empty());
    }

    #[tokio::test]
    async fn list_returns_added_entries() {
        let app = TestApp::new();
        let (token, _) = register_and_login(&app).await;
        add_entry(&app, &token).await;

        let req = Request::builder()
            .uri("/list")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp).await;
        let entries = json.as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["service_name"], "GitHub");
    }

    #[tokio::test]
    async fn view_returns_entry_details() {
        let app = TestApp::new();
        let (token, _) = register_and_login(&app).await;
        let entry_id = add_entry(&app, &token).await;

        let req = Request::builder()
            .uri(format!("/view/{entry_id}"))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp).await;
        assert_eq!(json["service_name"], "GitHub");
        assert_eq!(json["service_url"], "https://github.com");
        assert_eq!(json["login"], "alex");
        assert_eq!(json["password"], "gh-pass");
        assert_eq!(json["notes"], "work account");
    }

    #[tokio::test]
    async fn delete_removes_entry() {
        let app = TestApp::new();
        let (token, _) = register_and_login(&app).await;
        let entry_id = add_entry(&app, &token).await;

        // Delete
        let req = Request::builder()
            .method("DELETE")
            .uri(format!("/delete/{entry_id}"))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify list is empty
        let req = Request::builder()
            .uri("/list")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.request(req).await;
        let json = body_json(resp).await;
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn view_nonexistent_entry_returns_404() {
        let app = TestApp::new();
        let (token, _) = register_and_login(&app).await;

        let req = Request::builder()
            .uri("/view/nonexistent-id")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ════════════════════════════════════════════
    // Unauthorized access
    // ════════════════════════════════════════════

    #[tokio::test]
    async fn list_without_token_returns_401() {
        let app = TestApp::new();
        let req = Request::builder().uri("/list").body(Body::empty()).unwrap();

        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn add_without_token_returns_401() {
        let app = TestApp::new();
        let req = Request::builder()
            .method("POST")
            .uri("/add")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"service_name":"X","service_url":"x","login":"x","password":"x","notes":""}"#,
            ))
            .unwrap();

        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ════════════════════════════════════════════
    // Refresh token rotation
    // ════════════════════════════════════════════

    #[tokio::test]
    async fn refresh_returns_new_tokens() {
        let app = TestApp::new();
        let (access_token, refresh_token) = register_and_login(&app).await;

        let req = Request::builder()
            .method("POST")
            .uri("/refresh")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let json = body_json(resp).await;
        let new_access = json["access_token"].as_str().unwrap();
        let new_refresh = json["refresh_token"].as_str().unwrap();
        assert!(!new_access.is_empty());
        assert!(!new_refresh.is_empty());
        assert_ne!(new_refresh, refresh_token);
    }

    #[tokio::test]
    async fn refresh_invalidates_old_token() {
        let app = TestApp::new();
        let (access_token, refresh_token) = register_and_login(&app).await;

        // First refresh — succeeds
        let req = Request::builder()
            .method("POST")
            .uri("/refresh")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Reuse old refresh token — should fail (rotation)
        let req = Request::builder()
            .method("POST")
            .uri("/refresh")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refresh_with_wrong_token_returns_401() {
        let app = TestApp::new();
        let (access_token, _) = register_and_login(&app).await;

        let req = Request::builder()
            .method("POST")
            .uri("/refresh")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "access_token": access_token,
                    "refresh_token": "totally-wrong-token",
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ════════════════════════════════════════════
    // Logout (revocation)
    // ════════════════════════════════════════════

    #[tokio::test]
    async fn logout_revokes_session() {
        let app = TestApp::new();
        let (token, _) = register_and_login(&app).await;

        // Bearer работает до logout
        let req = Request::builder()
            .uri("/list")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Logout
        let req = Request::builder()
            .method("POST")
            .uri("/logout")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Bearer после logout → 401 (SessionExpired)
        let req = Request::builder()
            .uri("/list")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_revokes_refresh_token() {
        let app = TestApp::new();
        let (access_token, refresh_token) = register_and_login(&app).await;

        // Logout
        let req = Request::builder()
            .method("POST")
            .uri("/logout")
            .header("authorization", format!("Bearer {access_token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Refresh после logout → 401 (токен удалён из auth.db)
        let req = Request::builder()
            .method("POST")
            .uri("/refresh")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logout_without_token_returns_401() {
        let app = TestApp::new();

        let req = Request::builder()
            .method("POST")
            .uri("/logout")
            .body(Body::empty())
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ════════════════════════════════════════════
    // Brute-force protection
    // ════════════════════════════════════════════

    #[tokio::test]
    async fn login_locked_after_max_attempts() {
        use crate::auth::failed_login_tracker::MAX_FAILED_ATTEMPTS;

        let app = TestApp::new();

        // Register
        let req = Request::builder()
            .method("POST")
            .uri("/register")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"victim@example.com","master_password":"Secret123!"}"#,
            ))
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // MAX_FAILED_ATTEMPTS раз неверный пароль → 401
        for _ in 0..MAX_FAILED_ATTEMPTS {
            let req = Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"victim@example.com","master_password":"WrongPass!"}"#,
                ))
                .unwrap();
            let resp = app.request(req).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        // Следующая попытка (даже с ПРАВИЛЬНЫМ паролем) → 403
        let req = Request::builder()
            .method("POST")
            .uri("/login")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"email":"victim@example.com","master_password":"Secret123!"}"#,
            ))
            .unwrap();
        let resp = app.request(req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
