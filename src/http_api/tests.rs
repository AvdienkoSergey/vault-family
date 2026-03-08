use super::AppState;
use super::auth_handlers::{
    api_login_handler, api_register_handler, login_handler, logout_handler, refresh_handler,
    register_handler,
};
use super::handlers::{generate_handler, health_handler};
use super::invite_handlers::{
    accept_invite_handler, complete_invite_handler, get_accepted_invites_handler,
    list_my_invites_handler, send_invite_handler,
};
use super::shared_vault_handlers::{
    api_create_vault_handler, api_delete_vault_handler, api_list_members_handler,
    api_list_vaults_handler, api_pull_entries_handler, api_push_entries_handler,
    api_revoke_member_handler, api_update_keys_handler,
};
use super::vault_handlers::{add_handler, delete_handler, list_handler, view_handler};
use crate::auth;
use crate::auth::{FailedLoginTracker, JwtSecret, SessionStore};
use crate::crypto_operations::FakeCrypto;
use crate::shared;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete as delete_method, get, post, put};
use http_body_util::BodyExt;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

// ════════════════════════════════════════════
// Test infrastructure
// ════════════════════════════════════════════

struct TestApp {
    router: Router,
    db_path: String,
    auth_db_path: String,
    shared_db_path: String,
}

impl TestApp {
    fn new() -> Self {
        let db_path = std::env::temp_dir()
            .join(format!("vault_handler_test_{}.db", Uuid::new_v4()))
            .to_str()
            .unwrap()
            .to_string();

        let auth_db_path = auth::auth_db_path(&db_path);
        let shared_db_path = shared::shared_db_path(&db_path);

        let state = AppState {
            db_path: db_path.clone(),
            auth_db_path: auth_db_path.clone(),
            shared_db_path: shared_db_path.clone(),
            jwt_secret: Arc::new(JwtSecret::new("test-jwt-secret-for-handlers".to_string())),
            session_store: SessionStore::new(),
            failed_login_tracker: FailedLoginTracker::new(),
            crypto: FakeCrypto,
        };

        let api_routes: Router<AppState<FakeCrypto>> = Router::new()
            .route(
                "/auth/register",
                post(api_register_handler::<FakeCrypto>),
            )
            .route("/auth/login", post(api_login_handler::<FakeCrypto>))
            .route(
                "/vaults",
                post(api_create_vault_handler::<FakeCrypto>)
                    .get(api_list_vaults_handler::<FakeCrypto>),
            )
            .route(
                "/vaults/{vault_id}",
                delete_method(api_delete_vault_handler::<FakeCrypto>),
            )
            .route(
                "/vaults/{vault_id}/invites",
                post(send_invite_handler::<FakeCrypto>),
            )
            .route(
                "/vaults/{vault_id}/invites/accepted",
                get(get_accepted_invites_handler::<FakeCrypto>),
            )
            .route("/invites", get(list_my_invites_handler::<FakeCrypto>))
            .route(
                "/invites/{invite_id}/accept",
                post(accept_invite_handler::<FakeCrypto>),
            )
            .route(
                "/invites/{invite_id}/complete",
                post(complete_invite_handler::<FakeCrypto>),
            )
            .route(
                "/vaults/{vault_id}/members",
                get(api_list_members_handler::<FakeCrypto>),
            )
            .route(
                "/vaults/{vault_id}/members/{user_id}",
                delete_method(api_revoke_member_handler::<FakeCrypto>),
            )
            .route(
                "/vaults/{vault_id}/keys",
                put(api_update_keys_handler::<FakeCrypto>),
            )
            .route(
                "/vaults/{vault_id}/entries",
                post(api_push_entries_handler::<FakeCrypto>)
                    .get(api_pull_entries_handler::<FakeCrypto>),
            );

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
            .nest("/api", api_routes)
            .with_state(state);

        Self {
            router,
            db_path,
            auth_db_path,
            shared_db_path,
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
        let _ = std::fs::remove_file(&self.shared_db_path);
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

// ════════════════════════════════════════════
// API helpers
// ════════════════════════════════════════════

/// Регистрация + логин через /api/auth/ — возвращает (user_id, token)
async fn api_register_and_login(app: &TestApp, email: &str, password: &str) -> (String, String) {
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "email": email,
                "master_password": password,
                "public_key": "aa".repeat(32),
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    (
        json["user_id"].as_str().unwrap().to_string(),
        json["token"].as_str().unwrap().to_string(),
    )
}

/// Создание shared vault — возвращает vault_id
async fn api_create_vault(app: &TestApp, token: &str, name: &str) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/api/vaults")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::json!({ "name": name }).to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let json = body_json(resp).await;
    json["vault_id"].as_str().unwrap().to_string()
}

/// Полный 4-шаговый invite flow, возвращает invite_id
async fn api_full_invite(
    app: &TestApp,
    owner_token: &str,
    vault_id: &str,
    invitee_email: &str,
    invitee_token: &str,
) -> String {
    // 1. Send invite
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/invites"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::from(
            serde_json::json!({
                "email": invitee_email,
                "role": "viewer",
                "permission": "read",
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let invite_id = json["invite_id"].as_str().unwrap().to_string();

    // 2. Accept invite
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/invites/{invite_id}/accept"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {invitee_token}"))
        .body(Body::from(
            serde_json::json!({
                "public_key": "cc".repeat(32),
                "confirmation_key": "dd".repeat(32),
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 3. Complete invite (owner)
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/invites/{invite_id}/complete"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::from(
            serde_json::json!({
                "encrypted_vault_key": "ee".repeat(32),
                "nonce": "ff".repeat(12),
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    invite_id
}

// ════════════════════════════════════════════
// API Auth
// ════════════════════════════════════════════

#[tokio::test]
async fn api_register_returns_user_id_and_token() {
    let app = TestApp::new();
    let (user_id, token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    assert!(!user_id.is_empty());
    assert!(!token.is_empty());
}

#[tokio::test]
async fn api_register_invalid_email_returns_400() {
    let app = TestApp::new();
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"bad","master_password":"S123!","public_key":"aa"}"#,
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn api_login_returns_user_id_and_token() {
    let app = TestApp::new();
    api_register_and_login(&app, "alice@example.com", "Secret123!").await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"alice@example.com","master_password":"Secret123!"}"#,
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(!json["user_id"].as_str().unwrap().is_empty());
    assert!(!json["token"].as_str().unwrap().is_empty());
}

// ════════════════════════════════════════════
// Shared Vaults CRUD
// ════════════════════════════════════════════

#[tokio::test]
async fn api_create_vault_returns_vault_id() {
    let app = TestApp::new();
    let (_, token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &token, "Family").await;
    assert!(!vault_id.is_empty());
}

#[tokio::test]
async fn api_list_vaults_returns_owned() {
    let app = TestApp::new();
    let (_, token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    api_create_vault(&app, &token, "Family").await;

    let req = Request::builder()
        .uri("/api/vaults")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let vaults = json.as_array().unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0]["name"], "Family");
    assert_eq!(vaults[0]["member_count"], 1);
    assert_eq!(vaults[0]["entry_count"], 0);
}

#[tokio::test]
async fn api_list_vaults_empty_for_new_user() {
    let app = TestApp::new();
    let (_, token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;

    let req = Request::builder()
        .uri("/api/vaults")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn api_create_vault_without_auth_returns_401() {
    let app = TestApp::new();
    let req = Request::builder()
        .method("POST")
        .uri("/api/vaults")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"X"}"#))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn api_delete_vault_owner_only() {
    let app = TestApp::new();
    let (_, owner_token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let (_, other_token) = api_register_and_login(&app, "bob@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    // Non-owner → 403
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/vaults/{vault_id}"))
        .header("authorization", format!("Bearer {other_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Owner → 204
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/vaults/{vault_id}"))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// ════════════════════════════════════════════
// 4-Step Invite Flow
// ════════════════════════════════════════════

#[tokio::test]
async fn api_send_invite_returns_code() {
    let app = TestApp::new();
    let (_, token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &token, "Family").await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/invites"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            r#"{"email":"bob@example.com","role":"viewer","permission":"read"}"#,
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert!(!json["invite_id"].as_str().unwrap().is_empty());
    assert!(!json["code"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn api_send_invite_non_owner_forbidden() {
    let app = TestApp::new();
    let (_, owner_token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let (_, other_token) = api_register_and_login(&app, "bob@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/invites"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {other_token}"))
        .body(Body::from(
            r#"{"email":"carol@example.com","role":"viewer","permission":"read"}"#,
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn api_list_my_invites() {
    let app = TestApp::new();
    let (_, owner_token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let (_, bob_token) = api_register_and_login(&app, "bob@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    // Send invite to bob
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/invites"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::from(
            r#"{"email":"bob@example.com","role":"viewer","permission":"read"}"#,
        ))
        .unwrap();
    app.request(req).await;

    // Bob lists his invites
    let req = Request::builder()
        .uri("/api/invites")
        .header("authorization", format!("Bearer {bob_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let invites = json.as_array().unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0]["vault_id"], vault_id);
}

#[tokio::test]
async fn api_accept_invite_sets_status() {
    let app = TestApp::new();
    let (_, owner_token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let (_, bob_token) = api_register_and_login(&app, "bob@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    // Send invite
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/invites"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::from(
            r#"{"email":"bob@example.com","role":"viewer","permission":"read"}"#,
        ))
        .unwrap();
    let resp = app.request(req).await;
    let json = body_json(resp).await;
    let invite_id = json["invite_id"].as_str().unwrap();

    // Accept
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/invites/{invite_id}/accept"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {bob_token}"))
        .body(Body::from(
            serde_json::json!({
                "public_key": "cc".repeat(32),
                "confirmation_key": "dd".repeat(32),
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn api_get_accepted_invites_owner_only() {
    let app = TestApp::new();
    let (_, owner_token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let (_, bob_token) = api_register_and_login(&app, "bob@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    // Non-owner → 403
    let req = Request::builder()
        .uri(format!("/api/vaults/{vault_id}/invites/accepted"))
        .header("authorization", format!("Bearer {bob_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Owner → 200
    let req = Request::builder()
        .uri(format!("/api/vaults/{vault_id}/invites/accepted"))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn api_complete_invite_adds_member() {
    let app = TestApp::new();
    let (_, owner_token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let (_, bob_token) = api_register_and_login(&app, "bob@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    api_full_invite(&app, &owner_token, &vault_id, "bob@example.com", &bob_token).await;

    // Verify member was added
    let req = Request::builder()
        .uri(format!("/api/vaults/{vault_id}/members"))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let members = json.as_array().unwrap();
    assert_eq!(members.len(), 2); // owner + bob
}

#[tokio::test]
async fn api_full_invite_flow() {
    let app = TestApp::new();
    let (owner_id, owner_token) =
        api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let (bob_id, bob_token) =
        api_register_and_login(&app, "bob@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    // Full flow
    api_full_invite(&app, &owner_token, &vault_id, "bob@example.com", &bob_token).await;

    // List vaults — owner sees member_count = 2
    let req = Request::builder()
        .uri("/api/vaults")
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    let json = body_json(resp).await;
    assert_eq!(json[0]["member_count"], 2);

    // List members — both users present
    let req = Request::builder()
        .uri(format!("/api/vaults/{vault_id}/members"))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    let json = body_json(resp).await;
    let members = json.as_array().unwrap();
    let member_ids: Vec<&str> = members.iter().map(|m| m["user_id"].as_str().unwrap()).collect();
    assert!(member_ids.contains(&owner_id.as_str()));
    assert!(member_ids.contains(&bob_id.as_str()));
}

#[tokio::test]
async fn api_accept_wrong_invite_returns_404() {
    let app = TestApp::new();
    let (_, token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/invites/nonexistent-id/accept")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::json!({
                "public_key": "cc".repeat(32),
                "confirmation_key": "dd".repeat(32),
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ════════════════════════════════════════════
// Members
// ════════════════════════════════════════════

#[tokio::test]
async fn api_list_members_returns_details() {
    let app = TestApp::new();
    let (_, token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &token, "Family").await;

    let req = Request::builder()
        .uri(format!("/api/vaults/{vault_id}/members"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let members = json.as_array().unwrap();
    assert_eq!(members.len(), 1);
    assert!(members[0]["user_id"].as_str().is_some());
    assert!(members[0]["permission"].as_str().is_some());
    assert!(members[0]["crypto_status"].as_str().is_some());
}

#[tokio::test]
async fn api_revoke_member_removes() {
    let app = TestApp::new();
    let (_, owner_token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let (bob_id, bob_token) =
        api_register_and_login(&app, "bob@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    api_full_invite(&app, &owner_token, &vault_id, "bob@example.com", &bob_token).await;

    // Revoke bob
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/vaults/{vault_id}/members/{bob_id}"))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify members list is 1 (owner only)
    let req = Request::builder()
        .uri(format!("/api/vaults/{vault_id}/members"))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    let json = body_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn api_revoke_owner_forbidden() {
    let app = TestApp::new();
    let (owner_id, owner_token) =
        api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/vaults/{vault_id}/members/{owner_id}"))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ════════════════════════════════════════════
// Entries (zero-knowledge)
// ════════════════════════════════════════════

#[tokio::test]
async fn api_push_entries_creates() {
    let app = TestApp::new();
    let (_, token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &token, "Family").await;

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::json!({
                "entries": [{
                    "id": "entry-1",
                    "category": "login",
                    "encrypted_data": "deadbeef",
                    "nonce": "aabbccdd",
                    "last_modified": "2024-01-01T00:00:00Z",
                }]
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn api_pull_entries_returns_pushed() {
    let app = TestApp::new();
    let (_, token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &token, "Family").await;

    // Push
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::json!({
                "entries": [{
                    "id": "entry-1",
                    "category": "login",
                    "encrypted_data": "deadbeef",
                    "nonce": "aabbccdd",
                    "last_modified": "2024-01-01T00:00:00Z",
                }]
            })
            .to_string(),
        ))
        .unwrap();
    app.request(req).await;

    // Pull
    let req = Request::builder()
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let entries = json.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"], "entry-1");
    assert_eq!(entries[0]["encrypted_data"], "deadbeef");
}

#[tokio::test]
async fn api_push_entries_upsert() {
    let app = TestApp::new();
    let (_, token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &token, "Family").await;

    let push_entry = |data: &str| {
        serde_json::json!({
            "entries": [{
                "id": "entry-1",
                "category": "login",
                "encrypted_data": data,
                "nonce": "aabbccdd",
                "last_modified": "2024-01-01T00:00:00Z",
            }]
        })
        .to_string()
    };

    // Push v1
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(push_entry("version1")))
        .unwrap();
    app.request(req).await;

    // Push v2 (same id, different data)
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(push_entry("version2")))
        .unwrap();
    app.request(req).await;

    // Pull — should have 1 entry, not 2
    let req = Request::builder()
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    let json = body_json(resp).await;
    let entries = json.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["encrypted_data"], "version2");
}

#[tokio::test]
async fn api_pull_entries_delta_sync() {
    let app = TestApp::new();
    let (_, token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &token, "Family").await;

    // Push old entry
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::json!({
                "entries": [{
                    "id": "old-entry",
                    "category": "login",
                    "encrypted_data": "old-data",
                    "nonce": "aabbccdd",
                    "last_modified": "2020-01-01T00:00:00Z",
                }]
            })
            .to_string(),
        ))
        .unwrap();
    app.request(req).await;

    // Push new entry
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .body(Body::from(
            serde_json::json!({
                "entries": [{
                    "id": "new-entry",
                    "category": "login",
                    "encrypted_data": "new-data",
                    "nonce": "eeff0011",
                    "last_modified": "2025-06-01T00:00:00Z",
                }]
            })
            .to_string(),
        ))
        .unwrap();
    app.request(req).await;

    // Pull with since=2024 — should only return new-entry
    let req = Request::builder()
        .uri(format!(
            "/api/vaults/{vault_id}/entries?since=2024-01-01T00:00:00Z"
        ))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let entries = json.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["id"], "new-entry");
}

#[tokio::test]
async fn api_entries_non_member_forbidden() {
    let app = TestApp::new();
    let (_, owner_token) = api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let (_, other_token) = api_register_and_login(&app, "bob@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    // Non-member push → 403
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {other_token}"))
        .body(Body::from(
            serde_json::json!({
                "entries": [{
                    "id": "entry-1",
                    "category": "login",
                    "encrypted_data": "data",
                    "nonce": "nonce",
                    "last_modified": "2024-01-01T00:00:00Z",
                }]
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Non-member pull → 403
    let req = Request::builder()
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("authorization", format!("Bearer {other_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ════════════════════════════════════════════
// Re-keying
// ════════════════════════════════════════════

#[tokio::test]
async fn api_update_keys_owner_only() {
    let app = TestApp::new();
    let (owner_id, owner_token) =
        api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let (_, other_token) = api_register_and_login(&app, "bob@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    let body = serde_json::json!({
        "members": [{
            "user_id": owner_id,
            "encrypted_vault_key": "newkey123",
            "nonce": "newnonce",
        }]
    })
    .to_string();

    // Non-owner → 403
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/vaults/{vault_id}/keys"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {other_token}"))
        .body(Body::from(body.clone()))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Owner → 204
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/vaults/{vault_id}/keys"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::from(body))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn api_rekey_after_revoke_flow() {
    let app = TestApp::new();
    let (owner_id, owner_token) =
        api_register_and_login(&app, "alice@example.com", "Secret123!").await;
    let (bob_id, bob_token) =
        api_register_and_login(&app, "bob@example.com", "Secret123!").await;
    let vault_id = api_create_vault(&app, &owner_token, "Family").await;

    // Invite bob
    api_full_invite(&app, &owner_token, &vault_id, "bob@example.com", &bob_token).await;

    // Push entry
    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::from(
            serde_json::json!({
                "entries": [{
                    "id": "entry-1",
                    "category": "login",
                    "encrypted_data": "secret-data",
                    "nonce": "aabbccdd",
                    "last_modified": "2024-01-01T00:00:00Z",
                }]
            })
            .to_string(),
        ))
        .unwrap();
    app.request(req).await;

    // Revoke bob
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/vaults/{vault_id}/members/{bob_id}"))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Re-key: update vault keys for owner
    let req = Request::builder()
        .method("PUT")
        .uri(format!("/api/vaults/{vault_id}/keys"))
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::from(
            serde_json::json!({
                "members": [{
                    "user_id": owner_id,
                    "encrypted_vault_key": "re-keyed-vault-key",
                    "nonce": "new-nonce-hex",
                }]
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Entries still accessible for owner
    let req = Request::builder()
        .uri(format!("/api/vaults/{vault_id}/entries"))
        .header("authorization", format!("Bearer {owner_token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    assert_eq!(json.as_array().unwrap().len(), 1);
}
