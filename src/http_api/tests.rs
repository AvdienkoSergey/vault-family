use super::AppState;
use super::auth_handlers::{login_handler, logout_handler, refresh_handler, register_handler};
use super::handlers::{generate_handler, health_handler};
use super::vault_handlers::{add_handler, delete_handler, list_handler, view_handler};
use crate::auth;
use crate::auth::{FailedLoginTracker, JwtSecret, SessionStore};
use crate::crypto_operations::FakeCrypto;
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{delete as delete_method, get, post};
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
