use crate::crypto_operations::RealCrypto;
use crate::password_generator::{Empty, PasswordGenerator};
use crate::sqlite::{Closed, DB};
use crate::types::{
    Email, EntryId, EntryPassword, Login, MasterPassword, PlainEntry, ServiceName, ServiceUrl,
    UserId,
};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

// ════════════════════════════════════════════════════════════════════
// Ошибки сервера
// ════════════════════════════════════════════════════════════════════

#[derive(Debug)]
pub enum ServerError {
    Connection(String),
}

impl std::error::Error for ServerError {}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::Connection(msg) => write!(f, "connection error: {msg}"),
        }
    }
}

// ════════════════════════════════════════════════════════════════════
// Shared state
// ════════════════════════════════════════════════════════════════════

#[derive(Clone)]
struct AppState {
    db_path: String,
}

// ════════════════════════════════════════════════════════════════════
// Request / Response structs
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    master_password: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    user_id: String,
    message: String,
}

#[derive(Deserialize)]
struct AddRequest {
    service_name: String,
    service_url: String,
    login: String,
    password: String,
    notes: String,
}

#[derive(Serialize)]
struct AddResponse {
    entry_id: String,
    message: String,
}

#[derive(Serialize)]
struct ListEntry {
    entry_id: String,
    service_name: String,
    created_at: String,
}

#[derive(Serialize)]
struct ViewResponse {
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
struct DeleteResponse {
    message: String,
}

#[derive(Deserialize)]
struct GenerateParams {
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
struct GenerateResponse {
    password: String,
}

// ════════════════════════════════════════════════════════════════════
// Basic Auth extractor
// ════════════════════════════════════════════════════════════════════

struct Credentials {
    email: String,
    master_password: String,
}

fn extract_basic_auth(headers: &axum::http::HeaderMap) -> Result<Credentials, StatusCode> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let encoded = header
        .strip_prefix("Basic ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let decoded = String::from_utf8(
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .map_err(|_| StatusCode::UNAUTHORIZED)?,
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let (email, password) = decoded.split_once(':').ok_or(StatusCode::UNAUTHORIZED)?;

    Ok(Credentials {
        email: email.to_string(),
        master_password: password.to_string(),
    })
}

// ════════════════════════════════════════════════════════════════════
// Handlers
// ════════════════════════════════════════════════════════════════════

async fn health_handler() -> &'static str {
    "ok"
}

/// POST /register — регистрация нового пользователя
async fn register_handler(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let db_path = state.db_path.clone();

    tokio::task::spawn_blocking(move || {
        let email = Email::parse(body.email).map_err(|_| StatusCode::BAD_REQUEST)?;

        let db = DB::<Closed, RealCrypto>::new(RealCrypto)
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

/// POST /add — добавить запись (Basic Auth)
async fn add_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<AddRequest>,
) -> Result<Json<AddResponse>, StatusCode> {
    let creds = extract_basic_auth(&headers)?;
    let db_path = state.db_path.clone();

    tokio::task::spawn_blocking(move || {
        let email = Email::parse(creds.email).map_err(|_| StatusCode::BAD_REQUEST)?;

        // Closed → Open → Authenticated
        let db = DB::<Closed, RealCrypto>::new(RealCrypto)
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let db = db
            .authenticate(email, MasterPassword::new(creds.master_password))
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        // Создаём PlainEntry и шифруем
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

/// GET /list — список всех записей (Basic Auth)
async fn list_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<Vec<ListEntry>>, StatusCode> {
    let creds = extract_basic_auth(&headers)?;
    let db_path = state.db_path.clone();

    tokio::task::spawn_blocking(move || {
        let email = Email::parse(creds.email).map_err(|_| StatusCode::BAD_REQUEST)?;

        let db = DB::<Closed, RealCrypto>::new(RealCrypto)
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let db = db
            .authenticate(email, MasterPassword::new(creds.master_password))
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

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

/// GET /view/:id — просмотр одной записи (Basic Auth)
async fn view_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(entry_id): Path<String>,
) -> Result<Json<ViewResponse>, StatusCode> {
    let creds = extract_basic_auth(&headers)?;
    let db_path = state.db_path.clone();

    tokio::task::spawn_blocking(move || {
        let email = Email::parse(creds.email).map_err(|_| StatusCode::BAD_REQUEST)?;

        let db = DB::<Closed, RealCrypto>::new(RealCrypto)
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let db = db
            .authenticate(email, MasterPassword::new(creds.master_password))
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        let user_id = UserId::new(db.user_id().as_str().to_string());
        let entries = db
            .list_entries(&user_id)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        // Ищем запись по ID
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

/// DELETE /delete/:id — удалить запись (Basic Auth)
async fn delete_handler(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(entry_id): Path<String>,
) -> Result<Json<DeleteResponse>, StatusCode> {
    let creds = extract_basic_auth(&headers)?;
    let db_path = state.db_path.clone();

    tokio::task::spawn_blocking(move || {
        let email = Email::parse(creds.email).map_err(|_| StatusCode::BAD_REQUEST)?;

        let db = DB::<Closed, RealCrypto>::new(RealCrypto)
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let db = db
            .authenticate(email, MasterPassword::new(creds.master_password))
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

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

/// GET /generate — генерация пароля (без аутентификации)
async fn generate_handler(
    Query(params): Query<GenerateParams>,
) -> Result<Json<GenerateResponse>, StatusCode> {
    let length = params.length;
    if length < 8 || length > 128 {
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
// Server
// ════════════════════════════════════════════════════════════════════

pub async fn run_server(host: &str, port: u16, db_path: String) -> Result<(), ServerError> {
    let socket_address = format!("{}:{}", &host, &port);
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("tower_http=debug")),
        )
        .compact()
        .init();
    let app: Router = Router::new()
        .route("/health", get(health_handler))
        .route("/register", post(register_handler))
        .route("/add", post(add_handler))
        .route("/list", get(list_handler))
        .route("/view/{id}", get(view_handler))
        .route("/delete/{id}", delete(delete_handler))
        .route("/generate", get(generate_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(AppState { db_path });

    let listener = TcpListener::bind(socket_address)
        .await
        .map_err(|e| ServerError::Connection(format!("Unable to open remote address: {}", e)))?;

    println!("Server started at http://{}:{}", host, port);

    axum::serve(listener, app)
        .await
        .map_err(|e| ServerError::Connection(format!("Unable to start server: {}", e)))?;

    Ok(())
}
