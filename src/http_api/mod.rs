mod auth_handlers;
mod dto;
mod handlers;
mod vault_handlers;

#[cfg(test)]
mod tests;

use axum::Router;
use axum::http::header::AUTHORIZATION;
use axum::routing::{delete, get, post};
use tokio::net::TcpListener;
use tower_http::sensitive_headers::SetSensitiveRequestHeadersLayer;
use tower_http::trace::{DefaultMakeSpan, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::Level;
use tracing_subscriber::EnvFilter;

use std::sync::Arc;

use crate::auth;
use crate::auth::{FailedLoginTracker, JwtSecret, SessionStore};
use crate::crypto_operations::{CryptoProvider, RealCrypto};

use auth_handlers::{login_handler, logout_handler, refresh_handler, register_handler};
use handlers::{generate_handler, health_handler};
use vault_handlers::{add_handler, delete_handler, list_handler, view_handler};

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
pub(crate) struct AppState<C: CryptoProvider + Clone> {
    /// Путь к vault.db (пользователи + записи)
    pub(crate) db_path: String,
    /// Путь к auth.db (refresh-токены)
    pub(crate) auth_db_path: String,
    /// JWT-секрет для подписи токенов
    pub(crate) jwt_secret: Arc<JwtSecret>,
    /// Серверное хранилище сессий (EncryptionKey в памяти, не в JWT)
    pub(crate) session_store: SessionStore,
    /// Трекер неудачных попыток входа (brute-force защита)
    pub(crate) failed_login_tracker: FailedLoginTracker,
    /// Криптопровайдер
    pub(crate) crypto: C,
}

// ════════════════════════════════════════════════════════════════════
// Server
// ════════════════════════════════════════════════════════════════════

pub async fn run_server(host: &str, port: u16, db_path: String) -> Result<(), ServerError> {
    let socket_address = format!("{}:{}", &host, &port);

    let jwt_secret = auth::jwt_secret::load_or_create_jwt_secret(&db_path)
        .map_err(|e| ServerError::Connection(format!("Failed to load JWT secret: {e}")))?;

    let auth_db_path = auth::auth_db_path(&db_path);

    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("vault_family=info,tower_http=info")),
        )
        .compact()
        .init();

    let app: Router = Router::new()
        .route("/health", get(health_handler))
        .route("/login", post(login_handler::<RealCrypto>))
        .route("/logout", post(logout_handler::<RealCrypto>))
        .route("/refresh", post(refresh_handler::<RealCrypto>))
        .route("/register", post(register_handler::<RealCrypto>))
        .route("/add", post(add_handler::<RealCrypto>))
        .route("/list", get(list_handler::<RealCrypto>))
        .route("/view/{id}", get(view_handler::<RealCrypto>))
        .route("/delete/{id}", delete(delete_handler::<RealCrypto>))
        .route("/generate", get(generate_handler))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(
                    DefaultMakeSpan::new()
                        .level(Level::INFO)
                        .include_headers(false),
                )
                .on_request(DefaultOnRequest::new().level(Level::INFO))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .layer(SetSensitiveRequestHeadersLayer::new([AUTHORIZATION]))
        .with_state(AppState {
            db_path,
            auth_db_path,
            jwt_secret: Arc::new(jwt_secret),
            session_store: SessionStore::new(),
            failed_login_tracker: FailedLoginTracker::new(),
            crypto: RealCrypto,
        });

    let listener = TcpListener::bind(socket_address)
        .await
        .map_err(|e| ServerError::Connection(format!("Unable to open remote address: {}", e)))?;

    println!("Server started at http://{}:{}", host, port);

    axum::serve(listener, app)
        .await
        .map_err(|e| ServerError::Connection(format!("Unable to start server: {}", e)))?;

    Ok(())
}
