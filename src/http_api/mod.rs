mod extractors;
mod handlers;
pub mod jwt;
pub mod jwt_secret;

use axum::Router;
use axum::routing::{delete, get, post};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use std::sync::Arc;

use crate::crypto_operations::{CryptoProvider, RealCrypto};
use crate::types::JwtSecret;

use handlers::{
    add_handler, delete_handler, generate_handler, health_handler, list_handler, login_handler,
    refresh_handler, register_handler, view_handler,
};

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
    pub(crate) db_path: String,
    pub(crate) jwt_secret: Arc<JwtSecret>,
    pub(crate) crypto: C,
}

// ════════════════════════════════════════════════════════════════════
// Server
// ════════════════════════════════════════════════════════════════════

pub async fn run_server(host: &str, port: u16, db_path: String) -> Result<(), ServerError> {
    let socket_address = format!("{}:{}", &host, &port);

    let jwt_secret = jwt_secret::load_or_create_jwt_secret(&db_path)
        .map_err(|e| ServerError::Connection(format!("Failed to load JWT secret: {e}")))?;

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
        .route("/login", post(login_handler::<RealCrypto>))
        .route("/refresh", post(refresh_handler::<RealCrypto>))
        .route("/register", post(register_handler::<RealCrypto>))
        .route("/add", post(add_handler::<RealCrypto>))
        .route("/list", get(list_handler::<RealCrypto>))
        .route("/view/{id}", get(view_handler::<RealCrypto>))
        .route("/delete/{id}", delete(delete_handler::<RealCrypto>))
        .route("/generate", get(generate_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(AppState {
            db_path,
            jwt_secret: Arc::new(jwt_secret),
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
