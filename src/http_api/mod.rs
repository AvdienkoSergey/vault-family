mod extractors;
mod handlers;

use axum::Router;
use axum::routing::{delete, get, post};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use handlers::{
    add_handler, delete_handler, generate_handler, health_handler, list_handler, register_handler,
    view_handler,
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
pub(crate) struct AppState {
    pub(crate) db_path: String,
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
