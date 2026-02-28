use crate::crypto_operations::RealCrypto;
use crate::sqlite::{Closed, DB};
use crate::types::{Email, MasterPassword};
use axum::routing::post;
use axum::{Json, Router, extract::State, http::StatusCode, routing::get};
use serde::{Deserialize, Serialize};
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[derive(Debug)]
pub enum ServerError {
    Connection(String),
    Controller(String),
}
impl std::error::Error for ServerError {}
impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::Connection(msg) => write!(f, "connection error: {msg}"),
            ServerError::Controller(msg) => write!(f, "controller error: {msg}"),
        }
    }
}
#[derive(Clone)]
struct AppState {
    db_path: String,
}
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
async fn health_handler() -> &'static str {
    "ok"
}
async fn register_handler(
    State(state): State<AppState>,
    Json(body): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, StatusCode> {
    let db_path = state.db_path.clone();

    let result = tokio::task::spawn_blocking(move || {
        // 1. Валидируем email
        let email = Email::parse(body.email).map_err(|_| StatusCode::BAD_REQUEST)?;

        // 2. Полный typestate lifecycle: Closed → Open → create_user
        let db = DB::<Closed, RealCrypto>::new(RealCrypto)
            .open(&db_path)
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let user = db
            .create_user(email, MasterPassword::new(body.master_password))
            .map_err(|_| StatusCode::BAD_REQUEST)?;

        // 3. Формируем ответ
        Ok(Json(RegisterResponse {
            user_id: user.id.as_str().to_string(),
            message: "User registered successfully".to_string(),
        }))
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?; // JoinError — если spawn_blocking упал

    result
}
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
