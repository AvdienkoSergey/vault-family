use axum::{
    Router,
    routing::get,
};
use tokio::net::TcpListener;

pub enum ServerError {
    Connection(String),
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::Connection(msg) => write!(f, "connection error: {msg}"),
        }
    }
}

async fn health_handler() -> &'static str {
    "ok"
}

pub async fn run_server(host: &str, port: u16, _db_path: String) -> Result<(), ServerError> {
    let socket_address = format!("{}:{}", &host, &port);
    let app: Router = Router::new()
        .route("/health", get(health_handler));

    let listener = TcpListener::bind(socket_address).await.map_err(
        |e| ServerError::Connection(format!("Unable to open remote address: {}", e))
    )?;

    println!("Server started at http://{}:{}", host, port);

    axum::serve(listener, app).await.map_err(
        |e| ServerError::Connection(format!("Unable to start server: {}", e))
    )?;

    Ok(())
}