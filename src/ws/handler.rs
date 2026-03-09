//! WebSocket handler — ticket-based upgrade + event forwarding.
//!
//! Flow:
//! 1. Client: `POST /api/ws/ticket` (Bearer JWT) → `{ ticket: "uuid" }`
//! 2. Client: `GET /ws?ticket=uuid` → 101 Switching Protocols
//! 3. Server pushes VaultEvent JSON frames to client
//! 4. Client sends only ping; server responds with pong

use axum::Json;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;

use crate::auth;
use crate::crypto_operations::CryptoProvider;
use crate::http_api::AppState;

// ════════════════════════════════════════════════════════════════════
// POST /api/ws/ticket — issue a one-time ticket (requires JWT)
// ════════════════════════════════════════════════════════════════════

#[derive(serde::Serialize)]
pub struct WsTicketResponse {
    pub ticket: String,
}

pub(crate) async fn ws_ticket_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    headers: axum::http::HeaderMap,
) -> Result<Json<WsTicketResponse>, StatusCode> {
    let jwt_secret = state.jwt_secret.clone();
    let session_store = state.session_store.clone();

    let pass = auth::guard(&headers, &jwt_secret, &session_store).map_err(StatusCode::from)?;

    let ticket = state
        .ticket_store
        .issue(
            pass.user_id().as_str().to_string(),
            pass.email().as_str().to_string(),
        )
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;

    Ok(Json(WsTicketResponse { ticket }))
}

// ════════════════════════════════════════════════════════════════════
// GET /ws?ticket=<TICKET> — WebSocket upgrade
// ════════════════════════════════════════════════════════════════════

#[derive(Deserialize)]
pub struct WsQuery {
    ticket: String,
}

pub(crate) async fn ws_upgrade_handler<C: CryptoProvider + Clone + Send + Sync + 'static>(
    State(state): State<AppState<C>>,
    Query(query): Query<WsQuery>,
    ws: axum::extract::WebSocketUpgrade,
) -> impl IntoResponse {
    // Validate ticket BEFORE upgrade (reject early = no resource waste)
    let (user_id, _email) = match state.ticket_store.consume(&query.ticket) {
        Some(identity) => identity,
        None => return StatusCode::UNAUTHORIZED.into_response(),
    };

    let registry = state.ws_registry.clone();

    ws.on_upgrade(move |socket| handle_socket(socket, user_id, registry))
        .into_response()
}

// ════════════════════════════════════════════════════════════════════
// Socket handler — two tasks: reader + writer
// ════════════════════════════════════════════════════════════════════

async fn handle_socket(
    socket: WebSocket,
    user_id: String,
    registry: super::registry::ConnectionRegistry,
) {
    let (mut ws_sink, mut ws_stream) = socket.split();

    // Register this connection — get sender (for unregister) and receiver (for events)
    let (sender, mut event_rx) = registry.register(&user_id);

    tracing::info!("WS connected: {user_id}");

    // Writer task: registry events → WebSocket frames
    let writer = tokio::spawn(async move {
        while let Some(event_json) = event_rx.recv().await {
            if ws_sink
                .send(Message::Text(event_json.into()))
                .await
                .is_err()
            {
                break; // WebSocket closed
            }
        }
    });

    // Reader task: client messages → handle pings, detect close
    let reader = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_stream.next().await {
            if let Message::Close(_) = msg {
                break;
            }
            // Axum handles Ping/Pong at the protocol level automatically;
            // all other client messages are ignored.
        }
    });

    // Wait for either task to finish (disconnect)
    tokio::select! {
        _ = writer => {},
        _ = reader => {},
    }

    // Cleanup
    registry.unregister(&user_id, &sender);
    tracing::info!("WS disconnected: {user_id}");
}
