//! WebSocket real-time event system for shared vault notifications.
//!
//! Architecture:
//! - `tickets` — one-time tokens for secure WS handshake (no JWT in URL)
//! - `registry` — user_id → Vec<sender> fan-out map
//! - `handler` — Axum WS upgrade + event forwarding
//! - `types` — VaultEvent enum (server→client only)

pub mod handler;
pub mod registry;
pub mod tickets;
pub mod types;

pub(crate) use handler::{ws_ticket_handler, ws_upgrade_handler};
pub use registry::ConnectionRegistry;
pub use tickets::TicketStore;
pub use types::VaultEvent;
