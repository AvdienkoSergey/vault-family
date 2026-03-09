//! One-time WebSocket tickets for secure handshake.
//!
//! # Why tickets?
//!
//! JWT in WebSocket query string leaks into server access logs,
//! proxy logs, and browser history. Instead:
//!
//! 1. Client: `POST /api/ws/ticket` (Bearer: JWT) → `{ ticket: "uuid" }`
//! 2. Client: `GET /ws?ticket=uuid` → WebSocket upgrade
//!
//! Ticket is single-use, 30-second TTL. Even if logged — already invalid.

use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

const TICKET_TTL_SECS: i64 = 30;
const MAX_TICKETS: usize = 100;

struct TicketEntry {
    user_id: String,
    email: String,
    created_at: DateTime<Utc>,
}

/// In-memory store for one-time WebSocket upgrade tickets.
#[derive(Clone)]
pub struct TicketStore {
    inner: Arc<RwLock<HashMap<String, TicketEntry>>>,
}

impl Default for TicketStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TicketStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Issue a ticket for a user. Returns ticket UUID.
    ///
    /// Fails if too many pending tickets (DoS protection).
    pub fn issue(&self, user_id: String, email: String) -> Result<String, &'static str> {
        let mut map = self.inner.write().expect("TicketStore lock poisoned");
        self.cleanup_expired(&mut map);

        if map.len() >= MAX_TICKETS {
            return Err("too many pending tickets");
        }

        let ticket_id = uuid::Uuid::new_v4().to_string();
        map.insert(
            ticket_id.clone(),
            TicketEntry {
                user_id,
                email,
                created_at: Utc::now(),
            },
        );

        Ok(ticket_id)
    }

    /// Consume a ticket (one-time use).
    ///
    /// Returns `(user_id, email)` if valid and not expired.
    pub fn consume(&self, ticket_id: &str) -> Option<(String, String)> {
        let mut map = self.inner.write().expect("TicketStore lock poisoned");
        let entry = map.remove(ticket_id)?;

        let age = Utc::now() - entry.created_at;
        if age > Duration::seconds(TICKET_TTL_SECS) {
            return None; // expired
        }

        Some((entry.user_id, entry.email))
    }

    /// Remove all expired tickets. Called on each `issue()`.
    pub fn cleanup_expired_public(&self) {
        let mut map = self.inner.write().expect("TicketStore lock poisoned");
        self.cleanup_expired(&mut map);
    }

    fn cleanup_expired(&self, map: &mut HashMap<String, TicketEntry>) {
        let cutoff = Utc::now() - Duration::seconds(TICKET_TTL_SECS);
        map.retain(|_, entry| entry.created_at > cutoff);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issue_and_consume() {
        let store = TicketStore::new();
        let ticket = store
            .issue("user-1".into(), "a@b.com".into())
            .unwrap();
        let (uid, email) = store.consume(&ticket).unwrap();
        assert_eq!(uid, "user-1");
        assert_eq!(email, "a@b.com");
    }

    #[test]
    fn consume_is_one_time() {
        let store = TicketStore::new();
        let ticket = store
            .issue("user-1".into(), "a@b.com".into())
            .unwrap();
        assert!(store.consume(&ticket).is_some());
        assert!(store.consume(&ticket).is_none());
    }

    #[test]
    fn consume_nonexistent_returns_none() {
        let store = TicketStore::new();
        assert!(store.consume("bogus").is_none());
    }

    #[test]
    fn expired_ticket_returns_none() {
        let store = TicketStore::new();
        let ticket_id = {
            let mut map = store.inner.write().unwrap();
            let id = "expired-ticket".to_string();
            map.insert(
                id.clone(),
                TicketEntry {
                    user_id: "u".into(),
                    email: "e".into(),
                    created_at: Utc::now() - Duration::seconds(TICKET_TTL_SECS + 1),
                },
            );
            id
        };
        assert!(store.consume(&ticket_id).is_none());
    }
}
