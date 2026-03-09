//! Connection registry — maps user_id → set of active WebSocket senders.
//!
//! Uses `DashMap` for lock-free concurrent reads (fan-out is read-heavy).
//! Each connection gets an `mpsc::UnboundedSender<String>` for push delivery.

use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Sender half for pushing JSON events to a single WebSocket connection.
pub type EventSender = mpsc::UnboundedSender<String>;

/// Thread-safe registry of active WebSocket connections.
///
/// Structure: `user_id → Vec<EventSender>` (one per device/connection).
#[derive(Clone)]
pub struct ConnectionRegistry {
    connections: Arc<DashMap<String, Vec<EventSender>>>,
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionRegistry {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
        }
    }

    /// Register a new WebSocket connection for a user.
    ///
    /// Returns `UnboundedReceiver` — the WS handler reads from it and
    /// forwards messages to the actual WebSocket.
    pub fn register(&self, user_id: &str) -> (EventSender, mpsc::UnboundedReceiver<String>) {
        let (tx, rx) = mpsc::unbounded_channel();
        self.connections
            .entry(user_id.to_string())
            .or_default()
            .push(tx.clone());
        (tx, rx)
    }

    /// Unregister a specific sender (called on WS disconnect).
    ///
    /// Compares by pointer identity — each `register()` creates a unique sender.
    pub fn unregister(&self, user_id: &str, sender: &EventSender) {
        if let Some(mut senders) = self.connections.get_mut(user_id) {
            senders.retain(|s| !s.same_channel(sender));
            if senders.is_empty() {
                drop(senders);
                self.connections.remove(user_id);
            }
        }
    }

    /// Send event to ALL connections of a specific user.
    pub fn send_to_user(&self, user_id: &str, event_json: &str) {
        if let Some(senders) = self.connections.get(user_id) {
            for sender in senders.iter() {
                // If send fails → receiver dropped → connection dead, cleaned up later
                let _ = sender.send(event_json.to_string());
            }
        }
    }

    /// Send event to multiple users.
    pub fn send_to_users(&self, user_ids: &[String], event_json: &str) {
        for uid in user_ids {
            self.send_to_user(uid, event_json);
        }
    }

    /// Remove dead senders (where the receiver has been dropped).
    pub fn cleanup_dead(&self) {
        self.connections.retain(|_, senders| {
            senders.retain(|s| !s.is_closed());
            !senders.is_empty()
        });
    }

    /// Total active connections (for diagnostics).
    #[allow(dead_code)]
    pub fn connection_count(&self) -> usize {
        self.connections.iter().map(|e| e.value().len()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn register_and_receive() {
        let registry = ConnectionRegistry::new();
        let (_tx, mut rx) = registry.register("user-1");

        registry.send_to_user("user-1", r#"{"type":"test"}"#);

        let msg = rx.recv().await.unwrap();
        assert!(msg.contains("test"));
    }

    #[tokio::test]
    async fn multiple_devices() {
        let registry = ConnectionRegistry::new();
        let (_tx1, mut rx1) = registry.register("user-1");
        let (_tx2, mut rx2) = registry.register("user-1");

        registry.send_to_user("user-1", "hello");

        assert_eq!(rx1.recv().await.unwrap(), "hello");
        assert_eq!(rx2.recv().await.unwrap(), "hello");
    }

    #[test]
    fn send_to_nonexistent_user_is_noop() {
        let registry = ConnectionRegistry::new();
        registry.send_to_user("nobody", "test"); // should not panic
    }

    #[tokio::test]
    async fn unregister_removes_sender() {
        let registry = ConnectionRegistry::new();
        let (tx, rx) = registry.register("user-1");

        registry.unregister("user-1", &tx);
        drop(rx);

        assert_eq!(registry.connection_count(), 0);
    }

    #[tokio::test]
    async fn cleanup_removes_dead() {
        let registry = ConnectionRegistry::new();
        let (_tx, rx) = registry.register("user-1");
        drop(rx); // receiver dropped → sender is "closed"

        registry.cleanup_dead();
        assert_eq!(registry.connection_count(), 0);
    }
}
