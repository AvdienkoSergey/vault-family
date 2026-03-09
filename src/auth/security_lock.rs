//! Security lock — permanent account lock triggered by the legitimate user.
//!
//! When a failed login attempt is detected and the legitimate user (already
//! authenticated via WS) confirms it's unauthorized, this store marks the
//! email as "security locked".
//!
//! On subsequent failed login attempts from the attacker's device, the server
//! returns HTTP 423 (Locked). The client interprets this as "wipe local data".
//!
//! In-memory only — resets on server restart. For a personal/family app
//! with 1–5 users, this is acceptable.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Thread-safe store of security-locked emails.
#[derive(Clone)]
pub struct SecurityLockStore {
    locked: Arc<RwLock<HashSet<String>>>,
}

impl Default for SecurityLockStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityLockStore {
    pub fn new() -> Self {
        Self {
            locked: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Activate security lock for an email (called by legitimate user).
    pub fn activate(&self, email: &str) {
        let mut set = self.locked.write().expect("SecurityLockStore poisoned");
        set.insert(email.to_lowercase());
    }

    /// Check if an email is security-locked.
    pub fn is_locked(&self, email: &str) -> bool {
        let set = self.locked.read().expect("SecurityLockStore poisoned");
        set.contains(&email.to_lowercase())
    }

    /// Deactivate security lock (legitimate user unlocks after changing password).
    pub fn deactivate(&self, email: &str) {
        let mut set = self.locked.write().expect("SecurityLockStore poisoned");
        set.remove(&email.to_lowercase());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initially_not_locked() {
        let store = SecurityLockStore::new();
        assert!(!store.is_locked("alice@test.com"));
    }

    #[test]
    fn activate_and_check() {
        let store = SecurityLockStore::new();
        store.activate("alice@test.com");
        assert!(store.is_locked("alice@test.com"));
        assert!(!store.is_locked("bob@test.com"));
    }

    #[test]
    fn deactivate() {
        let store = SecurityLockStore::new();
        store.activate("alice@test.com");
        store.deactivate("alice@test.com");
        assert!(!store.is_locked("alice@test.com"));
    }

    #[test]
    fn case_insensitive() {
        let store = SecurityLockStore::new();
        store.activate("Alice@Test.com");
        assert!(store.is_locked("alice@test.com"));
    }

    #[test]
    fn clone_shares_state() {
        let store1 = SecurityLockStore::new();
        let store2 = store1.clone();
        store1.activate("alice@test.com");
        assert!(store2.is_locked("alice@test.com"));
    }
}
