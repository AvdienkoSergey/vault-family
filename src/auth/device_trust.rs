//! Device trust — track which devices have successfully authenticated.
//!
//! When a device (identified by `X-Device-ID` header) logs in with the correct
//! password, it becomes "trusted" for that email. Trusted devices are exempt
//! from brute-force (403) and security lock (423) blocks.
//!
//! This prevents the legitimate user's phone from being blocked when an
//! attacker triggers brute-force protection on the same account.
//!
//! # Limitations
//!
//! - **In-memory**: resets on server restart. Acceptable for 1–5 users.
//! - **Device ID is client-generated**: an attacker could spoof it, but they'd
//!   need to know the exact UUID of a trusted device. Random UUID = 122 bits
//!   of entropy — not guessable.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

/// Thread-safe store of trusted (email → device_ids).
#[derive(Clone)]
pub struct DeviceTrustStore {
    /// email (lowercase) → set of trusted device IDs
    inner: Arc<RwLock<HashMap<String, HashSet<String>>>>,
}

impl Default for DeviceTrustStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceTrustStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Mark a device as trusted for an email (called after successful login).
    pub fn trust(&self, email: &str, device_id: &str) {
        if device_id.is_empty() {
            return;
        }
        let mut map = self.inner.write().expect("DeviceTrustStore poisoned");
        map.entry(email.to_lowercase())
            .or_default()
            .insert(device_id.to_string());
    }

    /// Check if a device is trusted for an email.
    pub fn is_trusted(&self, email: &str, device_id: &str) -> bool {
        if device_id.is_empty() {
            return false;
        }
        let map = self.inner.read().expect("DeviceTrustStore poisoned");
        map.get(&email.to_lowercase())
            .map(|devices| devices.contains(device_id))
            .unwrap_or(false)
    }

    /// Remove all trusted devices for an email (e.g. after password change).
    pub fn revoke_all(&self, email: &str) {
        let mut map = self.inner.write().expect("DeviceTrustStore poisoned");
        map.remove(&email.to_lowercase());
    }
}

// ════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_device_id_never_trusted() {
        let store = DeviceTrustStore::new();
        store.trust("alice@test.com", "");
        assert!(!store.is_trusted("alice@test.com", ""));
    }

    #[test]
    fn trust_and_check() {
        let store = DeviceTrustStore::new();
        store.trust("alice@test.com", "device-1");
        assert!(store.is_trusted("alice@test.com", "device-1"));
        assert!(!store.is_trusted("alice@test.com", "device-2"));
    }

    #[test]
    fn case_insensitive_email() {
        let store = DeviceTrustStore::new();
        store.trust("Alice@Test.com", "device-1");
        assert!(store.is_trusted("alice@test.com", "device-1"));
    }

    #[test]
    fn different_emails_isolated() {
        let store = DeviceTrustStore::new();
        store.trust("alice@test.com", "device-1");
        assert!(!store.is_trusted("bob@test.com", "device-1"));
    }

    #[test]
    fn multiple_devices_per_email() {
        let store = DeviceTrustStore::new();
        store.trust("alice@test.com", "phone");
        store.trust("alice@test.com", "tablet");
        assert!(store.is_trusted("alice@test.com", "phone"));
        assert!(store.is_trusted("alice@test.com", "tablet"));
    }

    #[test]
    fn revoke_all_clears_devices() {
        let store = DeviceTrustStore::new();
        store.trust("alice@test.com", "phone");
        store.trust("alice@test.com", "tablet");
        store.revoke_all("alice@test.com");
        assert!(!store.is_trusted("alice@test.com", "phone"));
        assert!(!store.is_trusted("alice@test.com", "tablet"));
    }

    #[test]
    fn clone_shares_state() {
        let store1 = DeviceTrustStore::new();
        let store2 = store1.clone();
        store1.trust("alice@test.com", "device-1");
        assert!(store2.is_trusted("alice@test.com", "device-1"));
    }
}
