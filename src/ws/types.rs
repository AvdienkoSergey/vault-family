//! WebSocket event types for real-time vault notifications.
//!
//! Events are server→client only. They carry minimal metadata
//! (vault_id, user_id) — never plaintext data. Zero-knowledge preserved.

use serde::Serialize;

/// An event pushed to connected clients via WebSocket.
///
/// Serialized as `{ "type": "MemberRevoked", "vault_id": "...", ... }`.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum VaultEvent {
    /// A member was removed from a vault.
    /// Sent to: revoked user + all remaining members.
    MemberRevoked {
        vault_id: String,
        revoked_user_id: String,
    },

    /// Vault was deleted by owner.
    /// Sent to: all former members (except owner).
    VaultDeleted { vault_id: String },

    /// Vault keys were updated (re-keying after revocation).
    /// Sent to: all current members.
    KeysUpdated { vault_id: String },

    /// A member's permission was changed.
    /// Sent to: all members.
    PermissionChanged {
        vault_id: String,
        user_id: String,
        new_permission: String,
    },

    /// New entries were pushed to a vault.
    /// Sent to: all members except the pusher.
    EntriesUpdated { vault_id: String },

    /// A new member joined (invite completed).
    /// Sent to: all existing members.
    MemberJoined { vault_id: String, user_id: String },

    /// Someone tried to login with this user's email but wrong password.
    /// Sent to: the legitimate user (all connected devices).
    UnauthorizedLoginAttempt { email: String, timestamp: String },
}
