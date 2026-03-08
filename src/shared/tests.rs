use super::*;
use crate::crypto_operations::FakeCrypto;
use crate::types::{
    EncryptionKey, Role, SharedVaultId, SharedVaultName, UserId, VaultPass, VaultPermission,
};

fn open_test_shared_db() -> SharedDB<FakeCrypto> {
    SharedDB::open(":memory:", FakeCrypto).unwrap()
}

fn make_pass(user_id: &str, email: &str, ek: &str) -> VaultPass {
    VaultPass::new(
        UserId::new(user_id.to_string()),
        crate::types::Email::new(email.to_string()),
        EncryptionKey::new(ek.to_string()),
    )
}

/// Helper: create vault + complete full invite flow for a member.
/// Returns the vault id.
fn setup_vault_with_member(
    db: &SharedDB<FakeCrypto>,
    owner: &VaultPass,
    member_id: &UserId,
    member_email: &str,
    permission: VaultPermission,
) -> SharedVaultId {
    let vault = db
        .create_shared_vault(owner, SharedVaultName::new("V".to_string()))
        .unwrap();

    // Full 4-step invite flow
    let (invite_id, _code) = db
        .create_invite(
            owner.user_id(),
            &vault.id,
            member_email,
            Role::Editor,
            permission,
        )
        .unwrap();

    db.accept_invite(&invite_id, member_id, "pub_key_hex", "confirm_key_hex")
        .unwrap();

    db.complete_invite(
        &invite_id,
        owner.user_id(),
        "encrypted_vault_key_hex",
        "nonce_hex",
    )
    .unwrap();

    vault.id
}

// ── Keypair ──

#[test]
fn save_and_check_user_keypair() {
    let db = open_test_shared_db();
    let uid = UserId::new("user-1".to_string());
    let ek = EncryptionKey::new("test_key_abc".to_string());

    assert!(!db.has_user_keypair(&uid).unwrap());
    let pk = db.save_user_keypair(&uid, &ek).unwrap();
    assert!(db.has_user_keypair(&uid).unwrap());

    let fetched = db.get_user_public_key(&uid).unwrap();
    assert_eq!(pk.as_str(), fetched.as_str());
}

#[test]
fn decrypt_user_private_key_roundtrip() {
    let db = open_test_shared_db();
    let uid = UserId::new("user-1".to_string());
    let ek = EncryptionKey::new("test_key_xyz".to_string());

    db.save_user_keypair(&uid, &ek).unwrap();
    let _priv_key = db.decrypt_user_private_key(&uid, &ek).unwrap();
}

// ── Shared vault lifecycle ──

#[test]
fn create_shared_vault_owner_is_member() {
    let db = open_test_shared_db();
    let pass = make_pass("owner-1", "owner@test.com", "ek_owner");
    db.save_user_keypair(pass.user_id(), pass.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&pass, SharedVaultName::new("Family".to_string()))
        .unwrap();

    assert_eq!(vault.owner_id.as_str(), "owner-1");

    let members = db.list_members(pass.user_id(), &vault.id).unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].user_id.as_str(), "owner-1");
    assert_eq!(members[0].permission, VaultPermission::ReadWrite);
}

#[test]
fn list_shared_vaults_returns_owned_and_member() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    let pass_b = make_pass("user-b", "b@test.com", "ek_b");
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();
    db.save_user_keypair(pass_b.user_id(), pass_b.encryption_key())
        .unwrap();

    let vault_id = setup_vault_with_member(
        &db,
        &pass_a,
        pass_b.user_id(),
        "b@test.com",
        VaultPermission::Read,
    );

    let a_vaults = db.list_shared_vaults(pass_a.user_id()).unwrap();
    let b_vaults = db.list_shared_vaults(pass_b.user_id()).unwrap();

    assert_eq!(a_vaults.len(), 1);
    assert_eq!(b_vaults.len(), 1);
    assert_eq!(a_vaults[0].id.as_str(), vault_id.as_str());
    assert_eq!(b_vaults[0].id.as_str(), vault_id.as_str());
}

// ── 4-step Invite flow ──

#[test]
fn full_invite_flow_adds_member() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();

    let uid_b = UserId::new("user-b".to_string());

    let vault_id =
        setup_vault_with_member(&db, &pass_a, &uid_b, "b@test.com", VaultPermission::Read);

    let members = db.list_members(pass_a.user_id(), &vault_id).unwrap();
    assert_eq!(members.len(), 2);
}

#[test]
fn invite_requires_ownership() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    let pass_b = make_pass("user-b", "b@test.com", "ek_b");
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();
    db.save_user_keypair(pass_b.user_id(), pass_b.encryption_key())
        .unwrap();

    let vault_id = setup_vault_with_member(
        &db,
        &pass_a,
        pass_b.user_id(),
        "b@test.com",
        VaultPermission::ReadWrite,
    );

    // B is a member but not owner — cannot create invite
    let result = db.create_invite(
        pass_b.user_id(),
        &vault_id,
        "c@test.com",
        Role::Viewer,
        VaultPermission::Read,
    );
    assert!(matches!(result, Err(SharedError::Forbidden(_))));
}

#[test]
fn invite_limit_5_members() {
    let db = open_test_shared_db();
    let owner_pass = make_pass("owner", "owner@test.com", "ek_owner");
    db.save_user_keypair(owner_pass.user_id(), owner_pass.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&owner_pass, SharedVaultName::new("V".to_string()))
        .unwrap();

    // Owner is member #1, invite 4 more (total 5)
    for i in 1..=4 {
        let uid = format!("user-{i}");
        let email = format!("{uid}@test.com");
        let (invite_id, _) = db
            .create_invite(
                owner_pass.user_id(),
                &vault.id,
                &email,
                Role::Viewer,
                VaultPermission::Read,
            )
            .unwrap();

        let member_uid = UserId::new(uid);
        db.accept_invite(&invite_id, &member_uid, "pk", "ck")
            .unwrap();
        db.complete_invite(&invite_id, owner_pass.user_id(), "evk", "n")
            .unwrap();
    }

    // 6th member should fail
    let result = db.create_invite(
        owner_pass.user_id(),
        &vault.id,
        "user5@test.com",
        Role::Viewer,
        VaultPermission::Read,
    );
    assert!(matches!(result, Err(SharedError::MemberLimit(_))));
}

#[test]
fn accept_invite_sets_status_accepted() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&pass_a, SharedVaultName::new("V".to_string()))
        .unwrap();

    let (invite_id, _code) = db
        .create_invite(
            pass_a.user_id(),
            &vault.id,
            "b@test.com",
            Role::Editor,
            VaultPermission::ReadWrite,
        )
        .unwrap();

    let uid_b = UserId::new("user-b".to_string());
    db.accept_invite(&invite_id, &uid_b, "pub_key", "conf_key")
        .unwrap();

    // Owner can see accepted invites
    let accepted = db
        .get_accepted_invites(&vault.id, pass_a.user_id())
        .unwrap();
    assert_eq!(accepted.len(), 1);
    assert_eq!(accepted[0].user_id.as_str(), "user-b");
    assert_eq!(accepted[0].public_key_hex, "pub_key");
}

#[test]
fn list_user_invites_returns_invites_by_email() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&pass_a, SharedVaultName::new("V".to_string()))
        .unwrap();

    let (_invite_id, _code) = db
        .create_invite(
            pass_a.user_id(),
            &vault.id,
            "b@test.com",
            Role::Viewer,
            VaultPermission::Read,
        )
        .unwrap();

    let uid_b = UserId::new("user-b".to_string());
    let invites = db.list_user_invites(&uid_b, "b@test.com").unwrap();
    assert_eq!(invites.len(), 1);
    assert_eq!(invites[0].vault_id.as_str(), vault.id.as_str());
}

// ── Revoke ──

#[test]
fn revoke_member_removes_from_members() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    let pass_b = make_pass("user-b", "b@test.com", "ek_b");
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();
    db.save_user_keypair(pass_b.user_id(), pass_b.encryption_key())
        .unwrap();

    let vault_id = setup_vault_with_member(
        &db,
        &pass_a,
        pass_b.user_id(),
        "b@test.com",
        VaultPermission::Read,
    );

    assert_eq!(db.member_count(&vault_id).unwrap(), 2);
    db.revoke_member(&pass_a, &vault_id, pass_b.user_id())
        .unwrap();
    assert_eq!(db.member_count(&vault_id).unwrap(), 1);
}

#[test]
fn revoke_owner_forbidden() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&pass_a, SharedVaultName::new("V".to_string()))
        .unwrap();

    let result = db.revoke_member(&pass_a, &vault.id, pass_a.user_id());
    assert!(matches!(result, Err(SharedError::Forbidden(_))));
}

// ── Update permission ──

#[test]
fn update_permission_read_to_readwrite() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    let pass_b = make_pass("user-b", "b@test.com", "ek_b");
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();
    db.save_user_keypair(pass_b.user_id(), pass_b.encryption_key())
        .unwrap();

    let vault_id = setup_vault_with_member(
        &db,
        &pass_a,
        pass_b.user_id(),
        "b@test.com",
        VaultPermission::Read,
    );

    db.update_member_permission(
        &pass_a,
        &vault_id,
        pass_b.user_id(),
        VaultPermission::ReadWrite,
    )
    .unwrap();

    let members = db.list_members(pass_a.user_id(), &vault_id).unwrap();
    let b_member = members
        .iter()
        .find(|m| m.user_id.as_str() == "user-b")
        .unwrap();
    assert_eq!(b_member.permission, VaultPermission::ReadWrite);
}

// ── Shared entries (zero-knowledge) ──

#[test]
fn add_and_list_shared_entries() {
    let db = open_test_shared_db();
    let pass = make_pass("owner", "owner@test.com", "ek_owner");
    db.save_user_keypair(pass.user_id(), pass.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&pass, SharedVaultName::new("V".to_string()))
        .unwrap();

    let entry_id = db
        .add_shared_entry(
            pass.user_id(),
            &vault.id,
            "entry-1",
            "encrypted_blob_hex",
            "nonce_hex",
            "passwords",
        )
        .unwrap();

    let entries = db
        .list_shared_entries(pass.user_id(), &vault.id, None)
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].id.as_str(), entry_id.as_str());
    assert_eq!(entries[0].encrypted_data.as_str(), "encrypted_blob_hex");
    assert_eq!(entries[0].category, "passwords");
    assert!(!entries[0].deleted);
}

#[test]
fn readonly_member_cannot_add_entry() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    let uid_b = UserId::new("user-b".to_string());
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();

    let vault_id =
        setup_vault_with_member(&db, &pass_a, &uid_b, "b@test.com", VaultPermission::Read);

    let result = db.add_shared_entry(&uid_b, &vault_id, "entry-1", "enc", "nonce", "cat");
    assert!(matches!(result, Err(SharedError::Forbidden(_))));
}

#[test]
fn non_member_cannot_list_entries() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    let uid_c = UserId::new("user-c".to_string());
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&pass_a, SharedVaultName::new("V".to_string()))
        .unwrap();

    db.add_shared_entry(
        pass_a.user_id(),
        &vault.id,
        "entry-1",
        "enc",
        "nonce",
        "cat",
    )
    .unwrap();

    let result = db.list_shared_entries(&uid_c, &vault.id, None);
    assert!(matches!(result, Err(SharedError::Forbidden(_))));
}

#[test]
fn soft_delete_shared_entry() {
    let db = open_test_shared_db();
    let pass = make_pass("owner", "owner@test.com", "ek_owner");
    db.save_user_keypair(pass.user_id(), pass.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&pass, SharedVaultName::new("V".to_string()))
        .unwrap();

    let entry_id = db
        .add_shared_entry(pass.user_id(), &vault.id, "entry-1", "enc", "nonce", "cat")
        .unwrap();

    let deleted = db
        .delete_shared_entry(pass.user_id(), &vault.id, &entry_id)
        .unwrap();
    assert!(deleted);

    // Without since, soft-deleted entries are NOT returned
    let entries = db
        .list_shared_entries(pass.user_id(), &vault.id, None)
        .unwrap();
    assert!(entries.is_empty());
}

#[test]
fn delta_sync_returns_tombstones() {
    let db = open_test_shared_db();
    let pass = make_pass("owner", "owner@test.com", "ek_owner");
    db.save_user_keypair(pass.user_id(), pass.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&pass, SharedVaultName::new("V".to_string()))
        .unwrap();

    // Add entry at time T0
    let before_add = chrono::Utc::now() - chrono::Duration::seconds(1);
    let entry_id = db
        .add_shared_entry(pass.user_id(), &vault.id, "entry-1", "enc", "nonce", "cat")
        .unwrap();

    // Delete entry
    db.delete_shared_entry(pass.user_id(), &vault.id, &entry_id)
        .unwrap();

    // Delta sync with `since` before the entry was created should show the tombstone
    let entries = db
        .list_shared_entries(pass.user_id(), &vault.id, Some(before_add))
        .unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].deleted);
}

#[test]
fn push_entries_upsert() {
    let db = open_test_shared_db();
    let pass = make_pass("owner", "owner@test.com", "ek_owner");
    db.save_user_keypair(pass.user_id(), pass.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&pass, SharedVaultName::new("V".to_string()))
        .unwrap();

    let now = chrono::Utc::now().to_rfc3339();
    let entries = vec![(
        "entry-1".to_string(),
        "enc_v1".to_string(),
        "nonce_v1".to_string(),
        "passwords".to_string(),
        now.clone(),
        false,
    )];

    let count = db
        .push_entries(pass.user_id(), &vault.id, &entries)
        .unwrap();
    assert_eq!(count, 1);

    // Push again with updated data — should upsert, not duplicate
    let entries_v2 = vec![(
        "entry-1".to_string(),
        "enc_v2".to_string(),
        "nonce_v2".to_string(),
        "passwords".to_string(),
        now,
        false,
    )];
    let count2 = db
        .push_entries(pass.user_id(), &vault.id, &entries_v2)
        .unwrap();
    assert_eq!(count2, 1);

    let all = db
        .list_shared_entries(pass.user_id(), &vault.id, None)
        .unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].encrypted_data.as_str(), "enc_v2");
}

// ── Update member keys (re-keying) ──

#[test]
fn update_member_keys_owner_only() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    let uid_b = UserId::new("user-b".to_string());
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();

    let vault_id = setup_vault_with_member(
        &db,
        &pass_a,
        &uid_b,
        "b@test.com",
        VaultPermission::ReadWrite,
    );

    let keys = vec![
        (
            "user-a".to_string(),
            "new_evk_a".to_string(),
            "new_nonce_a".to_string(),
        ),
        (
            "user-b".to_string(),
            "new_evk_b".to_string(),
            "new_nonce_b".to_string(),
        ),
    ];

    db.update_member_keys(pass_a.user_id(), &vault_id, &keys)
        .unwrap();
}

// ── Revocation + re-key ──

#[test]
fn revoked_member_cannot_access_vault() {
    let db = open_test_shared_db();
    let pass_a = make_pass("user-a", "a@test.com", "ek_a");
    let uid_b = UserId::new("user-b".to_string());
    db.save_user_keypair(pass_a.user_id(), pass_a.encryption_key())
        .unwrap();

    let vault_id =
        setup_vault_with_member(&db, &pass_a, &uid_b, "b@test.com", VaultPermission::Read);

    db.add_shared_entry(
        pass_a.user_id(),
        &vault_id,
        "entry-1",
        "enc",
        "nonce",
        "cat",
    )
    .unwrap();

    // Revoke B
    db.revoke_member(&pass_a, &vault_id, &uid_b).unwrap();

    // B cannot list entries anymore
    let result = db.list_shared_entries(&uid_b, &vault_id, None);
    assert!(matches!(result, Err(SharedError::Forbidden(_))));
}

// ── Delete vault ──

#[test]
fn delete_shared_vault_removes_all() {
    let db = open_test_shared_db();
    let pass = make_pass("owner", "owner@test.com", "ek_owner");
    db.save_user_keypair(pass.user_id(), pass.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&pass, SharedVaultName::new("V".to_string()))
        .unwrap();

    db.add_shared_entry(pass.user_id(), &vault.id, "entry-1", "enc", "nonce", "cat")
        .unwrap();

    db.delete_shared_vault(&pass, &vault.id).unwrap();

    let vaults = db.list_shared_vaults(pass.user_id()).unwrap();
    assert!(vaults.is_empty());
}

// ── List vaults with counts ──

#[test]
fn list_shared_vaults_with_counts() {
    let db = open_test_shared_db();
    let pass = make_pass("owner", "owner@test.com", "ek_owner");
    db.save_user_keypair(pass.user_id(), pass.encryption_key())
        .unwrap();

    let vault = db
        .create_shared_vault(&pass, SharedVaultName::new("V".to_string()))
        .unwrap();

    db.add_shared_entry(pass.user_id(), &vault.id, "entry-1", "enc", "nonce", "cat")
        .unwrap();

    let vaults = db.list_shared_vaults_with_counts(pass.user_id()).unwrap();
    assert_eq!(vaults.len(), 1);
    assert_eq!(vaults[0].member_count, 1);
    assert_eq!(vaults[0].entry_count, 1);
}
