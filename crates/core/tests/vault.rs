// SPDX-License-Identifier: AGPL-3.0-or-later
use std::fs;
use std::path::PathBuf;

use krypton_core::{Item, ItemKind, KdfParams, Vault, VaultError};
use serde_json::Value;

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("krypton-test-{tag}-{suffix}"));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn password() -> &'static str {
    "correct horse battery staple"
}

fn credential(title: &str, username: &str, secret: &str) -> Item {
    Item::new(
        title,
        ItemKind::Credential {
            username: username.into(),
            password: secret.into(),
            url: Some("https://example.com".into()),
            notes: None,
        },
    )
    .unwrap()
}

fn create(path: &PathBuf) -> Vault {
    Vault::create_with_params(path, password(), KdfParams::weak_for_tests()).unwrap()
}

#[test]
fn create_then_open_round_trips_items() {
    let dir = TempDir::new("roundtrip");
    let path = dir.file("vault.kv");

    let mut vault = create(&path);
    vault
        .items_mut()
        .push(credential("github", "r4venw4rd", "hunter2"));
    vault.items_mut().push(
        Item::new(
            "recovery",
            ItemKind::Note {
                body: "offline".into(),
            },
        )
        .unwrap(),
    );
    vault.save().unwrap();

    let reopened = Vault::open(&path, password()).unwrap();
    assert_eq!(reopened.items().len(), 2);
    let github = &reopened.items()[0];
    assert_eq!(github.title, "github");
    match &github.kind {
        ItemKind::Credential {
            username, password, ..
        } => {
            assert_eq!(username, "r4venw4rd");
            assert_eq!(password, "hunter2");
        }
        other => panic!("unexpected kind: {other:?}"),
    }
}

#[test]
fn wrong_password_is_rejected() {
    let dir = TempDir::new("wrong-password");
    let path = dir.file("vault.kv");
    create(&path).save().unwrap();

    let err = Vault::open(&path, "wrong password").unwrap_err();
    assert!(matches!(err, VaultError::Decrypt));
}

#[test]
fn tampered_kdf_params_are_rejected() {
    let dir = TempDir::new("tampered-header");
    let path = dir.file("vault.kv");
    create(&path).save().unwrap();

    // Weak test parameters are 1 iteration; raising the cost must not
    // "upgrade" the header silently - the AEAD tag covers the header bytes.
    let raw = fs::read_to_string(&path).unwrap();
    let mut json: Value = serde_json::from_str(&raw).unwrap();
    json["kdf"]["iterations"] = Value::from(2);
    fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

    let err = Vault::open(&path, password()).unwrap_err();
    assert!(matches!(err, VaultError::Decrypt));
}

#[test]
fn nonce_rotates_on_each_save() {
    let dir = TempDir::new("nonce");
    let path = dir.file("vault.kv");
    let vault = create(&path);

    let first: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    vault.save().unwrap();
    let second: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

    assert_ne!(first["nonce"], second["nonce"]);
    assert_ne!(first["ciphertext"], second["ciphertext"]);
    assert_eq!(first["salt"], second["salt"]);
}

#[test]
fn plaintext_body_never_appears_on_disk() {
    let dir = TempDir::new("opaque");
    let path = dir.file("vault.kv");
    let mut vault = create(&path);
    vault
        .items_mut()
        .push(credential("aws", "root", "super-secret-value"));
    vault.save().unwrap();

    let raw = fs::read_to_string(&path).unwrap();
    assert!(!raw.contains("aws"));
    assert!(!raw.contains("super-secret-value"));
    assert!(!raw.contains("r4venw4rd"));
}

#[test]
fn export_then_import_preserves_items() {
    let dir = TempDir::new("export-import");
    let vault_path = dir.file("vault.kv");
    let plain_path = dir.file("backup.json");
    let imported_path = dir.file("vault-copy.kv");

    let mut vault = create(&vault_path);
    vault
        .items_mut()
        .push(credential("gitlab", "r4venw4rd", "s3cret"));
    vault.save().unwrap();
    vault.export_plaintext(&plain_path).unwrap();

    let imported =
        Vault::import_plaintext(&plain_path, &imported_path, "another master password").unwrap();
    assert_eq!(imported.items().len(), 1);
    assert_eq!(imported.items()[0].title, "gitlab");

    let reopened = Vault::open(&imported_path, "another master password").unwrap();
    assert_eq!(reopened.items()[0].title, "gitlab");
}

#[test]
fn changing_password_rotates_salt_and_rejects_the_old_one() {
    let dir = TempDir::new("change-password");
    let path = dir.file("vault.kv");

    let mut vault = create(&path);
    vault
        .items_mut()
        .push(credential("mail", "r4venw4rd", "pw"));
    vault.save().unwrap();

    let before: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    vault
        .change_password("a brand new master password")
        .unwrap();
    let after: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();

    assert_ne!(before["salt"], after["salt"]);
    assert_ne!(before["nonce"], after["nonce"]);

    let err = Vault::open(&path, password()).unwrap_err();
    assert!(matches!(err, VaultError::Decrypt));

    let reopened = Vault::open(&path, "a brand new master password").unwrap();
    assert_eq!(reopened.items().len(), 1);
    assert_eq!(reopened.items()[0].title, "mail");
}

#[test]
fn changing_password_to_empty_keeps_the_vault_readable() {
    let dir = TempDir::new("change-password-empty");
    let path = dir.file("vault.kv");
    let mut vault = create(&path);

    let err = vault.change_password("").unwrap_err();
    assert!(matches!(err, VaultError::EmptyPassword));
    assert!(Vault::open(&path, password()).is_ok());
}

#[test]
fn creating_over_existing_vault_is_refused() {
    let dir = TempDir::new("exists");
    let path = dir.file("vault.kv");
    create(&path);

    let err = Vault::create(&path, password()).unwrap_err();
    assert!(matches!(err, VaultError::AlreadyExists(_)));
}

#[test]
fn opening_missing_vault_reports_not_found() {
    let dir = TempDir::new("missing");
    let err = Vault::open(dir.file("nope.kv"), password()).unwrap_err();
    assert!(matches!(err, VaultError::NotFound(_)));
}

#[test]
fn empty_password_is_refused() {
    let dir = TempDir::new("empty-password");
    let err = Vault::create(dir.file("vault.kv"), "").unwrap_err();
    assert!(matches!(err, VaultError::EmptyPassword));
}

#[test]
fn unsupported_version_is_rejected() {
    let dir = TempDir::new("version");
    let path = dir.file("vault.kv");
    create(&path).save().unwrap();

    let raw = fs::read_to_string(&path).unwrap();
    let mut json: Value = serde_json::from_str(&raw).unwrap();
    json["version"] = Value::from(99);
    fs::write(&path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();

    let err = Vault::open(&path, password()).unwrap_err();
    assert!(matches!(err, VaultError::UnsupportedVersion(99)));
}
