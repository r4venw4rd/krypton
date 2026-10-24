// SPDX-License-Identifier: AGPL-3.0-or-later
use std::fs;
use std::path::PathBuf;

use krypton_core::device::{DeviceKey, DeviceRecord};
use krypton_core::sync::{self, SyncError};
use krypton_core::{Item, ItemKind, KdfParams, Vault};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("krypton-sync-test-{tag}-{suffix}"));
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

const PASSWORD: &str = "shared master password";

struct Fixture {
    dir: TempDir,
    alice: DeviceKey,
    bob: DeviceKey,
    vault_a: Vault,
    vault_b: Vault,
}

/// Two devices that unlocked the same vault material (same salt + password)
/// and already paired with each other.
fn fixture() -> Fixture {
    let dir = TempDir::new("pair");
    let path_a = dir.file("a.kv");
    let path_b = dir.file("b.kv");

    let mut vault_a = Vault::create_with_params(&path_a, PASSWORD, KdfParams::weak_for_tests())
        .expect("create vault");
    vault_a.items_mut().push(
        Item::new(
            "mail",
            ItemKind::Note {
                body: "hello".into(),
            },
        )
        .unwrap(),
    );
    vault_a.save().unwrap();

    fs::copy(&path_a, &path_b).unwrap();
    let mut vault_b = Vault::open(&path_b, PASSWORD).unwrap();

    let alice = DeviceKey::generate().unwrap();
    let bob = DeviceKey::generate().unwrap();
    let records = [
        DeviceRecord::new("alice-laptop", &alice),
        DeviceRecord::new("bob-phone", &bob),
    ];

    for vault in [&mut vault_a, &mut vault_b] {
        vault.devices_mut().extend(records.iter().cloned());
        vault.save().unwrap();
    }

    Fixture {
        dir,
        alice,
        bob,
        vault_a,
        vault_b,
    }
}

#[test]
fn payload_round_trip_delivers_items_and_devices() {
    let mut fixture = fixture();
    let payload =
        sync::create_payload(&fixture.vault_a, &fixture.alice, &fixture.bob.public_key()).unwrap();

    // A payload is opaque: no titles or bodies in the clear.
    let raw = String::from_utf8_lossy(&payload);
    assert!(!raw.contains("mail"));
    assert!(!raw.contains("hello"));

    let incoming = sync::read_payload(&fixture.vault_b, &fixture.bob, &payload).unwrap();
    assert_eq!(incoming.sender.name, "alice-laptop");
    assert_eq!(incoming.body.items.len(), 1);

    // Bob's own item set is empty; the merge brings A's item over.
    fixture.vault_b.items_mut().clear();
    let stats = sync::merge(fixture.vault_b.body_mut(), incoming.body);
    assert_eq!(stats.items_added, 1);
    assert_eq!(stats.devices_added, 0);
    fixture.vault_b.save().unwrap();

    let reopened = Vault::open(fixture.dir.file("b.kv"), PASSWORD).unwrap();
    assert_eq!(reopened.items()[0].title, "mail");
}

#[test]
fn merging_twice_is_idempotent() {
    let mut fixture = fixture();
    let payload =
        sync::create_payload(&fixture.vault_a, &fixture.alice, &fixture.bob.public_key()).unwrap();

    let first = sync::read_payload(&fixture.vault_b, &fixture.bob, &payload).unwrap();
    let stats = sync::merge(fixture.vault_b.body_mut(), first.body);
    assert_eq!(stats.items_added, 0); // both vaults started with the same item

    let second = sync::read_payload(&fixture.vault_b, &fixture.bob, &payload).unwrap();
    let stats = sync::merge(fixture.vault_b.body_mut(), second.body);
    assert_eq!(stats.changed(), 0);
}

#[test]
fn payload_for_another_device_is_rejected() {
    let fixture = fixture();
    let payload =
        sync::create_payload(&fixture.vault_a, &fixture.alice, &fixture.bob.public_key()).unwrap();

    let mallory = DeviceKey::generate().unwrap();
    let err = sync::read_payload(&fixture.vault_b, &mallory, &payload).unwrap_err();
    assert!(matches!(err, SyncError::WrongRecipient));
}

#[test]
fn untrusted_sender_is_rejected() {
    let fixture = fixture();
    let payload =
        sync::create_payload(&fixture.vault_a, &fixture.alice, &fixture.bob.public_key()).unwrap();

    // A vault that never paired with Alice.
    let dir = TempDir::new("untrusted");
    let path = dir.file("c.kv");
    let mut stranger =
        Vault::create_with_params(&path, PASSWORD, KdfParams::weak_for_tests()).unwrap();
    stranger
        .devices_mut()
        .push(DeviceRecord::new("bob-phone", &fixture.bob));
    stranger.save().unwrap();

    let err = sync::read_payload(&stranger, &fixture.bob, &payload).unwrap_err();
    assert!(matches!(err, SyncError::UntrustedSender(_)));
}

#[test]
fn tampered_payload_is_rejected() {
    let fixture = fixture();
    let payload =
        sync::create_payload(&fixture.vault_a, &fixture.alice, &fixture.bob.public_key()).unwrap();

    let mut wire: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    let ciphertext = wire["ciphertext"].as_str().unwrap().to_string();
    let mut bytes = ciphertext.into_bytes();
    let last = bytes.len() - 2;
    bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
    wire["ciphertext"] = serde_json::Value::from(String::from_utf8(bytes).unwrap());

    let err = sync::read_payload(
        &fixture.vault_b,
        &fixture.bob,
        &serde_json::to_vec(&wire).unwrap(),
    )
    .unwrap_err();
    assert!(matches!(err, SyncError::SignatureInvalid));
}

#[test]
fn sealing_for_yourself_is_refused() {
    let fixture = fixture();
    let err = sync::create_payload(
        &fixture.vault_a,
        &fixture.alice,
        &fixture.alice.public_key(),
    )
    .unwrap_err();
    assert!(matches!(err, SyncError::SelfAddressed));
}
