// SPDX-License-Identifier: AGPL-3.0-or-later
//! Encrypted device-to-device sync payloads.
//!
//! A payload carries the whole vault body, sealed with a key derived from the
//! vault key and both device public keys:
//!
//! `HKDF-SHA256(ikm = vault key, salt = "krypton-sync-v1",
//!              info = sender_pub || 0x00 || recipient_pub)`
//!
//! The sender's Ed25519 signature covers the header and ciphertext, so the
//! recipient knows which trusted device produced the payload. Transport is left
//! to the caller (file, message, later a network channel).
//!
//! Assumptions for this phase: both devices already unlocked a vault with the
//! same key material (same salt and master password), and the sender is in the
//! recipient's trust list. Merging is last-write-wins per item id: deletions are
//! not propagated yet and there is no CRDT.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use krypton_crypto::aead::{self, NONCE_LEN};
use krypton_crypto::{CryptoError, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use crate::device::{DeviceKey, verify};
use crate::vault::VaultBody;
use crate::{Vault, device::DeviceRecord};

/// Marker for a sync payload.
pub const SYNC_TYPE: &str = "krypton-sync";
/// Payload version understood by this build.
pub const VERSION: u32 = 1;
const HKDF_SALT: &[u8] = b"krypton-sync-v1";

/// Failures from sealing, verifying or merging sync payloads.
#[derive(Debug, Error)]
pub enum SyncError {
    /// A base64 field did not decode.
    #[error("sync payload is not valid base64")]
    Encoding,
    /// The payload or vault body is not valid JSON.
    #[error("sync payload is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The payload is not a krypton sync payload.
    #[error("unexpected sync payload type: {0}")]
    UnexpectedType(String),
    /// The payload was produced by a newer format version.
    #[error("unsupported sync payload version {0}")]
    UnsupportedVersion(u32),
    /// The payload is addressed to a different device key.
    #[error("sync payload is addressed to another device")]
    WrongRecipient,
    /// The local device tried to sync with itself.
    #[error("sync payload was sent by this device")]
    SelfAddressed,
    /// The sender's key is not in the vault's trust list.
    #[error("sender {0} is not in the trust list; pair the devices first")]
    UntrustedSender(String),
    /// The signature or the AEAD tag did not verify.
    #[error("sync payload signature is invalid")]
    SignatureInvalid,
    /// A header field has an impossible value.
    #[error("sync payload is malformed: {0}")]
    Malformed(String),
    /// A crypto primitive failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    /// A payload file could not be read.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A verified payload from a trusted device.
#[derive(Debug)]
pub struct Incoming {
    /// Trust-list entry the payload's signature verified under.
    pub sender: DeviceRecord,
    /// Decrypted body sent by that device.
    pub body: VaultBody,
}

/// How many entries a merge changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MergeStats {
    /// Items that did not exist locally before the merge.
    pub items_added: usize,
    /// Existing items replaced by the incoming version.
    pub items_updated: usize,
    /// Device records that were new to the trust list.
    pub devices_added: usize,
}

impl MergeStats {
    /// Total number of entries the merge touched.
    #[must_use]
    pub const fn changed(&self) -> usize {
        self.items_added + self.items_updated + self.devices_added
    }
}

/// Seals the local vault body for `recipient_public_key`, signed by `sender`.
///
/// # Errors
///
/// Returns [`SyncError::SelfAddressed`] when the recipient is the sender,
/// [`SyncError::Crypto`] if encryption fails, or [`SyncError::Json`] if the
/// body cannot be serialised.
pub fn create_payload(
    vault: &Vault,
    sender: &DeviceKey,
    recipient_public_key: &str,
) -> Result<Vec<u8>, SyncError> {
    if sender.public_key() == recipient_public_key {
        return Err(SyncError::SelfAddressed);
    }

    let sender_public_key = sender.public_key();
    let key = derive_key(vault.secret_key(), &sender_public_key, recipient_public_key)?;
    let aad = associated_data(&sender_public_key, recipient_public_key);

    let body = serde_json::to_vec(vault.body())?;
    let sealed = aead::seal(&key, &body, aad.as_bytes())?;
    let ciphertext = BASE64.encode(&sealed.ciphertext);
    let signature = sender.sign(signed_payload(&aad, &ciphertext).as_bytes());

    let wire = SyncWire {
        kind: SYNC_TYPE.to_string(),
        version: VERSION,
        sender: sender_public_key,
        recipient: recipient_public_key.to_string(),
        nonce: BASE64.encode(sealed.nonce),
        ciphertext,
        signature,
    };
    Ok(serde_json::to_vec(&wire)?)
}

/// Verifies and decrypts a payload addressed to `recipient`.
///
/// The sender must appear in the vault's trust list, which is also where the
/// returned [`DeviceRecord`] comes from.
///
/// # Errors
///
/// Returns [`SyncError::WrongRecipient`] when the payload names another device,
/// [`SyncError::UntrustedSender`] when the sender is not in the trust list, and
/// [`SyncError::SignatureInvalid`] for a bad signature, tampered ciphertext or
/// a decryption failure. Structural problems surface as [`SyncError::Json`],
/// [`SyncError::UnexpectedType`] or [`SyncError::UnsupportedVersion`].
pub fn read_payload(
    vault: &Vault,
    recipient: &DeviceKey,
    bytes: &[u8],
) -> Result<Incoming, SyncError> {
    let wire: SyncWire = serde_json::from_slice(bytes)?;
    if wire.kind != SYNC_TYPE {
        return Err(SyncError::UnexpectedType(wire.kind));
    }
    if wire.version != VERSION {
        return Err(SyncError::UnsupportedVersion(wire.version));
    }

    let recipient_public_key = recipient.public_key();
    if wire.sender == recipient_public_key {
        return Err(SyncError::SelfAddressed);
    }
    if wire.recipient != recipient_public_key {
        return Err(SyncError::WrongRecipient);
    }

    let sender_record = vault
        .devices()
        .iter()
        .find(|device| device.public_key == wire.sender)
        .cloned()
        .ok_or_else(|| SyncError::UntrustedSender(crate::device::fingerprint(&wire.sender)))?;

    let aad = associated_data(&wire.sender, &wire.recipient);
    if !verify(
        &wire.sender,
        signed_payload(&aad, &wire.ciphertext).as_bytes(),
        &wire.signature,
    ) {
        return Err(SyncError::SignatureInvalid);
    }

    let nonce = decode_nonce(&wire.nonce)?;
    let ciphertext = BASE64
        .decode(&wire.ciphertext)
        .map_err(|_| SyncError::Encoding)?;

    let key = derive_key(vault.secret_key(), &wire.sender, &wire.recipient)?;
    let plaintext = aead::open(&key, &nonce, &ciphertext, aad.as_bytes())
        .map_err(|_| SyncError::SignatureInvalid)?;
    let body: VaultBody = serde_json::from_slice(&plaintext)?;

    Ok(Incoming {
        sender: sender_record,
        body,
    })
}

/// Merges `incoming` into `into`: items by id (incoming wins), devices by key.
pub fn merge(into: &mut VaultBody, incoming: VaultBody) -> MergeStats {
    let mut stats = MergeStats::default();

    for item in incoming.items {
        if let Some(existing) = into
            .items
            .iter_mut()
            .find(|existing| existing.id == item.id)
        {
            if *existing != item {
                *existing = item;
                stats.items_updated += 1;
            }
        } else {
            into.items.push(item);
            stats.items_added += 1;
        }
    }

    for device in incoming.devices {
        if !into
            .devices
            .iter()
            .any(|existing| existing.public_key == device.public_key)
        {
            into.devices.push(device);
            stats.devices_added += 1;
        }
    }

    stats
}

fn derive_key(
    vault_key: &SecretKey,
    sender: &str,
    recipient: &str,
) -> Result<SecretKey, SyncError> {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), vault_key.as_bytes());

    let mut info = Vec::with_capacity(sender.len() + recipient.len() + 1);
    info.extend_from_slice(sender.as_bytes());
    info.push(0);
    info.extend_from_slice(recipient.as_bytes());

    let mut okm = [0u8; krypton_crypto::KEY_LEN];
    hkdf.expand(&info, &mut okm)
        .map_err(|_| SyncError::Malformed("HKDF rejected the sync key length".to_string()))?;
    Ok(SecretKey::from_bytes(okm))
}

fn associated_data(sender: &str, recipient: &str) -> String {
    format!("{SYNC_TYPE}\n{VERSION}\n{sender}\n{recipient}")
}

fn signed_payload(aad: &str, ciphertext: &str) -> String {
    format!("{aad}\n{ciphertext}")
}

fn decode_nonce(encoded: &str) -> Result<[u8; NONCE_LEN], SyncError> {
    let bytes = BASE64.decode(encoded).map_err(|_| SyncError::Encoding)?;
    bytes
        .try_into()
        .map_err(|_| SyncError::Malformed(format!("nonce must be {NONCE_LEN} bytes")))
}

#[derive(Serialize, Deserialize)]
struct SyncWire {
    #[serde(rename = "type")]
    kind: String,
    version: u32,
    sender: String,
    recipient: String,
    nonce: String,
    ciphertext: String,
    signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ItemKind;

    #[test]
    fn merge_adds_new_items_and_updates_existing_ones() {
        let mut local = VaultBody::default();
        local
            .items
            .push(crate::Item::new("mail", ItemKind::Note { body: "old".into() }).unwrap());

        let mut incoming = VaultBody::default();
        incoming.items.push(crate::Item {
            id: local.items[0].id.clone(),
            title: "mail".into(),
            kind: ItemKind::Note { body: "new".into() },
        });
        incoming
            .items
            .push(crate::Item::new("bank", ItemKind::Note { body: "x".into() }).unwrap());

        let stats = merge(&mut local, incoming);
        assert_eq!(stats.items_updated, 1);
        assert_eq!(stats.items_added, 1);
        assert_eq!(local.items.len(), 2);
        assert!(matches!(&local.items[0].kind, ItemKind::Note { body } if body == "new"));
    }

    #[test]
    fn merge_is_idempotent_for_devices() {
        let mut local = VaultBody::default();
        local.devices.push(DeviceRecord {
            name: "laptop".into(),
            public_key: "pk".into(),
            created_at: 1,
        });

        let mut incoming = VaultBody::default();
        incoming.devices.push(local.devices[0].clone());

        let stats = merge(&mut local, incoming);
        assert_eq!(stats.devices_added, 0);
        assert_eq!(local.devices.len(), 1);
    }

    #[test]
    fn derived_keys_are_direction_specific() {
        let vault_key = SecretKey::from_bytes([7u8; krypton_crypto::KEY_LEN]);
        let forward = derive_key(&vault_key, "alice", "bob").unwrap();
        let backward = derive_key(&vault_key, "bob", "alice").unwrap();
        assert_ne!(forward.as_bytes(), backward.as_bytes());
    }

    #[test]
    fn merge_preserves_unrelated_items() {
        let mut local = VaultBody::default();
        local
            .items
            .push(crate::Item::new("keep", ItemKind::Note { body: "me".into() }).unwrap());

        let incoming = VaultBody::default();
        merge(&mut local, incoming);
        assert_eq!(local.items.len(), 1);
    }
}
