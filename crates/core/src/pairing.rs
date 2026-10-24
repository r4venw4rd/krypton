// SPDX-License-Identifier: AGPL-3.0-or-later
//! Two-message device pairing.
//!
//! Pairing exchanges two signed blobs that can travel over any channel (chat,
//! QR, copy/paste):
//!
//! 1. The initiating device prints an **invite**, signed with its device key.
//! 2. The joining device verifies the signature, then prints an **acceptance**
//!    that echoes the invite nonce and is signed with its own key.
//! 3. The initiator verifies the acceptance, which binds both public keys to
//!    the same nonce.
//!
//! Both sides end up with the other's public key, and each learns the other's
//! fingerprint to compare out of band. Replay of an old invite cannot *pair* a
//! device by itself (the attacker still has to obtain a valid acceptance), but
//! invites expire so stale blobs are rejected.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use krypton_crypto::{CryptoError, random_bytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::device::{DeviceKey, DeviceRecord, verify};

/// Marker for an invite blob.
pub const INVITE_TYPE: &str = "krypton-pairing-invite";
/// Marker for an acceptance blob.
pub const ACCEPTANCE_TYPE: &str = "krypton-pairing-acceptance";
/// Version understood by this build.
pub const VERSION: u32 = 1;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 16;
/// Invites older than this are rejected (a day leaves room for manual
/// out-of-band exchange).
pub const INVITE_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Failures from creating, parsing or answering pairing blobs.
#[derive(Debug, Error)]
pub enum PairingError {
    /// The blob is not valid base64.
    #[error("pairing blob is not valid base64")]
    Encoding,
    /// The decoded blob is not valid JSON for its wire type.
    #[error("pairing blob is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The blob is an invite where an acceptance was expected, or similar.
    #[error("unexpected pairing blob type: {0}")]
    UnexpectedType(String),
    /// The blob was produced by a newer pairing format.
    #[error("unsupported pairing version {0}")]
    UnsupportedVersion(u32),
    /// The Ed25519 signature did not verify against the embedded key.
    #[error("pairing signature is invalid")]
    SignatureInvalid,
    /// The invite is older than [`INVITE_MAX_AGE_SECS`].
    #[error("pairing invite has expired; create a new one")]
    Expired,
    /// The acceptance answers a different invite nonce.
    #[error("acceptance does not answer this invite")]
    NonceMismatch,
    /// No nonce could be generated.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// A verified invite from another device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    /// Device name chosen by the inviting machine.
    pub name: String,
    /// Base64 Ed25519 public key of the inviting device.
    pub public_key: String,
    /// Unix timestamp (seconds) the invite was signed at.
    pub created_at: u64,
    /// Base64 nonce that the acceptance must echo.
    pub nonce: String,
}

impl Invite {
    /// Public identity to store in the trust list.
    #[must_use]
    pub fn record(&self) -> DeviceRecord {
        DeviceRecord {
            name: self.name.clone(),
            public_key: self.public_key.clone(),
            created_at: self.created_at,
        }
    }
}

/// A verified acceptance from the joining device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acceptance {
    /// Device name chosen by the joining machine.
    pub name: String,
    /// Base64 Ed25519 public key of the joining device.
    pub public_key: String,
    /// Unix timestamp (seconds) the acceptance was signed at.
    pub created_at: u64,
}

impl Acceptance {
    /// Public identity to store in the trust list.
    #[must_use]
    pub fn record(&self) -> DeviceRecord {
        DeviceRecord {
            name: self.name.clone(),
            public_key: self.public_key.clone(),
            created_at: self.created_at,
        }
    }
}

/// Creates an invite signed by `key`.
///
/// # Errors
///
/// Returns [`PairingError::Crypto`] if no nonce can be generated, or
/// [`PairingError::Json`] if the wire form cannot be serialised.
pub fn create_invite(name: &str, key: &DeviceKey) -> Result<String, PairingError> {
    create_invite_at(name, key, now())
}

/// Creates an invite with an explicit timestamp (tests, deterministic flows).
///
/// # Errors
///
/// Same as [`create_invite`].
pub fn create_invite_at(
    name: &str,
    key: &DeviceKey,
    created_at: u64,
) -> Result<String, PairingError> {
    let nonce = BASE64.encode(random_bytes::<NONCE_LEN>()?);
    let public_key = key.public_key();
    let signature = key.sign(invite_payload(name, &public_key, created_at, &nonce).as_bytes());

    encode(&InviteWire {
        kind: INVITE_TYPE.to_string(),
        version: VERSION,
        name: name.to_string(),
        public_key,
        created_at,
        nonce,
        signature,
    })
}

/// Verifies an invite blob and returns the peer's identity.
///
/// # Errors
///
/// Returns [`PairingError::Encoding`] or [`PairingError::Json`] for malformed
/// input, [`PairingError::UnexpectedType`] / [`PairingError::UnsupportedVersion`]
/// for foreign blobs, [`PairingError::Expired`] for stale invites, and
/// [`PairingError::SignatureInvalid`] when the signature does not verify.
pub fn parse_invite(blob: &str) -> Result<Invite, PairingError> {
    parse_invite_at(blob, now())
}

/// Verifies an invite blob against an explicit "now" (tests).
///
/// # Errors
///
/// Same as [`parse_invite`], evaluated against `now`.
pub fn parse_invite_at(blob: &str, now: u64) -> Result<Invite, PairingError> {
    let wire: InviteWire = decode(blob)?;
    if wire.kind != INVITE_TYPE {
        return Err(PairingError::UnexpectedType(wire.kind));
    }
    if wire.version != VERSION {
        return Err(PairingError::UnsupportedVersion(wire.version));
    }
    if now.saturating_sub(wire.created_at) > INVITE_MAX_AGE_SECS {
        return Err(PairingError::Expired);
    }

    let payload = invite_payload(&wire.name, &wire.public_key, wire.created_at, &wire.nonce);
    if !verify(&wire.public_key, payload.as_bytes(), &wire.signature) {
        return Err(PairingError::SignatureInvalid);
    }

    Ok(Invite {
        name: wire.name,
        public_key: wire.public_key,
        created_at: wire.created_at,
        nonce: wire.nonce,
    })
}

/// Answers a verified invite, signed by the joining device's key.
///
/// # Errors
///
/// Returns [`PairingError::Crypto`] if no nonce can be generated, or
/// [`PairingError::Json`] if the wire form cannot be serialised.
pub fn create_acceptance(
    invite: &Invite,
    name: &str,
    key: &DeviceKey,
) -> Result<String, PairingError> {
    create_acceptance_at(invite, name, key, now())
}

/// Answers an invite with an explicit timestamp (tests).
///
/// # Errors
///
/// Same as [`create_acceptance`].
pub fn create_acceptance_at(
    invite: &Invite,
    name: &str,
    key: &DeviceKey,
    created_at: u64,
) -> Result<String, PairingError> {
    let nonce = BASE64.encode(random_bytes::<NONCE_LEN>()?);
    let public_key = key.public_key();
    let signature = key
        .sign(acceptance_payload(name, &public_key, created_at, &nonce, &invite.nonce).as_bytes());

    encode(&AcceptanceWire {
        kind: ACCEPTANCE_TYPE.to_string(),
        version: VERSION,
        name: name.to_string(),
        public_key,
        created_at,
        invite_nonce: invite.nonce.clone(),
        nonce,
        signature,
    })
}

/// Verifies that `blob` answers `invite` and returns the joining identity.
///
/// # Errors
///
/// Returns [`PairingError::NonceMismatch`] when the acceptance answers a
/// different invite, plus the encoding, type, version and signature errors
/// documented on [`parse_invite`].
pub fn parse_acceptance(blob: &str, invite: &Invite) -> Result<Acceptance, PairingError> {
    let wire: AcceptanceWire = decode(blob)?;
    if wire.kind != ACCEPTANCE_TYPE {
        return Err(PairingError::UnexpectedType(wire.kind));
    }
    if wire.version != VERSION {
        return Err(PairingError::UnsupportedVersion(wire.version));
    }
    if wire.invite_nonce != invite.nonce {
        return Err(PairingError::NonceMismatch);
    }

    let payload = acceptance_payload(
        &wire.name,
        &wire.public_key,
        wire.created_at,
        &wire.nonce,
        &wire.invite_nonce,
    );
    if !verify(&wire.public_key, payload.as_bytes(), &wire.signature) {
        return Err(PairingError::SignatureInvalid);
    }

    Ok(Acceptance {
        name: wire.name,
        public_key: wire.public_key,
        created_at: wire.created_at,
    })
}

#[derive(Serialize, Deserialize)]
struct InviteWire {
    #[serde(rename = "type")]
    kind: String,
    version: u32,
    name: String,
    public_key: String,
    created_at: u64,
    nonce: String,
    signature: String,
}

#[derive(Serialize, Deserialize)]
struct AcceptanceWire {
    #[serde(rename = "type")]
    kind: String,
    version: u32,
    name: String,
    public_key: String,
    created_at: u64,
    /// Defaulted so a blob of the wrong type reports its type instead of a
    /// confusing missing-field error.
    #[serde(default)]
    invite_nonce: String,
    nonce: String,
    signature: String,
}

fn invite_payload(name: &str, public_key: &str, created_at: u64, nonce: &str) -> String {
    format!("krypton-pairing-invite-v1\n{name}\n{public_key}\n{created_at}\n{nonce}")
}

fn acceptance_payload(
    name: &str,
    public_key: &str,
    created_at: u64,
    nonce: &str,
    invite_nonce: &str,
) -> String {
    format!(
        "krypton-pairing-accept-v1\n{name}\n{public_key}\n{created_at}\n{nonce}\n{invite_nonce}"
    )
}

fn encode<T: Serialize>(value: &T) -> Result<String, PairingError> {
    Ok(BASE64.encode(serde_json::to_vec(value)?))
}

fn decode<T: for<'de> Deserialize<'de>>(blob: &str) -> Result<T, PairingError> {
    let raw = BASE64
        .decode(blob.trim())
        .map_err(|_| PairingError::Encoding)?;
    Ok(serde_json::from_slice(&raw)?)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn keys() -> (DeviceKey, DeviceKey) {
        (
            DeviceKey::generate().unwrap(),
            DeviceKey::generate().unwrap(),
        )
    }

    #[test]
    fn two_message_pairing_binds_both_keys() {
        let (alice, bob) = keys();

        let invite_blob = create_invite_at("alice-laptop", &alice, NOW).unwrap();
        let invite = parse_invite_at(&invite_blob, NOW).unwrap();
        assert_eq!(invite.name, "alice-laptop");
        assert_eq!(invite.public_key, alice.public_key());

        let acceptance_blob = create_acceptance_at(&invite, "bob-phone", &bob, NOW).unwrap();
        let acceptance = parse_acceptance(&acceptance_blob, &invite).unwrap();

        assert_eq!(acceptance.name, "bob-phone");
        assert_eq!(acceptance.public_key, bob.public_key());
        assert_eq!(acceptance.record().public_key, bob.public_key());
        assert_eq!(invite.record().fingerprint(), alice.fingerprint());
    }

    #[test]
    fn tampered_invite_is_rejected() {
        let (alice, _) = keys();
        let blob = create_invite_at("alice-laptop", &alice, NOW).unwrap();

        let mut wire: serde_json::Value =
            serde_json::from_slice(&BASE64.decode(&blob).unwrap()).unwrap();
        wire["name"] = serde_json::Value::from("mallory-laptop");
        let tampered = BASE64.encode(serde_json::to_vec(&wire).unwrap());

        let err = parse_invite_at(&tampered, NOW).unwrap_err();
        assert!(matches!(err, PairingError::SignatureInvalid));
    }

    #[test]
    fn acceptance_must_answer_the_invite_nonce() {
        let (alice, bob) = keys();
        let invite_a = parse_invite_at(&create_invite_at("a", &alice, NOW).unwrap(), NOW).unwrap();
        let invite_b =
            parse_invite_at(&create_invite_at("b", &alice, NOW + 1).unwrap(), NOW + 1).unwrap();

        let acceptance = create_acceptance_at(&invite_a, "bob", &bob, NOW).unwrap();
        let err = parse_acceptance(&acceptance, &invite_b).unwrap_err();
        assert!(matches!(err, PairingError::NonceMismatch));
    }

    #[test]
    fn acceptance_signed_by_another_key_is_rejected() {
        let (alice, bob) = keys();
        let mallory = DeviceKey::generate().unwrap();
        let invite =
            parse_invite_at(&create_invite_at("alice", &alice, NOW).unwrap(), NOW).unwrap();

        let acceptance = create_acceptance_at(&invite, "bob", &bob, NOW).unwrap();
        let mut wire: serde_json::Value =
            serde_json::from_slice(&BASE64.decode(&acceptance).unwrap()).unwrap();
        // Swap in Mallory's key but keep Bob's signature.
        wire["public_key"] = serde_json::Value::from(mallory.public_key());
        let tampered = BASE64.encode(serde_json::to_vec(&wire).unwrap());

        let err = parse_acceptance(&tampered, &invite).unwrap_err();
        assert!(matches!(err, PairingError::SignatureInvalid));
    }

    #[test]
    fn stale_invites_expire() {
        let (alice, _) = keys();
        let blob = create_invite_at("alice", &alice, NOW).unwrap();

        let err = parse_invite_at(&blob, NOW + INVITE_MAX_AGE_SECS + 1).unwrap_err();
        assert!(matches!(err, PairingError::Expired));
        assert!(parse_invite_at(&blob, NOW + INVITE_MAX_AGE_SECS).is_ok());
    }

    #[test]
    fn wrong_blob_type_is_rejected() {
        let (alice, bob) = keys();
        let invite_blob = create_invite_at("alice", &alice, NOW).unwrap();
        let invite = parse_invite_at(&invite_blob, NOW).unwrap();
        let acceptance = create_acceptance_at(&invite, "bob", &bob, NOW).unwrap();

        let err = parse_invite_at(&acceptance, NOW).unwrap_err();
        assert!(matches!(err, PairingError::UnexpectedType(_)));
        let err = parse_acceptance(&invite_blob, &invite).unwrap_err();
        assert!(matches!(err, PairingError::UnexpectedType(_)));
    }

    #[test]
    fn garbage_input_is_reported() {
        assert!(matches!(
            parse_invite("not base64!!"),
            Err(PairingError::Encoding)
        ));
        let not_json = BASE64.encode(b"hello");
        assert!(matches!(
            parse_invite(&not_json),
            Err(PairingError::Json(_))
        ));
    }
}
