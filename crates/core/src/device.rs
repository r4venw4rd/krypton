// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-device Ed25519 identities.
//!
//! Each device generates its own signing key and keeps the seed in a local
//! `0600` file next to the vault. Only the public half is stored in the vault,
//! so copying the vault file to another machine does not hand it a trusted
//! identity. TPM / secure-enclave binding is not implemented yet.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use krypton_crypto::{CryptoError, random_bytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::vault::write_private;

/// Seed length of an Ed25519 signing key.
pub const SEED_LEN: usize = 32;
/// Ed25519 public key length.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum DeviceError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error("device key file is malformed: {0}")]
    Malformed(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Public identity of a device, as stored in the vault body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub name: String,
    /// Base64 Ed25519 public key.
    pub public_key: String,
    pub created_at: u64,
}

impl DeviceRecord {
    pub fn new(name: impl Into<String>, key: &DeviceKey) -> Self {
        Self {
            name: name.into(),
            public_key: key.public_key(),
            created_at: now(),
        }
    }

    /// Short human-comparable fingerprint, e.g. `1a2b-3c4d-5e6f-7a8b`.
    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_key)
    }
}

/// A device's private signing key. The seed is zeroized on drop.
pub struct DeviceKey(SigningKey);

impl DeviceKey {
    /// Generates a new key from the OS CSPRNG.
    pub fn generate() -> Result<Self, DeviceError> {
        let seed = random_bytes::<SEED_LEN>()?;
        Ok(Self(SigningKey::from_bytes(&seed)))
    }

    pub fn from_seed(seed: &[u8]) -> Result<Self, DeviceError> {
        let bytes: [u8; SEED_LEN] = seed
            .try_into()
            .map_err(|_| DeviceError::Malformed(format!("seed must be {SEED_LEN} bytes")))?;
        Ok(Self(SigningKey::from_bytes(&bytes)))
    }

    /// The raw seed, for persistence only.
    pub fn seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// Base64 public key, matching [`DeviceRecord::public_key`].
    pub fn public_key(&self) -> String {
        BASE64.encode(self.0.verifying_key().to_bytes())
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.public_key())
    }

    /// Signs `message` and returns the base64 signature.
    pub fn sign(&self, message: &[u8]) -> String {
        BASE64.encode(self.0.sign(message).to_bytes())
    }

    /// Reads a key from a base64 seed file.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, DeviceError> {
        let raw = fs::read_to_string(path)?;
        let seed = decode_fixed::<SEED_LEN>(&raw)
            .ok_or_else(|| DeviceError::Malformed("seed is not valid base64".to_string()))?;
        Self::from_seed(&seed)
    }

    /// Writes the seed with owner-only permissions, replacing `path` atomically.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), DeviceError> {
        let seed = self.seed();
        let encoded = format!("{}\n", BASE64.encode(seed.as_slice()));
        write_private(path.as_ref(), encoded.as_bytes())?;
        Ok(())
    }
}

/// Verifies a base64 signature over `message` by `public_key`.
pub fn verify(public_key: &str, message: &[u8], signature: &str) -> bool {
    let Some(key_bytes) = decode_fixed::<PUBLIC_KEY_LEN>(public_key) else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_bytes(&key_bytes) else {
        return false;
    };
    let Some(signature_bytes) = decode_fixed::<SIGNATURE_LEN>(signature) else {
        return false;
    };
    verifying
        .verify(message, &Signature::from_bytes(&signature_bytes))
        .is_ok()
}

/// Short fingerprint of a base64 public key: first 8 bytes as `xxxx-xxxx-xxxx-xxxx`.
pub fn fingerprint(public_key: &str) -> String {
    let Some(bytes) = decode_fixed::<PUBLIC_KEY_LEN>(public_key) else {
        return "invalid".to_string();
    };
    let hex: Vec<String> = bytes[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    hex.chunks(2)
        .map(|pair| pair.concat())
        .collect::<Vec<_>>()
        .join("-")
}

/// Local device-key path for a vault: `vault.kv` -> `vault.device.key`.
pub fn device_key_path(vault_path: impl AsRef<Path>) -> PathBuf {
    vault_path.as_ref().with_extension("device.key")
}

fn decode_fixed<const N: usize>(encoded: &str) -> Option<[u8; N]> {
    BASE64.decode(encoded.trim()).ok()?.try_into().ok()
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

    #[test]
    fn signature_round_trip() {
        let key = DeviceKey::generate().unwrap();
        let signature = key.sign(b"pair me");
        assert!(verify(&key.public_key(), b"pair me", &signature));
    }

    #[test]
    fn tampered_message_fails_verification() {
        let key = DeviceKey::generate().unwrap();
        let signature = key.sign(b"pair me");
        assert!(!verify(&key.public_key(), b"pair me!", &signature));
    }

    #[test]
    fn another_key_cannot_forge() {
        let key = DeviceKey::generate().unwrap();
        let other = DeviceKey::generate().unwrap();
        let signature = key.sign(b"trust this");
        assert!(!verify(&other.public_key(), b"trust this", &signature));
    }

    #[test]
    fn malformed_keys_and_signatures_are_rejected() {
        let key = DeviceKey::generate().unwrap();
        let signature = key.sign(b"msg");
        assert!(!verify("not-base64", b"msg", &signature));
        assert!(!verify(&key.public_key(), b"msg", "not-base64"));
        assert!(!verify(&key.public_key(), b"msg", &signature[..8]));
    }

    #[test]
    fn fingerprint_is_stable_and_grouped() {
        let key = DeviceKey::generate().unwrap();
        let print = key.fingerprint();
        assert_eq!(print.len(), 19);
        assert_eq!(print.matches('-').count(), 3);
        assert_eq!(print, fingerprint(&key.public_key()));
        assert_eq!(fingerprint("nope"), "invalid");
    }

    #[test]
    fn seed_round_trips_through_a_file() {
        let dir = std::env::temp_dir().join(format!(
            "krypton-device-{}",
            std::process::id() as u128 * 1_000 + now() as u128
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.device.key");

        let key = DeviceKey::generate().unwrap();
        key.save(&path).unwrap();

        let loaded = DeviceKey::load(&path).unwrap();
        assert_eq!(loaded.public_key(), key.public_key());
        assert!(verify(
            &loaded.public_key(),
            b"hello",
            &loaded.sign(b"hello")
        ));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_key_path_sits_beside_the_vault() {
        assert_eq!(
            device_key_path("/home/me/.krypton/vault.kv"),
            PathBuf::from("/home/me/.krypton/vault.device.key")
        );
    }

    #[test]
    fn records_are_built_from_a_key() {
        let key = DeviceKey::generate().unwrap();
        let record = DeviceRecord::new("laptop", &key);
        assert_eq!(record.name, "laptop");
        assert_eq!(record.public_key, key.public_key());
        assert_eq!(record.fingerprint(), key.fingerprint());
        assert!(record.created_at > 0);
    }
}
