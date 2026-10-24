// SPDX-License-Identifier: AGPL-3.0-or-later
//! Cryptographic primitives for krypton.
//!
//! Two building blocks only, both chosen to keep the key material off disk:
//! * [`kdf`] derives a 256-bit key from the master password with Argon2id.
//! * [`aead`] seals/opens vault bodies with XChaCha20-Poly1305.
//!
//! The derived key never leaves [`SecretKey`], which zeroizes itself on drop.

pub mod aead;
pub mod kdf;

pub use aead::{Sealed, open, seal};
pub use kdf::{KdfParams, SALT_LEN, derive_key};

use std::fmt;

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of a symmetric key in bytes (256 bits).
pub const KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("key derivation failed: {0}")]
    Kdf(#[from] argon2::Error),
    #[error("unsupported key derivation algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("salt must be {SALT_LEN} bytes")]
    InvalidSalt,
    #[error("system randomness is unavailable: {0}")]
    Random(#[from] getrandom::Error),
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed: wrong password or tampered data")]
    Decrypt,
}

/// A 256-bit symmetric key. Redacted from debug output and zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    /// Wraps raw key bytes, taking ownership so the caller can wipe its copy.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

/// Fills a buffer of `N` bytes from the operating system CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_key_debug_is_redacted() {
        let key = SecretKey::from_bytes([7u8; KEY_LEN]);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "SecretKey(<redacted>)");
        assert!(!rendered.contains("7"));
    }

    #[test]
    fn random_bytes_differ_between_calls() {
        let a = random_bytes::<16>().unwrap();
        let b = random_bytes::<16>().unwrap();
        assert_ne!(a, b);
    }
}
