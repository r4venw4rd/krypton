// SPDX-License-Identifier: AGPL-3.0-or-later
//! Authenticated encryption of vault payloads.
//!
//! The 24-byte `XChaCha20` nonce is random per seal, so re-sealing the same body
//! (every save) never repeats a nonce. Callers pass associated data to bind the
//! header (format, version, KDF parameters, salt) to the ciphertext, which makes
//! downgrade or parameter-swap edits fail to decrypt.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::{CryptoError, SecretKey, random_bytes};

/// `XChaCha20` nonce length in bytes.
pub const NONCE_LEN: usize = 24;

/// A sealed payload: random nonce plus ciphertext (which includes the tag).
#[derive(Debug, Clone)]
pub struct Sealed {
    /// Random nonce that must travel with the ciphertext.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext including the Poly1305 tag.
    pub ciphertext: Vec<u8>,
}

/// Encrypts `plaintext` under `key`, authenticating `aad` alongside it.
///
/// # Errors
///
/// Returns [`CryptoError::Random`] if no nonce can be generated, or
/// [`CryptoError::Encrypt`] if the cipher rejects the input.
pub fn seal(key: &SecretKey, plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CryptoError> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Encrypt)?;

    Ok(Sealed { nonce, ciphertext })
}

/// Decrypts a sealed payload, verifying the tag covers `aad`.
///
/// # Errors
///
/// Returns [`CryptoError::Decrypt`] for a wrong key, a modified ciphertext or
/// mismatched associated data; the three cases are intentionally
/// indistinguishable.
pub fn open(
    key: &SecretKey,
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KEY_LEN, kdf::KdfParams};

    fn key() -> SecretKey {
        crate::derive_key(b"pw", &[9u8; crate::SALT_LEN], &KdfParams::weak_for_tests()).unwrap()
    }

    #[test]
    fn round_trip() {
        let sealed = seal(&key(), b"secret body", b"header").unwrap();
        let opened = open(&key(), &sealed.nonce, &sealed.ciphertext, b"header").unwrap();
        assert_eq!(&opened[..], b"secret body");
    }

    #[test]
    fn nonce_changes_on_every_seal() {
        let a = seal(&key(), b"same body", b"").unwrap();
        let b = seal(&key(), b"same body", b"").unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let mut sealed = seal(&key(), b"secret body", b"").unwrap();
        let last = sealed.ciphertext.len() - 1;
        sealed.ciphertext[last] ^= 0x01;
        let err = open(&key(), &sealed.nonce, &sealed.ciphertext, b"").unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn mismatched_aad_is_rejected() {
        let sealed = seal(&key(), b"secret body", b"header-v1").unwrap();
        let err = open(&key(), &sealed.nonce, &sealed.ciphertext, b"header-v2").unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }

    #[test]
    fn wrong_key_is_rejected() {
        let sealed = seal(&key(), b"secret body", b"").unwrap();
        let other = SecretKey::from_bytes([42u8; KEY_LEN]);
        let err = open(&other, &sealed.nonce, &sealed.ciphertext, b"").unwrap_err();
        assert!(matches!(err, CryptoError::Decrypt));
    }
}
