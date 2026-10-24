// SPDX-License-Identifier: AGPL-3.0-or-later
//! Master-password key derivation.
//!
//! Argon2id with 64 MiB / 3 passes / 1 lane by default. The parameters are
//! stored in the vault header next to the salt, so a vault stays readable after
//! the defaults are raised later.

use serde::{Deserialize, Serialize};

use crate::{CryptoError, KEY_LEN, SecretKey};

/// Argon2id salt length in bytes.
pub const SALT_LEN: usize = 16;

/// Identifier written into the vault header.
pub const ALGORITHM: &str = "argon2id";

/// Argon2id cost parameters as persisted in the vault header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Human-readable algorithm identifier; only `argon2id` is accepted today.
    pub algorithm: String,
    /// Memory cost in kibibytes.
    pub memory_kib: u32,
    /// Number of passes over the memory.
    pub iterations: u32,
    /// Degree of parallelism (lanes).
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            algorithm: ALGORITHM.to_string(),
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfParams {
    /// Cheap parameters for tests only. Never use these for a real vault.
    #[doc(hidden)]
    pub fn weak_for_tests() -> Self {
        Self {
            algorithm: ALGORITHM.to_string(),
            memory_kib: 8,
            iterations: 1,
            parallelism: 1,
        }
    }
}

/// Derives the vault key from the master password and salt.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<SecretKey, CryptoError> {
    if salt.len() != SALT_LEN {
        return Err(CryptoError::InvalidSalt);
    }
    if params.algorithm != ALGORITHM {
        return Err(CryptoError::UnsupportedAlgorithm(params.algorithm.clone()));
    }

    let argon_params = argon2::Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEY_LEN),
    )?;
    let argon2 = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon_params,
    );

    let mut key = [0u8; KEY_LEN];
    argon2.hash_password_into(password, salt, &mut key)?;
    Ok(SecretKey::from_bytes(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivation_is_deterministic() {
        let params = KdfParams::weak_for_tests();
        let salt = [1u8; SALT_LEN];
        let a = derive_key(b"correct horse", &salt, &params).unwrap();
        let b = derive_key(b"correct horse", &salt, &params).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_salt_yields_different_key() {
        let params = KdfParams::weak_for_tests();
        let a = derive_key(b"correct horse", &[1u8; SALT_LEN], &params).unwrap();
        let b = derive_key(b"correct horse", &[2u8; SALT_LEN], &params).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_password_yields_different_key() {
        let params = KdfParams::weak_for_tests();
        let salt = [3u8; SALT_LEN];
        let a = derive_key(b"password-a", &salt, &params).unwrap();
        let b = derive_key(b"password-b", &salt, &params).unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn rejects_wrong_salt_length() {
        let err = derive_key(b"pw", &[0u8; 8], &KdfParams::weak_for_tests()).unwrap_err();
        assert!(matches!(err, CryptoError::InvalidSalt));
    }

    #[test]
    fn rejects_unknown_algorithm() {
        let params = KdfParams {
            algorithm: "scrypt".to_string(),
            ..KdfParams::weak_for_tests()
        };
        let err = derive_key(b"pw", &[0u8; SALT_LEN], &params).unwrap_err();
        assert!(matches!(err, CryptoError::UnsupportedAlgorithm(_)));
    }
}
