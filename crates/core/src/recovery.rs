// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shamir secret sharing over GF(256) for threshold recovery.
//!
//! A secret (the master password bytes) is split into `n` shares such that any
//! `k` of them reconstruct it and fewer reveal nothing beyond their length. The
//! share files are printed as small JSON envelopes so guardians can store them
//! as text; combining them yields the master password again.
//!
//! Shamir shares carry no integrity tag: a corrupted share produces a wrong
//! secret rather than an error, which is why the CLI verifies the result by
//! opening the vault before showing it.

use std::collections::HashSet;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use krypton_crypto::{CryptoError, random_bytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Marker written into every share file.
pub const SHARE_TYPE: &str = "krypton-recovery-share";
/// Share format version understood by this build.
pub const VERSION: u32 = 1;
/// Fewest shares that can form a threshold.
pub const MIN_THRESHOLD: u8 = 2;
/// Most shares a single split can produce (indices are one GF(256) byte).
pub const MAX_SHARES: u8 = 255;

/// Failures from splitting, combining or decoding recovery shares.
#[derive(Debug, Error)]
pub enum RecoveryError {
    /// `threshold`/`total` do not describe a usable split.
    #[error("invalid split: need 2 <= threshold <= shares <= 255")]
    InvalidParameters,
    /// Splitting an empty secret is refused.
    #[error("secret must not be empty")]
    EmptySecret,
    /// Fewer shares than the threshold were supplied.
    #[error("need at least {needed} shares to reconstruct, got {got}")]
    TooFewShares {
        /// Threshold recorded in the shares.
        needed: usize,
        /// Number of shares supplied.
        got: usize,
    },
    /// Shares came from different splits.
    #[error("shares disagree on threshold, total or length")]
    MismatchedShares,
    /// The same share index was supplied twice.
    #[error("duplicate share index {0}")]
    DuplicateIndex(u8),
    /// A share index is zero or above the split's total.
    #[error("share index {0} is out of range")]
    InvalidIndex(u8),
    /// The share text is not valid base64.
    #[error("recovery share is not valid base64")]
    Encoding,
    /// The share text is not valid JSON.
    #[error("recovery share is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The text is not a krypton recovery share.
    #[error("unexpected recovery share type: {0}")]
    UnexpectedType(String),
    /// The share uses a newer format.
    #[error("unsupported recovery share version {0}")]
    UnsupportedVersion(u32),
    /// No randomness was available for the polynomial coefficients.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// One point of the polynomial: index plus the evaluated bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// x coordinate, 1-based.
    pub index: u8,
    /// How many shares are needed.
    pub threshold: u8,
    /// How many shares exist in this split.
    pub total: u8,
    /// y coordinates, one per secret byte.
    pub data: Vec<u8>,
}

impl Share {
    /// Serialises the share as a base64 JSON envelope.
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Json`] if serialisation fails.
    pub fn encode(&self) -> Result<String, RecoveryError> {
        let wire = ShareWire {
            kind: SHARE_TYPE.to_string(),
            version: VERSION,
            threshold: self.threshold,
            total: self.total,
            index: self.index,
            data: BASE64.encode(&self.data),
        };
        Ok(BASE64.encode(serde_json::to_vec(&wire)?))
    }

    /// Parses a share produced by [`Share::encode`].
    ///
    /// # Errors
    ///
    /// Returns [`RecoveryError::Encoding`] or [`RecoveryError::Json`] for
    /// malformed text, [`RecoveryError::UnexpectedType`] /
    /// [`RecoveryError::UnsupportedVersion`] for foreign envelopes, and
    /// [`RecoveryError::InvalidParameters`] or [`RecoveryError::InvalidIndex`]
    /// when the header describes an impossible share.
    pub fn decode(text: &str) -> Result<Self, RecoveryError> {
        let raw = BASE64
            .decode(text.trim())
            .map_err(|_| RecoveryError::Encoding)?;
        let wire: ShareWire = serde_json::from_slice(&raw)?;

        if wire.kind != SHARE_TYPE {
            return Err(RecoveryError::UnexpectedType(wire.kind));
        }
        if wire.version != VERSION {
            return Err(RecoveryError::UnsupportedVersion(wire.version));
        }
        if wire.threshold < MIN_THRESHOLD || wire.total < wire.threshold || wire.total < 2 {
            return Err(RecoveryError::InvalidParameters);
        }
        if wire.index == 0 || wire.index > wire.total {
            return Err(RecoveryError::InvalidIndex(wire.index));
        }

        let data = BASE64
            .decode(&wire.data)
            .map_err(|_| RecoveryError::Encoding)?;
        if data.is_empty() {
            return Err(RecoveryError::EmptySecret);
        }

        Ok(Self {
            index: wire.index,
            threshold: wire.threshold,
            total: wire.total,
            data,
        })
    }
}

/// Splits `secret` into `total` shares, any `threshold` of which reconstruct it.
///
/// # Errors
///
/// Returns [`RecoveryError::InvalidParameters`] for an unusable split,
/// [`RecoveryError::EmptySecret`] for an empty secret, and
/// [`RecoveryError::Crypto`] if no randomness is available.
pub fn split(secret: &[u8], threshold: u8, total: u8) -> Result<Vec<Share>, RecoveryError> {
    // total is a u8, so MAX_SHARES is implicit; the constant documents the bound.
    if threshold < MIN_THRESHOLD || total < threshold {
        return Err(RecoveryError::InvalidParameters);
    }
    if secret.is_empty() {
        return Err(RecoveryError::EmptySecret);
    }

    let mut shares: Vec<Share> = (1..=total)
        .map(|index| Share {
            index,
            threshold,
            total,
            data: vec![0u8; secret.len()],
        })
        .collect();

    let mut coefficients = vec![0u8; threshold as usize];
    for (position, byte) in secret.iter().enumerate() {
        coefficients[0] = *byte;
        for coefficient in &mut coefficients[1..] {
            *coefficient = random_bytes::<1>()?[0];
        }

        for share in &mut shares {
            share.data[position] = evaluate(&coefficients, share.index);
        }
    }

    Ok(shares)
}

/// Reconstructs the secret from at least `threshold` shares.
///
/// # Errors
///
/// Returns [`RecoveryError::TooFewShares`] when too few shares are supplied,
/// [`RecoveryError::MismatchedShares`] for shares from different splits,
/// [`RecoveryError::DuplicateIndex`] for repeated coordinates, and
/// [`RecoveryError::InvalidIndex`] for out-of-range coordinates.
pub fn combine(shares: &[Share]) -> Result<Vec<u8>, RecoveryError> {
    let Some(first) = shares.first() else {
        return Err(RecoveryError::TooFewShares { needed: 0, got: 0 });
    };

    let threshold = first.threshold as usize;
    let total = first.total;
    let length = first.data.len();

    if shares.iter().any(|share| {
        share.threshold != first.threshold || share.total != total || share.data.len() != length
    }) {
        return Err(RecoveryError::MismatchedShares);
    }
    if shares.len() < threshold {
        return Err(RecoveryError::TooFewShares {
            needed: threshold,
            got: shares.len(),
        });
    }

    let mut seen = HashSet::new();
    for share in shares {
        if share.index == 0 || share.index > total {
            return Err(RecoveryError::InvalidIndex(share.index));
        }
        if !seen.insert(share.index) {
            return Err(RecoveryError::DuplicateIndex(share.index));
        }
    }

    let used = &shares[..threshold];
    let mut secret = vec![0u8; length];

    for (position, slot) in secret.iter_mut().enumerate() {
        let mut accumulator = 0u8;
        for (i, share) in used.iter().enumerate() {
            let mut numerator = 1u8;
            let mut denominator = 1u8;
            for (j, other) in used.iter().enumerate() {
                if i == j {
                    continue;
                }
                numerator = gf_mul(numerator, other.index);
                denominator = gf_mul(denominator, other.index ^ share.index);
            }
            let inverse = gf_inv(denominator).ok_or(RecoveryError::DuplicateIndex(share.index))?;
            let basis = gf_mul(numerator, inverse);
            accumulator ^= gf_mul(share.data[position], basis);
        }
        *slot = accumulator;
    }

    Ok(secret)
}

fn evaluate(coefficients: &[u8], x: u8) -> u8 {
    let mut value = 0u8;
    let mut power = 1u8;
    for coefficient in coefficients {
        value ^= gf_mul(*coefficient, power);
        power = gf_mul(power, x);
    }
    value
}

/// GF(256) multiplication with the AES polynomial `x^8 + x^4 + x^3 + x + 1`.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high_bit = a & 0x80;
        a <<= 1;
        if high_bit != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

fn gf_pow(mut base: u8, mut exponent: u8) -> u8 {
    let mut result = 1u8;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

fn gf_inv(value: u8) -> Option<u8> {
    if value == 0 {
        None
    } else {
        Some(gf_pow(value, 254))
    }
}

#[derive(Serialize, Deserialize)]
struct ShareWire {
    #[serde(rename = "type")]
    kind: String,
    version: u32,
    threshold: u8,
    total: u8,
    index: u8,
    data: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"correct horse battery staple";

    #[test]
    fn any_threshold_subset_reconstructs_the_secret() {
        let shares = split(SECRET, 3, 5).unwrap();

        for a in 0..5 {
            for b in (a + 1)..5 {
                for c in (b + 1)..5 {
                    let subset = [shares[a].clone(), shares[b].clone(), shares[c].clone()];
                    assert_eq!(combine(&subset).unwrap(), SECRET, "subset {a},{b},{c}");
                }
            }
        }
    }

    #[test]
    fn more_than_threshold_shares_are_fine() {
        let shares = split(SECRET, 2, 5).unwrap();
        assert_eq!(combine(&shares).unwrap(), SECRET);
    }

    #[test]
    fn every_share_differs_from_the_secret() {
        let shares = split(SECRET, 3, 5).unwrap();
        for share in &shares {
            assert_ne!(share.data, SECRET);
        }
        assert_eq!(shares.len(), 5);
        assert_eq!(shares[0].index, 1);
        assert_eq!(shares[4].index, 5);
    }

    #[test]
    fn too_few_shares_are_rejected() {
        let shares = split(SECRET, 3, 5).unwrap();
        let err = combine(&shares[..2]).unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::TooFewShares { needed: 3, got: 2 }
        ));
    }

    #[test]
    fn duplicate_shares_are_rejected() {
        let shares = split(SECRET, 2, 3).unwrap();
        let duplicates = [shares[0].clone(), shares[0].clone()];
        assert!(matches!(
            combine(&duplicates),
            Err(RecoveryError::DuplicateIndex(1))
        ));
    }

    #[test]
    fn mixed_splits_are_rejected() {
        let first = split(SECRET, 2, 3).unwrap();
        let second = split(b"another secret", 2, 3).unwrap();
        let mixed = [first[0].clone(), second[1].clone()];
        // Same parameters and length? No: lengths differ here, so this is a
        // mismatch rather than silent garbage.
        assert!(matches!(
            combine(&mixed),
            Err(RecoveryError::MismatchedShares)
        ));
    }

    #[test]
    fn corrupted_share_yields_a_wrong_secret() {
        let mut shares = split(SECRET, 2, 3).unwrap();
        shares[0].data[0] ^= 0xff;
        let secret = combine(&shares[..2]).unwrap();
        assert_ne!(secret, SECRET);
    }

    #[test]
    fn shares_round_trip_through_their_envelope() {
        let shares = split(SECRET, 3, 5).unwrap();
        for share in &shares {
            let encoded = share.encode().unwrap();
            assert_eq!(Share::decode(&encoded).unwrap(), *share);
        }
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        assert!(matches!(
            split(SECRET, 1, 3),
            Err(RecoveryError::InvalidParameters)
        ));
        assert!(matches!(
            split(SECRET, 4, 3),
            Err(RecoveryError::InvalidParameters)
        ));
        assert!(matches!(split(b"", 2, 3), Err(RecoveryError::EmptySecret)));
    }

    #[test]
    fn malformed_envelopes_are_rejected() {
        assert!(matches!(
            Share::decode("not base64!!"),
            Err(RecoveryError::Encoding)
        ));
        assert!(matches!(
            Share::decode(&BASE64.encode(b"hello")),
            Err(RecoveryError::Json(_))
        ));

        let shares = split(SECRET, 2, 3).unwrap();
        let mut wire: serde_json::Value =
            serde_json::from_slice(&BASE64.decode(shares[0].encode().unwrap()).unwrap()).unwrap();
        wire["type"] = serde_json::Value::from("krypton-share");
        let foreign = BASE64.encode(serde_json::to_vec(&wire).unwrap());
        assert!(matches!(
            Share::decode(&foreign),
            Err(RecoveryError::UnexpectedType(_))
        ));

        wire["type"] = serde_json::Value::from(SHARE_TYPE);
        wire["index"] = serde_json::Value::from(9);
        let out_of_range = BASE64.encode(serde_json::to_vec(&wire).unwrap());
        assert!(matches!(
            Share::decode(&out_of_range),
            Err(RecoveryError::InvalidIndex(9))
        ));
    }

    #[test]
    fn gf_inverse_round_trips() {
        for value in 1..=255u8 {
            let inverse = gf_inv(value).unwrap();
            assert_eq!(gf_mul(value, inverse), 1, "value {value}");
        }
        assert!(gf_inv(0).is_none());
    }
}
