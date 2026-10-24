// SPDX-License-Identifier: AGPL-3.0-or-later
//! RFC 6238 TOTP generation and validation (SHA-1, 6 digits, 30 seconds).
//!
//! Secrets are stored base32 as authenticator apps export them; spaces and
//! hyphens are ignored and padding is optional.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use thiserror::Error;

type HmacSha1 = Hmac<Sha1>;

/// Time step in seconds, as mandated by the RFC 6238 default profile.
pub const PERIOD: u64 = 30;
/// Number of digits in a generated code.
pub const DIGITS: u32 = 6;

/// Failures from decoding a stored TOTP secret.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TotpError {
    /// The stored secret has no characters left after normalisation.
    #[error("TOTP secret is empty")]
    EmptySecret,
    /// The stored secret is not decodable base32.
    #[error("TOTP secret is not valid base32")]
    InvalidSecret,
    /// HMAC could not be initialised; should not happen for SHA-1.
    #[error("could not initialise the HMAC")]
    Hmac,
}

/// Seconds left in the current time step.
#[must_use]
pub const fn seconds_remaining(unix_time: u64) -> u64 {
    PERIOD - (unix_time % PERIOD)
}

/// Generates the code for `unix_time`.
///
/// # Errors
///
/// Returns [`TotpError::EmptySecret`] or [`TotpError::InvalidSecret`] when the
/// stored secret is unusable, and [`TotpError::Hmac`] if HMAC setup fails.
pub fn generate(secret: &str, unix_time: u64) -> Result<String, TotpError> {
    let key = decode_secret(secret)?;
    let counter = unix_time / PERIOD;

    let mut mac = HmacSha1::new_from_slice(&key).map_err(|_| TotpError::Hmac)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let binary = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;

    let code = binary % 10u32.pow(DIGITS);
    Ok(format!("{code:0width$}", width = DIGITS as usize))
}

/// Checks `code` against the steps in `[unix_time - window, unix_time + window]`,
/// which is what a small clock skew between devices needs.
#[must_use]
pub fn verify(secret: &str, unix_time: u64, code: &str, window: u32) -> bool {
    let code = code.trim().replace(' ', "");
    if code.len() != DIGITS as usize || !code.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }

    let current = unix_time / PERIOD;
    for step in 0..=u64::from(window) {
        let candidates = [
            (current + step) * PERIOD,
            current * PERIOD,
            current.saturating_sub(step) * PERIOD,
        ];

        for shifted in candidates {
            match generate(secret, shifted) {
                Ok(candidate) if candidate == code => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    }
    false
}

fn decode_secret(secret: &str) -> Result<Vec<u8>, TotpError> {
    let normalized: String = secret
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    if normalized.is_empty() {
        return Err(TotpError::EmptySecret);
    }

    base32::decode(base32::Alphabet::Rfc4648 { padding: false }, &normalized)
        .or_else(|| base32::decode(base32::Alphabet::Rfc4648 { padding: true }, &normalized))
        .filter(|bytes| !bytes.is_empty())
        .ok_or(TotpError::InvalidSecret)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 appendix B seed: "12345678901234567890".
    const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn matches_rfc_6238_vectors_truncated_to_six_digits() {
        // (unix time, last six digits of the RFC's eight-digit value)
        let vectors = [
            (59u64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000, "353130"),
        ];

        for (time, expected) in vectors {
            assert_eq!(generate(SEED, time).unwrap(), expected, "time {time}");
        }
    }

    #[test]
    fn accepts_lowercase_spaced_and_padded_secrets() {
        let spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq";
        let padded = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====";
        assert_eq!(generate(spaced, 59).unwrap(), "287082");
        assert_eq!(generate(padded, 59).unwrap(), "287082");
    }

    #[test]
    fn verify_accepts_current_step_and_one_step_skew() {
        assert!(verify(SEED, 59, "287082", 1));
        // The same step, 2 seconds after the vector's timestamp.
        assert!(verify(SEED, 31, "287082", 0));
        // The next step needs a window: at T=89 the counter has moved on.
        assert!(!verify(SEED, 89, "287082", 0));
        // Previous step (T=29) is 755224; accepted only with a window of 1.
        assert!(verify(SEED, 59, "755224", 1));
        assert!(!verify(SEED, 59, "755224", 0));
        // Two steps back is outside a window of 1 (t=119 -> counter 3,
        // the code above belongs to counter 1).
        assert!(!verify(SEED, 119, "755224", 1));
    }

    #[test]
    fn verify_rejects_malformed_codes() {
        assert!(!verify(SEED, 59, "", 1));
        assert!(!verify(SEED, 59, "2870", 1));
        assert!(!verify(SEED, 59, "abcdef", 1));
        assert!(!verify(SEED, 59, "2870821", 1));
    }

    #[test]
    fn invalid_secret_is_reported() {
        assert_eq!(generate("", 59).unwrap_err(), TotpError::EmptySecret);
        assert_eq!(
            generate("not-base32!!", 59).unwrap_err(),
            TotpError::InvalidSecret
        );
    }

    #[test]
    fn seconds_remaining_counts_down_within_the_step() {
        assert_eq!(seconds_remaining(0), 30);
        assert_eq!(seconds_remaining(1), 29);
        assert_eq!(seconds_remaining(29), 1);
        assert_eq!(seconds_remaining(30), 30);
    }
}
