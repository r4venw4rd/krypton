// SPDX-License-Identifier: AGPL-3.0-or-later
//! Password generation.
//!
//! Characters come from the OS CSPRNG with rejection sampling, so no modulo
//! bias creeps in, and the result always contains at least one character from
//! every enabled class.

use krypton_crypto::{CryptoError, random_bytes};
use thiserror::Error;

/// Length used when the caller does not ask for a specific one.
pub const DEFAULT_LENGTH: usize = 24;
/// Upper bound that keeps generated secrets within printable ASCII.
pub const MAX_LENGTH: usize = 256;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{}:,.?/";

/// Failures from password generation.
#[derive(Debug, Error)]
pub enum PasswordError {
    /// The requested length cannot hold one character per class.
    #[error("password length must be at least {min}")]
    TooShort {
        /// Smallest length that satisfies every enabled class.
        min: usize,
    },
    /// The requested length is above [`MAX_LENGTH`].
    #[error("password length must be at most {MAX_LENGTH}")]
    TooLong,
    /// The OS CSPRNG was unavailable.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Generates a random password of `length` characters.
///
/// # Errors
///
/// Returns [`PasswordError::TooShort`] when `length` is smaller than the number
/// of enabled classes, [`PasswordError::TooLong`] above [`MAX_LENGTH`], and
/// [`PasswordError::Crypto`] if the OS CSPRNG fails.
pub fn generate(length: usize, include_symbols: bool) -> Result<String, PasswordError> {
    let classes: Vec<&[u8]> = if include_symbols {
        vec![LOWER, UPPER, DIGITS, SYMBOLS]
    } else {
        vec![LOWER, UPPER, DIGITS]
    };

    if length < classes.len() {
        return Err(PasswordError::TooShort { min: classes.len() });
    }
    if length > MAX_LENGTH {
        return Err(PasswordError::TooLong);
    }

    let mut chars: Vec<char> = Vec::with_capacity(length);
    for class in &classes {
        chars.push(pick(class)?);
    }

    let pool: Vec<u8> = classes.concat();
    while chars.len() < length {
        chars.push(pick(&pool)?);
    }

    shuffle(&mut chars)?;
    Ok(chars.into_iter().collect())
}

fn pick(alphabet: &[u8]) -> Result<char, PasswordError> {
    let index = random_index(alphabet.len())?;
    // Alphabets are ASCII, so indexing is safe and conversion cannot fail.
    Ok(char::from(alphabet[index]))
}

/// Uniform index in `0..bound`, rejecting the biased tail of the u32 range.
fn random_index(bound: usize) -> Result<usize, PasswordError> {
    let bound = u32::try_from(bound).map_err(|_| PasswordError::TooLong)?;
    let limit = (u32::MAX / bound) * bound;

    loop {
        let value = u32::from_le_bytes(random_bytes::<4>()?);
        if value < limit {
            return Ok((value % bound) as usize);
        }
    }
}

fn shuffle(chars: &mut [char]) -> Result<(), PasswordError> {
    for i in (1..chars.len()).rev() {
        let j = random_index(i + 1)?;
        chars.swap(i, j);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respects_the_requested_length() {
        assert_eq!(generate(24, true).unwrap().len(), 24);
        assert_eq!(generate(8, false).unwrap().len(), 8);
        assert_eq!(generate(MAX_LENGTH, true).unwrap().len(), MAX_LENGTH);
    }

    #[test]
    fn includes_every_enabled_class() {
        for _ in 0..50 {
            let password = generate(8, true).unwrap();
            assert!(
                password.chars().any(|c| c.is_ascii_lowercase()),
                "{password}"
            );
            assert!(
                password.chars().any(|c| c.is_ascii_uppercase()),
                "{password}"
            );
            assert!(password.chars().any(|c| c.is_ascii_digit()), "{password}");
            assert!(
                password.chars().any(|c| !c.is_ascii_alphanumeric()),
                "{password}"
            );
        }
    }

    #[test]
    fn symbols_can_be_excluded() {
        for _ in 0..50 {
            let password = generate(12, false).unwrap();
            assert!(
                password.chars().all(|c| c.is_ascii_alphanumeric()),
                "{password}"
            );
        }
    }

    #[test]
    fn consecutive_passwords_differ() {
        let first = generate(16, true).unwrap();
        let second = generate(16, true).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn rejects_impossible_lengths() {
        assert!(matches!(
            generate(2, true),
            Err(PasswordError::TooShort { min: 4 })
        ));
        assert!(matches!(
            generate(2, false),
            Err(PasswordError::TooShort { min: 3 })
        ));
        assert!(matches!(
            generate(MAX_LENGTH + 1, true),
            Err(PasswordError::TooLong)
        ));
    }

    #[test]
    fn characters_stay_in_the_expected_alphabet() {
        let password = generate(64, true).unwrap();
        let allowed: Vec<char> = [LOWER, UPPER, DIGITS, SYMBOLS]
            .concat()
            .iter()
            .map(|byte| char::from(*byte))
            .collect();
        assert!(password.chars().all(|c| allowed.contains(&c)), "{password}");
    }
}
